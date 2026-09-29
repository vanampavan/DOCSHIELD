"""DocShield AI backend: real crypto, auth, step-up verification, encrypted storage, expiring shares, audit log."""
import smtplib, ssl, os, re, io, json, time, uuid, hmac, base64, hashlib, secrets, sqlite3, datetime as dt
from functools import wraps
from email.message import EmailMessage
from flask import Flask, g, request, jsonify, send_file, abort
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pyotp

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.environ.get("DOCSHIELD_DATA", os.path.join(BASE, "data"))
os.makedirs(os.path.join(DATA, "vault"), exist_ok=True)

def _key(name, env):  # real deployments: inject from KMS/secret manager via env
    if os.environ.get(env): return base64.b64decode(os.environ[env])
    p = os.path.join(DATA, name)
    if not os.path.exists(p):
        with os.fdopen(os.open(p, os.O_WRONLY | os.O_CREAT, 0o600), "wb") as f: f.write(os.urandom(32))
    return open(p, "rb").read()
MK, SECRET = _key(".master", "DOCSHIELD_MASTER_KEY"), _key(".secret", "DOCSHIELD_TOKEN_SECRET")
ACCESS_TTL, STEPUP_TTL, REFRESH_TTL, MAX_BYTES = 900, 300, 30 * 86400, 5 * 1024 * 1024
MAGIC = {"pdf": b"%PDF", "png": b"\x89PNG", "jpg": b"\xff\xd8\xff", "jpeg": b"\xff\xd8\xff"}
ph = PasswordHasher()  # Argon2id
app = Flask(__name__); app.config["MAX_CONTENT_LENGTH"] = MAX_BYTES + 4096
DB = os.path.join(DATA, "docshield.db")
SCHEMA = """CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,name TEXT,email TEXT UNIQUE,pw TEXT,totp TEXT,mfa INT DEFAULT 0,failed INT DEFAULT 0,locked REAL DEFAULT 0);
CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY,uid TEXT,rh TEXT,device TEXT,created REAL,seen REAL,revoked INT DEFAULT 0);
CREATE TABLE IF NOT EXISTS docs(id TEXT PRIMARY KEY,uid TEXT,name TEXT,cat TEXT,ext TEXT,mime TEXT,size INT,blob TEXT,wk BLOB,meta TEXT,created REAL);
CREATE TABLE IF NOT EXISTS shares(id TEXT PRIMARY KEY,doc TEXT,uid TEXT,rcpt TEXT,perm TEXT,th TEXT UNIQUE,exp REAL,revoked INT DEFAULT 0,created REAL);
CREATE TABLE IF NOT EXISTS challenges(id INTEGER PRIMARY KEY AUTOINCREMENT,th TEXT,ch TEXT,ts REAL,exp REAL,tries INT DEFAULT 0);
CREATE TABLE IF NOT EXISTS logs(id INTEGER PRIMARY KEY AUTOINCREMENT,uid TEXT,ts REAL,action TEXT,doc TEXT,actor TEXT);"""

OUTBOX = []  # dev only (DOCSHIELD_DEV=1): lets tests read codes instead of sending mail
def send_mail(to, subject, body):
    if os.environ.get("DOCSHIELD_DEV") == "1": OUTBOX.append((to, subject, body)); return
    if not os.environ.get("SMTP_HOST"): raise RuntimeError("SMTP not configured")
    m = EmailMessage(); m["From"], m["To"], m["Subject"] = os.environ.get("MAIL_FROM", os.environ.get("SMTP_USER", "no-reply@docshield.local")), to, subject; m.set_content(body)
    with smtplib.SMTP(os.environ["SMTP_HOST"], int(os.environ.get("SMTP_PORT", 587)), timeout=15) as s:
        s.starttls(context=ssl.create_default_context()); os.environ.get("SMTP_USER") and s.login(os.environ["SMTP_USER"], os.environ.get("SMTP_PASS", "")); s.send_message(m)
def hint(e): u, d = e.split("@"); return u[0] + "***@" + d
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB); g.db.row_factory = sqlite3.Row; g.db.executescript(SCHEMA)
    return g.db
@app.teardown_appcontext
def _close(_):
    d = g.pop("db", None); d and d.close()
def q(sql, *a): return db().execute(sql, a)
def commit(): db().commit()
def log(uid, action, doc=None, actor="owner"):  # never log document content or identifiers
    q("INSERT INTO logs(uid,ts,action,doc,actor) VALUES(?,?,?,?,?)", uid, time.time(), action, doc, actor); commit()
PAGE_CSP = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' blob: data:; frame-src blob:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
INDEX = os.path.join(BASE, "static", "index.html")
@app.get("/")
def index(): return send_file(INDEX)
@app.after_request
def _hdr(r):
    r.headers.update({"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store", "Referrer-Policy": "no-referrer",
                      "Content-Security-Policy": PAGE_CSP if r.mimetype == "text/html" else "default-src 'none'; frame-ancestors 'none'"}); return r

# ---- tokens (HMAC-signed, short-lived) ----
def sign(p):
    b = base64.urlsafe_b64encode(json.dumps(p).encode()).decode().rstrip("=")
    return b + "." + hmac.new(SECRET, b.encode(), "sha256").hexdigest()
def unsign(t):
    try:
        b, s = t.split(".")
        if not hmac.compare_digest(s, hmac.new(SECRET, b.encode(), "sha256").hexdigest()): return None
        p = json.loads(base64.urlsafe_b64decode(b + "=" * (-len(b) % 4)))
        return p if p["exp"] > time.time() else None
    except Exception: return None
def err(msg, code): return jsonify(error=msg), code
def auth(f):
    @wraps(f)
    def w(*a, **k):
        p = unsign(request.headers.get("Authorization", "")[7:]); s = p and q("SELECT * FROM sessions WHERE id=? AND revoked=0", p.get("sid")).fetchone()
        if not p or p.get("typ") != "a" or not s: return err("For your security, please sign in again.", 401)
        g.uid, g.sid = p["sub"], p["sid"]; q("UPDATE sessions SET seen=? WHERE id=?", time.time(), g.sid); commit(); return f(*a, **k)
    return w
def stepup(f):  # sensitive actions need a fresh re-authentication token bound to this user+session
    @wraps(f)
    def w(*a, **k):
        p = unsign(request.headers.get("X-Step-Up", ""))
        if not p or p.get("typ") != "s" or p["sub"] != g.uid or p["sid"] != g.sid: return err("Please confirm it's you to continue.", 403)
        return f(*a, **k)
    return w
def issue(uid, device):
    sid, rt = uuid.uuid4().hex, secrets.token_urlsafe(32)
    q("INSERT INTO sessions VALUES(?,?,?,?,?,?,0)", sid, uid, hashlib.sha256(rt.encode()).hexdigest(), device, time.time(), time.time()); commit()
    return {"access": sign({"typ": "a", "sub": uid, "sid": sid, "exp": time.time() + ACCESS_TTL}), "refresh": sid + "." + rt}

# ---- account ----
@app.post("/api/register")
def register():
    j = request.get_json(force=True, silent=True) or {}; name, email, pw = j.get("name", "").strip(), j.get("email", "").strip().lower(), j.get("password", "")
    if not name or not re.match(r"^[^@\s]+@[^@\s]+\.\w+$", email): return err("Enter your name and a valid email.", 400)
    if len(pw) < 10 or not re.search(r"\d", pw) or not re.search(r"[A-Za-z]", pw): return err("Use at least 10 characters with letters and numbers.", 400)
    if q("SELECT 1 FROM users WHERE email=?", email).fetchone(): return err("That email can't be used. Try signing in.", 409)
    uid, sec = uuid.uuid4().hex, pyotp.random_base32()
    q("INSERT INTO users(id,name,email,pw,totp) VALUES(?,?,?,?,?)", uid, name, email, ph.hash(pw), sec); commit(); log(uid, "Account created")
    return jsonify(totp_uri=pyotp.TOTP(sec).provisioning_uri(email, "DocShield AI"), next="POST /api/mfa/verify with a code from your authenticator"), 201
@app.post("/api/mfa/verify")
def mfa_verify():
    j = request.get_json(force=True, silent=True) or {}; u = q("SELECT * FROM users WHERE email=?", j.get("email", "").lower()).fetchone()
    if not u or not ph_check(u, j.get("password", "")) or not pyotp.TOTP(u["totp"]).verify(str(j.get("code", "")), valid_window=1): return err("That code didn't work. Check the time on your device and try again.", 400)
    q("UPDATE users SET mfa=1 WHERE id=?", u["id"]); commit(); log(u["id"], "MFA enabled"); return jsonify(ok=True)
def ph_check(u, pw):
    try: return ph.verify(u["pw"], pw)
    except VerifyMismatchError: return False
@app.post("/api/login")
def login():
    j = request.get_json(force=True, silent=True) or {}; u = q("SELECT * FROM users WHERE email=?", j.get("email", "").lower()).fetchone()
    if u and u["locked"] > time.time(): return err("Too many attempts. Try again in a few minutes.", 429)
    ok = u and ph_check(u, j.get("password", "")) and (not u["mfa"] or pyotp.TOTP(u["totp"]).verify(str(j.get("code", "")), valid_window=1))
    if not ok:
        if u:
            f = u["failed"] + 1; q("UPDATE users SET failed=?,locked=? WHERE id=?", f, time.time() + 300 if f >= 5 else 0, u["id"]); commit(); log(u["id"], "Failed sign-in")
        return err("Email, password or code is incorrect.", 401)
    q("UPDATE users SET failed=0,locked=0 WHERE id=?", u["id"]); commit(); log(u["id"], "Signed in")
    return jsonify(issue(u["id"], (request.headers.get("User-Agent") or "Unknown")[:80]))
@app.post("/api/refresh")  # rotation: each refresh token works once; reuse revokes the session
def refresh():
    try: sid, rt = (request.get_json(force=True).get("refresh") or "").split(".", 1)
    except Exception: return err("For your security, please sign in again.", 401)
    s = q("SELECT * FROM sessions WHERE id=? AND revoked=0", sid).fetchone()
    if not s or time.time() - s["created"] > REFRESH_TTL: return err("For your security, please sign in again.", 401)
    if not hmac.compare_digest(s["rh"], hashlib.sha256(rt.encode()).hexdigest()):
        q("UPDATE sessions SET revoked=1 WHERE id=?", sid); commit(); log(s["uid"], "Refresh token reuse: session revoked"); return err("For your security, please sign in again.", 401)
    new = secrets.token_urlsafe(32); q("UPDATE sessions SET rh=? WHERE id=?", hashlib.sha256(new.encode()).hexdigest(), sid); commit()
    return jsonify(access=sign({"typ": "a", "sub": s["uid"], "sid": sid, "exp": time.time() + ACCESS_TTL}), refresh=sid + "." + new)
@app.post("/api/logout")
@auth
def logout(): q("UPDATE sessions SET revoked=1 WHERE id=?", g.sid); commit(); log(g.uid, "Signed out"); return jsonify(ok=True)
@app.post("/api/reauth")
@auth
def reauth():
    j = request.get_json(force=True, silent=True) or {}; u = q("SELECT * FROM users WHERE id=?", g.uid).fetchone()
    if not (ph_check(u, j.get("password", "")) and (not u["mfa"] or pyotp.TOTP(u["totp"]).verify(str(j.get("code", "")), valid_window=1))): log(g.uid, "Failed re-authentication"); return err("That didn't match. Try again.", 401)
    return jsonify(step_up=sign({"typ": "s", "sub": g.uid, "sid": g.sid, "exp": time.time() + STEPUP_TTL}), expires_in=STEPUP_TTL)
@app.get("/api/sessions")
@auth
def sessions():
    return jsonify([dict(id=r["id"], device=r["device"], last_active=r["seen"], current=r["id"] == g.sid) for r in q("SELECT * FROM sessions WHERE uid=? AND revoked=0", g.uid)])
@app.delete("/api/sessions/<sid>")
@auth
def kill(sid): q("UPDATE sessions SET revoked=1 WHERE id=? AND uid=?", sid, g.uid); commit(); log(g.uid, "Session signed out"); return jsonify(ok=True)
@app.post("/api/sessions/revoke-others")
@auth
def kill_others(): q("UPDATE sessions SET revoked=1 WHERE uid=? AND id<>?", g.uid, g.sid); commit(); log(g.uid, "Signed out other devices"); return jsonify(ok=True)

# ---- encryption + analysis ----
def encrypt(data, did):
    dek, n, wn = AESGCM.generate_key(256), os.urandom(12), os.urandom(12)  # per-document key, wrapped by the master key
    return n + AESGCM(dek).encrypt(n, data, did.encode()), wn + AESGCM(MK).encrypt(wn, dek, did.encode())
def decrypt(blob, wk, did):
    dek = AESGCM(MK).decrypt(wk[:12], wk[12:], did.encode()); return AESGCM(dek).decrypt(blob[:12], blob[12:], did.encode())
def extract_text(data, ext):
    try:
        if ext == "pdf":
            from pypdf import PdfReader; return "\n".join(p.extract_text() or "" for p in PdfReader(io.BytesIO(data)).pages)
        import pytesseract; from PIL import Image; return pytesseract.image_to_string(Image.open(io.BytesIO(data)))  # optional OCR
    except Exception: return ""
MON = "jan feb mar apr may jun jul aug sep oct nov dec".split()
def parse_date(s):
    m = re.search(r"(\d{1,2})[/-](\d{1,2})[/-](\d{4})", s) or re.search(r"(\d{1,2})\s+([A-Za-z]{3})[a-z]*\.?,?\s+(\d{4})", s)
    if not m: return None
    d, mo, y = m.groups(); mo = int(mo) if mo.isdigit() else MON.index(mo.lower()) + 1 if mo.lower() in MON else 0
    try: return dt.date(int(y), mo, int(d)).isoformat()
    except ValueError: return None
def analyze(text, cat):
    ev, checks, t = {}, [], text.strip()
    checks.append({"ok": bool(t), "label": "Document readable", "evidence": f"{len(t)} characters read" if t else "No text could be read; try a clearer file"})
    if not t: return {"checks": checks, "name": None, "expiry": None, "masked": None, "type": None, "note": "Document couldn't be read. Try a clearer image or PDF."}
    typ = next((k for k, w in {"Aadhaar": "aadhaar", "PAN": "permanent account", "Degree": "degree", "Income Certificate": "income", "Passport": "passport", "Insurance": "insurance"}.items() if w in t.lower()), None)
    nm = re.search(r"(?:name|holder)\s*[:\-]\s*([A-Z][A-Za-z.' ]{1,60})", t, re.I); name = nm.group(1).strip() if nm else None
    ex = re.search(r"(?:valid until|valid upto|expiry|expires?|expiration)[^\n\d]{0,20}([^\n]{0,30})", t, re.I); expiry = parse_date(ex.group(1)) if ex else None
    aad = re.search(r"\b(\d{4})\s?(\d{4})\s?(\d{4})\b", t); pan = re.search(r"\b[A-Z]{5}\d{4}[A-Z]\b", t)
    masked = f"XXXX XXXX {aad.group(3)}" if aad else (f"XXXXX{pan.group()[5:]}" if pan else None)  # only masked form is stored
    checks += [{"ok": bool(typ), "label": "Document type identified", "evidence": typ or "No known type keywords found"},
               {"ok": bool(name), "label": "Name detected", "evidence": bool(name) and "Name field found" or "No name field found"},
               {"ok": bool(expiry), "label": "Expiry date detected", "evidence": expiry or "No expiry date detected"}]
    return {"checks": checks, "name": name, "expiry": expiry, "masked": masked, "type": typ,
            "note": "Official authenticity could not be independently confirmed. These are automated checks, not a legal verdict."}
def expiry_status(e):
    if not e: return "No expiry date detected"
    d = (dt.date.fromisoformat(e) - dt.date.today()).days
    return "Expired" if d < 0 else f"Expires in {d} days" if d <= 60 else "Valid"
def view(r):
    m = json.loads(r["meta"]); return dict(id=r["id"], name=r["name"], category=r["cat"], size=r["size"], created=r["created"], masked_id=m.get("masked"),
                                          status=expiry_status(m.get("expiry")), expiry=m.get("expiry"), analysis=m)

# ---- documents ----
@app.post("/api/documents")
@auth
def upload():
    f = request.files.get("file")
    if not f: return err("Choose a file to upload.", 400)
    ext = (f.filename.rsplit(".", 1)[-1] if "." in f.filename else "").lower(); data = f.read(MAX_BYTES + 1)
    if ext not in MAGIC: return err("Unsupported file. Upload a PDF, JPG or PNG.", 415)
    if len(data) > MAX_BYTES: return err("File is too large. Choose one under 5 MB.", 413)
    if not data.startswith(MAGIC[ext]): return err("This file's contents don't match its type. Try another file.", 415)
    did = uuid.uuid4().hex; blob, wk = encrypt(data, did)
    path = os.path.join(DATA, "vault", did + ".bin"); open(path, "wb").write(blob)  # server-generated name, never executed
    a = analyze(extract_text(data, ext), request.form.get("category", "Other"))
    q("INSERT INTO docs VALUES(?,?,?,?,?,?,?,?,?,?,?)", did, g.uid, re.sub(r"[^\w .-]", "", f.filename.rsplit(".", 1)[0])[:60] or "Document",
      request.form.get("category", "Other")[:30], ext, "application/pdf" if ext == "pdf" else "image/" + ("png" if ext == "png" else "jpeg"), len(data), path, wk, json.dumps(a), time.time())
    commit(); log(g.uid, "Uploaded", did); return jsonify(view(q("SELECT * FROM docs WHERE id=?", did).fetchone())), 201
def own(did):
    r = q("SELECT * FROM docs WHERE id=? AND uid=?", did, g.uid).fetchone()
    if not r: abort(404)
    return r
@app.get("/api/documents")
@auth
def listdocs(): return jsonify([view(r) for r in q("SELECT * FROM docs WHERE uid=? ORDER BY created DESC", g.uid)])
@app.get("/api/documents/<did>")
@auth
def one(did): return jsonify(view(own(did)))
def stream(r, disp):
    data = decrypt(open(r["blob"], "rb").read(), r["wk"], r["id"])
    return send_file(io.BytesIO(data), mimetype=r["mime"], as_attachment=disp == "attachment", download_name=f'{r["name"]}.{r["ext"]}')
@app.get("/api/documents/<did>/content")
@auth
@stepup
def content(did): r = own(did); log(g.uid, "Viewed", did); return stream(r, "inline")
@app.get("/api/documents/<did>/download")
@auth
@stepup
def download(did): r = own(did); log(g.uid, "Downloaded", did); return stream(r, "attachment")
@app.delete("/api/documents/<did>")
@auth
@stepup
def delete(did):
    r = own(did); os.path.exists(r["blob"]) and os.remove(r["blob"])
    q("DELETE FROM docs WHERE id=?", did); q("UPDATE shares SET revoked=1 WHERE doc=?", did); commit(); log(g.uid, "Deleted", did); return jsonify(ok=True)
@app.get("/api/consistency")  # cross-document check; reports differences, never declares fraud
def _c(): return consistency()
@auth
def consistency():
    names = {}
    for r in q("SELECT id,name,meta FROM docs WHERE uid=?", g.uid):
        n = json.loads(r["meta"]).get("name")
        if n: names.setdefault(re.sub(r"[^a-z ]", "", n.lower()).strip(), []).append({"doc": r["name"], "reads": n})
    return jsonify(possible_inconsistency=len(names) > 1, variants=names, message="Two documents contain different versions of the name. This isn't proof of a problem." if len(names) > 1 else "Names match across documents.")

# ---- sharing ----
@app.post("/api/documents/<did>/share")
@auth
@stepup
def share(did):
    r = own(did); j = request.get_json(force=True, silent=True) or {}; rc = str(j.get("recipient", "")).strip()
    ttl = min(max(int(j.get("ttl_minutes", 1440)), 1), 60 * 24 * 30); perm = "download" if j.get("permission") == "download" else "view"
    if not re.match(r"^[^@\s]+@[^@\s]+\.\w+$", rc): return err("Enter the recipient's email address so we can verify who opens it.", 400)
    tok = secrets.token_urlsafe(32); sid = uuid.uuid4().hex  # 256-bit random; only its hash is stored
    q("INSERT INTO shares VALUES(?,?,?,?,?,?,?,0,?)", sid, did, g.uid, rc, perm, hashlib.sha256(tok.encode()).hexdigest(), time.time() + ttl * 60, time.time()); commit(); log(g.uid, f"Shared ({perm})", did, rc)
    return jsonify(share_id=sid, link=f"/s/{tok}", permission=perm, expires_in_minutes=ttl), 201
@app.get("/api/shares")
@auth
def shares():
    return jsonify([dict(id=s["id"], document=s["name"], recipient=s["rcpt"], permission=s["perm"], expires=s["exp"], state="revoked" if s["revoked"] else "expired" if s["exp"] < time.time() else "active")
                    for s in q("SELECT s.*,d.name FROM shares s JOIN docs d ON d.id=s.doc WHERE s.uid=? ORDER BY s.created DESC", g.uid)])
@app.delete("/api/shares/<sid>")
@auth
def revoke(sid):
    s = q("SELECT * FROM shares WHERE id=? AND uid=?", sid, g.uid).fetchone()
    if not s: abort(404)
    q("UPDATE shares SET revoked=1 WHERE id=?", sid); commit(); log(g.uid, "Access revoked", s["doc"], s["rcpt"]); return jsonify(ok=True)
def resolve(tok, need_download=False, verified=False):  # every recipient request is authorized server-side
    s = q("SELECT * FROM shares WHERE th=?", hashlib.sha256(tok.encode()).hexdigest()).fetchone()
    if not s: abort(404)
    if s["revoked"]: abort(410, "This access was revoked by the owner.")
    if s["exp"] < time.time(): abort(410, "Access expired.")
    if need_download and s["perm"] != "download": abort(403, "The owner shared this as view-only.")
    if verified:
        p = unsign(request.headers.get("X-Recipient", ""))
        if not p or p.get("typ") != "r" or p.get("share") != s["id"]: abort(401, "Please verify your email to open this document.")
    r = q("SELECT * FROM docs WHERE id=?", s["doc"]).fetchone() or abort(410, "Access expired."); return s, r
@app.get("/s/<tok>")
def s_meta(tok):
    acc = request.headers.get("Accept", "")
    if "text/html" in acc and "application/json" not in acc: return send_file(INDEX)  # recipient page; data loads via JSON below
    s, r = resolve(tok); p = unsign(request.headers.get("X-Recipient", "")); ok = p and p.get("typ") == "r" and p.get("share") == s["id"]
    out = dict(permission=s["perm"], expires=s["exp"], recipient_hint=hint(s["rcpt"]))  # document name only after email verification
    if ok: out.update(document=r["name"], recipient=s["rcpt"])
    return jsonify(out)
@app.post("/s/<tok>/challenge")
def s_challenge(tok):
    s, r = resolve(tok)
    if q("SELECT COUNT(*) FROM challenges WHERE th=? AND ts>?", s["th"], time.time() - 3600).fetchone()[0] >= 5: return err("Too many codes requested. Try again later.", 429)
    code = f"{secrets.randbelow(10**6):06d}"
    q("INSERT INTO challenges(th,ch,ts,exp) VALUES(?,?,?,?)", s["th"], hashlib.sha256((code + s["th"]).encode()).hexdigest(), time.time(), time.time() + 600); commit()
    try: send_mail(s["rcpt"], "Your DocShield verification code", f"Your code is {code}. It expires in 10 minutes. If you weren't expecting this, ignore this email.")
    except Exception: return err("We couldn't send the code. Ask the owner to try again.", 503)
    return jsonify(sent_to=hint(s["rcpt"]))
@app.post("/s/<tok>/verify")
def s_verify(tok):
    s, r = resolve(tok); code = str((request.get_json(force=True, silent=True) or {}).get("code", ""))
    c = q("SELECT * FROM challenges WHERE th=? AND exp>? ORDER BY id DESC LIMIT 1", s["th"], time.time()).fetchone()
    if not c or c["tries"] >= 5: return err("That code expired. Request a new one.", 400)
    q("UPDATE challenges SET tries=tries+1 WHERE id=?", c["id"]); commit()
    if not hmac.compare_digest(c["ch"], hashlib.sha256((code + s["th"]).encode()).hexdigest()): return err("That code doesn't match. Check it and try again.", 400)
    q("DELETE FROM challenges WHERE th=?", s["th"]); commit(); log(s["uid"], "Recipient verified", s["doc"], s["rcpt"])
    return jsonify(access=sign({"typ": "r", "share": s["id"], "exp": time.time() + 900}))
@app.get("/s/<tok>/content")
def s_view(tok): s, r = resolve(tok, verified=True); log(s["uid"], "Viewed", r["id"], s["rcpt"]); return stream(r, "inline")
@app.get("/s/<tok>/download")
def s_dl(tok): s, r = resolve(tok, True, True); log(s["uid"], "Downloaded", r["id"], s["rcpt"]); return stream(r, "attachment")
@app.errorhandler(410)
@app.errorhandler(401)
@app.errorhandler(403)
@app.errorhandler(404)
def _e(e): return jsonify(error=getattr(e, "description", "Not found")), e.code

@app.get("/api/activity")
@auth
def activity():
    return jsonify([dict(time=r["ts"], action=r["action"], document=r["name"], who=r["actor"]) for r in q("SELECT l.*,d.name FROM logs l LEFT JOIN docs d ON d.id=l.doc WHERE l.uid=? ORDER BY l.id DESC LIMIT 100", g.uid)])
@app.get("/api/security")
@auth
def security():
    u = q("SELECT * FROM users WHERE id=?", g.uid).fetchone(); return jsonify(checklist={"password_hashed_argon2id": True, "mfa_enabled": bool(u["mfa"]), "active_sessions": q("SELECT COUNT(*) FROM sessions WHERE uid=? AND revoked=0", g.uid).fetchone()[0]},
                                                                             recent_failed_signins=q("SELECT COUNT(*) FROM logs WHERE uid=? AND action='Failed sign-in' AND ts>?", g.uid, time.time() - 86400).fetchone()[0])
if __name__ == "__main__": app.run(debug=False, port=5000)
