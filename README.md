# DocShield AI backend
Run: `pip install -r requirements.txt && python app.py` (API on :5000). Test: `python tests/test_flow.py`.
Production: set DOCSHIELD_MASTER_KEY and DOCSHIELD_TOKEN_SECRET (base64, 32 bytes) from a secret manager, serve behind HTTPS, use Postgres + object storage.
Real: Argon2id, AES-256-GCM (per-document key wrapped by master key), TOTP MFA, step-up re-auth, rotating refresh tokens, hashed share tokens, server-side authz, audit log.
Not yet real: email/SMS OTP delivery, identity verification provider, OCR for images (needs tesseract), malware scanning, official document authentication, the web UI is not wired to this API yet.

## Full stack
- Web app: `python app.py` then open http://localhost:5000 (UI in `static/`, talks to the real API; recipients open `/s/<token>`).
- Android: `android/` is a native Kotlin shell (BiometricPrompt + PIN fallback, FLAG_SECURE, locked-down WebView). Set `SERVER_URL` in `android/app/build.gradle.kts` to your HTTPS deployment, open in Android Studio, Build > Build APK. Not compiled in this environment.
- The API needs HTTPS in production; Android blocks cleartext traffic by design.

## Deploy (HTTPS URL for the Android app)
Docker image includes Tesseract OCR. Render: push this folder to GitHub, create a Blueprint from `render.yaml`, set the env vars from `.env.example` (keys + SMTP), and use the resulting https URL as `SERVER_URL` in the Android project. The vault lives on the mounted `/data` disk (keep the keys safe: losing the master key makes documents unrecoverable). Recipients now verify with an emailed one-time code before a shared document opens; their email is watermarked over the preview (a deterrent, not screenshot prevention).
