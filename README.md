# 🛡️ DocShield AI

### Secure Document Storage, Verification & Controlled Sharing Platform

DocShield AI is a security-focused document management platform designed to securely upload, store, analyze, verify, and share sensitive documents.

The system combines **AI-assisted document analysis** with modern application-security mechanisms such as **AES-256-GCM encryption, Argon2id password hashing, TOTP multi-factor authentication, step-up verification, rotating refresh tokens, expiring document-sharing links, recipient verification, and audit logging**.

> **Important:** Automated document analysis provides indicators and consistency checks. It does **not** independently prove that a document is authentic or legally valid.

---

## ✨ Key Features

### 🔐 Secure Authentication

* User registration and login
* Argon2id password hashing
* Password policy enforcement
* TOTP-based Multi-Factor Authentication
* Failed-login protection and temporary account lockout
* Short-lived access tokens
* Rotating refresh tokens
* Session management
* Logout from individual devices
* Revoke all other active sessions

### 🔒 Document Security

* AES-256-GCM encryption
* Unique encryption key for every document
* Document keys wrapped using a master key
* Encrypted documents stored outside the public web directory
* Server-generated document identifiers
* File-size restrictions
* File-type and file-signature validation

### 🤖 AI-Assisted Document Analysis

The backend extracts information from uploaded documents and performs automated checks including:

* Document readability
* Document-type identification
* Name detection
* Expiry-date detection
* Aadhaar number masking
* PAN number masking
* Document expiry status
* Cross-document name consistency checking

Supported document categories include:

* Aadhaar
* PAN
* Degree
* Income Certificate
* Passport
* Insurance
* Other

### 📄 Supported Files

| File Type  | Support |
| ---------- | ------- |
| PDF        | ✅       |
| JPG / JPEG | ✅       |
| PNG        | ✅       |

Maximum upload size:

**5 MB per document**

### 👥 Secure Document Sharing

Document owners can share documents with recipients using:

* Random access tokens
* Expiring links
* View-only permissions
* Download permissions
* Recipient email verification
* One-time verification codes
* Share revocation
* Server-side authorization

Recipient access requires verification before the document content is released.

### 🧾 Audit Logging

Important security events are recorded, including:

* Account creation
* Successful sign-in
* Failed sign-in
* MFA activation
* Re-authentication failures
* Document upload
* Document viewing
* Document download
* Document deletion
* Document sharing
* Share revocation
* Recipient verification
* Session revocation

Document contents themselves are not written to the audit log.

### 🛡️ Security Headers

The application applies security-related HTTP headers including:

* `X-Content-Type-Options`
* `Cache-Control`
* `Referrer-Policy`
* Content Security Policy
* `frame-ancestors`

---

# 🏗️ System Architecture

```text
                    ┌─────────────────────┐
                    │      User / Admin   │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │   Web / Android UI  │
                    └──────────┬──────────┘
                               │ HTTPS
                               ▼
                    ┌─────────────────────┐
                    │     Flask API       │
                    │     DocShield AI    │
                    └──────────┬──────────┘
                               │
             ┌─────────────────┼─────────────────┐
             │                 │                 │
             ▼                 ▼                 ▼
      ┌────────────┐    ┌─────────────┐   ┌──────────────┐
      │   Auth &   │    │  Document   │   │   Sharing &  │
      │    MFA     │    │  Analysis   │   │ Verification │
      └─────┬──────┘    └──────┬──────┘   └──────┬───────┘
            │                  │                  │
            └──────────────────┼──────────────────┘
                               ▼
                    ┌─────────────────────┐
                    │ Encryption Layer    │
                    │     AES-256-GCM     │
                    └──────────┬──────────┘
                               ▼
                    ┌─────────────────────┐
                    │ SQLite + Encrypted  │
                    │      Vault           │
                    └─────────────────────┘
```

---

# 🔄 Document Processing Flow

```text
User selects document
        │
        ▼
File Upload
        │
        ▼
Extension Validation
        │
        ▼
File Signature Validation
        │
        ▼
5 MB Size Check
        │
        ▼
Text Extraction / OCR
        │
        ▼
Document Analysis
        │
        ├── Document Type
        ├── Name
        ├── Expiry Date
        └── Masked Identifier
        │
        ▼
Generate Document ID
        │
        ▼
Generate Per-Document AES Key
        │
        ▼
Encrypt Document
        │
        ▼
Wrap Document Key
        │
        ▼
Store Encrypted File
        │
        ▼
Store Metadata + Analysis
        │
        ▼
Audit Log
```

---

# 🔐 Security Architecture

## Password Security

Passwords are protected using **Argon2id** rather than storing plaintext passwords.

```text
Password
   │
   ▼
Argon2id
   │
   ▼
Password Hash
   │
   ▼
Database
```

## Document Encryption

Each document receives its own encryption key.

```text
Original Document
       │
       ▼
Generate 256-bit DEK
       │
       ▼
AES-256-GCM Encryption
       │
       ▼
Encrypted Document
       │
       └──── DEK
               │
               ▼
        Master Key Encryption
               │
               ▼
        Wrapped Document Key
```

The implementation uses AES-GCM with a per-document key and wraps that key with the master key.

---

# 🔑 Multi-Factor Authentication

DocShield AI supports TOTP-based MFA.

```text
Email + Password
       │
       ▼
Authenticator Code
       │
       ▼
TOTP Verification
       │
       ▼
Authenticated Session
```

MFA is implemented using `pyotp`.

---

# 🚨 Step-Up Verification

Sensitive operations require recent re-authentication.

Examples:

* View document content
* Download document
* Delete document
* Create a share link

```text
Authenticated User
        │
        ▼
Sensitive Operation
        │
        ▼
Password + MFA Code
        │
        ▼
Step-Up Token
        │
        ▼
Operation Allowed
```

---

# 📤 Secure Sharing Flow

```text
Owner
 │
 ├── Select Document
 │
 ├── Enter Recipient Email
 │
 ├── Select Permission
 │      ├── View
 │      └── Download
 │
 └── Set Expiration
          │
          ▼
     Secure Share Token
          │
          ▼
      Recipient Link
          │
          ▼
    Email Verification
          │
          ▼
      One-Time Code
          │
          ▼
     Recipient Token
          │
          ▼
      Document Access
```

Share tokens are stored as hashes, and access can be revoked or automatically expire.

---

# 🤖 Document Analysis

The analysis engine extracts text from PDFs and can use OCR for image documents.

### PDF

```text
PDF
 │
 ▼
PyPDF
 │
 ▼
Extracted Text
 │
 ▼
Analysis
```

### Image

```text
JPG / PNG
 │
 ▼
Tesseract OCR
 │
 ▼
Extracted Text
 │
 ▼
Analysis
```

The project includes `pypdf`, `pytesseract`, and Pillow as dependencies.

---

# 🧠 Automated Checks

The system performs automated checks such as:

| Check            | Purpose                                   |
| ---------------- | ----------------------------------------- |
| Readability      | Determines whether text can be extracted  |
| Document Type    | Detects known document keywords           |
| Name Detection   | Attempts to identify document holder name |
| Expiry Detection | Finds expiry/validity dates               |
| ID Masking       | Stores only a masked identifier           |
| Expiry Status    | Determines expired/valid status           |
| Consistency      | Compares names across documents           |

### Important Limitation

DocShield AI does **not** independently authenticate government-issued documents.

The analysis is an automated security/verification aid and should not be treated as a legal authenticity verdict.

---

# 🗄️ Database

The current backend uses SQLite.

Main tables include:

```text
users
sessions
docs
shares
challenges
logs
```

### Users

Stores:

* User ID
* Name
* Email
* Password hash
* TOTP secret
* MFA status
* Failed-login information
* Lock status

### Documents

Stores:

* Document ID
* Owner ID
* Name
* Category
* Extension
* MIME type
* File size
* Encrypted file location
* Wrapped encryption key
* Analysis metadata
* Creation timestamp

### Shares

Stores:

* Share ID
* Document ID
* Owner ID
* Recipient
* Permission
* Hashed token
* Expiration
* Revocation status

### Logs

Stores security/activity events without storing document contents.

---

# 📁 Project Structure

```text
DocShield-AI/
│
├── app.py
├── Dockerfile
├── render.yaml
├── requirements.txt
├── .env.example
├── README.md
│
├── static/
│   └── index.html
│
├── data/
│   └── vault/
│
├── android/
│   └── ...
│
└── tests/
    └── test_flow.py
```

> The exact Android and test files should be present in the repository when those components are included in the deployment.

---

# ⚙️ Technology Stack

| Layer             | Technology                 |
| ----------------- | -------------------------- |
| Backend           | Python                     |
| Web Framework     | Flask                      |
| Authentication    | Argon2id                   |
| MFA               | TOTP / PyOTP               |
| Encryption        | AES-256-GCM                |
| Database          | SQLite                     |
| PDF Processing    | PyPDF                      |
| OCR               | Tesseract                  |
| Image Processing  | Pillow                     |
| Production Server | Gunicorn                   |
| Containerization  | Docker                     |
| Deployment        | Render                     |
| Android           | Kotlin                     |
| Storage           | Encrypted filesystem vault |

---

# 🚀 Installation

## 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/docshield-ai.git
cd docshield-ai
```

## 2. Create a virtual environment

### Windows

```bash
python -m venv venv
venv\Scripts\activate
```

### Linux / macOS

```bash
python3 -m venv venv
source venv/bin/activate
```

## 3. Install dependencies

```bash
pip install -r requirements.txt
```

The current dependency set includes Flask, Argon2, cryptography, PyOTP, PyPDF, Tesseract/Pillow support, and Gunicorn.

## 4. Configure environment variables

Copy:

```bash
.env.example
```

to:

```bash
.env
```

Generate a 32-byte Base64 key:

```bash
python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"
```

Set:

```env
DOCSHIELD_MASTER_KEY=
DOCSHIELD_TOKEN_SECRET=

SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASS=
MAIL_FROM=
```

Never commit `.env` or production secrets to GitHub.

---

# ▶️ Run Locally

```bash
python app.py
```

The application starts on:

```text
http://localhost:5000
```

The backend exposes the API under:

```text
/api/
```

---

# 🐳 Docker

Build:

```bash
docker build -t docshield-ai .
```

Run:

```bash
docker run -p 5000:5000 docshield-ai
```

The Docker image installs Tesseract OCR and runs the application with Gunicorn.

---

# ☁️ Render Deployment

The project includes a `render.yaml` Blueprint configuration.

Render deployment uses:

```text
Docker
   │
   ▼
DocShield AI
   │
   ├── Persistent /data disk
   ├── Master encryption key
   ├── Token secret
   └── SMTP configuration
```

The current configuration defines a Docker web service with a persistent `/data` disk and environment variables for encryption and SMTP configuration.

### Deployment Steps

1. Push the project to GitHub.
2. Open Render.
3. Create a new Blueprint.
4. Connect the GitHub repository.
5. Use the included `render.yaml`.
6. Configure the secret environment variables.
7. Deploy.
8. Enable HTTPS.
9. Use the generated HTTPS URL for the Android application.

---

# 📱 Android Application

The project architecture also includes an Android Kotlin shell.

It is designed to use:

* Android `BiometricPrompt`
* PIN fallback
* Secure WebView
* `FLAG_SECURE`
* HTTPS-only backend communication

Configure:

```text
SERVER_URL
```

in:

```text
android/app/build.gradle.kts
```

The Android client should point to the deployed HTTPS API.

---

# 🔌 Important API Endpoints

## Authentication

```text
POST /api/register
POST /api/mfa/verify
POST /api/login
POST /api/refresh
POST /api/logout
POST /api/reauth
```

## Sessions

```text
GET    /api/sessions
DELETE /api/sessions/<sid>
POST   /api/sessions/revoke-others
```

## Documents

```text
POST   /api/documents
GET    /api/documents
GET    /api/documents/<id>
GET    /api/documents/<id>/content
GET    /api/documents/<id>/download
DELETE /api/documents/<id>
GET    /api/consistency
```

## Sharing

```text
POST   /api/documents/<id>/share
GET    /api/shares
DELETE /api/shares/<share_id>
```

## Recipient Access

```text
GET  /s/<token>
POST /s/<token>/challenge
POST /s/<token>/verify
GET  /s/<token>/content
GET  /s/<token>/download
```

## Security / Activity

```text
GET /api/activity
GET /api/security
```

---

# 🧪 Testing

If the repository contains the test suite:

```bash
python tests/test_flow.py
```

For API testing, tools such as Postman or cURL can also be used.

---

# ⚠️ Current Limitations

The current implementation still has several components that should be strengthened before production use:

* Production email/SMS OTP infrastructure needs to be configured.
* A dedicated identity-verification provider is not integrated.
* OCR requires Tesseract.
* Malware scanning is not implemented.
* Official document authenticity verification is not implemented.
* Production deployment should use PostgreSQL and object storage rather than SQLite/local vault storage.
* The frontend/API integration should be validated end-to-end.
* Production deployment must use HTTPS.
* The master encryption key must be backed up securely.

These limitations are also identified in the supplied project README.

---

# 🔐 Production Security Checklist

Before production deployment:

* [ ] Use HTTPS
* [ ] Store secrets in a secret manager
* [ ] Back up the master encryption key securely
* [ ] Never commit `.env`
* [ ] Replace SQLite with PostgreSQL
* [ ] Use secure object storage
* [ ] Configure production SMTP
* [ ] Add malware/antivirus scanning
* [ ] Add rate limiting
* [ ] Add centralized monitoring
* [ ] Configure database backups
* [ ] Review access-control rules
* [ ] Perform security testing
* [ ] Perform dependency vulnerability scanning
* [ ] Validate Android certificate/network security configuration

**Critical:** Losing the master encryption key can make encrypted documents unrecoverable.

---

# 🎯 Project Objectives

DocShield AI aims to provide:

1. Secure document storage
2. Privacy-preserving document handling
3. Automated document analysis
4. Multi-factor authentication
5. Controlled document sharing
6. Recipient verification
7. Expiring access
8. Document access auditing
9. Cross-document consistency checking
10. Secure web and Android access

---

# 🔮 Future Enhancements

Potential future improvements include:

* Government/official document verification APIs
* Advanced OCR
* AI-based fraud/anomaly detection
* Malware scanning
* Digital signatures
* Blockchain-based verification records
* PostgreSQL migration
* Cloud object storage
* Role-based access control
* Organization/team accounts
* Advanced analytics dashboard
* Push notifications
* Improved Android native experience
* Document version history
* Watermark customization
* Security alerts
* SIEM integration

---

# 📜 Security Disclaimer

DocShield AI is a software project intended to demonstrate secure document management and automated document analysis.

Automated checks should **not** be interpreted as legal certification, government verification, or definitive proof that a document is genuine.

Always verify important documents through the appropriate official authority or issuing organization.

---

# 👨‍💻 Development

Built with:

```text
Python + Flask
Argon2id
AES-256-GCM
TOTP MFA
PyPDF
Tesseract OCR
SQLite
Docker
Gunicorn
Kotlin Android
```

---

# 📄 License

Add the project's chosen license here, for example:

```text
MIT License
```

If a license has not yet been selected, replace this section with the appropriate license before publishing the repository.

---

## ⭐ Project Summary

**DocShield AI** is a secure document management platform combining:

> 🔐 Authentication
> 🔒 Encryption
> 🤖 AI-assisted analysis
> 📄 Document management
> 👥 Controlled sharing
> 🔑 MFA
> ⏱️ Expiring access
> 🧾 Audit logging
> 📱 Android support

The goal is to provide a secure foundation for handling sensitive documents while clearly separating automated analysis from authoritative document authentication.
