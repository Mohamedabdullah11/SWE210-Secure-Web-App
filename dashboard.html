# 🔐 SecureApp — SWE210 Group Project

A secure web application built with Flask demonstrating authentication, role-based access control (RBAC), and field-level encryption.

## Security Features

| Feature | Implementation |
|---|---|
| Password Hashing | bcrypt via Werkzeug (`generate_password_hash`) |
| Authentication | Session-based login with server-side validation |
| Access Control | RBAC — `admin` and `user` roles with route decorators |
| Data Encryption | Fernet symmetric encryption (AES-128-CBC + HMAC-SHA256) |
| Database | SQLite — encrypted fields stored as ciphertext |

---

## Project Structure

```
secure_web_app/
├── app.py                  # Main Flask application
├── requirements.txt        # Python dependencies
├── encryption.key          # Auto-generated Fernet key (gitignored)
├── instance/
│   └── secure_app.db       # SQLite database (auto-created)
├── static/
│   ├── css/style.css       # Dark security-themed stylesheet
│   └── js/main.js          # Password strength + UX scripts
└── templates/
    ├── base.html           # Shared layout + navbar
    ├── login.html          # Login page
    ├── register.html       # Registration page
    ├── dashboard.html      # User dashboard
    ├── profile.html        # Profile + encryption demo
    ├── admin.html          # Admin panel (admin only)
    ├── 403.html            # Forbidden error page
    └── 404.html            # Not found error page
```

---

## Setup & Run

### 1. Clone the repository
```bash
git clone <your-repo-url>
cd secure_web_app
```

### 2. Create a virtual environment
```bash
python -m venv venv
source venv/bin/activate        # Linux/Mac
venv\Scripts\activate           # Windows
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the application
```bash
python app.py
```

### 5. Open in browser
```
http://127.0.0.1:5000
```

---

## Default Admin Credentials

| Username | Password  |
|----------|-----------|
| admin    | Admin@1234 |

> ⚠️ Change these in production.

---

## How Authentication Works

1. User submits credentials via POST form
2. `check_password_hash()` compares input against bcrypt hash in DB
3. On success → user data stored in signed server-side session
4. `@login_required` decorator protects all authenticated routes
5. `@admin_required` decorator checks `role == 'admin'`, returns 403 otherwise

## How Encryption Works

1. User enters email/phone in plaintext
2. `fernet.encrypt(plaintext.encode())` applies AES-128-CBC + HMAC-SHA256
3. Resulting base64 token is stored in `email_enc` / `phone_enc` columns
4. On read: `fernet.decrypt()` is called server-side — plaintext never touches the DB

---

## Course

**SWE210 — Software Security**  
İstinye University, Istanbul
