# 🛡️ SECURECORE

### Secure Authentication · Cybersecurity Simulation · Security Monitoring

<p align="center">
  <a href="https://securecore.onrender.com/">
    <img src="https://img.shields.io/badge/🚀_LIVE_DEMO-Visit_SECURECORE-B8FF65?style=for-the-badge&logo=render&logoColor=black" alt="Live Demo">
  </a>
  <a href="https://github.com/cyberorg2006/SECURECORE">
    <img src="https://img.shields.io/badge/GitHub-Source_Code-181717?style=for-the-badge&logo=github" alt="GitHub Repository">
  </a>
</p>

<p align="center">
  A hands-on cybersecurity project focused on secure authentication, controlled attack simulation, and security monitoring.
</p>

---

## 🚀 Live Demo

**Explore SECURECORE:** https://securecore.onrender.com/

> Note: The application is hosted on Render's free tier. It may take a little time to start after being inactive.

## 📌 About the Project

SECURECORE is a web-based secure login and cybersecurity simulation platform built to demonstrate authentication security, attack prevention, and security monitoring.

It provides a practical environment to understand how authentication systems protect user accounts and respond to suspicious login activity.

## ✨ Key Features

| Feature | Description |
|---|---|
| 🔐 Secure Authentication | User registration, login, and logout |
| 🔑 Argon2id Password Hashing | Secure password hashing |
| 📱 Multi-Factor Authentication | TOTP-based MFA |
| 🛡️ Brute-Force Simulation | Controlled, bounded mock attack scenarios |
| 🚨 Account Protection | Rate limiting and temporary account lockout |
| 📊 Security Monitoring | Login activity and security event monitoring |
| ⚔️ Attack vs Defence | Visual security simulation dashboard |
| 🖥️ Admin Terminal | Administrative security interface |
| 🎮 3D Security Experience | Interactive 3D security-room experience |

## 🧰 Technology Stack

**Backend**
- Python
- Flask
- Flask-SQLAlchemy
- Flask-Limiter

**Security**
- Argon2id
- PyOTP (TOTP MFA)
- CSRF protection
- Redis rate-limit storage

**Frontend**
- HTML5
- CSS3
- JavaScript
- Three.js
- GSAP

**Database & Deployment**
- SQLite
- Redis
- Gunicorn
- Render

## 🏗️ Project Structure

```text
SECURECORE/
│
├── app/
│   ├── static/
│   │   ├── css/
│   │   ├── js/
│   │   └── model/
│   │
│   ├── templates/
│   ├── __init__.py
│   ├── extensions.py
│   ├── models.py
│   └── routes.py
│
├── tests/
│   └── test_auth.py
│
├── config.py
├── requirements.txt
├── run.py
├── .env.example
└── README.md
```

## ⚙️ Run Locally

### 1. Clone the repository

```bash
git clone https://github.com/cyberorg2006/SECURECORE.git
cd SECURECORE
```

### 2. Create a virtual environment

```bash
python -m venv venv
```

### 3. Activate the environment (Windows PowerShell)

```powershell
.\venv\Scripts\Activate.ps1
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

### 5. Configure environment variables

Copy the example environment file:

```powershell
Copy-Item .env.example .env
```

Open `.env` and configure the required values, including a strong, private `SECRET_KEY`.

Never upload your real `.env` file or credentials to GitHub.

### 6. Start the application

```bash
python run.py
```

Open your browser:

```text
http://127.0.0.1:5000
```

## 🧪 Run Tests

Run the automated test suite:

```powershell
python -m unittest discover -s tests -v
```

**Latest local test result:** 28 tests passed.

## 🔒 Security Notes

- Passwords are hashed using Argon2id.
- MFA uses time-based one-time passwords (TOTP).
- Login attempts are protected using rate limiting.
- CSRF protection is enabled.
- Brute-force demonstrations use bounded mock scenarios.
- Never use the public demo for real passwords or sensitive personal information.

> **Disclaimer:** SECURECORE is an educational cybersecurity project. Its attack simulations are intended for controlled demonstration and learning, not for attacking real accounts or systems.

## ☁️ Deployment

SECURECORE is deployed using **Render**.

Live application: https://securecore.onrender.com/

The free hosting environment may sleep after inactivity. Its local SQLite storage is not intended for permanent production user data.

## 👨‍💻 Developer

**P Manikanta**

Cybersecurity Student | Aspiring Security Professional

- GitHub: https://github.com/cyberorg2006
- Project: https://github.com/cyberorg2006/SECURECORE
- Live Demo: https://securecore.onrender.com/

---

<p align="center">
  <strong>🛡️ SECURECORE — Learn. Simulate. Secure.</strong>
</p>
