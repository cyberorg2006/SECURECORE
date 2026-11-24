# 🛡️ SECURECORE

### Secure Authentication | Cybersecurity Simulation | Security Monitoring

<p align="center">
  <a href="https://securecore.onrender.com/">
    <img src="https://img.shields.io/badge/🚀_LIVE_DEMO-Explore_SECURECORE-B8FF65?style=for-the-badge&logo=render&logoColor=black" alt="Live Demo">
  </a>
  <a href="https://github.com/cyberorg2006/SECURECORE">
    <img src="https://img.shields.io/badge/GitHub-Repository-181717?style=for-the-badge&logo=github" alt="GitHub">
  </a>
</p>

<p align="center">
  <strong>A hands-on cybersecurity platform demonstrating secure authentication, controlled brute-force simulation, account protection, and security monitoring.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.x-blue?style=flat-square&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/Flask-Backend-black?style=flat-square&logo=flask" alt="Flask">
  <img src="https://img.shields.io/badge/Security-Argon2id-green?style=flat-square" alt="Argon2id">
  <img src="https://img.shields.io/badge/Deployment-Render-purple?style=flat-square&logo=render" alt="Render">
</p>

---

## 🚀 Live Application

<blockquote>
  <strong>Experience SECURECORE online:</strong>

  https://securecore.onrender.com/

  Hosted on Render's free tier. The first visit after inactivity may take a little time while the service starts.
</blockquote>

## 📌 About SECURECORE

SECURECORE is a web-based cybersecurity project designed to demonstrate how modern authentication systems protect user accounts and respond to suspicious login activity.

The project combines secure login functionality with controlled attack simulations, security dashboards, and an interactive 3D security-room experience.

It is built as an educational platform to explore practical cybersecurity concepts through a working web application.

## ✨ Key Features

### 🔐 Secure Authentication
- User registration and login
- Secure password storage using Argon2id
- User logout and session management
- CSRF protection

### 🔑 Multi-Factor Authentication
- TOTP-based multi-factor authentication
- Authenticator app integration
- MFA verification workflow

### 🛡️ Account Protection
- Login attempt tracking
- Rate limiting
- Temporary account lockout
- Security event logging

### ⚔️ Brute-Force Simulation
- Controlled mock attack scenarios
- Bounded simulation attempts
- Attack and defence demonstrations
- Authentication protection analysis

### 📊 Security Monitoring
- Security monitoring dashboard
- Login activity visibility
- Security event information
- Attack vs Defence dashboard

### 🖥️ Admin & 3D Experience
- Administrative security interface
- Admin terminal experience
- Interactive 3D security room
- Animated and responsive user interface

## 🖥️ Project Preview

Explore the deployed application to experience its interface and functionality:

<p align="center">
  <a href="https://securecore.onrender.com/">
    <img src="https://img.shields.io/badge/OPEN-SECURECORE_LIVE_APPLICATION-B8FF65?style=for-the-badge&logo=render&logoColor=black" alt="Open SECURECORE">
  </a>
</p>

## 🧰 Technology Stack

| Category | Technologies |
|---|---|
| Programming Language | Python |
| Backend Framework | Flask |
| Frontend | HTML5, CSS3, JavaScript |
| Database | SQLite |
| Password Security | Argon2id |
| Multi-Factor Authentication | PyOTP |
| Rate Limiting | Flask-Limiter |
| Rate Limit Storage | Redis |
| 3D Graphics | Three.js |
| Animations | GSAP |
| Production Server | Gunicorn |
| Deployment | Render |
| Version Control | Git & GitHub |

## 🏗️ Project Architecture

```text
SECURECORE/
│
├── app/
│   ├── static/
│   │   ├── css/
│   │   │   ├── style.css
│   │   │   ├── experience.css
│   │   │   └── admin_terminal.css
│   │   │
│   │   ├── js/
│   │   │   ├── auth.js
│   │   │   ├── site.js
│   │   │   ├── experience.js
│   │   │   ├── security_monitoring.js
│   │   │   ├── attack_vs_defence.js
│   │   │   ├── brute_force_simulator.js
│   │   │   └── admin_terminal.js
│   │   │
│   │   └── model/
│   │       └── security-room.glb
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
├── .gitignore
└── README.md
```

## ⚙️ Installation & Setup

Follow these steps to run SECURECORE locally.

### 1. Clone the repository

```bash
git clone https://github.com/cyberorg2006/SECURECORE.git
```

### 2. Open the project directory

```bash
cd SECURECORE
```

### 3. Create a Python virtual environment

```bash
python -m venv venv
```

### 4. Activate the virtual environment

**Windows PowerShell:**

```powershell
.\venv\Scripts\Activate.ps1
```

### 5. Install dependencies

```bash
pip install -r requirements.txt
```

### 6. Configure environment variables

Create your local `.env` file from the example:

```powershell
Copy-Item .env.example .env
```

Configure the required environment variables in `.env`, including a strong secret key.

Never upload your actual `.env` file, passwords, secret keys, or Redis credentials to GitHub.

### 7. Run the application

```bash
python run.py
```

Open the application in your browser:

```text
http://127.0.0.1:5000
```

## 🧪 Testing

SECURECORE includes automated authentication and security tests.

Run the test suite:

```powershell
python -m unittest discover -s tests -v
```

**Latest recorded test result:**

<p align="center">
  <img src="https://img.shields.io/badge/Automated_Tests-28_Passed-success?style=for-the-badge&logo=checkmarx&logoColor=white" alt="28 tests passed">
</p>

All 28 tests passed in the latest recorded local test run.

## 🔒 Security Considerations

SECURECORE demonstrates several important security practices:

- Argon2id password hashing
- TOTP-based multi-factor authentication
- CSRF protection
- Rate limiting
- Temporary account lockout
- Secure session configuration
- Controlled and bounded mock attack simulations

**Important:** This project is intended for educational and demonstration purposes. Do not use the public demo with real passwords or sensitive personal information. The free hosting environment and its local SQLite storage are not designed for permanent production data.

## ☁️ Deployment

The application is deployed using Render.

| Item | Details |
|---|---|
| Hosting | Render |
| Production Server | Gunicorn |
| Rate Limit Storage | Upstash Redis |
| Live URL | https://securecore.onrender.com/ |
| Source Code | GitHub |

## 🎯 Project Objectives

- Understand secure authentication workflows.
- Learn practical password security.
- Explore multi-factor authentication.
- Demonstrate brute-force attack scenarios safely.
- Understand rate limiting and account protection.
- Monitor login activity and security events.
- Build and deploy a full-stack cybersecurity application.

## 🔮 Future Improvements

- Advanced security analytics
- Enhanced suspicious-login detection
- More security event visualizations
- Expanded authentication testing
- Additional monitoring capabilities

## 👨‍💻 Developer & Credits

<p align="center">
  <strong>P Manikanta</strong>
  <br>
  Cybersecurity Student | Aspiring Security Professional
  <br>
  Passionate about Cybersecurity, Secure Systems, and Technology.
</p>

### 📬 Connect With Me

<p align="center">
  <a href="https://www.linkedin.com/in/p-mani-kanta-156285292/">
    <img src="https://img.shields.io/badge/LinkedIn-Connect_with_Me-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white" alt="LinkedIn">
  </a>
  <a href="mailto:csecurityexpert@gmail.com">
    <img src="https://img.shields.io/badge/Gmail-Contact_Me-EA4335?style=for-the-badge&logo=gmail&logoColor=white" alt="Gmail">
  </a>
  <a href="https://github.com/cyberorg2006">
    <img src="https://img.shields.io/badge/GitHub-Follow_Me-181717?style=for-the-badge&logo=github&logoColor=white" alt="GitHub">
  </a>
</p>

| Platform | Link |
|---|---|
| LinkedIn | https://www.linkedin.com/in/p-mani-kanta-156285292/ |
| Email | csecurityexpert@gmail.com |
| GitHub | https://github.com/cyberorg2006 |
| Project Repository | https://github.com/cyberorg2006/SECURECORE |
| Live Application | https://securecore.onrender.com/ |

---

<p align="center">
  <strong>🛡️ SECURECORE</strong>
  <br>
  <em>Learn. Simulate. Secure.</em>
  <br><br>
  Built with passion for Cybersecurity.
</p>