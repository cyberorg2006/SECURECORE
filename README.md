# SECURECORE
# 🛡️ SECURECORE

### Secure Authentication • Cybersecurity Simulation • Security Monitoring

\<p align="center">
&#x20; \<a href="[https://securecore.onrender.com/](https://securecore.onrender.com/)">
&#x20;   \<img src="[https://img.shields.io/badge/LIVE_DEMO-Visit_SECURECORE-B8FF65?style=for-the-badge&logo=render&logoColor=black](https://img.shields.io/badge/LIVE_DEMO-Visit_SECURECORE-B8FF65?style=for-the-badge\&logo=render\&logoColor=black)" alt="Live Demo">
&#x20; \</a>
&#x20; \<a href="[https://github.com/cyberorg2006/SECURECORE](https://github.com/cyberorg2006/SECURECORE)">
&#x20;   \<img src="[https://img.shields.io/badge/GitHub-Source_Code-181717?style=for-the-badge&logo=github](https://img.shields.io/badge/GitHub-Source_Code-181717?style=for-the-badge\&logo=github)" alt="GitHub Repository">
&#x20; \</a>
\</p>

\<p align="center">
&#x20; \<strong>A hands-on cybersecurity project focused on secure authentication, attack simulation, and security monitoring.\</strong>
\</p>

---

## 🚀 Live Demo

**Explore SECURECORE:** [https://securecore.onrender.com/](https://securecore.onrender.com/)

> The application is hosted on Render's free tier. It may take a little time to start after being inactive.

## 📌 About the Project

SECURECORE is a web-based secure login and cybersecurity simulation platform built with Python and Flask.

It demonstrates how authentication security works and provides an interactive environment to explore simulated attacks, defensive mechanisms, and security events.

The project combines backend security concepts with a modern dashboard and an interactive 3D security-room experience.

## ✨ Key Features

| Feature                        | Description                                       |
| ------------------------------ | ------------------------------------------------- |
| 🔐 Secure Authentication       | User registration, login, and logout              |
| 🔑 Password Protection         | Argon2id password hashing                         |
| 📱 Multi-Factor Authentication | TOTP-based MFA verification                       |
| 🛑 Brute-Force Simulation      | Bounded, controlled attack simulation             |
| ⏱️ Account Protection          | Rate limiting and temporary lockout               |
| 📊 Security Monitoring         | View and inspect security events                  |
| ⚔️ Attack vs Defence           | Explore simulated attacks and defensive responses |
| 🖥️ Admin Dashboard            | Administrative security overview                  |
| 🎮 3D Security Room            | Interactive 3D project experience                 |

## 🧰 Technology Stack

**Backend**

- Python
- Flask
- Flask-SQLAlchemy
- Flask-Limiter

**Security**

- Argon2id
- TOTP / PyOTP
- CSRF protection
- Session security
- Rate limiting

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
│   ├── templates/
│   ├── __init__.py
│   ├── extensions.py
│   ├── models.py
│   └── routes.py
│
├── tests/
├── config.py
├── requirements.txt
├── run.py
├── .env.example
├── .gitignore
└── README.md
```

## ⚙️ Run Locally

### 1. Clone the repository

```bash
git clone https://github.com/cyberorg2006/SECURECORE.git
cd SECURECORE
```

### 2. Create a virtual environment

**Windows PowerShell:**

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```powershell
pip install -r requirements.txt
```

### 4. Configure environment variables

Create your local `.env` file using `.env.example` as a template.

Set a secure `SECRET_KEY` and configure the other required settings for your environment. Never upload your real `.env` file or credentials to GitHub.

### 5. Start the application

```powershell
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

## 🔒 Security Notes

- Passwords are stored using Argon2id hashing.
- MFA uses time-based one-time passwords.
- The brute-force simulator is designed for controlled local testing.
- Do not use this demonstration application to store real user credentials or sensitive production data.
- Keep secret keys and database credentials out of source control.
- The hosted free-tier deployment may use temporary storage. Do not rely on it for permanent user data.

## 🗺️ Future Improvements

- Advanced security analytics
- AI-assisted security event analysis
- More authentication security tests
- Improved dashboard visualizations
- Additional defensive simulations

*These are planned enhancements, not claims about currently implemented functionality.*

## 👨‍💻 Project

**SECURECORE** — A cybersecurity learning and portfolio project.

- **Repository:** [https://github.com/cyberorg2006/SECURECORE](https://github.com/cyberorg2006/SECURECORE)
- **Live Application:** [https://securecore.onrender.com/](https://securecore.onrender.com/)

---

\<p align="center">   \<strong>SECURECORE — Understand. Simulate. Defend.\</strong> \</p>

