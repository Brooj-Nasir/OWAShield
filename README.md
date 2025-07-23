<<<<<<< HEAD

# OWASP Security Labs

![OWASP Logo](static/logo.png)

A hands-on learning environment for understanding OWASP Top 10 vulnerabilities.

# OWAShield 🔒  
**Interactive OWASP Top 10 Security Labs for Practical & Theoretical Learning**  
By [Brooj Nasir](https://github.com/Brooj-Nasir)

---

OWAShield is an open-source, hands-on educational platform designed to teach and demonstrate the **OWASP Top 10 Web Application Security Risks** through interactive labs and theoretical documentation. Built using **Python (Flask)**, OWAShield helps students, developers, and security enthusiasts understand how vulnerabilities work — and how to fix them securely.

> 🧪 Practical Labs + 📚 Integrated OWASP Docs = 🔐 Complete Secure Coding Environment

---

## 🚀 Features

### 🔍 Interactive Lab Modules
Explore 12 security labs with vulnerable and secure implementations:
- ✅ SQL Injection (A03:2021)
- ✅ Cross-Site Scripting (XSS)
- ✅ Broken Access Control
- ✅ Security Misconfiguration
- ✅ Insecure Deserialization
- ✅ Sensitive Data Exposure
- ✅ Server-Side Request Forgery (SSRF)
- ✅ Broken Authentication
- ✅ Vulnerable Components
- ✅ Security Logging & Monitoring Failures
- ✅ Insecure Design

Each module provides:
- ⚠️ Vulnerable code demonstration
- ✅ Secure code side-by-side
- 🧪 Predefined JSON-based attack payloads
- 🧠 Real-time output of successful/blocked attacks

### 📖 Theoretical OWASP Docs
- Full OWASP Top 10 2021 website included
- Available in multiple languages (EN, ES, FR, etc.)
- Linked PDF references, examples, and prevention strategies

### 💡 Educational Pathway
1. **Read** → Understand OWASP risks (built-in docs)
2. **Explore** → Run attacks in labs
3. **Fix** → See mitigation in secure modules
4. **Practice** → Create your own payloads

---

## 🛠️ Technology Stack

### 🔧 Backend:
- Python 3.6+
- Flask
- SQLite

### 🎨 Frontend:
- HTML5, CSS3, JS
- Bootstrap (responsive)
- Jinja2 Templates

### 🔐 Security:
- Flask-Talisman (security headers)
- Flask-SeaSurf (CSRF protection)
- bcrypt, cryptography
- bleach (sanitization)
- defusedxml (secure XML)

---

## 🗂️ Project Structure



## 🌐 Access

After starting, access at:  
http://localhost:5000

## 🛠️ Project Structure

```text
.
├── app.py                # Main application
├── init_db.py            # Database setup
├── requirements.txt      # Dependencies
├── static/               # Static assets
│   ├── css/
│   ├── js/
│   └── logo.png
├── templates/            # HTML templates
│   ├── base.html
│   └── vulnerabilities/
└── vulnerabilities/      # Vulnerability modules
    ├── sql_injection.py
    └── ...
```

## 🎯 Available Labs

| Vulnerability | Route |
|--------------|-------|
| SQL Injection | `/sql-injection` |
| XSS | `/xss` |
| Broken Access Control | `/broken-access-control` |
| Security Misconfiguration | `/security-misconfiguration` |
| Insecure Deserialization | `/insecure-deserialization` |
| More.. | .. |



## Summary

1. Run `pip install -r .\requirements.txt` to install dependeicnies.
2. Run `python3 init_db.py` to setup database.
3. Run `python3 app.py` to run the application.


=======
# OWAShield
>>>>>>> 3ef91d85b640862bbf27c4ad42c84bcff8ffe9df
