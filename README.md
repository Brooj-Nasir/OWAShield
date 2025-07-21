
# OWASP Security Labs

![OWASP Logo](static/logo.png)

A hands-on learning environment for understanding OWASP Top 10 vulnerabilities.

## 🚀 Quick Start

1. Install dependencies:
```bash
pip install -r requirements.txt
```
2. Initialize database:
```bash
python3 init_db.py
```

3. Run the application:
```bash
python3 app.py
```

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


