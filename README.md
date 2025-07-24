# OWAShield  
<p align="center">
  <img src="static/logo.png" alt="OWASP Logo" width="800">
</p>


# OWASP Security Labs
**Interactive OWASP Top 10 Security Labs for Practical & Theoretical Learning**  
By [Brooj Nasir](https://github.com/Brooj-Nasir)

---

OWAShield is an open-source, hands-on educational platform designed to teach and demonstrate the **OWASP Top 10 Web Application Security Risks** through interactive labs and theoretical documentation. Built using **Python (Flask)**, OWAShield helps students, developers, and security enthusiasts understand how vulnerabilities work — and how to fix them securely.

> 🧪 Practical Labs + 📚 Integrated OWASP Docs = 🔐 Complete Secure Coding Environment
<img width="1380" height="607" alt="image" src="https://github.com/user-attachments/assets/42e0a18e-8f78-4739-b5de-afe518e07ff3" />
<img width="1380" height="632" alt="image" src="https://github.com/user-attachments/assets/bb6e43b9-e8e2-425f-a145-a82e745c3dac" />

---

## 🚀 Features

### 🔍 Interactive Lab Modules
Explore 12 security labs with vulnerable and secure implementations:
-  SQL Injection (A03:2021)
-  Cross-Site Scripting (XSS) (A03:2021)
-  Broken Access Control (A01:2021)
-  Security Misconfiguration (A05:2021)
-  Insecure Deserialization(A08:2021)
-  Sensitive Data Exposure  (A02:2021)
-  Server-Side Request Forgery (SSRF) (A10:2021)
-  Broken Authentication  (A07:2021)
-  Vulnerable Components  (A06:2021)
-  Security Logging & Monitoring Failures (A09:2021)
-  Insecure Design(A04:2021)
 <p align="center">
<img width="486" height="395" alt="image" src="https://github.com/user-attachments/assets/844b9e75-97f9-4e5b-a283-344dc20faab1" />
</p>
<p align="center">
<img width="1357" height="537" alt="image" src="https://github.com/user-attachments/assets/10992fa9-d993-42d1-abe7-bcf7d82f8da6" />
</p>


Each module provides:
- Vulnerable code demonstration
- Secure code side-by-side
- **Dual Mode Demonstrations**: Vulnerable vs. Secure implementations
- **SQLite Database** for realistic attack scenarios
- **User-friendly Interface**
-  Predefined JSON-based attack payloads
-  Real-time output of successful/blocked attacks
<img width="1362" height="521" alt="image" src="https://github.com/user-attachments/assets/1b91f630-cdcf-4bba-aed0-4c1a43504832" />
<img width="1210" height="584" alt="image" src="https://github.com/user-attachments/assets/bf96d42d-05c5-484a-97f0-a9ef1c82d376" />



### 📖 Theoretical OWASP Docs
- Full OWASP Top 10 2021 website included
- Available in multiple languages (EN, ES, FR, etc.)
- Linked PDF references, examples, and prevention strategies
<img width="1160" height="250" alt="image" src="https://github.com/user-attachments/assets/a6fd2b9f-6dbc-4534-b19e-bdb979acc6dc" />
<img width="1341" height="595" alt="image" src="https://github.com/user-attachments/assets/aef8a903-943e-40ae-b708-82a5b856f7c9" />
<img width="1341" height="592" alt="image" src="https://github.com/user-attachments/assets/496c6343-5c7d-46b9-91f1-b342e821b015" />
<img width="1348" height="598" alt="image" src="https://github.com/user-attachments/assets/1b5a7d4e-f37e-4994-a3a6-c18e8cb26f9f" />


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
- Bootstrap for responsive design
- Jinja2 Templates

### 🔐 Security:
- Flask-Talisman (security headers)
- Flask-SeaSurf (CSRF protection)
- Werkzeug for WSGI utilities
- bcrypt, cryptography
- bleach (sanitization)
- defusedxml (secure XML)
- PyPDF2 for PDF handling

---

## 🗂️ Project Structure
```text

flask_owasp_lab/ 
│ 
├── app.py                
├── config.py             
settings). 
├── init_db.py            
├── requirements.txt      
├── README.md             
│ 
├── vulnerabilities/      
│   ├── sql_injection.py  # Example: Logic for SQL Injection (insecure and secure versions). 
│   ├── xss.py 
│   └── ... (other vulnerability .py files like access_control.py, ssrf.py etc.) 
│ 
├── templates/            
│   ├── layout.html       
│   ├── home.html         
│   ├── navbar.html       
# Contains HTML templates for rendering web pages. 
# Base template for common page structure. 
# Homepage listing available vulnerability labs. 
# Navigation bar component. 
│   ├── owasp_clone.html  # Template for displaying cloned OWASP documentation. 
│   ├── top10.html        
# Template for displaying PDF (likely jimmanico_owasptop10.pdf). 
│   └── search_results.html # Template to display search results for vulnerabilities. 
│   └── vulnerabilities/  # HTML templates specific to each vulnerability. 
│       ├── sql_injection.html # Example: UI for SQL Injection lab. 
│       └── ... (other vulnerability .html files) 
│ 
├── static/               
│   ├── style.css         
# Contains static assets like CSS, JavaScript, images, and documents. 
# Custom CSS styles for the application. 
│   ├── insecure_uploads/ # Folder for uploads in security misconfiguration demo. 
│   ├── secure_uploads/   # Secure folder for uploads in security misconfiguration demo. 
│   ├── pdf/ 
│   │   └── jimmanico_owasptop10.pdf # Supplementary OWASP Top 10 PDF resource. 
│   └── top10/            
# Cloned OWASP Top 10 website for reference. 
│       └── ... (HTML, CSS, JS files for the OWASP documentation) 
│ 
├── payloads/             
# JSON files containing payloads for testing each vulnerability. 
│   ├── sql_injection.json # Example: Payloads for SQL Injection. 
│   └── ... (other vulnerability .json files) 
│ 
└── data/                 
# Data files, including the database. 
├── init_db.sql       
└── users.db          
# SQL script for creating the database schema. 
# SQLite database file.  ...
```


## ⚙️ Getting Started

### Prerequisites:
- Python 3.6+
- `pip`
- Any modern browser
  
### Installation

1. Clone the repository:
```
 git clone https://github.com/yourusername/OWAShield.git
 cd OWAShield
 ```
2. Install dependencies:
```
pip install -r requirements.txt
```
3. Initialize the database:
```
python init_db.py
```
4. Run the application:
```
python app.py
```
5. Access the lab in your browser at:
```
http://localhost:5000
```
## 🎓 Learning Outcomes
With OWAShield, learners will:

- Understand OWASP Top 10 vulnerabilities deeply
- See live exploit attempts and consequences
- Learn how to secure against each attack
- Strengthen practical secure coding skills
- Practice threat modeling and mitigation

## 🤝 Contributions Welcome
Help make OWAShield better:
- Add new lab modules (e.g., IDOR, CSP)
- Improve UI/UX and visuals
- Add translations
- Contribute example payloads or CVE references
-  Please open an issue first to discuss proposed changes.
## 📝 License
This project is open-source and available under the MIT License.
## 🌐 Acknowledgements

I gratefully acknowledge the following communities and individuals whose work made this project possible:

- **[OWASP Foundation](https://owasp.org/)** — for setting the global standard in web application security through the OWASP Top 10 and other excellent resources.
- **[Flask](https://flask.palletsprojects.com/)** and the broader **Python open-source community** — for providing powerful, flexible tools for web development.
- **Cybersecurity educators, researchers, and mentors** — for continually advancing the field of secure software development.
- **The creators and maintainers of supporting libraries**, including:
  - `bcrypt`, `cryptography`, `Werkzeug`, `Flask-Talisman`, `Flask-SeaSurf`, `defusedxml`, and `bleach` — for essential security features.
- **UI/UX and frontend framework teams** like:
  - [Bootstrap](https://getbootstrap.com/) — for enabling responsive and accessible design.
- **SQLite and the DB-API community** — for making lightweight relational database testing possible.
- **Open security labs and training communities** — whose philosophies of hands-on learning inspired this project.
- **All contributors to security education** — from blog writers to conference speakers to GitHub maintainers who share knowledge openly.

> *Security is a shared responsibility. This project is the result of a community-wide commitment to building safer digital systems.*
> *💡 Learn. Hack. Secure. Share.OWAShield — because secure coding starts with understanding.*



# OWAShield
