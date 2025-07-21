# app.py
from flask import Flask, render_template, request, json
import os
import logging
from vulnerabilities.sql_injection import insecure_code, secure_code
from vulnerabilities.xss import insecure_code as xss_insecure, secure_code as xss_secure
from vulnerabilities.access_control import insecure_access, secure_access
from vulnerabilities.security_misconfig import insecure_file_handler, secure_file_handler
from vulnerabilities.insecure_deserialization import insecure_deserialization, secure_deserialization
from vulnerabilities.sensitive_data_exposure import insecure_storage, secure_storage
from vulnerabilities.ssrf import insecure_fetch, secure_fetch
from vulnerabilities.broken_auth import insecure_login, secure_login
from vulnerabilities.vulnerable_components import insecure_parse, secure_parse
from vulnerabilities.logging_monitoring import insecure_log, secure_log
from vulnerabilities.crypto_failures import insecure_encrypt, secure_encrypt
from vulnerabilities.insecure_design import insecure_password_reset, secure_password_reset

#top ten details
from flask import send_from_directory



app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'static/uploads'

# Add to app.py
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
security_logger = logging.getLogger('security')
security_logger.setLevel(logging.WARNING)

# Load payloads
def load_payloads(vuln_type):
    payload_path = os.path.join('payloads', f'{vuln_type}.json')
    with open(payload_path) as f:
        return json.load(f)

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/sql-injection', methods=['GET', 'POST'])
def sql_injection():
    payloads = load_payloads('sql_injection')
    result_insecure = None
    result_secure = None
    
    if request.method == 'POST':
        payload = request.form.get('payload')
        selected_payload = next((p for p in payloads if p['payload'] == payload), None)
        
        if selected_payload:
            try:
                result_insecure = insecure_code(payload)
            except Exception as e:
                result_insecure = f"Error: {str(e)}"
            
            try:
                result_secure = secure_code(payload)
            except Exception as e:
                result_secure = f"Error: {str(e)}"
    
    return render_template('vulnerabilities/sql_injection.html', 
                         payloads=payloads,
                         result_insecure=result_insecure,
                         result_secure=result_secure)

# Add new route
@app.route('/xss', methods=['GET', 'POST'])
def xss():
    payloads = load_payloads('xss')
    result_insecure = None
    result_secure = None
    
    if request.method == 'POST':
        payload = request.form.get('payload')
        selected_payload = next((p for p in payloads if p['payload'] == payload), None)
        
        if selected_payload:
            try:
                result_insecure = xss_insecure(payload)
            except Exception as e:
                result_insecure = f"Error: {str(e)}"
            
            try:
                result_secure = xss_secure(payload)
            except Exception as e:
                result_secure = f"Error: {str(e)}"
    
    return render_template('vulnerabilities/xss.html',
                         payloads=payloads,
                         result_insecure=result_insecure,
                         result_secure=result_secure)

@app.route('/broken-access-control', methods=['GET', 'POST'])
def broken_access_control():
    payloads = load_payloads('broken_access_control')
    result_insecure = None
    result_secure = None
    
    if request.method == 'POST':
        user_id = request.form.get('payload')
        try:
            # Insecure version
            result_insecure = insecure_access(user_id)
        except Exception as e:
            result_insecure = f"Error: {str(e)}"
        
        try:
            # Secure version
            result_secure = secure_access(user_id)
        except Exception as e:
            result_secure = f"Error: {str(e)}"
    
    return render_template('vulnerabilities/broken_access_control.html',
                         payloads=payloads,
                         result_insecure=result_insecure,
                         result_secure=result_secure)

@app.route('/security-misconfiguration', methods=['GET', 'POST'])
def security_misconfiguration():
    payloads = load_payloads('security_misconfiguration')
    result_insecure = None
    result_secure = None
    
    if request.method == 'POST':
        filename = request.form.get('payload')
        try:
            result_insecure = insecure_file_handler(filename)
        except Exception as e:
            result_insecure = f"Error: {str(e)}"
        
        try:
            result_secure = secure_file_handler(filename)
        except Exception as e:
            result_secure = f"Error: {str(e)}"
    
    return render_template('vulnerabilities/security_misconfiguration.html',
                         payloads=payloads,
                         result_insecure=result_insecure,
                         result_secure=result_secure)

@app.route('/insecure-deserialization', methods=['GET', 'POST'])  # Correct URL
def insecure_deser():
    payloads = load_payloads('insecure_deserialization')
    result_insecure = result_secure = None
    
    if request.method == 'POST':
        payload = request.form.get('payload')
        try:
            result_insecure = insecure_deserialization(payload)
        except Exception as e:
            result_insecure = f"Error: {str(e)}"
            
        try:
            result_secure = secure_deserialization(payload)
        except Exception as e:
            result_secure = f"Error: {str(e)}"

    return render_template('vulnerabilities/insecure_deserialization.html',
                         payloads=payloads,
                         result_insecure=result_insecure,
                         result_secure=result_secure)

@app.route('/sensitive-data-exposure', methods=['GET', 'POST'])  # Correct URL
def sensitive_data():
    payloads = load_payloads('sensitive_data_exposure')
    result_insecure = result_secure = None
    
    if request.method == 'POST':
        credit_card = request.form.get('payload')
        result_insecure = insecure_storage(credit_card)
        result_secure = secure_storage(credit_card)

    return render_template('vulnerabilities/sensitive_data_exposure.html',
                         payloads=payloads,
                         result_insecure=result_insecure,
                         result_secure=result_secure)

@app.route('/ssrf', methods=['GET', 'POST'])
def ssrf():
    payloads = load_payloads('ssrf')
    result_insecure = result_secure = None
    
    if request.method == 'POST':
        url = request.form.get('payload')
        try:
            result_insecure = insecure_fetch(url)
        except Exception as e:
            result_insecure = f"Error: {str(e)}"
            
        try:
            result_secure = secure_fetch(url)
        except Exception as e:
            result_secure = f"Error: {str(e)}"

    return render_template('vulnerabilities/ssrf.html',
                         payloads=payloads,
                         result_insecure=result_insecure,
                         result_secure=result_secure)

@app.route('/broken_auth', methods=['GET', 'POST'])
def broken_auth():
    payloads = load_payloads('broken_auth')
    result_insecure = result_secure = None
    
    if request.method == 'POST':
        credentials = {
            'username': request.form.get('username'),
            'password': request.form.get('password')
        }
        
        try:
            result_insecure = insecure_login(credentials)
        except Exception as e:
            result_insecure = f"Error: {str(e)}"
            
        try:
            result_secure = secure_login(credentials)
        except Exception as e:
            result_secure = f"Error: {str(e)}"

    return render_template('vulnerabilities/broken_auth.html',
                         payloads=payloads,
                         result_insecure=result_insecure,
                         result_secure=result_secure)

@app.route('/vulnerable_components', methods=['GET', 'POST'])
def vulnerable_components():
    payloads = load_payloads('vulnerable_components')
    result_insecure = result_secure = None
    
    if request.method == 'POST':
        xml_data = request.form.get('payload')
        try:
            result_insecure = insecure_parse(xml_data)
        except Exception as e:
            result_insecure = f"Error: {str(e)}"
            
        try:
            result_secure = secure_parse(xml_data)
        except Exception as e:
            result_secure = f"Error: {str(e)}"

    return render_template('vulnerabilities/vulnerable_components.html',
                         payloads=payloads,
                         result_insecure=result_insecure,
                         result_secure=result_secure)

@app.route('/logging_monitoring', methods=['GET', 'POST'])
def insufficient_logging():
    payloads = load_payloads('logging_monitoring')
    result_insecure = result_secure = None
    
    if request.method == 'POST':
        attempt = request.form.get('payload')
        try:
            result_insecure = insecure_log(attempt)
        except Exception as e:
            result_insecure = f"Error: {str(e)}"
            
        try:
            result_secure = secure_log(attempt)
        except Exception as e:
            result_secure = f"Error: {str(e)}"

    return render_template('vulnerabilities/logging_monitoring.html',
                         payloads=payloads,
                         result_insecure=result_insecure,
                         result_secure=result_secure)

@app.route('/crypto_failures', methods=['GET', 'POST'])
def crypto_failures():
    payloads = load_payloads('crypto_failures')
    result_insecure = {'error': None, 'output': None}
    result_secure = {'error': None, 'salt': None, 'iv': None, 'ciphertext': None, 'tag': None}
    
    if request.method == 'POST':
        data = request.form.get('payload')
        try:
            # Insecure encryption
            insecure_bytes = insecure_encrypt(data)
            result_insecure['output'] = insecure_bytes.hex()
        except Exception as e:
            result_insecure['error'] = f"Error: {str(e)}"
            
        try:
            # Secure encryption
            salt, iv, ct, tag = secure_encrypt(data)
            result_secure.update({
                'salt': salt.hex(),
                'iv': iv.hex(),
                'ciphertext': ct.hex(),
                'tag': tag.hex()
            })
        except Exception as e:
            result_secure['error'] = f"Error: {str(e)}"

    return render_template('vulnerabilities/crypto_failures.html',
                         payloads=payloads,
                         result_insecure=result_insecure,
                         result_secure=result_secure)

@app.route('/insecure_design', methods=['GET', 'POST'])
def insecure_design():
    payloads = load_payloads('insecure_design')
    result_insecure = result_secure = None
    
    if request.method == 'POST':
        email = request.form.get('payload')
        try:
            result_insecure = insecure_password_reset(email)
            result_secure = secure_password_reset(email)
        except Exception as e:
            result_insecure = f"Error: {str(e)}"
            result_secure = f"Error: {str(e)}"

    return render_template('vulnerabilities/insecure_design.html',
                         payloads=payloads,
                         result_insecure=result_insecure,
                         result_secure=result_secure)

# top ten details
@app.route('/owasp_clone')
def owasp_clone():
    return render_template('owasp_clone.html')

# Sample vulnerability data (You can replace this with a database or dynamic list)
vulnerabilities = [
    {'name': 'SQL Injection', 'url': '/sql-injection'},
    {'name': 'Cross-Site Scripting (XSS)', 'url': '/xss'},
    {'name': 'Broken Access Control', 'url': '/broken-access-control'},
    {'name': 'Security Misconfiguration', 'url': '/security-misconfiguration'},
    {'name': 'Insecure Deserialization', 'url': '/insecure-deserialization'},
    {'name': 'Sensitive Data Exposure', 'url': '/sensitive-data-exposure'},
    {'name': 'Broken Authentication', 'url': '/broken_auth'},
    {'name': 'Server-Side Request Forgery (SSRF)', 'url': '/ssrf'},
    {'name': 'Logging and Monitoring', 'url': '/logging_monitoring'},
    {'name': 'Vulnerable Components', 'url': '/vulnerable_components'},
    {'name': 'Insecure Design', 'url': '/insecure_design'},
    {'name': 'Read OWASP TOP 10 Vulnerabilities', 'url': '/owasp_clone'},

    # {'name': 'Cryptographic Failures', 'url': '/crypto_failures'}
]

@app.route('/search')
def search():
    query = request.args.get('q', '').strip().lower()
    
    if not query:
        return render_template('search_results.html', query=query, results=[])

    # Filter vulnerabilities based on query match
    matched_items = [
        vuln for vuln in vulnerabilities
        if query in vuln['name'].lower()
    ]

    return render_template('search_results.html', query=query, results=matched_items)


if __name__ == '__main__':
    app.run(debug=True)