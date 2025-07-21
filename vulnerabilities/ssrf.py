import requests
from urllib.parse import urlparse

ALLOWED_DOMAINS = ['api.trusted-domain.com']

def insecure_fetch(url):
    response = requests.get(url)
    return f"Status: {response.status_code}\nContent: {response.text[:200]}..."

def secure_fetch(url):
    parsed = urlparse(url)
    if parsed.hostname not in ALLOWED_DOMAINS:
        raise ValueError("Unauthorized domain requested")
    
    response = requests.get(url, timeout=5)
    return f"Status: {response.status_code}\nContent: {response.text[:200]}..."