# vulnerabilities/xss.py
import html

def insecure_code(payload):
    # Dangerously return unescaped input
    return f"<div>User input: {payload}</div>"

def secure_code(payload):
    # Properly escape HTML characters
    safe_payload = html.escape(payload)
    return f"<div>User input: {safe_payload}</div>"