import os
from flask import send_from_directory

INSECURE_UPLOADS = 'static/insecure_uploads'
SECURE_UPLOADS = 'static/secure_uploads'

def insecure_file_handler(filename):
    """Dangerous file handling without validation"""
    try:
        filepath = os.path.join(INSECURE_UPLOADS, filename)
        with open(filepath, 'r') as f:
            content = f.read()
        return content
    except Exception as e:
        return f"Error: {str(e)}"

def secure_file_handler(filename):
    """Secure file handling with validation"""
    try:
        # Prevent directory traversal
        if '../' in filename:
            raise ValueError("Invalid filename")
        
        safe_path = os.path.abspath(os.path.join(SECURE_UPLOADS, filename))
        if not safe_path.startswith(os.path.abspath(SECURE_UPLOADS)):
            raise PermissionError("Access denied")
        
        if not os.path.exists(safe_path):
            raise FileNotFoundError("File not found")
        
        with open(safe_path, 'r') as f:
            content = f.read()
        return content
    except Exception as e:
        return f"Error: {str(e)}"