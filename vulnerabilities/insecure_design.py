import random
import time
from flask import abort

# Insecure implementation
RESET_ATTEMPTS = {}

def insecure_password_reset(email):
    # No rate limiting or validation
    token = str(random.randint(100000, 999999))
    return f"Reset token {token} sent to {email}"

# Secure implementation
def secure_password_reset(email):
    # Rate limiting and validation
    if RESET_ATTEMPTS.get(email, 0) >= 3:
        abort(429, "Too many reset attempts")
    
    if '@' not in email:
        abort(400, "Invalid email format")
    
    token = str(random.randint(100000, 999999))
    RESET_ATTEMPTS[email] = RESET_ATTEMPTS.get(email, 0) + 1
    return f"Reset token {token} sent to {email} (Rate limited)"