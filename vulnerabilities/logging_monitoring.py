import logging
from datetime import datetime

def insecure_log(attempt):
    # No security logging
    return "Login attempt processed (no logging)"

def secure_log(attempt):
    logger = logging.getLogger('security')
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'event': 'login_attempt',
        'details': attempt,
        'ip_address': '192.168.1.1'
    }
    logger.warning(str(log_entry))
    return f"Logged: {log_entry}"