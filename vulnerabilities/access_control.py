# vulnerabilities/access_control.py
import sqlite3
from contextlib import closing

def get_user_role(user_id):
    with closing(sqlite3.connect('data/users.db')) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
        return cursor.fetchone()[0]

def insecure_access(user_id):
    """No permission check - insecure implementation"""
    with closing(sqlite3.connect('data/users.db')) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM sensitive_data WHERE user_id = ?", (user_id,))
        return cursor.fetchall()

def secure_access(user_id):
    """Secure implementation with role check"""
    role = get_user_role(user_id)
    if role != 'admin':
        raise PermissionError("Unauthorized access attempt")
    
    with closing(sqlite3.connect('data/users.db')) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM sensitive_data WHERE user_id = ?", (user_id,))
        return cursor.fetchall()