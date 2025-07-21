import sqlite3
from contextlib import closing
import bcrypt

def insecure_login(credentials):
    with closing(sqlite3.connect('data/users.db')) as conn:
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM users WHERE username = '{credentials['username']}' AND password = '{credentials['password']}'")
        user = cursor.fetchone()
        if user:
            return f"Logged in as {user[1]} (Insecure)"
        return "Invalid credentials"

def secure_login(credentials):
    with closing(sqlite3.connect('data/users.db')) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (credentials['username'],))
        user = cursor.fetchone()
        if user and bcrypt.checkpw(credentials['password'].encode(), user[3]):
            return f"Logged in as {user[1]} (Secure)"
        return "Invalid credentials"