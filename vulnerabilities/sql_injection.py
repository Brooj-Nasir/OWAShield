# vulnerabilities/sql_injection.py
import sqlite3
from contextlib import closing

def get_db_connection():
    return sqlite3.connect('data/users.db')

def insecure_code(payload):
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        query = f"SELECT * FROM users WHERE username = '{payload}'"
        cursor.execute(query)
        results = cursor.fetchall()
    return results

def secure_code(payload):
    with closing(get_db_connection()) as conn:
        cursor = conn.cursor()
        query = "SELECT * FROM users WHERE username = ?"
        cursor.execute(query, (payload,))
        results = cursor.fetchall()
    return results