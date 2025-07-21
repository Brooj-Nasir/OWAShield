# init_db.py
import sqlite3

# Create database and tables
conn = sqlite3.connect('data/users.db')
with open('data/init_db.sql') as f:
    conn.executescript(f.read())
conn.commit()
conn.close()