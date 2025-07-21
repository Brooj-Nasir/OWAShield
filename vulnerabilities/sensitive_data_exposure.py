from cryptography.fernet import Fernet
import sqlite3

KEY = Fernet.generate_key()

def insecure_storage(card_number):
    conn = sqlite3.connect('data/users.db')
    conn.execute("INSERT INTO payment_info (card_number) VALUES (?)", 
                (card_number,))
    conn.commit()
    return f"Stored: {card_number}"

def secure_storage(card_number):
    cipher = Fernet(KEY)
    encrypted = cipher.encrypt(card_number.encode())
    conn = sqlite3.connect('data/users.db')
    conn.execute("INSERT INTO payment_info (encrypted_card) VALUES (?)", 
                (encrypted,))
    conn.commit()
    return f"Stored: {encrypted.decode()}"