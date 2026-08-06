# test_repo/app.py
import sqlite3

# VULNERABILITY 1: Hardcoded sensitive credential
AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"

def get_user_profile(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # VULNERABILITY 2: SQL Injection via direct string concatenation
    query = f"SELECT * FROM profiles WHERE id = '{user_id}'"
    cursor.execute(query)
    
    return cursor.fetchone()