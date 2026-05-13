import sqlite3
import os

# HARDCODED CREDENTIALS (VULNERABILITY)
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DB_PASSWORD = "super_secret_production_password_123!"

def login(username, password):
    # SQL INJECTION (VULNERABILITY)
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    result = cursor.fetchall()
    return result

def ping_server(ip_address):
    # OS COMMAND INJECTION (VULNERABILITY)
    os.system(f"ping -c 4 {ip_address}")

if __name__ == "__main__":
    print("Running vulnerable application...")
    # This app is highly vulnerable to injection attacks and leaks credentials!
