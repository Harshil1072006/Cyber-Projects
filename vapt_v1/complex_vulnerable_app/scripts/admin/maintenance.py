
import os
import sqlite3
from flask import Flask, request

app = Flask(__name__)

# Hardcoded DB credentials!
DB_PASSWORD = "production_db_pasSw0rd!#@"

@app.route('/ping')
def ping_server():
    ip = request.args.get('ip')
    # SQL INJECTION & COMMAND INJECTION HERE!
    os.system(f"ping -c 4 {ip}")
    return "Ping complete!"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
