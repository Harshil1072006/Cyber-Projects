import os
import shutil
import random
import string
import zipfile

def generate_random_string(length=20):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def create_complex_payload(base_dir="complex_vulnerable_app"):
    if os.path.exists(base_dir):
        shutil.rmtree(base_dir)
    os.makedirs(base_dir)
    
    # 1. Obscure deeply nested folders
    deep_path = os.path.join(base_dir, "src", "main", "java", "com", "enterprise", "legacy", "utils", "security", "internal")
    os.makedirs(deep_path)
    
    # Hidden AWS token in a java file
    java_code = """
package com.enterprise.legacy.utils.security.internal;

public class SecurityContextHolder {
    // This API key should never be checked in!
    // TODO: remove before production
    private static final String AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    private static final String AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
    
    public static boolean authenticate() {
        return true;
    }
}
"""
    with open(os.path.join(deep_path, "SecurityContextHolder.java"), "w") as f:
        f.write(java_code)
        
    # 2. Outdated vulnerable package in package.json
    front_dir = os.path.join(base_dir, "frontend", "dashboard")
    os.makedirs(front_dir)
    
    package_json = """{
  "name": "enterprise-dashboard",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "4.17.4",
    "react-scripts": "1.0.0",
    "axios": "0.18.0"
  }
}"""
    with open(os.path.join(front_dir, "package.json"), "w") as f:
        f.write(package_json)
        
    # 3. Dockerfile with root user and old base image
    docker_code = """FROM ubuntu:14.04
RUN apt-get update && apt-get install -y openssh-server
USER root
ENV MYSQL_ROOT_PASSWORD=super_secret_db_password_123
CMD ["bash"]
"""
    with open(os.path.join(base_dir, "Dockerfile"), "w") as f:
        f.write(docker_code)
        
    # 4. Generate random junk files to simulate a large project
    for i in range(10):
        junk_dir = os.path.join(base_dir, "modules", f"module_{i}")
        os.makedirs(junk_dir, exist_ok=True)
        for j in range(50): # 500 files total
            with open(os.path.join(junk_dir, f"DataProcessor{j}.txt"), "w") as f:
                f.write(f"Class component data {generate_random_string(500)}")
                
    # 5. A vulnerable Python script (Command Injection & Hardcoded credentials)
    py_dir = os.path.join(base_dir, "scripts", "admin")
    os.makedirs(py_dir, exist_ok=True)
    
    py_code = """
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
"""
    with open(os.path.join(py_dir, "maintenance.py"), "w") as f:
        f.write(py_code)

    # 6. Zip it up
    zip_name = "complex_vulnerable_app.zip"
    print(f"Zipping to {zip_name}...")
    with zipfile.ZipFile(zip_name, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(base_dir):
            for file in files:
                file_path = os.path.join(root, file)
                # Keep the internal folder structure
                arcname = os.path.relpath(file_path, base_dir)
                zipf.write(file_path, arcname)
                
    print(f"Created {zip_name} successfully (Size: {os.path.getsize(zip_name)/1024:.2f} KB) with over 500 files!")

if __name__ == "__main__":
    create_complex_payload()
