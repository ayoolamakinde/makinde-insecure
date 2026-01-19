"""
Insecure Python Application - For Security Scanner Testing Only
Contains multiple intentional vulnerabilities for SAST detection
"""

import os
import pickle
import sqlite3
import subprocess
import yaml
from flask import Flask, request, render_template_string

app = Flask(__name__)

# Hardcoded credentials (Secrets Detection)
DATABASE_PASSWORD = "SuperSecret123!"
API_KEY = "sk_live_4eC39HqLyjWDarhtT657tMo5k"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF6R3r4Lv7m8EqFLYrTZY...
-----END RSA PRIVATE KEY-----"""

# SQL Injection vulnerability
@app.route('/user/<user_id>')
def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # Vulnerable to SQL injection
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return str(cursor.fetchone())

# Command Injection vulnerability
@app.route('/ping')
def ping():
    host = request.args.get('host', 'localhost')
    # Vulnerable to command injection
    result = os.system(f"ping -c 1 {host}")
    return f"Ping result: {result}"

# Path Traversal vulnerability
@app.route('/read_file')
def read_file():
    filename = request.args.get('file')
    # Vulnerable to path traversal
    with open(f"/var/data/{filename}", 'r') as f:
        return f.read()

# XSS vulnerability
@app.route('/search')
def search():
    query = request.args.get('q', '')
    # Vulnerable to XSS
    return render_template_string(f"<h1>Results for: {query}</h1>")

# Insecure Deserialization
@app.route('/deserialize', methods=['POST'])
def deserialize():
    data = request.get_data()
    # Vulnerable to insecure deserialization
    obj = pickle.loads(data)
    return str(obj)

# YAML Deserialization vulnerability
@app.route('/parse_yaml', methods=['POST'])
def parse_yaml():
    data = request.get_data()
    # Vulnerable to YAML deserialization attack
    parsed = yaml.load(data, Loader=yaml.Loader)
    return str(parsed)

# Weak cryptography
def weak_hash(password):
    import hashlib
    # Using weak MD5 hash
    return hashlib.md5(password.encode()).hexdigest()

# Subprocess with shell=True (command injection)
@app.route('/execute')
def execute_command():
    cmd = request.args.get('cmd')
    # Dangerous: shell injection possible
    output = subprocess.check_output(cmd, shell=True)
    return output

# SSRF vulnerability
@app.route('/fetch')
def fetch_url():
    import urllib.request
    url = request.args.get('url')
    # Vulnerable to SSRF
    response = urllib.request.urlopen(url)
    return response.read()

# Hardcoded JWT secret
JWT_SECRET = "this-is-my-secret-key"

# Insecure random number generation
def generate_token():
    import random
    # Using insecure random
    return random.randint(1000, 9999)

# SQL injection in login
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # Vulnerable SQL injection
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    user = cursor.fetchone()
    if user:
        return "Login successful"
    return "Login failed"

# Writing sensitive data to logs
@app.route('/log_user')
def log_user():
    password = request.args.get('password')
    # Logging sensitive data
    app.logger.info(f"User logged in with password: {password}")
    return "Logged"

# Insecure file upload
@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files['file']
    # No validation on file type or content
    file.save(f"/uploads/{file.filename}")
    return "File uploaded"

# Using eval (code injection)
@app.route('/calculate')
def calculate():
    expr = request.args.get('expr')
    # Dangerous: arbitrary code execution
    result = eval(expr)
    return str(result)

# Hardcoded database connection
def get_db_connection():
    import psycopg2
    # Hardcoded credentials
    conn = psycopg2.connect(
        host="db.example.com",
        database="mydb",
        user="admin",
        password="admin123"
    )
    return conn

# Insecure cookie settings
@app.route('/set_cookie')
def set_cookie():
    from flask import make_response
    resp = make_response("Cookie set")
    # No secure or httponly flags
    resp.set_cookie('session', 'sensitive-data', secure=False, httponly=False)
    return resp

# LDAP injection
@app.route('/ldap_search')
def ldap_search():
    import ldap
    username = request.args.get('username')
    # Vulnerable to LDAP injection
    search_filter = f"(uid={username})"
    return search_filter

# XML External Entity (XXE)
@app.route('/parse_xml', methods=['POST'])
def parse_xml():
    import xml.etree.ElementTree as ET
    xml_data = request.get_data()
    # Vulnerable to XXE
    tree = ET.fromstring(xml_data)
    return ET.tostring(tree)

# Insecure temporary file
@app.route('/create_temp')
def create_temp():
    import tempfile
    # Predictable temp file name
    temp_file = "/tmp/predictable_file.txt"
    with open(temp_file, 'w') as f:
        f.write("sensitive data")
    return temp_file

if __name__ == '__main__':
    # Running in debug mode (insecure in production)
    # Binding to 0.0.0.0 (accessible from anywhere)
    app.run(debug=True, host='0.0.0.0', port=5000)
