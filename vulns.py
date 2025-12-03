# vulnerable_app.py
# Purpose: Demonstration of GitHub CodeQL's scanning capabilities.
#
# WARNING: This script is INTENTIONALLY vulnerable and contains numerous security flaws.
# DO NOT RUN, DEPLOY, OR USE THIS CODE IN ANY PRODUCTION OR DEVELOPMENT ENVIRONMENT.
# It is designed solely to trigger alerts from a SAST scanner like CodeQL.

import os
import subprocess
import sqlite3
import pickle
import hashlib
import tempfile
import logging
import requests
from flask import Flask, request, Markup, make_response
from xml.etree import ElementTree

# --- App Setup ---
app = Flask(__name__)

# --- Vulnerability Configuration ---

# CWE-798: Use of Hard-coded Credentials
# CodeQL Alert: Hard-coded credentials
API_KEY = "sk-live-2zscaler_fake_key_for_roop_singh_demo" 
DB_PASSWORD = "password123"

# --- Vulnerabilities ---

@app.route('/command')
def command_injection():
    """
    CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
    CodeQL Alert: OS command injection
    """
    domain = request.args.get('domain')
    # Unsanitized user input is passed directly to a shell command.
    os.system(f"nslookup {domain}") 
    return "Command executed."

@app.route('/user_data')
def sql_injection():
    """
    CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
    CodeQL Alert: SQL injection
    """
    user_id = request.args.get('id')
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    # User input is concatenated directly into a SQL query.
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    return str(cursor.fetchall())

@app a.route('/hello')
def cross_site_scripting():
    """
    CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
    CodeQL Alert: Reflected cross-site scripting
    """
    name = request.args.get('name')
    # User input is directly rendered in the HTML response without sanitization.
    return Markup(f"<h1>Hello, {name}!</h1>") 

@app.route('/file')
def path_traversal():
    """
    CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
    CodeQL Alert: Path injection
    """
    filename = request.args.get('filename')
    # User can provide '..' to navigate the file system.
    with open(f'/var/www/data/{filename}', 'r') as f:
        return f.read()

@app.route('/deserialize')
def insecure_deserialization():
    """
    CWE-502: Deserialization of Untrusted Data
    CodeQL Alert: Deserialization of untrusted data
    """
    pickled_data = request.get_data()
    # The 'pickle' module can execute arbitrary code.
    deserialized_obj = pickle.loads(pickled_data)
    return f"Deserialized: {deserialized_obj}"

@app.route('/login', methods=['POST'])
def weak_hashing():
    """
    CWE-327: Use of a Broken or Risky Cryptographic Algorithm
    CodeQL Alert: Use of a weak cryptographic hash function
    """
    password = request.form['password']
    # MD5 is cryptographically broken and should not be used for passwords.
    hashed_password = hashlib.md5(password.encode()).hexdigest()
    # Also using SHA1 for another alert
    sha1_hash = hashlib.sha1(password.encode()).hexdigest()
    return f"MD5 Hash: {hashed_password}<br>SHA1 Hash: {sha1_hash}"

@app.route('/xml')
def xml_external_entity():
    """
    CWE-611: Improper Restriction of XML External Entity Reference ('XXE')
    CodeQL Alert: XML external entity injection
    """
    xml_string = request.args.get('xml')
    # The default XML parser is vulnerable to XXE attacks.
    root = ElementTree.fromstring(xml_string)
    return f"Parsed XML element: {root.tag}"

@app.route('/proxy')
def server_side_request_forgery():
    """
    CWE-918: Server-Side Request Forgery (SSRF)
    CodeQL Alert: Server-side request forgery
    """
    url = request.args.get('url')
    # The server makes a request to a URL supplied by the user.
    response = requests.get(url)
    return response.text

@app.route('/log')
def log_injection():
    """
    CWE-117: Improper Output Neutralization for Logs
    CodeQL Alert: Log injection
    """
    username = request.args.get('username')
    logging.basicConfig(filename='app.log', level=logging.INFO)
    # Malicious input can inject newlines and forge log entries.
    logging.info(f'Login attempt for user: {username}')
    return "Logged event."

@appoken('/redirect')
def open_redirect():
    """
    CWE-601: URL Redirection to Untrusted Site ('Open Redirect')
    CodeQL Alert: URL redirection from remote sources
    """
    target_url = request.args.get('url')
    # Redirecting to a user-controlled URL.
    return flask.redirect(target_url)

@app.route('/run_code')
def remote_code_execution_eval():
    """
    CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Code Injection')
    CodeQL Alert: Use of eval
    """
    code = request.args.get('code')
    # 'eval' executes string expressions, a massive security risk with user input.
    result = eval(code)
    return f"Executed. Result: {result}"

@app.route('/tmpfile')
def insecure_temp_file():
    """
    CWE-377: Insecure Temporary File
    CodeQL Alert: Insecure temporary file
    """
    # mktemp is insecure due to a race condition.
    filename = tempfile.mktemp()
    with open(filename, "w") as f:
        f.write("This is a temporary file.")
    return f"Created insecure temp file: {filename}"
    
@app.route('/admin')
def csrf_vulnerable_form():
    """
    CWE-352: Cross-Site Request Forgery (CSRF)
    CodeQL Alert: Flask CSRF protection disabled
    This route would be part of a larger app where CSRF protection is missing globally.
    CodeQL may flag the lack of CSRF middleware for the entire Flask app.
    """
    return """
    <form method="POST" action="/change_password">
        New Password: <input type="password" name="new_password">
        <input type="submit" value="Change Password">
    </form>
    """

if __name__ == '__main__':
    # CWE-215: Insertion of Sensitive Information into Sent Data
    # CodeQL Alert: Application is running in debug mode
    # Running Flask in debug mode exposes a remote debugger and is highly insecure.
    app.run(host='0.0.0.0', port=5000, debug=True)
