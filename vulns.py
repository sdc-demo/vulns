# vulnerable_app.py
#
#
# A demonstration Python application containing a wide variety of vulnerabilities
# for the purpose of testing static analysis security tools (SAST) like CodeQL.
#
# --- INTENTIONALLY INSECURE & SYNTACTICALLY CORRECT ---

import os
import subprocess
import sqlite3
import yaml
from lxml import etree
from flask import Flask, request

# --- Vulnerable Application Setup ---

app = Flask(__name__)

# CWE-798: Use of Hard-coded Credentials
# CodeQL ID: python/hardcoded-credentials
# This is a simple, high-confidence finding for SAST tools.
API_KEY = "sk_live_12345abcdeFGHIjklmnoPQRSTuvwXYz12345"
DATABASE_PASSWORD = "password123!"


# --- Vulnerable Function Definitions ---

def command_injection(user_input):
    """
    CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
    CodeQL ID: python/command-line-injection
    """
    print(f"\n[!] Triggering OS Command Injection (CWE-78) with input: {user_input}")
    # BAD: Using shell=True with user-controllable input allows command injection.
    # An input like "test.txt; ls -la" would execute the 'ls' command.
    subprocess.call(f"ls {user_input}", shell=True)


def sql_injection(user_id):
    """
    CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
    CodeQL ID: python/sql-injection
    """
    print(f"\n[!] Triggering SQL Injection (CWE-89) with input: '{user_id}'")
    db = sqlite3.connect(":memory:")
    cursor = db.cursor()
    # BAD: Constructing a query with an f-string using raw user input.
    # An input like "' OR '1'='1" would return all users.
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    print(f"    Executing query: {query}")
    try:
        cursor.execute(query)
    except sqlite3.OperationalError as e:
        print(f"    (Query failed as expected, table 'users' does not exist: {e})")
    db.close()


def unsafe_deserialization(yaml_string):
    """
    CWE-502: Deserialization of Untrusted Data
    CodeQL ID: python/unsafe-deserialization
    """
    print(f"\n[!] Triggering Unsafe Deserialization (CWE-502) with YAML")
    # BAD: yaml.load is unsafe and can lead to arbitrary code execution if the input is crafted.
    # The safe alternative is yaml.safe_load().
    try:
        data = yaml.load(yaml_string, Loader=yaml.FullLoader)
        print(f"    Deserialized data: {data}")
    except Exception as e:
        print(f"    An error occurred during deserialization: {e}")


def path_traversal(filename):
    """
    CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
    CodeQL ID: python/path-injection
    """
    print(f"\n[!] Triggering Path Traversal (CWE-22) with input: {filename}")
    base_dir = "/var/www/uploads"
    # BAD: Joining a path with untrusted input without sanitization.
    # An input like "../../../../etc/passwd" could allow access to sensitive files.
    full_path = os.path.join(base_dir, filename)
    print(f"    Attempting to access file at: {full_path}")
    # In a real app, this would be followed by `open(full_path, 'r')`
    # We will just print the path to demonstrate the vulnerability.


def xxe_vulnerability(xml_string):
    """
    CWE-611: Improper Restriction of XML External Entity Reference ('XXE')
    CodeQL ID: python/xxe
    """
    print(f"\n[!] Triggering XXE (CWE-611) with XML input")
    # BAD: The default XML parser in lxml is vulnerable to XXE.
    # An attacker can supply malicious XML to read local files or perform SSRF.
    parser = etree.XMLParser() # The default parser is not secure
    try:
        tree = etree.fromstring(xml_string, parser)
        print("    XML parsed successfully (this is bad if input is malicious).")
    except etree.XMLSyntaxError as e:
        print(f"    XML parsing failed: {e}")


@app.route('/hello')
def hello_xss():
    """
    CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
    CodeQL ID: python/jinja2-autoescaping-disabled, python/unsafe-html-construction
    
    This function will be flagged by CodeQL when it analyzes the Flask application context.
    """
    # Source of taint: user input from a request argument.
    name = request.args.get('name', 'guest')
    print(f"\n[!] Flask route /hello triggered with name='{name}' for XSS (CWE-79)")
    # BAD: Returning raw, unescaped HTML containing user input.
    # A request to /hello?name=<script>alert(1)</script> would execute JavaScript.
    return f"<h1>Hello, {name}!</h1>"


# --- Main execution block to demonstrate vulnerabilities ---
def main():
    """
    Main function to run all vulnerability demonstrations.
    This part is for local execution and helps confirm the syntax is correct.
    CodeQL analyzes the functions themselves, regardless of whether they are called.
    """
    print("--- Starting Vulnerable Python Application Demonstration ---")
    print(f"User: {USER_INFO['name']} ({USER_INFO['email']})")

    # Define malicious inputs
    cmd_injection_input = "nonexistent.txt; whoami"
    sql_injection_input = "' or '1'='1"
    # Malicious YAML for RCE (runs 'id' command)
    deserialization_input = "!!python/object/apply:os.system ['id']"
    path_traversal_input = "../../../../etc/hosts"
    # Malicious XML for XXE (tries to read /etc/passwd)
    xxe_input = """<?xml version="1.0"?>
    <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
    <foo>&xxe;</foo>"""

    # Trigger vulnerable functions
    command_injection(cmd_injection_input)
    sql_injection(sql_injection_input)
    unsafe_deserialization(deserialization_input)
    path_traversal(path_traversal_input)
    xxe_vulnerability(xxe_input)
    
    print("\n--- Vulnerability demonstrations complete. ---")
    print("Note: The XSS vulnerability (CWE-79) is in a Flask route.")
    print("CodeQL will detect it by analyzing the web framework, not by direct execution here.")


if __name__ == "__main__":
    USER_INFO = {
        "name": "Roop Singh",
        "email": "roop.singh@zscaler.com"
    }
    main()
    # To run the web app part for live testing:
    # app.run(debug=True)
