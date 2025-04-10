import requests
from bs4 import BeautifulSoup
import time

# Function to test for SQL Injection (A1)
def test_sql_injection(url):
    print("Testing for SQL Injection (A1)...")
    payload = "' OR '1'='1'; --"
    response = requests.get(url, params={'username': payload, 'password': 'password'})
    if "Welcome" in response.text:  # This is a simplistic check for a successful login page
        return True
    return False

# Function to test for XSS (Cross-Site Scripting) (A7)
def test_xss(url):
    print("Testing for Cross-Site Scripting (XSS) (A7)...")
    payload = "<script>alert('XSS')</script>"
    response = requests.get(url + "/search", params={'query': payload})
    if payload in response.text:
        return True
    return False

# Function to test for Sensitive Data Exposure (A3)
def test_sensitive_data_exposure(url):
    print("Testing for Sensitive Data Exposure (A3)...")
    response = requests.get(url + "/account")
    if "password" in response.text.lower():  # Look for password information in the response
        return True
    return False

# Function to test for Security Misconfiguration (A6)
def test_security_misconfiguration(url):
    print("Testing for Security Misconfiguration (A6)...")
    response = requests.get(url + "/admin")
    if response.status_code == 200:
        return True
    return False

# Function to test for Broken Authentication (A2)
def test_broken_authentication(url):
    print("Testing for Broken Authentication (A2)...")
    response = requests.post(url + "/login", data={'username': 'admin', 'password': 'incorrect'})
    if "Invalid credentials" not in response.text:
        return True
    return False

# Function to test for Broken Access Control (A5)
def test_broken_access_control(url):
    print("Testing for Broken Access Control (A5)...")
    response = requests.get(url + "/admin")
    if response.status_code == 200:
        return True
    return False

# Function to test for XML External Entities (XXE) (A4)
def test_xxe(url):
    print("Testing for XML External Entities (XXE) (A4)...")
    payload = """<?xml version="1.0" encoding="ISO-8859-1"?>
                <!DOCTYPE foo [ 
                <!ELEMENT foo ANY >
                <!ENTITY xxe SYSTEM "file:///etc/passwd" >] >
                <foo>&xxe;</foo>"""
    headers = {'Content-Type': 'application/xml'}
    response = requests.post(url + "/upload", data=payload, headers=headers)
    if "root" in response.text:  # Checking if we get system file contents
        return True
    return False

# Function to test for Insecure Deserialization (A8)
def test_insecure_deserialization(url):
    print("Testing for Insecure Deserialization (A8)...")
    payload = "dummy_payload"
    response = requests.post(url + "/login", data={'username': 'admin', 'password': payload})
    if "error" not in response.text:  # Checking for unexpected responses
        return True
    return False

# Function to test for Using Components with Known Vulnerabilities (A9)
def test_known_vulnerabilities(url):
    print("Testing for Known Vulnerabilities (A9)...")
    response = requests.get(url)
    headers = response.headers
    if "Server" in headers and "Apache" in headers["Server"]:
        return True
    return False

# Function to test for Insufficient Logging & Monitoring (A10)
def test_insufficient_logging(url):
    print("Testing for Insufficient Logging & Monitoring (A10)...")
    # This is a simple check. A full check would involve monitoring logs for unusual activity
    response = requests.get(url + "/login")
    if response.status_code == 200:  # If a response is successful, assume monitoring is insufficient
        return True
    return False

# Function to conduct a full OWASP Top 10 test suite
def test_owasp_top_10(url):
    vulnerabilities = {}

    # Perform tests
    vulnerabilities['SQL Injection (A1)'] = test_sql_injection(url)
    vulnerabilities['XSS (A7)'] = test_xss(url)
    vulnerabilities['Sensitive Data Exposure (A3)'] = test_sensitive_data_exposure(url)
    vulnerabilities['Security Misconfiguration (A6)'] = test_security_misconfiguration(url)
    vulnerabilities['Broken Authentication (A2)'] = test_broken_authentication(url)
    vulnerabilities['Broken Access Control (A5)'] = test_broken_access_control(url)
    vulnerabilities['XXE (A4)'] = test_xxe(url)
    vulnerabilities['Insecure Deserialization (A8)'] = test_insecure_deserialization(url)
    vulnerabilities['Known Vulnerabilities (A9)'] = test_known_vulnerabilities(url)
    vulnerabilities['Insufficient Logging & Monitoring (A10)'] = test_insufficient_logging(url)

    return vulnerabilities

# Function to generate the report
def generate_report(vulnerabilities):
    print("\nSecurity Vulnerability Report")
    print("="*30)
    for vuln, is_vulnerable in vulnerabilities.items():
        status = "Vulnerable" if is_vulnerable else "Not Vulnerable"
        print(f"{vuln}: {status}")
    print("="*30)

def main():
    print("Welcome to Web Application Security Testing Tool")
    
    # Get the web application URL from user
    target_url = input("Enter the web application URL (e.g., http://example.com): ").strip()

    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        print("Invalid URL. Please make sure the URL starts with http:// or https://.")
        return
    
    # Run OWASP Top 10 tests
    print("\nStarting OWASP Top 10 Vulnerability Assessment...")
    vulnerabilities = test_owasp_top_10(target_url)

    # Generate and display the report
    generate_report(vulnerabilities)

    # Optionally, save the results to a file
    with open("security_report.txt", "w") as file:
        for vuln, is_vulnerable in vulnerabilities.items():
            file.write(f"{vuln}: {'Vulnerable' if is_vulnerable else 'Not Vulnerable'}\n")
    print("\nSecurity report saved as 'security_report.txt'.")

if __name__ == '__main__':
    main()
