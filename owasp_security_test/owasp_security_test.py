import requests
from bs4 import BeautifulSoup

# A01:2021 - Broken Access Control
def test_broken_access_control(url):
    print("[+] Testing for Broken Access Control (A01:2021)...")
    response = requests.get(url + "/admin")
    return response.status_code == 200

# A02:2021 - Cryptographic Failures
def test_cryptographic_failures(url):
    print("[+] Testing for Cryptographic Failures (A02:2021)...")
    response = requests.get(url + "/account")
    return 'http://' in response.text or 'set-cookie' in response.headers and 'Secure' not in response.headers['set-cookie']

# A03:2021 - Injection
def test_injection(url):
    print("[+] Testing for Injection (A03:2021)...")
    payload = "' OR '1'='1"  # SQLi payload
    response = requests.get(url, params={'username': payload, 'password': 'pass'})
    return "Welcome" in response.text

# A04:2021 - Insecure Design (Basic detection)
def test_insecure_design(url):
    print("[+] Testing for Insecure Design (A04:2021)...")
    response = requests.get(url + "/debug")
    return response.status_code == 200 and "debug" in response.text.lower()

# A05:2021 - Security Misconfiguration
def test_security_misconfiguration(url):
    print("[+] Testing for Security Misconfiguration (A05:2021)...")
    response = requests.get(url + "/.git/config")
    return response.status_code == 200 and "repository" in response.text.lower()

# A06:2021 - Vulnerable and Outdated Components
def test_outdated_components(url):
    print("[+] Testing for Vulnerable and Outdated Components (A06:2021)...")
    response = requests.get(url)
    server_header = response.headers.get("Server", "")
    return any(kw in server_header.lower() for kw in ["apache/2.2", "php/5.", "nginx/1.0"])

# A07:2021 - Identification and Authentication Failures
def test_authentication_failures(url):
    print("[+] Testing for Identification and Authentication Failures (A07:2021)...")
    response = requests.post(url + "/login", data={'username': 'admin', 'password': 'wrong'})
    return "Invalid" not in response.text

# A08:2021 - Software and Data Integrity Failures
def test_data_integrity_failures(url):
    print("[+] Testing for Software and Data Integrity Failures (A08:2021)...")
    response = requests.get(url + "/static/scripts.js")
    return 'eval' in response.text or '<script src="http://' in response.text

# A09:2021 - Security Logging and Monitoring Failures
def test_logging_monitoring_failures(url):
    print("[+] Testing for Security Logging and Monitoring Failures (A09:2021)...")
    response = requests.get(url + "/login")
    return response.status_code == 200

# A10:2021 - SSRF
def test_ssrf(url):
    print("[+] Testing for Server-Side Request Forgery (A10:2021)...")
    payload = {'url': 'http://127.0.0.1:80'}
    response = requests.post(url + "/fetch-url", data=payload)
    return "localhost" in response.text or "127.0.0.1" in response.text


def test_owasp_top_10_2021(url):
    results = {}
    results['Broken Access Control (A01)'] = test_broken_access_control(url)
    results['Cryptographic Failures (A02)'] = test_cryptographic_failures(url)
    results['Injection (A03)'] = test_injection(url)
    results['Insecure Design (A04)'] = test_insecure_design(url)
    results['Security Misconfiguration (A05)'] = test_security_misconfiguration(url)
    results['Outdated Components (A06)'] = test_outdated_components(url)
    results['Authentication Failures (A07)'] = test_authentication_failures(url)
    results['Data Integrity Failures (A08)'] = test_data_integrity_failures(url)
    results['Logging and Monitoring Failures (A09)'] = test_logging_monitoring_failures(url)
    results['Server-Side Request Forgery (A10)'] = test_ssrf(url)
    return results


def generate_report(vulns):
    print("\nOWASP Top 10 - 2021 Vulnerability Report")
    print("=" * 40)
    for issue, found in vulns.items():
        print(f"{issue}: {'VULNERABLE' if found else 'Safe'}")
    print("=" * 40)


def main():
    print("OWASP Top 10 (2021) Vulnerability Scanner")
    target = input("Enter the target URL (e.g., http://example.com): ").strip()
    if not target.startswith("http"):
        print("[!] Invalid URL format.")
        return
    vulns = test_owasp_top_10_2021(target)
    generate_report(vulns)
    with open("owasp2021_report.txt", "w") as f:
        for k, v in vulns.items():
            f.write(f"{k}: {'VULNERABLE' if v else 'Safe'}\n")
    print("[+] Report saved as owasp2021_report.txt")


if __name__ == '__main__':
    main()
