# 🛡️ OWASP-VulnScanner

A Python-based custom vulnerability scanner for web applications. This tool checks for common security flaws based on the **OWASP Top 10** list (2021).

---

## 🚀 Features

- ✅ SQL Injection (A1)
- ✅ Broken Authentication (A2)
- ✅ Sensitive Data Exposure (A3)
- ✅ XML External Entities (XXE) (A4)
- ✅ Broken Access Control (A5)
- ✅ Security Misconfiguration (A6)
- ✅ Cross Site Scripting (XSS) (A7)
- ✅ Insecure Deserialization (A8)
- ✅ Components with Known Vulnerabilities (A9)
- ✅ Insufficient Logging & Monitoring (A10)

---

## 🧠 How It Works

The tool sends crafted HTTP requests to your target and analyzes the responses to detect vulnerabilities. It's **for educational and ethical testing purposes only**.

---

## 📦 Requirements

Install dependencies:

```bash
pip install -r requirements.txt
