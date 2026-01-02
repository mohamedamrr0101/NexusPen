# NexusPen - Penetration Testing Framework

<div align="center">

![NexusPen Logo](https://img.shields.io/badge/NexusPen-v1.0.0-red?style=for-the-badge&logo=hackthebox)

[![Python](https://img.shields.io/badge/Python-3.9+-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-Passing-success?style=flat-square)](tests/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue?style=flat-square&logo=docker)](Dockerfile)

**Professional Penetration Testing Framework**

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [Modules](#modules) • [Contributing](#contributing)

</div>

---

## ⚠️ Disclaimer

**This tool is for authorized security testing only.** Unauthorized access to computer systems is illegal. Always obtain proper authorization before testing.

---

## 🎯 Features

### 🌐 Web Security
- SQL Injection (Error, Blind, Time-based)
- Cross-Site Scripting (Reflected, Stored, DOM)
- Server-Side Request Forgery (SSRF)
- XML External Entity (XXE)
- Server-Side Template Injection (SSTI)
- Local/Remote File Inclusion (LFI/RFI)
- API Security (REST, GraphQL)
- JWT/Session Analysis

### 🪟 Windows Security
- Privilege Escalation Detection
- Vulnerability Scanning (EternalBlue, BlueKeep, etc.)
- Credential Extraction (Mimikatz integration)
- Lateral Movement (PSExec, WMI, WinRM)
- Defense Evasion (AMSI, UAC Bypass)
- Persistence Techniques

### 🐧 Linux Security
- Privilege Escalation Checks
- SUID/Capability Abuse
- Cron Job Analysis
- Kernel Exploit Detection
- Persistence Mechanisms

### 🏢 Active Directory
- Domain Enumeration
- BloodHound Integration
- Kerberoasting & AS-REP Roasting
- DCSync Attacks
- Golden/Silver Tickets
- Trust Abuse

### 📡 Wireless Security
- WiFi Network Scanning
- WPA/WPA2 Attacks
- WPS Exploitation
- Bluetooth/BLE Attacks
- Evil Twin Attacks

### 🔐 Password Attacks
- Hash Identification & Cracking
- Online Brute Forcing
- Password Spraying
- Credential Dumping
- Wordlist Generation

### 🌍 Network Security
- Port Scanning
- Service Detection
- Network Attacks (ARP, DNS, MITM)
- Protocol Analysis

### 📊 Reporting
- HTML Reports
- JSON/XML Export
- Markdown Reports
- PDF Generation
- Executive Summaries

---

## 📦 Installation

### Requirements
- Python 3.9+
- pip

### Quick Install

```bash
# Clone the repository
git clone https://github.com/nexuspen/nexuspen.git
cd nexuspen

# Install dependencies
pip install -r requirements.txt

# Run NexusPen
python nexuspen.py
```

### Install as Package

```bash
pip install -e .
nexuspen --help
```

### Docker

```bash
# Build
docker build -t nexuspen:latest .

# Run
docker run -it --rm nexuspen:latest shell
```

---

## 🚀 Usage

### Interactive Shell

```bash
python nexuspen.py shell
```

### Quick Scan

```bash
python nexuspen.py scan -t example.com -m web
```

### Full Assessment

```bash
python nexuspen.py full -t 192.168.1.0/24 -o report.html
```

### Module Examples

```python
from modules.web import SQLiScanner, XSSScanner
from modules.windows import WindowsPrivEsc
from modules.ad import ADEnumerator

# SQL Injection scan
scanner = SQLiScanner("http://target.com?id=1")
vulns = scanner.test_all_params()

# Windows privilege escalation
privesc = WindowsPrivEsc()
vectors = privesc.check_all()

# AD enumeration
ad = ADEnumerator("dc.domain.local", "user", "password")
users = ad.enum_users()
```

---

## 📚 Modules

| Module | Files | Description |
|--------|-------|-------------|
| **Web** | 13 | Web vulnerability scanning |
| **Windows** | 9 | Windows attacks & enumeration |
| **Linux** | 6 | Linux privilege escalation |
| **AD** | 7 | Active Directory attacks |
| **Network** | 5 | Network scanning & attacks |
| **Password** | 6 | Password cracking & spraying |
| **Wireless** | 5 | WiFi & Bluetooth attacks |
| **Exploit** | 6 | Exploitation framework |
| **Common** | 10 | Shared utilities |
| **Report** | 7 | Report generation |

---

## 🧪 Testing

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Run tests
pytest

# With coverage
pytest --cov=modules --cov-report=html
```

---

## 🤝 Contributing

We welcome contributions! Please read our [Contributing Guidelines](CONTRIBUTING.md) first.

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- Metasploit Framework
- Impacket Library
- Nmap Project
- The security community

---

<div align="center">

**Made with ❤️ for the security community**

</div>
