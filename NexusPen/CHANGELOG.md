# Changelog

All notable changes to NexusPen will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- Mobile security testing module (Android/iOS)
- Cloud security module (AWS/Azure/GCP)
- Social engineering toolkit integration
- Forensics/DFIR module
- Web dashboard UI

---

## [1.0.0] - 2026-01-02

### Added

#### Core Framework
- `nexuspen.py` - Main CLI entry point with interactive shell
- `core/engine.py` - Central scanning engine
- `core/database.py` - SQLite database for findings storage
- `core/detector.py` - Automatic technology detection
- `core/logger.py` - Centralized logging system
- `core/utils.py` - Utility functions

#### Web Module (13 files, ~197KB)
- SQL Injection scanner (error-based, blind, time-based)
- XSS scanner (reflected, stored, DOM-based)
- LFI/RFI scanner with PHP filter bypass
- SSRF scanner with cloud metadata checks
- XXE/SSTI injection scanner
- IDOR vulnerability scanner
- API security scanner (REST, GraphQL)
- Command injection scanner
- JWT/Session security analyzer
- CMS scanner (WordPress, Joomla, Drupal)
- Web reconnaissance tools
- Directory/subdomain fuzzer

#### Windows Module (9 files, ~129KB)
- Windows enumeration (users, services, processes)
- Privilege escalation checker (unquoted paths, tokens)
- Vulnerability scanner (EternalBlue, BlueKeep, PrintNightmare)
- Persistence techniques (registry, scheduled tasks, WMI)
- Lateral movement tools (PSExec, WMI, WinRM, PTH/PTT)
- Defense evasion (AMSI, Defender, UAC bypass)
- Credential access (Mimikatz, Kerberoast, AS-REP roast)

#### Linux Module (6 files, ~92KB)
- Linux enumeration and reconnaissance
- Privilege escalation detection
- Vulnerability scanning
- Persistence techniques
- System information gathering

#### Active Directory Module (7 files, ~121KB)
- AD enumeration (users, groups, GPOs, trusts)
- AD attacks (Kerberoasting, DCSync, Silver/Golden tickets)
- BloodHound integration and analysis
- AD persistence techniques
- AD vulnerability detection

#### Network Module (5 files, ~69KB)
- Port scanning with service detection
- Network enumeration
- Network-based attacks (ARP, DNS, MITM)
- Network vulnerability scanning

#### Password Module (6 files, ~92KB)
- Online brute forcing (Hydra, Medusa)
- Offline hash cracking (Hashcat, John)
- Password spraying
- Credential dumping
- Wordlist generation

#### Wireless Module (5 files, ~67KB)
- WiFi scanning and reconnaissance
- WPA/WPA2 attacks (handshake, PMKID)
- WPS attacks (Reaver, Pixie Dust)
- Evil Twin and Rogue AP
- Bluetooth/BLE attacks

#### Exploit Module (6 files, ~81KB)
- Metasploit integration
- Auto-exploitation engine
- Shellcode generation
- Privilege escalation exploits
- Post-exploitation tools

#### Common Module (10 files, ~133KB)
- AI assistant integration (Gemini/OpenAI)
- CVE intelligence lookups
- Credential management
- Payload generation
- Encoding utilities
- Network utilities

#### Report Module (7 files, ~93KB)
- HTML report generation
- JSON report output
- Markdown reports
- XML/JUnit reports
- PDF reports (WeasyPrint)
- Executive summary generation

### Security
- All tools designed for authorized testing only
- Logging of all activities
- Credential protection

---

## [0.1.0] - 2025-12-01

### Added
- Initial project structure
- Basic scanning capabilities
- Core framework design

---

## Version History

| Version | Date | Description |
|---------|------|-------------|
| 1.0.0 | 2026-01-02 | Full release with all modules |
| 0.1.0 | 2025-12-01 | Initial alpha release |

---

## Contributors

- NexusPen Development Team

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
