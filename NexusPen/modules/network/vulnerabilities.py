#!/usr/bin/env python3
"""
NexusPen - Network Vulnerabilities Module
==========================================
Network device and protocol vulnerability scanning.
"""

import subprocess
import socket
from typing import Dict, List, Optional
from dataclasses import dataclass

from rich.console import Console
from rich.table import Table

console = Console()


@dataclass
class NetworkVulnerability:
    """Network vulnerability."""
    name: str
    cve: Optional[str]
    severity: str
    protocol: str
    description: str
    affected_device: str
    exploit_available: bool = False
    metasploit_module: Optional[str] = None


class NetworkVulnScanner:
    """
    Network vulnerability scanner.
    Checks for common network device and protocol vulnerabilities.
    """
    
    # Router/Switch vulnerabilities
    ROUTER_VULNS = {
        'CVE-2018-0171': {
            'name': 'Cisco Smart Install RCE',
            'severity': 'critical',
            'protocol': 'TCP/4786',
            'msf': 'exploit/linux/misc/cisco_rv130_rce',
            'description': 'Cisco Smart Install protocol exploitation'
        },
        'CVE-2019-1653': {
            'name': 'Cisco RV320 Information Disclosure',
            'severity': 'high',
            'protocol': 'HTTPS',
            'description': 'Configuration disclosure vulnerability'
        },
        'CVE-2020-3452': {
            'name': 'Cisco ASA/FTD Path Traversal',
            'severity': 'high',
            'protocol': 'HTTPS',
            'msf': 'auxiliary/scanner/http/cisco_asa_traversal',
            'description': 'Read sensitive files via web interface'
        },
    }
    
    # Protocol vulnerabilities
    PROTOCOL_VULNS = {
        'SNMP': {
            'default_community': {
                'name': 'Default SNMP Community',
                'severity': 'high',
                'description': 'Default community string (public/private) allows information disclosure'
            },
            'snmpv1': {
                'name': 'SNMPv1 Cleartext',
                'severity': 'medium',
                'description': 'SNMPv1 sends community strings in cleartext'
            },
        },
        'Telnet': {
            'cleartext': {
                'name': 'Telnet Cleartext Protocol',
                'severity': 'high',
                'description': 'Telnet sends credentials in cleartext'
            },
        },
        'FTP': {
            'anonymous': {
                'name': 'Anonymous FTP Access',
                'severity': 'medium',
                'description': 'FTP allows anonymous login'
            },
            'cleartext': {
                'name': 'FTP Cleartext Protocol',
                'severity': 'medium',
                'description': 'FTP sends credentials in cleartext'
            },
        },
        'TFTP': {
            'no_auth': {
                'name': 'TFTP No Authentication',
                'severity': 'high',
                'description': 'TFTP has no authentication - can read/write files'
            },
        },
        'NTP': {
            'monlist': {
                'name': 'NTP Monlist DDoS Amplification',
                'severity': 'medium',
                'cve': 'CVE-2013-5211',
                'description': 'NTP monlist can be used for DDoS amplification'
            },
        },
        'DNS': {
            'zone_transfer': {
                'name': 'DNS Zone Transfer',
                'severity': 'medium',
                'description': 'DNS server allows zone transfers'
            },
            'recursion': {
                'name': 'Open DNS Recursion',
                'severity': 'medium',
                'description': 'DNS server allows recursive queries from any host'
            },
        },
    }
    
    def __init__(self, target: str):
        self.target = target
        self.findings: List[NetworkVulnerability] = []
    
    def check_snmp_default(self, communities: List[str] = None) -> List[NetworkVulnerability]:
        """Check for default SNMP community strings."""
        console.print(f"\n[cyan]🔍 Checking SNMP on {self.target}...[/cyan]")
        
        vulns = []
        communities = communities or ['public', 'private', 'community', 'manager']
        
        for community in communities:
            try:
                result = subprocess.run(
                    ['snmpwalk', '-v2c', '-c', community, '-t', '2', 
                     self.target, '1.3.6.1.2.1.1.1'],
                    capture_output=True, text=True, timeout=5
                )
                
                if result.returncode == 0 and result.stdout:
                    vuln = NetworkVulnerability(
                        name=f'SNMP Default Community: {community}',
                        cve=None,
                        severity='high',
                        protocol='SNMP/UDP161',
                        description=f'SNMP responds to community string "{community}"',
                        affected_device=self.target,
                        exploit_available=True
                    )
                    vulns.append(vuln)
                    self.findings.append(vuln)
                    console.print(f"[red]  ⚠️ Community '{community}' works![/red]")
                    
            except:
                pass
        
        return vulns
    
    def check_telnet(self) -> Optional[NetworkVulnerability]:
        """Check for Telnet service."""
        console.print(f"\n[cyan]🔍 Checking Telnet on {self.target}...[/cyan]")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((self.target, 23))
            sock.close()
            
            if result == 0:
                vuln = NetworkVulnerability(
                    name='Telnet Enabled',
                    cve=None,
                    severity='high',
                    protocol='Telnet/TCP23',
                    description='Telnet service is enabled - cleartext protocol',
                    affected_device=self.target,
                    exploit_available=True
                )
                self.findings.append(vuln)
                console.print("[red]  ⚠️ Telnet is enabled![/red]")
                return vuln
                
        except:
            pass
        
        return None
    
    def check_ftp_anonymous(self) -> Optional[NetworkVulnerability]:
        """Check for anonymous FTP access."""
        console.print(f"\n[cyan]🔍 Checking anonymous FTP on {self.target}...[/cyan]")
        
        try:
            from ftplib import FTP
            ftp = FTP()
            ftp.connect(self.target, 21, timeout=10)
            ftp.login('anonymous', 'test@test.com')
            ftp.quit()
            
            vuln = NetworkVulnerability(
                name='Anonymous FTP Access',
                cve=None,
                severity='medium',
                protocol='FTP/TCP21',
                description='FTP server allows anonymous login',
                affected_device=self.target,
                exploit_available=True
            )
            self.findings.append(vuln)
            console.print("[red]  ⚠️ Anonymous FTP allowed![/red]")
            return vuln
            
        except:
            pass
        
        return None
    
    def check_tftp(self) -> Optional[NetworkVulnerability]:
        """Check for TFTP service."""
        console.print(f"\n[cyan]🔍 Checking TFTP on {self.target}...[/cyan]")
        
        try:
            # Try to connect to TFTP port
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            sock.sendto(b'\x00\x01test\x00octet\x00', (self.target, 69))
            data, addr = sock.recvfrom(512)
            sock.close()
            
            if data:
                vuln = NetworkVulnerability(
                    name='TFTP Enabled',
                    cve=None,
                    severity='high',
                    protocol='TFTP/UDP69',
                    description='TFTP service is enabled - no authentication',
                    affected_device=self.target,
                    exploit_available=True
                )
                self.findings.append(vuln)
                console.print("[red]  ⚠️ TFTP is enabled![/red]")
                return vuln
                
        except:
            pass
        
        return None
    
    def check_dns_zone_transfer(self, domain: str) -> Optional[NetworkVulnerability]:
        """Check for DNS zone transfer."""
        console.print(f"\n[cyan]🔍 Checking DNS zone transfer for {domain}...[/cyan]")
        
        try:
            result = subprocess.run(
                ['dig', 'axfr', domain, f'@{self.target}'],
                capture_output=True, text=True, timeout=30
            )
            
            if 'Transfer failed' not in result.stdout and 'XFR size' in result.stdout:
                vuln = NetworkVulnerability(
                    name='DNS Zone Transfer Allowed',
                    cve=None,
                    severity='high',
                    protocol='DNS/TCP53',
                    description=f'DNS server allows zone transfer for {domain}',
                    affected_device=self.target,
                    exploit_available=True
                )
                self.findings.append(vuln)
                console.print("[red]  ⚠️ Zone transfer allowed![/red]")
                return vuln
                
        except:
            pass
        
        return None
    
    def check_ntp_monlist(self) -> Optional[NetworkVulnerability]:
        """Check for NTP monlist vulnerability."""
        console.print(f"\n[cyan]🔍 Checking NTP monlist on {self.target}...[/cyan]")
        
        try:
            result = subprocess.run(
                ['ntpdc', '-n', '-c', 'monlist', self.target],
                capture_output=True, text=True, timeout=10
            )
            
            if result.stdout and 'remote address' not in result.stdout.lower():
                if len(result.stdout) > 100:
                    vuln = NetworkVulnerability(
                        name='NTP Monlist DDoS Amplification',
                        cve='CVE-2013-5211',
                        severity='medium',
                        protocol='NTP/UDP123',
                        description='NTP server vulnerable to monlist amplification',
                        affected_device=self.target,
                        exploit_available=True
                    )
                    self.findings.append(vuln)
                    console.print("[red]  ⚠️ NTP monlist vulnerable![/red]")
                    return vuln
                    
        except:
            pass
        
        return None
    
    def check_ipmi(self) -> Optional[NetworkVulnerability]:
        """Check for IPMI vulnerabilities."""
        console.print(f"\n[cyan]🔍 Checking IPMI on {self.target}...[/cyan]")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            sock.sendto(b'\x06\x00\xff\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x20\x18\xc8\x81\x00\x38\x8e\x04\xb5', (self.target, 623))
            data, addr = sock.recvfrom(512)
            sock.close()
            
            if data:
                vuln = NetworkVulnerability(
                    name='IPMI Cipher Zero Authentication Bypass',
                    cve='CVE-2013-4786',
                    severity='critical',
                    protocol='IPMI/UDP623',
                    description='IPMI service vulnerable to authentication bypass',
                    affected_device=self.target,
                    exploit_available=True,
                    metasploit_module='auxiliary/scanner/ipmi/ipmi_cipher_zero'
                )
                self.findings.append(vuln)
                console.print("[red]  ⚠️ IPMI vulnerable![/red]")
                return vuln
                
        except:
            pass
        
        return None
    
    def check_cisco_smart_install(self) -> Optional[NetworkVulnerability]:
        """Check for Cisco Smart Install vulnerability."""
        console.print(f"\n[cyan]🔍 Checking Cisco Smart Install...[/cyan]")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((self.target, 4786))
            sock.close()
            
            if result == 0:
                vuln = NetworkVulnerability(
                    name='Cisco Smart Install Enabled',
                    cve='CVE-2018-0171',
                    severity='critical',
                    protocol='TCP/4786',
                    description='Cisco Smart Install protocol is enabled - RCE possible',
                    affected_device=self.target,
                    exploit_available=True,
                    metasploit_module='auxiliary/scanner/misc/cisco_smart_install'
                )
                self.findings.append(vuln)
                console.print("[red]  ⚠️ Cisco Smart Install vulnerable![/red]")
                return vuln
                
        except:
            pass
        
        return None
    
    def check_ssl_vulnerabilities(self, port: int = 443) -> List[NetworkVulnerability]:
        """Check for SSL/TLS vulnerabilities."""
        console.print(f"\n[cyan]🔍 Checking SSL/TLS on {self.target}:{port}...[/cyan]")
        
        vulns = []
        
        try:
            result = subprocess.run(
                ['nmap', '--script', 'ssl-enum-ciphers,ssl-heartbleed,ssl-poodle,ssl-dh-params',
                 '-p', str(port), self.target],
                capture_output=True, text=True, timeout=60
            )
            
            output = result.stdout.lower()
            
            if 'heartbleed' in output and 'vulnerable' in output:
                vuln = NetworkVulnerability(
                    name='Heartbleed',
                    cve='CVE-2014-0160',
                    severity='critical',
                    protocol=f'TLS/TCP{port}',
                    description='OpenSSL Heartbleed memory disclosure',
                    affected_device=self.target,
                    exploit_available=True,
                    metasploit_module='auxiliary/scanner/ssl/openssl_heartbleed'
                )
                vulns.append(vuln)
                self.findings.append(vuln)
                console.print("[red]  ⚠️ Heartbleed vulnerable![/red]")
            
            if 'poodle' in output and 'vulnerable' in output:
                vuln = NetworkVulnerability(
                    name='POODLE',
                    cve='CVE-2014-3566',
                    severity='medium',
                    protocol=f'SSL/TCP{port}',
                    description='SSLv3 POODLE attack possible',
                    affected_device=self.target,
                    exploit_available=True
                )
                vulns.append(vuln)
                self.findings.append(vuln)
                console.print("[red]  ⚠️ POODLE vulnerable![/red]")
            
            if 'sslv2' in output or 'sslv3' in output:
                vuln = NetworkVulnerability(
                    name='Weak SSL/TLS Version',
                    cve=None,
                    severity='medium',
                    protocol=f'SSL/TCP{port}',
                    description='Weak SSL/TLS versions enabled (SSLv2/SSLv3)',
                    affected_device=self.target,
                    exploit_available=False
                )
                vulns.append(vuln)
                self.findings.append(vuln)
                
        except:
            pass
        
        return vulns
    
    def run_full_scan(self, domain: str = None) -> List[NetworkVulnerability]:
        """Run complete network vulnerability scan."""
        console.print("\n[bold red]═══════════════════════════════════════════════════════════[/bold red]")
        console.print("[bold red]              NETWORK VULNERABILITY SCAN                    [/bold red]")
        console.print("[bold red]═══════════════════════════════════════════════════════════[/bold red]")
        
        self.check_snmp_default()
        self.check_telnet()
        self.check_ftp_anonymous()
        self.check_tftp()
        self.check_ipmi()
        self.check_cisco_smart_install()
        self.check_ssl_vulnerabilities()
        self.check_ntp_monlist()
        
        if domain:
            self.check_dns_zone_transfer(domain)
        
        self.display_findings()
        
        return self.findings
    
    def display_findings(self):
        """Display all vulnerabilities found."""
        if not self.findings:
            console.print("\n[green]No vulnerabilities found![/green]")
            return
        
        table = Table(title="Network Vulnerabilities Found", show_header=True,
                     header_style="bold red")
        table.add_column("Vulnerability", style="cyan", width=30)
        table.add_column("CVE", width=15)
        table.add_column("Severity", width=10)
        table.add_column("Protocol", width=15)
        
        for vuln in self.findings:
            severity_color = {'critical': 'red', 'high': 'yellow', 'medium': 'cyan', 'low': 'green'}.get(vuln.severity, 'white')
            table.add_row(
                vuln.name,
                vuln.cve or "-",
                f"[{severity_color}]{vuln.severity}[/{severity_color}]",
                vuln.protocol
            )
        
        console.print(table)
