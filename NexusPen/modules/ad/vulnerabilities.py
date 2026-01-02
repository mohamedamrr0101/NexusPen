#!/usr/bin/env python3
"""
NexusPen - Active Directory Vulnerabilities Module
===================================================
Comprehensive AD vulnerability checks.

CVEs Covered:
- CVE-2020-1472 (Zerologon)
- CVE-2021-42287/42278 (sAMAccountName Spoofing - noPac)
- CVE-2021-34527 (PrintNightmare)
- CVE-2022-26923 (Certifried)
- CVE-2021-1675 (PrintNightmare LPE)
- CVE-2021-36942 (PetitPotam)
- MS14-068 (Kerberos Checksum)
- MS17-010 (EternalBlue)
"""

import subprocess
import re
from typing import Dict, List, Optional
from dataclasses import dataclass

from rich.console import Console
from rich.table import Table

console = Console()


@dataclass
class ADVulnerability:
    """Represents an AD vulnerability."""
    cve_id: str
    name: str
    severity: str
    description: str
    exploitable: bool
    details: Optional[str] = None
    remediation: Optional[str] = None


class ADVulnerabilityScanner:
    """
    Active Directory vulnerability scanner.
    Checks for known critical AD vulnerabilities.
    """
    
    def __init__(self, dc_ip: str, domain: str, config: Dict = None):
        self.dc_ip = dc_ip
        self.domain = domain
        self.config = config or {}
        self.vulnerabilities: List[ADVulnerability] = []
    
    def scan_all(self, username: str = None, password: str = None) -> List[ADVulnerability]:
        """Run all vulnerability checks."""
        console.print("\n[bold cyan]═══════════════════════════════════════════════════════════[/bold cyan]")
        console.print("[bold cyan]         ACTIVE DIRECTORY VULNERABILITY SCAN               [/bold cyan]")
        console.print("[bold cyan]═══════════════════════════════════════════════════════════[/bold cyan]")
        
        checks = [
            ('Zerologon (CVE-2020-1472)', self.check_zerologon),
            ('noPac (CVE-2021-42287)', lambda: self.check_nopac(username, password)),
            ('PrintNightmare (CVE-2021-34527)', self.check_printnightmare),
            ('PetitPotam (CVE-2021-36942)', self.check_petitpotam),
            ('Certifried (CVE-2022-26923)', lambda: self.check_certifried(username, password)),
            ('MS17-010 (EternalBlue)', self.check_ms17_010),
            ('SMB Signing', self.check_smb_signing),
            ('LDAP Signing', self.check_ldap_signing),
            ('LDAP Channel Binding', self.check_ldap_channel_binding),
            ('WebDAV on DC', self.check_webdav),
            ('Spooler Service', self.check_spooler),
            ('Coercion Attacks', self.check_coercion_vectors),
        ]
        
        for name, check_func in checks:
            console.print(f"\n[cyan]🔍 Checking {name}...[/cyan]")
            try:
                check_func()
            except Exception as e:
                console.print(f"[yellow]  Check failed: {e}[/yellow]")
        
        self._display_results()
        return self.vulnerabilities
    
    def check_zerologon(self) -> bool:
        """Check for Zerologon vulnerability (CVE-2020-1472)."""
        try:
            # Use zerologon_tester
            cmd = ['zerologon_tester.py', self.dc_ip.split('.')[0], self.dc_ip]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if 'VULNERABLE' in result.stdout.upper() or 'Success!' in result.stdout:
                self.vulnerabilities.append(ADVulnerability(
                    cve_id='CVE-2020-1472',
                    name='Zerologon',
                    severity='CRITICAL',
                    description='Domain Controller vulnerable to Zerologon. Full domain compromise possible without authentication.',
                    exploitable=True,
                    remediation='Apply Microsoft security updates immediately. Enable secure RPC.'
                ))
                console.print("[red]  ⚠️ VULNERABLE to Zerologon![/red]")
                return True
            else:
                console.print("[green]  ✓ Not vulnerable[/green]")
                return False
                
        except FileNotFoundError:
            # Try nmap script
            cmd = ['nmap', '--script', 'smb-vuln-zerologon', '-p', '445', self.dc_ip]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                if 'VULNERABLE' in result.stdout.upper():
                    self.vulnerabilities.append(ADVulnerability(
                        cve_id='CVE-2020-1472',
                        name='Zerologon',
                        severity='CRITICAL',
                        description='Domain Controller vulnerable to Zerologon',
                        exploitable=True
                    ))
                    return True
            except:
                pass
        except:
            pass
        
        return False
    
    def check_nopac(self, username: str, password: str) -> bool:
        """Check for noPac/sAMAccountName spoofing (CVE-2021-42287/42278)."""
        if not username or not password:
            console.print("[yellow]  Requires credentials[/yellow]")
            return False
        
        try:
            cmd = [
                'noPac.py',
                f'{self.domain}/{username}:{password}',
                '-dc-ip', self.dc_ip,
                'scan'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if 'vulnerable' in result.stdout.lower():
                self.vulnerabilities.append(ADVulnerability(
                    cve_id='CVE-2021-42287',
                    name='noPac / sAMAccountName Spoofing',
                    severity='CRITICAL',
                    description='Domain vulnerable to noPac attack. Allows privilege escalation to Domain Admin.',
                    exploitable=True,
                    remediation='Apply KB5008380 and KB5008602 patches.'
                ))
                console.print("[red]  ⚠️ VULNERABLE to noPac![/red]")
                return True
            else:
                console.print("[green]  ✓ Not vulnerable[/green]")
                
        except FileNotFoundError:
            console.print("[yellow]  noPac.py not found[/yellow]")
        except:
            pass
        
        return False
    
    def check_printnightmare(self) -> bool:
        """Check for PrintNightmare (CVE-2021-34527 / CVE-2021-1675)."""
        try:
            # Check if spooler service is running and RPC is accessible
            cmd = ['rpcdump.py', f'{self.dc_ip}', '-port', '135']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if 'MS-RPRN' in result.stdout or 'spoolss' in result.stdout.lower():
                self.vulnerabilities.append(ADVulnerability(
                    cve_id='CVE-2021-34527',
                    name='PrintNightmare',
                    severity='CRITICAL',
                    description='Print Spooler service exposed. May be vulnerable to PrintNightmare RCE.',
                    exploitable=True,
                    remediation='Disable Print Spooler service on DCs or apply patches.'
                ))
                console.print("[red]  ⚠️ Print Spooler exposed - possible PrintNightmare![/red]")
                return True
            else:
                console.print("[green]  ✓ Print Spooler not exposed[/green]")
                
        except:
            pass
        
        return False
    
    def check_petitpotam(self) -> bool:
        """Check for PetitPotam vulnerability (CVE-2021-36942)."""
        try:
            cmd = ['rpcdump.py', f'{self.dc_ip}']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            # Check for EFS RPC
            if 'MS-EFSR' in result.stdout or 'lsarpc' in result.stdout.lower():
                self.vulnerabilities.append(ADVulnerability(
                    cve_id='CVE-2021-36942',
                    name='PetitPotam',
                    severity='HIGH',
                    description='EFS RPC endpoints accessible. Can be used to coerce NTLM authentication.',
                    exploitable=True,
                    remediation='Apply Microsoft patches. Enable EPA on all services.'
                ))
                console.print("[yellow]  ⚠️ Potential PetitPotam target (EFS RPC accessible)[/yellow]")
                return True
                
        except:
            pass
        
        return False
    
    def check_certifried(self, username: str, password: str) -> bool:
        """Check for Certifried (CVE-2022-26923) - AD CS privilege escalation."""
        if not username or not password:
            return False
        
        try:
            cmd = [
                'certipy', 'find',
                '-u', f'{username}@{self.domain}',
                '-p', password,
                '-dc-ip', self.dc_ip,
                '-vulnerable',
                '-stdout'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if 'ESC' in result.stdout:
                esc_vulns = re.findall(r'ESC\d+', result.stdout)
                unique_vulns = list(set(esc_vulns))
                
                self.vulnerabilities.append(ADVulnerability(
                    cve_id='CVE-2022-26923',
                    name='ADCS Vulnerabilities (Certifried)',
                    severity='CRITICAL',
                    description=f'AD Certificate Services vulnerabilities found: {", ".join(unique_vulns)}',
                    exploitable=True,
                    details=', '.join(unique_vulns),
                    remediation='Review and fix certificate template permissions.'
                ))
                console.print(f"[red]  ⚠️ ADCS vulnerabilities: {', '.join(unique_vulns)}[/red]")
                return True
            else:
                console.print("[green]  ✓ No ADCS vulnerabilities found[/green]")
                
        except FileNotFoundError:
            console.print("[yellow]  certipy not found[/yellow]")
        except:
            pass
        
        return False
    
    def check_ms17_010(self) -> bool:
        """Check for MS17-010 (EternalBlue)."""
        try:
            cmd = ['nmap', '--script', 'smb-vuln-ms17-010', '-p', '445', self.dc_ip]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if 'VULNERABLE' in result.stdout.upper():
                self.vulnerabilities.append(ADVulnerability(
                    cve_id='CVE-2017-0144',
                    name='EternalBlue (MS17-010)',
                    severity='CRITICAL',
                    description='Domain Controller vulnerable to EternalBlue SMB exploit.',
                    exploitable=True,
                    remediation='Apply MS17-010 security update immediately.'
                ))
                console.print("[red]  ⚠️ VULNERABLE to EternalBlue![/red]")
                return True
            else:
                console.print("[green]  ✓ Not vulnerable[/green]")
                
        except:
            pass
        
        return False
    
    def check_smb_signing(self) -> bool:
        """Check SMB signing configuration."""
        try:
            cmd = ['nmap', '--script', 'smb2-security-mode', '-p', '445', self.dc_ip]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if 'signing enabled but not required' in result.stdout.lower():
                self.vulnerabilities.append(ADVulnerability(
                    cve_id='N/A',
                    name='SMB Signing Not Required',
                    severity='MEDIUM',
                    description='SMB signing is not enforced. Allows NTLM relay attacks.',
                    exploitable=True,
                    remediation='Enable mandatory SMB signing via GPO.'
                ))
                console.print("[yellow]  ⚠️ SMB signing not required[/yellow]")
                return True
            else:
                console.print("[green]  ✓ SMB signing enforced[/green]")
                
        except:
            pass
        
        return False
    
    def check_ldap_signing(self) -> bool:
        """Check LDAP signing configuration."""
        try:
            cmd = [
                'ldapsearch', '-x', '-H', f'ldap://{self.dc_ip}',
                '-s', 'base', '-b', '', 'supportedCapabilities'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            # If simple bind works without signing, it's not enforced
            if result.returncode == 0:
                self.vulnerabilities.append(ADVulnerability(
                    cve_id='N/A',
                    name='LDAP Signing Not Required',
                    severity='MEDIUM',
                    description='LDAP signing is not enforced. Allows LDAP relay attacks.',
                    exploitable=True,
                    remediation='Enable LDAP signing via GPO (Domain controller: LDAP server signing requirements).'
                ))
                console.print("[yellow]  ⚠️ LDAP signing not enforced[/yellow]")
                return True
                
        except:
            pass
        
        console.print("[green]  ✓ LDAP signing check complete[/green]")
        return False
    
    def check_ldap_channel_binding(self) -> bool:
        """Check LDAP channel binding (CBT) configuration."""
        # This would require a more complex check
        console.print("[yellow]  Manual check recommended[/yellow]")
        return False
    
    def check_webdav(self) -> bool:
        """Check if WebDAV is enabled (useful for coercion)."""
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((self.dc_ip, 80))
            sock.close()
            
            if result == 0:
                import requests
                response = requests.options(f'http://{self.dc_ip}/', timeout=5)
                
                if 'DAV' in response.headers.get('Allow', ''):
                    self.vulnerabilities.append(ADVulnerability(
                        cve_id='N/A',
                        name='WebDAV Enabled on DC',
                        severity='LOW',
                        description='WebDAV is enabled, can be used for coercion attacks.',
                        exploitable=True,
                        remediation='Disable WebDAV on Domain Controllers.'
                    ))
                    console.print("[yellow]  ⚠️ WebDAV enabled[/yellow]")
                    return True
                    
        except:
            pass
        
        console.print("[green]  ✓ WebDAV not detected[/green]")
        return False
    
    def check_spooler(self) -> bool:
        """Check if Print Spooler service is running."""
        try:
            cmd = ['rpcclient', '-U', '', '-N', self.dc_ip, '-c', 'enumprinters']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0 or 'printer' in result.stdout.lower():
                self.vulnerabilities.append(ADVulnerability(
                    cve_id='N/A',
                    name='Print Spooler Running',
                    severity='MEDIUM',
                    description='Print Spooler service is running on DC. Target for PrinterBug/PrintNightmare.',
                    exploitable=True,
                    remediation='Disable Print Spooler service on Domain Controllers.'
                ))
                console.print("[yellow]  ⚠️ Print Spooler running[/yellow]")
                return True
                
        except:
            pass
        
        console.print("[green]  ✓ Print Spooler appears disabled[/green]")
        return False
    
    def check_coercion_vectors(self) -> bool:
        """Check for various coercion attack vectors."""
        vectors_found = []
        
        try:
            cmd = ['rpcdump.py', self.dc_ip]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            coercion_services = {
                'MS-RPRN': 'PrinterBug',
                'MS-EFSR': 'PetitPotam',
                'MS-FSRVP': 'ShadowCoerce',
                'MS-DFSNM': 'DFSCoerce',
            }
            
            for service, attack in coercion_services.items():
                if service in result.stdout:
                    vectors_found.append(attack)
            
            if vectors_found:
                self.vulnerabilities.append(ADVulnerability(
                    cve_id='N/A',
                    name='Coercion Attack Vectors',
                    severity='MEDIUM',
                    description=f'Coercion vectors available: {", ".join(vectors_found)}',
                    exploitable=True,
                    details=', '.join(vectors_found),
                    remediation='Disable unnecessary RPC services. Enable EPA.'
                ))
                console.print(f"[yellow]  ⚠️ Coercion vectors: {', '.join(vectors_found)}[/yellow]")
                return True
                
        except:
            pass
        
        return False
    
    def _display_results(self):
        """Display vulnerability scan results."""
        console.print("\n")
        console.print("[bold]═══════════════════════════════════════════════════════════[/bold]")
        console.print("[bold]                    VULNERABILITY SUMMARY                   [/bold]")
        console.print("[bold]═══════════════════════════════════════════════════════════[/bold]")
        
        if not self.vulnerabilities:
            console.print("\n[green]✓ No critical vulnerabilities found![/green]")
            return
        
        table = Table(show_header=True, header_style="bold red")
        table.add_column("CVE", style="cyan", width=18)
        table.add_column("Name", style="yellow", width=25)
        table.add_column("Severity", width=10)
        table.add_column("Exploitable", width=10)
        
        for vuln in self.vulnerabilities:
            severity_color = {
                'CRITICAL': 'red',
                'HIGH': 'orange1',
                'MEDIUM': 'yellow',
                'LOW': 'green'
            }.get(vuln.severity, 'white')
            
            table.add_row(
                vuln.cve_id,
                vuln.name,
                f"[{severity_color}]{vuln.severity}[/{severity_color}]",
                "[green]Yes[/green]" if vuln.exploitable else "No"
            )
        
        console.print(table)
        
        critical = len([v for v in self.vulnerabilities if v.severity == 'CRITICAL'])
        high = len([v for v in self.vulnerabilities if v.severity == 'HIGH'])
        
        console.print(f"\n[red]⚠️ Total: {len(self.vulnerabilities)} vulnerabilities ({critical} critical, {high} high)[/red]")
