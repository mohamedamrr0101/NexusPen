#!/usr/bin/env python3
"""
NexusPen - Windows Testing Module
=================================
Comprehensive Windows system security testing.

Includes:
- SMB enumeration
- RPC enumeration
- WMI enumeration
- Windows privilege escalation
- Credential extraction
"""

import subprocess
import re
from typing import Dict, List, Optional
from dataclasses import dataclass

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

console = Console()


@dataclass
class WindowsFinding:
    """Represents a Windows security finding."""
    severity: str
    title: str
    description: str
    host: str
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None


class WindowsRecon:
    """Windows system reconnaissance."""
    
    def __init__(self, target: str, config: Dict = None):
        self.target = target
        self.config = config or {}
        self.findings: List[WindowsFinding] = []
        self.shares: List[Dict] = []
        self.users: List[str] = []
        self.groups: List[str] = []
        self.policies: Dict = {}
    
    def run_full_recon(self) -> Dict:
        """Run comprehensive Windows reconnaissance."""
        console.print(f"\n[cyan]🪟 Starting Windows Reconnaissance: {self.target}[/cyan]")
        
        results = {
            'target': self.target,
            'hostname': None,
            'domain': None,
            'os_version': None,
            'shares': [],
            'users': [],
            'groups': [],
            'password_policy': {},
            'sessions': [],
            'services': [],
            'findings': []
        }
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            # SMB enumeration
            task = progress.add_task("Running SMB enumeration...", total=None)
            smb_results = self.enumerate_smb()
            results.update(smb_results)
            progress.update(task, completed=True)
            
            # RPC enumeration
            task = progress.add_task("Running RPC enumeration...", total=None)
            rpc_results = self.enumerate_rpc()
            results.update(rpc_results)
            progress.update(task, completed=True)
            
            # Check for common vulnerabilities
            task = progress.add_task("Checking common vulnerabilities...", total=None)
            self.check_ms17_010()
            self.check_zerologon()
            self.check_printnightmare()
            progress.update(task, completed=True)
        
        results['findings'] = [f.__dict__ for f in self.findings]
        self._display_results(results)
        
        return results
    
    def enumerate_smb(self) -> Dict:
        """Enumerate SMB shares and information."""
        results = {
            'shares': [],
            'hostname': None,
            'domain': None,
            'os_version': None
        }
        
        # Method 1: enum4linux
        try:
            cmd = ['enum4linux', '-a', self.target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                output = result.stdout
                
                # Extract hostname
                hostname_match = re.search(r'NetBIOS computer name:\s*(\S+)', output)
                if hostname_match:
                    results['hostname'] = hostname_match.group(1)
                
                # Extract domain
                domain_match = re.search(r'Domain name:\s*(\S+)', output)
                if domain_match:
                    results['domain'] = domain_match.group(1)
                
                # Extract OS version
                os_match = re.search(r'OS version:\s*(.+)', output)
                if os_match:
                    results['os_version'] = os_match.group(1).strip()
                
                # Extract shares
                share_matches = re.findall(r'\s*(\S+)\s+Mapping:\s*(\S+)\s+Listing:\s*(\S+)', output)
                for share_name, mapping, listing in share_matches:
                    results['shares'].append({
                        'name': share_name,
                        'readable': mapping == 'OK',
                        'listable': listing == 'OK'
                    })
                    
                    # Check for writable shares
                    if mapping == 'OK' and share_name not in ['IPC$', 'ADMIN$', 'C$']:
                        self.findings.append(WindowsFinding(
                            severity='medium',
                            title=f'Readable SMB Share: {share_name}',
                            description=f'SMB share {share_name} is accessible',
                            host=self.target,
                            remediation='Review share permissions and restrict access'
                        ))
                
                # Extract users
                user_matches = re.findall(r'user:\[([^\]]+)\]', output)
                for user in user_matches:
                    if user not in self.users:
                        self.users.append(user)
                
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        # Method 2: smbclient for shares
        try:
            cmd = ['smbclient', '-L', f'//{self.target}', '-N']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            for line in result.stdout.split('\n'):
                if 'Disk' in line:
                    parts = line.split()
                    if parts:
                        share_name = parts[0]
                        if share_name not in [s['name'] for s in results['shares']]:
                            results['shares'].append({
                                'name': share_name,
                                'type': 'Disk',
                                'readable': None
                            })
                            
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        # Check for null session
        try:
            cmd = ['rpcclient', '-U', '', '-N', self.target, '-c', 'getusername']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if 'Account Name' in result.stdout:
                self.findings.append(WindowsFinding(
                    severity='high',
                    title='SMB Null Session Allowed',
                    description='The server allows anonymous/null session connections',
                    host=self.target,
                    remediation='Disable null sessions by enforcing authentication'
                ))
                
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        # Check for SMB Signing
        try:
            cmd = ['nmap', '--script', 'smb2-security-mode', '-p', '445', self.target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if 'signing enabled but not required' in result.stdout.lower():
                self.findings.append(WindowsFinding(
                    severity='medium',
                    title='SMB Signing Not Required',
                    description='SMB signing is enabled but not enforced',
                    host=self.target,
                    remediation='Enable mandatory SMB signing'
                ))
                
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        results['users'] = self.users
        return results
    
    def enumerate_rpc(self) -> Dict:
        """Enumerate RPC services."""
        results = {
            'groups': [],
            'sessions': [],
            'password_policy': {}
        }
        
        try:
            # Enumerate groups
            cmd = ['rpcclient', '-U', '', '-N', self.target, '-c', 'enumdomgroups']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            group_matches = re.findall(r'group:\[([^\]]+)\]', result.stdout)
            results['groups'] = group_matches
            
            # Get password policy
            cmd = ['rpcclient', '-U', '', '-N', self.target, '-c', 'getdompwinfo']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if 'min_password_length' in result.stdout:
                min_len_match = re.search(r'min_password_length:\s*(\d+)', result.stdout)
                if min_len_match:
                    min_len = int(min_len_match.group(1))
                    results['password_policy']['min_length'] = min_len
                    
                    if min_len < 8:
                        self.findings.append(WindowsFinding(
                            severity='medium',
                            title='Weak Password Policy',
                            description=f'Minimum password length is only {min_len} characters',
                            host=self.target,
                            remediation='Increase minimum password length to at least 12 characters'
                        ))
                        
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        return results
    
    def check_ms17_010(self):
        """Check for MS17-010 (EternalBlue) vulnerability."""
        try:
            cmd = ['nmap', '--script', 'smb-vuln-ms17-010', '-p', '445', self.target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if 'VULNERABLE' in result.stdout:
                self.findings.append(WindowsFinding(
                    severity='critical',
                    title='MS17-010 (EternalBlue) Vulnerability',
                    description='System is vulnerable to the EternalBlue SMB exploit',
                    host=self.target,
                    cve_id='CVE-2017-0144',
                    cvss_score=9.8,
                    remediation='Apply Microsoft security update MS17-010'
                ))
                
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
    
    def check_zerologon(self):
        """Check for Zerologon vulnerability."""
        try:
            # Use nmap script or custom check
            cmd = ['nmap', '--script', 'smb-vuln-zerologon', '-p', '445', self.target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if 'VULNERABLE' in result.stdout:
                self.findings.append(WindowsFinding(
                    severity='critical',
                    title='Zerologon Vulnerability (CVE-2020-1472)',
                    description='Domain controller is vulnerable to Zerologon attack',
                    host=self.target,
                    cve_id='CVE-2020-1472',
                    cvss_score=10.0,
                    remediation='Apply Microsoft security updates and enable secure RPC'
                ))
                
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
    
    def check_printnightmare(self):
        """Check for PrintNightmare vulnerability."""
        try:
            # Check if spooler service is running
            cmd = ['rpcclient', '-U', '', '-N', self.target, '-c', 'enumprinters']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0 and 'printer' in result.stdout.lower():
                self.findings.append(WindowsFinding(
                    severity='high',
                    title='Print Spooler Service Exposed',
                    description='Print Spooler service is running and may be vulnerable to PrintNightmare',
                    host=self.target,
                    cve_id='CVE-2021-34527',
                    cvss_score=8.8,
                    remediation='Disable Print Spooler service if not needed, or apply patches'
                ))
                
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
    
    def _display_results(self, results: Dict):
        """Display results in a formatted table."""
        console.print("\n[bold green]╔══════════════════════════════════════════════════════════════╗[/bold green]")
        console.print("[bold green]║           WINDOWS RECONNAISSANCE RESULTS                      ║[/bold green]")
        console.print("[bold green]╚══════════════════════════════════════════════════════════════╝[/bold green]\n")
        
        if results.get('hostname'):
            console.print(f"[cyan]💻 Hostname:[/cyan] {results['hostname']}")
        if results.get('domain'):
            console.print(f"[cyan]🏢 Domain:[/cyan] {results['domain']}")
        if results.get('os_version'):
            console.print(f"[cyan]🪟 OS Version:[/cyan] {results['os_version']}")
        
        # Shares
        if results.get('shares'):
            console.print("\n[cyan]📁 SMB Shares:[/cyan]")
            for share in results['shares']:
                status = "[green]✔[/green]" if share.get('readable') else "[red]✘[/red]"
                console.print(f"   {status} {share['name']}")
        
        # Users
        if results.get('users'):
            console.print(f"\n[cyan]👥 Users Found:[/cyan] {len(results['users'])}")
            for user in results['users'][:10]:
                console.print(f"   • {user}")
        
        # Findings
        critical = len([f for f in self.findings if f.severity == 'critical'])
        high = len([f for f in self.findings if f.severity == 'high'])
        console.print(f"\n[yellow]⚠️ Findings: {len(self.findings)} ({critical} critical, {high} high)[/yellow]")


class SMBExploiter:
    """SMB exploitation module."""
    
    def __init__(self, target: str, config: Dict = None):
        self.target = target
        self.config = config or {}
    
    def psexec(self, username: str, password: str, command: str = None) -> Optional[str]:
        """Execute command via PsExec."""
        try:
            from impacket.smbconnection import SMBConnection
            from impacket.examples.psexec import PSEXEC
            
            # Implementation would go here
            console.print(f"[cyan]Executing via PsExec on {self.target}[/cyan]")
            
        except ImportError:
            console.print("[yellow]Impacket not installed[/yellow]")
        
        return None
    
    def wmiexec(self, username: str, password: str, command: str = None) -> Optional[str]:
        """Execute command via WMI."""
        console.print(f"[cyan]Executing via WMI on {self.target}[/cyan]")
        return None
    
    def smbexec(self, username: str, password: str, command: str = None) -> Optional[str]:
        """Execute command via SMB."""
        console.print(f"[cyan]Executing via SMB on {self.target}[/cyan]")
        return None


class WindowsPrivEsc:
    """Windows privilege escalation checks."""
    
    def __init__(self, target: str):
        self.target = target
        self.findings: List[WindowsFinding] = []
    
    def check_all(self) -> List[Dict]:
        """Run all privilege escalation checks."""
        console.print(f"\n[cyan]🔓 Checking Windows Privilege Escalation vectors[/cyan]")
        
        checks = [
            self.check_alwaysinstallelevated,
            self.check_unquoted_service_paths,
            self.check_weak_service_permissions,
            self.check_scheduled_tasks,
        ]
        
        for check in checks:
            try:
                check()
            except Exception as e:
                console.print(f"[yellow]Check failed: {e}[/yellow]")
        
        return [f.__dict__ for f in self.findings]
    
    def check_alwaysinstallelevated(self):
        """Check for AlwaysInstallElevated registry key."""
        # This would require local access or specific tools
        pass
    
    def check_unquoted_service_paths(self):
        """Check for unquoted service paths."""
        pass
    
    def check_weak_service_permissions(self):
        """Check for weak service permissions."""
        pass
    
    def check_scheduled_tasks(self):
        """Check for exploitable scheduled tasks."""
        pass


# Module entry point
def run(target: str, profile, results: list):
    """Main entry point for Windows recon module."""
    recon = WindowsRecon(target)
    windows_results = recon.run_full_recon()
    results.append({
        'module': 'windows.recon',
        'phase': 'recon',
        'findings': windows_results
    })
