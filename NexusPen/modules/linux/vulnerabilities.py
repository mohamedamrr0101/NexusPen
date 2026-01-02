#!/usr/bin/env python3
"""
NexusPen - Linux Vulnerabilities Module
========================================
Linux vulnerability scanning and detection.
"""

import subprocess
import re
from typing import Dict, List, Optional
from dataclasses import dataclass

from rich.console import Console
from rich.table import Table

console = Console()


@dataclass
class LinuxVulnerability:
    """Linux vulnerability."""
    name: str
    cve: str
    severity: str  # critical, high, medium, low
    description: str
    affected: str
    exploit_available: bool = False
    metasploit_module: Optional[str] = None
    check_result: Optional[str] = None


class LinuxVulnScanner:
    """
    Linux vulnerability scanner.
    Checks for kernel exploits, service vulnerabilities, and misconfigurations.
    """
    
    # Known kernel exploits
    KERNEL_EXPLOITS = {
        'CVE-2022-0847': {
            'name': 'DirtyPipe',
            'kernels': ['5.8', '5.9', '5.10', '5.11', '5.12', '5.13', '5.14', '5.15', '5.16'],
            'severity': 'critical',
            'msf': 'exploit/linux/local/cve_2022_0847_dirtypipe',
            'description': 'Arbitrary file overwrite via pipe buffer flags manipulation'
        },
        'CVE-2021-4034': {
            'name': 'PwnKit (Polkit)',
            'universal': True,  # Affects most Linux distros
            'severity': 'critical',
            'msf': 'exploit/linux/local/cve_2021_4034_pwnkit_lpe',
            'description': 'Memory corruption in pkexec leads to local privilege escalation'
        },
        'CVE-2021-3156': {
            'name': 'Baron Samedit (Sudo)',
            'sudo_versions': ['1.8.2', '1.9.5p1'],
            'severity': 'critical',
            'msf': 'exploit/linux/local/cve_2021_3156_sudo_heap_overflow',
            'description': 'Heap-based buffer overflow in sudo'
        },
        'CVE-2021-22555': {
            'name': 'Netfilter Heap Overflow',
            'kernels': ['2.6.19', '5.12'],
            'severity': 'high',
            'msf': None,
            'description': 'Heap out-of-bounds write in Netfilter'
        },
        'CVE-2016-5195': {
            'name': 'DirtyCOW',
            'kernels': ['2.6.22', '4.8'],
            'severity': 'critical',
            'msf': 'exploit/linux/local/dirtycow',
            'description': 'Race condition in memory management'
        },
        'CVE-2019-14287': {
            'name': 'Sudo User ID Bypass',
            'sudo_versions': ['1.8.28'],
            'severity': 'high',
            'msf': None,
            'description': 'Sudo allows privilege escalation via -u#-1'
        },
        'CVE-2021-33909': {
            'name': 'Sequoia',
            'kernels': ['3.16', '5.13'],
            'severity': 'high',
            'msf': None,
            'description': 'Integer overflow in filesystem layer'
        },
        'CVE-2022-2588': {
            'name': 'DirtyCtrl',
            'kernels': ['5.8', '5.19'],
            'severity': 'high',
            'msf': None,
            'description': 'Use-after-free in route4_change'
        },
        'CVE-2023-0386': {
            'name': 'OverlayFS Privilege Escalation',
            'kernels': ['5.11', '6.2'],
            'severity': 'high',
            'msf': None,
            'description': 'Local privilege escalation via OverlayFS'
        },
        'CVE-2023-32233': {
            'name': 'Netfilter nf_tables',
            'kernels': ['5.1', '6.3'],
            'severity': 'critical',
            'msf': None,
            'description': 'Use-after-free in nf_tables'
        },
    }
    
    # Service vulnerabilities
    SERVICE_VULNS = {
        'SSH': {
            'CVE-2018-15473': {
                'name': 'OpenSSH User Enumeration',
                'versions': ['<7.7'],
                'severity': 'medium',
            },
            'CVE-2016-10009': {
                'name': 'OpenSSH Agent RCE',
                'versions': ['<7.1p2'],
                'severity': 'high',
            },
        },
        'Apache': {
            'CVE-2021-41773': {
                'name': 'Path Traversal RCE',
                'versions': ['2.4.49'],
                'severity': 'critical',
                'msf': 'exploit/multi/http/apache_normalize_path_rce',
            },
            'CVE-2021-42013': {
                'name': 'Path Traversal RCE',
                'versions': ['2.4.49', '2.4.50'],
                'severity': 'critical',
                'msf': 'exploit/multi/http/apache_normalize_path_rce',
            },
            'CVE-2014-6271': {
                'name': 'Shellshock',
                'severity': 'critical',
                'msf': 'exploit/multi/http/apache_mod_cgi_bash_env_exec',
            },
        },
        'Nginx': {
            'CVE-2021-23017': {
                'name': 'DNS Resolver Vulnerability',
                'versions': ['<1.21.0'],
                'severity': 'high',
            },
        },
        'ProFTPD': {
            'CVE-2015-3306': {
                'name': 'mod_copy RCE',
                'versions': ['1.3.5'],
                'severity': 'critical',
                'msf': 'exploit/unix/ftp/proftpd_modcopy_exec',
            },
        },
        'vsftpd': {
            'CVE-2011-2523': {
                'name': 'Backdoor',
                'versions': ['2.3.4'],
                'severity': 'critical',
                'msf': 'exploit/unix/ftp/vsftpd_234_backdoor',
            },
        },
        'Samba': {
            'CVE-2017-7494': {
                'name': 'is_known_pipename RCE',
                'versions': ['3.5.0-4.6.4'],
                'severity': 'critical',
                'msf': 'exploit/linux/samba/is_known_pipename',
            },
        },
        'Redis': {
            'CVE-2022-0543': {
                'name': 'Lua Sandbox Escape',
                'severity': 'critical',
                'msf': 'exploit/linux/redis/redis_debian_sandbox_escape',
            },
        },
    }
    
    def __init__(self, target: str = None):
        self.target = target
        self.findings: List[LinuxVulnerability] = []
    
    def check_kernel_version(self, kernel_string: str) -> List[LinuxVulnerability]:
        """Check kernel version for known exploits."""
        console.print("\n[cyan]🔍 Checking kernel vulnerabilities...[/cyan]")
        
        vulns = []
        
        # Extract kernel version
        match = re.search(r'(\d+\.\d+\.\d+)', kernel_string)
        if not match:
            console.print("[yellow]Could not parse kernel version[/yellow]")
            return vulns
        
        kernel_version = match.group(1)
        major_minor = '.'.join(kernel_version.split('.')[:2])
        
        console.print(f"[dim]Kernel: {kernel_version}[/dim]")
        
        for cve, info in self.KERNEL_EXPLOITS.items():
            vulnerable = False
            
            if info.get('universal'):
                vulnerable = True
            elif 'kernels' in info:
                for k in info['kernels']:
                    if major_minor.startswith(k) or major_minor == k:
                        vulnerable = True
                        break
            
            if vulnerable:
                vuln = LinuxVulnerability(
                    name=info['name'],
                    cve=cve,
                    severity=info['severity'],
                    description=info['description'],
                    affected=f"Kernel {kernel_version}",
                    exploit_available=True,
                    metasploit_module=info.get('msf')
                )
                vulns.append(vuln)
                self.findings.append(vuln)
                
                severity_color = {'critical': 'red', 'high': 'yellow', 'medium': 'cyan'}.get(info['severity'], 'white')
                console.print(f"[{severity_color}]  ⚠️ {cve} - {info['name']}[/{severity_color}]")
        
        return vulns
    
    def check_sudo_version(self, sudo_version: str = None) -> List[LinuxVulnerability]:
        """Check sudo version for vulnerabilities."""
        console.print("\n[cyan]🔍 Checking sudo vulnerabilities...[/cyan]")
        
        vulns = []
        
        if not sudo_version:
            result = subprocess.run(['sudo', '--version'], capture_output=True, text=True)
            sudo_version = result.stdout.split('\n')[0] if result.stdout else ''
        
        console.print(f"[dim]{sudo_version}[/dim]")
        
        # Check Baron Samedit
        match = re.search(r'(\d+\.\d+\.?\d*)', sudo_version)
        if match:
            version = match.group(1)
            # Simplified version check
            if version < '1.9.5p2':
                vuln = LinuxVulnerability(
                    name='Baron Samedit',
                    cve='CVE-2021-3156',
                    severity='critical',
                    description='Heap-based buffer overflow in sudo',
                    affected=f"Sudo {version}",
                    exploit_available=True,
                    metasploit_module='exploit/linux/local/cve_2021_3156_sudo_heap_overflow'
                )
                vulns.append(vuln)
                self.findings.append(vuln)
                console.print(f"[red]  ⚠️ CVE-2021-3156 - Baron Samedit[/red]")
        
        return vulns
    
    def check_polkit(self) -> Optional[LinuxVulnerability]:
        """Check for PwnKit vulnerability."""
        console.print("\n[cyan]🔍 Checking Polkit/PwnKit...[/cyan]")
        
        # Check if pkexec exists and has SUID
        result = subprocess.run(['ls', '-la', '/usr/bin/pkexec'], capture_output=True, text=True)
        
        if '-rwsr-' in result.stdout:
            # Check version
            version_result = subprocess.run(['pkexec', '--version'], capture_output=True, text=True)
            version = version_result.stdout.strip() if version_result.stdout else 'unknown'
            
            vuln = LinuxVulnerability(
                name='PwnKit',
                cve='CVE-2021-4034',
                severity='critical',
                description='Memory corruption in pkexec leads to local privilege escalation',
                affected=f"Polkit {version}",
                exploit_available=True,
                metasploit_module='exploit/linux/local/cve_2021_4034_pwnkit_lpe'
            )
            self.findings.append(vuln)
            console.print(f"[red]  ⚠️ CVE-2021-4034 - PwnKit (pkexec SUID found)[/red]")
            return vuln
        
        return None
    
    def check_shellshock(self, target_url: str = None) -> Optional[LinuxVulnerability]:
        """Check for Shellshock vulnerability."""
        console.print("\n[cyan]🔍 Checking Shellshock...[/cyan]")
        
        # Local check
        result = subprocess.run(
            ['env', 'x=() { :;}; echo vulnerable', 'bash', '-c', 'echo test'],
            capture_output=True, text=True
        )
        
        if 'vulnerable' in result.stdout:
            vuln = LinuxVulnerability(
                name='Shellshock',
                cve='CVE-2014-6271',
                severity='critical',
                description='Bash RCE via environment variables',
                affected='Bash',
                exploit_available=True,
                metasploit_module='exploit/multi/http/apache_mod_cgi_bash_env_exec'
            )
            self.findings.append(vuln)
            console.print(f"[red]  ⚠️ CVE-2014-6271 - Shellshock VULNERABLE![/red]")
            return vuln
        
        return None
    
    def check_dirtypipe(self) -> Optional[LinuxVulnerability]:
        """Check for DirtyPipe vulnerability."""
        console.print("\n[cyan]🔍 Checking DirtyPipe...[/cyan]")
        
        result = subprocess.run(['uname', '-r'], capture_output=True, text=True)
        kernel = result.stdout.strip()
        
        # Check if in vulnerable range (5.8 - 5.16)
        match = re.search(r'(\d+)\.(\d+)', kernel)
        if match:
            major, minor = int(match.group(1)), int(match.group(2))
            if major == 5 and 8 <= minor <= 16:
                vuln = LinuxVulnerability(
                    name='DirtyPipe',
                    cve='CVE-2022-0847',
                    severity='critical',
                    description='Arbitrary file overwrite via pipe buffer flags',
                    affected=f"Kernel {kernel}",
                    exploit_available=True,
                    metasploit_module='exploit/linux/local/cve_2022_0847_dirtypipe'
                )
                self.findings.append(vuln)
                console.print(f"[red]  ⚠️ CVE-2022-0847 - DirtyPipe VULNERABLE![/red]")
                return vuln
        
        return None
    
    def check_service_vulns(self, services: List[Dict]) -> List[LinuxVulnerability]:
        """Check services for known vulnerabilities."""
        console.print("\n[cyan]🔍 Checking service vulnerabilities...[/cyan]")
        
        vulns = []
        
        for svc in services:
            name = svc.get('name', '').lower()
            version = svc.get('version', '')
            
            for service_name, cves in self.SERVICE_VULNS.items():
                if service_name.lower() in name:
                    for cve, info in cves.items():
                        # Simplified version check
                        if 'versions' in info:
                            for v in info['versions']:
                                if v in version:
                                    vuln = LinuxVulnerability(
                                        name=info['name'],
                                        cve=cve,
                                        severity=info['severity'],
                                        description=info.get('description', ''),
                                        affected=f"{name} {version}",
                                        exploit_available=bool(info.get('msf')),
                                        metasploit_module=info.get('msf')
                                    )
                                    vulns.append(vuln)
                                    self.findings.append(vuln)
                                    console.print(f"[red]  ⚠️ {cve} - {info['name']}[/red]")
        
        return vulns
    
    def run_linux_exploit_suggester(self) -> str:
        """Run Linux Exploit Suggester script."""
        console.print("\n[cyan]🔧 Running Linux Exploit Suggester...[/cyan]")
        
        cmd = "curl -sL https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh | bash"
        
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
            return result.stdout
        except:
            return "Could not run exploit suggester"
    
    def generate_les_command(self) -> str:
        """Generate Linux Exploit Suggester command."""
        return "curl -L https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh | bash"
    
    def display_findings(self):
        """Display all vulnerabilities found."""
        if not self.findings:
            console.print("\n[green]No vulnerabilities found![/green]")
            return
        
        table = Table(title="Linux Vulnerabilities Found", show_header=True,
                     header_style="bold red")
        table.add_column("CVE", style="cyan", width=18)
        table.add_column("Name", style="white", width=25)
        table.add_column("Severity", width=10)
        table.add_column("Metasploit", width=15)
        
        for vuln in self.findings:
            severity_color = {'critical': 'red', 'high': 'yellow', 'medium': 'cyan', 'low': 'green'}.get(vuln.severity, 'white')
            table.add_row(
                vuln.cve,
                vuln.name,
                f"[{severity_color}]{vuln.severity}[/{severity_color}]",
                "✓" if vuln.metasploit_module else "-"
            )
        
        console.print(table)
    
    def run_full_scan(self) -> List[LinuxVulnerability]:
        """Run complete vulnerability scan."""
        console.print("\n[bold red]═══════════════════════════════════════════════════════════[/bold red]")
        console.print("[bold red]              LINUX VULNERABILITY SCAN                       [/bold red]")
        console.print("[bold red]═══════════════════════════════════════════════════════════[/bold red]")
        
        # Get kernel version
        result = subprocess.run(['uname', '-a'], capture_output=True, text=True)
        self.check_kernel_version(result.stdout)
        
        # Check specific vulnerabilities
        self.check_sudo_version()
        self.check_polkit()
        self.check_shellshock()
        self.check_dirtypipe()
        
        # Display results
        self.display_findings()
        
        return self.findings
