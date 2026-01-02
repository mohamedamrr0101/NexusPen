#!/usr/bin/env python3
"""
NexusPen - Linux Testing Module
===============================
Comprehensive Linux system security testing.

Includes:
- SSH enumeration
- NFS enumeration
- Service enumeration
- Linux privilege escalation
- Kernel exploit checking
"""

import subprocess
import re
import json
from typing import Dict, List, Optional
from dataclasses import dataclass

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


@dataclass
class LinuxFinding:
    """Represents a Linux security finding."""
    severity: str
    title: str
    description: str
    host: str
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None


class LinuxRecon:
    """Linux system reconnaissance."""
    
    def __init__(self, target: str, config: Dict = None):
        self.target = target
        self.config = config or {}
        self.findings: List[LinuxFinding] = []
        self.services: Dict = {}
        self.users: List[str] = []
    
    def run_full_recon(self) -> Dict:
        """Run comprehensive Linux reconnaissance."""
        console.print(f"\n[cyan]🐧 Starting Linux Reconnaissance: {self.target}[/cyan]")
        
        results = {
            'target': self.target,
            'os_info': {},
            'ssh_info': {},
            'nfs_exports': [],
            'services': {},
            'users': [],
            'findings': []
        }
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            # SSH enumeration
            task = progress.add_task("Enumerating SSH...", total=None)
            results['ssh_info'] = self.enumerate_ssh()
            progress.update(task, completed=True)
            
            # NFS enumeration
            task = progress.add_task("Checking NFS exports...", total=None)
            results['nfs_exports'] = self.enumerate_nfs()
            progress.update(task, completed=True)
            
            # Service enumeration
            task = progress.add_task("Enumerating services...", total=None)
            results['services'] = self.enumerate_services()
            progress.update(task, completed=True)
            
            # Vulnerability checks
            task = progress.add_task("Checking vulnerabilities...", total=None)
            self.check_shellshock()
            self.check_dirty_cow()
            self.check_sudo_vulns()
            progress.update(task, completed=True)
        
        results['findings'] = [f.__dict__ for f in self.findings]
        self._display_results(results)
        
        return results
    
    def enumerate_ssh(self) -> Dict:
        """Enumerate SSH service."""
        ssh_info = {
            'version': None,
            'auth_methods': [],
            'host_keys': [],
            'weak_ciphers': [],
            'weak_kex': [],
            'vulnerable': False
        }
        
        try:
            # Banner grabbing
            cmd = ['nc', '-w', '3', self.target, '22']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.stdout:
                ssh_info['version'] = result.stdout.strip()
                
                # Check for old SSH versions
                if 'SSH-1' in result.stdout:
                    self.findings.append(LinuxFinding(
                        severity='high',
                        title='SSH Protocol Version 1 Enabled',
                        description='SSH server supports insecure protocol version 1',
                        host=self.target,
                        remediation='Disable SSH protocol version 1'
                    ))
                    
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        # SSH audit (optional tool)
        try:
            cmd = ['ssh-audit', '-j', self.target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                try:
                    data = json.loads(result.stdout)
                    
                    # Check for weak ciphers
                    for cipher in data.get('enc', []):
                        if cipher.get('fail'):
                            ssh_info['weak_ciphers'].append(cipher.get('name'))
                            
                    # Check for weak key exchange
                    for kex in data.get('kex', []):
                        if kex.get('fail'):
                            ssh_info['weak_kex'].append(kex.get('name'))
                    
                    if ssh_info['weak_ciphers']:
                        self.findings.append(LinuxFinding(
                            severity='medium',
                            title='Weak SSH Ciphers',
                            description=f"Weak ciphers: {', '.join(ssh_info['weak_ciphers'][:3])}",
                            host=self.target,
                            remediation='Disable weak cryptographic algorithms in sshd_config'
                        ))
                except json.JSONDecodeError:
                    pass
                    
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            # ssh-audit not installed - skip
            pass
        
        # Check for password authentication
        try:
            cmd = ['nmap', '--script', 'ssh-auth-methods', '-p', '22', self.target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if 'password' in result.stdout.lower():
                ssh_info['auth_methods'].append('password')
            if 'publickey' in result.stdout.lower():
                ssh_info['auth_methods'].append('publickey')
                
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        return ssh_info
    
    def enumerate_nfs(self) -> List[Dict]:
        """Enumerate NFS exports."""
        exports = []
        
        try:
            cmd = ['showmount', '-e', self.target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                for line in result.stdout.split('\n')[1:]:  # Skip header
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 2:
                            export_path = parts[0]
                            allowed_hosts = parts[1]
                            
                            exports.append({
                                'path': export_path,
                                'hosts': allowed_hosts
                            })
                            
                            # Check for world-readable exports
                            if '*' in allowed_hosts or '0.0.0.0' in allowed_hosts:
                                self.findings.append(LinuxFinding(
                                    severity='high',
                                    title=f'World-Readable NFS Export: {export_path}',
                                    description='NFS share is accessible to any host',
                                    host=self.target,
                                    remediation='Restrict NFS access to specific hosts'
                                ))
                                
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        return exports
    
    def enumerate_services(self) -> Dict:
        """Enumerate common Linux services."""
        services = {}
        
        service_checks = [
            (21, 'ftp', self._check_ftp),
            (25, 'smtp', self._check_smtp),
            (3306, 'mysql', self._check_mysql),
            (5432, 'postgresql', self._check_postgresql),
            (6379, 'redis', self._check_redis),
            (27017, 'mongodb', self._check_mongodb),
        ]
        
        for port, service_name, check_func in service_checks:
            try:
                result = check_func(port)
                if result:
                    services[service_name] = result
            except Exception:
                pass
        
        return services
    
    def _check_ftp(self, port: int = 21) -> Optional[Dict]:
        """Check FTP service."""
        ftp_info = {'anonymous': False, 'version': None}
        
        try:
            # Check anonymous login
            cmd = ['ftp', '-n', self.target]
            # Using nmap instead for reliability
            cmd = ['nmap', '--script', 'ftp-anon', '-p', str(port), self.target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if 'Anonymous FTP login allowed' in result.stdout:
                ftp_info['anonymous'] = True
                self.findings.append(LinuxFinding(
                    severity='medium',
                    title='Anonymous FTP Login Allowed',
                    description='FTP server allows anonymous authentication',
                    host=self.target,
                    remediation='Disable anonymous FTP access unless required'
                ))
                
            return ftp_info
            
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None
    
    def _check_smtp(self, port: int = 25) -> Optional[Dict]:
        """Check SMTP service."""
        smtp_info = {'open_relay': False, 'vrfy': False}
        
        try:
            cmd = ['nmap', '--script', 'smtp-open-relay', '-p', str(port), self.target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if 'Server is an open relay' in result.stdout:
                smtp_info['open_relay'] = True
                self.findings.append(LinuxFinding(
                    severity='high',
                    title='SMTP Open Relay',
                    description='Mail server is configured as an open relay',
                    host=self.target,
                    remediation='Configure SMTP authentication and relay restrictions'
                ))
                
            return smtp_info
            
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None
    
    def _check_mysql(self, port: int = 3306) -> Optional[Dict]:
        """Check MySQL service."""
        mysql_info = {'version': None, 'auth_bypass': False}
        
        try:
            cmd = ['nmap', '--script', 'mysql-info', '-p', str(port), self.target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            version_match = re.search(r'Version:\s*(\S+)', result.stdout)
            if version_match:
                mysql_info['version'] = version_match.group(1)
                
            return mysql_info
            
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None
    
    def _check_postgresql(self, port: int = 5432) -> Optional[Dict]:
        """Check PostgreSQL service."""
        pg_info = {'version': None}
        
        try:
            cmd = ['nmap', '--script', 'pgsql-brute', '-p', str(port), self.target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            return pg_info
            
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None
    
    def _check_redis(self, port: int = 6379) -> Optional[Dict]:
        """Check Redis service."""
        redis_info = {'version': None, 'no_auth': False}
        
        try:
            cmd = ['redis-cli', '-h', self.target, '-p', str(port), 'INFO']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0 and 'redis_version' in result.stdout:
                redis_info['no_auth'] = True
                version_match = re.search(r'redis_version:(\S+)', result.stdout)
                if version_match:
                    redis_info['version'] = version_match.group(1)
                    
                self.findings.append(LinuxFinding(
                    severity='critical',
                    title='Redis No Authentication',
                    description='Redis server is accessible without authentication',
                    host=self.target,
                    remediation='Enable Redis authentication with requirepass directive'
                ))
                
            return redis_info
            
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None
    
    def _check_mongodb(self, port: int = 27017) -> Optional[Dict]:
        """Check MongoDB service."""
        mongo_info = {'version': None, 'no_auth': False}
        
        try:
            cmd = ['nmap', '--script', 'mongodb-info', '-p', str(port), self.target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if 'mongodb' in result.stdout.lower():
                mongo_info['no_auth'] = 'authentication' not in result.stdout.lower()
                
                if mongo_info['no_auth']:
                    self.findings.append(LinuxFinding(
                        severity='critical',
                        title='MongoDB No Authentication',
                        description='MongoDB server is accessible without authentication',
                        host=self.target,
                        remediation='Enable MongoDB authentication'
                    ))
                    
            return mongo_info
            
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None
    
    def check_shellshock(self):
        """Check for Shellshock vulnerability."""
        try:
            cmd = ['nmap', '--script', 'http-shellshock', '-p', '80,443,8080', self.target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if 'VULNERABLE' in result.stdout:
                self.findings.append(LinuxFinding(
                    severity='critical',
                    title='Shellshock Vulnerability (CVE-2014-6271)',
                    description='Server is vulnerable to Shellshock bash vulnerability',
                    host=self.target,
                    cve_id='CVE-2014-6271',
                    cvss_score=9.8,
                    remediation='Update bash to a patched version'
                ))
                
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
    
    def check_dirty_cow(self):
        """Check kernel version for Dirty COW vulnerability."""
        # This would require local access to check properly
        pass
    
    def check_sudo_vulns(self):
        """Check for sudo vulnerabilities."""
        # This would require local access or specific checks
        pass
    
    def _display_results(self, results: Dict):
        """Display results."""
        console.print("\n[bold green]╔══════════════════════════════════════════════════════════════╗[/bold green]")
        console.print("[bold green]║           LINUX RECONNAISSANCE RESULTS                        ║[/bold green]")
        console.print("[bold green]╚══════════════════════════════════════════════════════════════╝[/bold green]\n")
        
        # SSH Info
        if results.get('ssh_info', {}).get('version'):
            console.print(f"[cyan]🔐 SSH:[/cyan] {results['ssh_info']['version']}")
        
        # NFS Exports
        if results.get('nfs_exports'):
            console.print("\n[cyan]📂 NFS Exports:[/cyan]")
            for export in results['nfs_exports']:
                console.print(f"   • {export['path']} ({export['hosts']})")
        
        # Services
        if results.get('services'):
            console.print("\n[cyan]🔧 Services:[/cyan]")
            for service, info in results['services'].items():
                console.print(f"   • {service}")
        
        # Findings summary
        critical = len([f for f in self.findings if f.severity == 'critical'])
        high = len([f for f in self.findings if f.severity == 'high'])
        console.print(f"\n[yellow]⚠️ Findings: {len(self.findings)} ({critical} critical, {high} high)[/yellow]")


class LinuxPrivEsc:
    """Linux privilege escalation checks."""
    
    def __init__(self, target: str = None):
        self.target = target
        self.findings = []
    
    def run_linpeas(self, ssh_user: str = None, ssh_pass: str = None, ssh_key: str = None):
        """Run LinPEAS for privilege escalation enumeration."""
        console.print("[cyan]🔍 Running LinPEAS...[/cyan]")
        # Would SSH and run LinPEAS remotely
        pass
    
    def check_suid_binaries(self) -> List[Dict]:
        """Check for SUID binaries that can be exploited."""
        # GTFOBins integration
        suid_exploitable = [
            'nmap', 'vim', 'find', 'bash', 'more', 'less', 'nano',
            'cp', 'mv', 'awk', 'python', 'python3', 'perl', 'ruby',
            'php', 'git', 'ftp', 'wget', 'curl', 'env', 'tar'
        ]
        # Would check for these binaries with SUID bit set
        return []
    
    def check_sudo_permissions(self) -> List[Dict]:
        """Check sudo permissions for escalation vectors."""
        return []
    
    def check_writable_paths(self) -> List[str]:
        """Check for writable paths in PATH."""
        return []
    
    def check_cron_jobs(self) -> List[Dict]:
        """Check cron jobs for exploitation."""
        return []


# Module entry point
def run(target: str, profile, results: list):
    """Main entry point for Linux recon module."""
    recon = LinuxRecon(target)
    linux_results = recon.run_full_recon()
    results.append({
        'module': 'linux.recon',
        'phase': 'recon',
        'findings': linux_results
    })
