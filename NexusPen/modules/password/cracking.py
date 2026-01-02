#!/usr/bin/env python3
"""
NexusPen - Password Cracking Module
====================================
Hash cracking with Hashcat, John, and more.
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
class CrackResult:
    """Crack result."""
    hash_value: str
    password: str
    hash_type: str
    tool: str
    time_taken: Optional[float] = None


class HashIdentifier:
    """
    Hash type identification.
    """
    
    # Common hash patterns
    HASH_PATTERNS = {
        r'^[a-fA-F0-9]{32}$': ['MD5', 'NTLM', 'MD4', 'LM'],
        r'^[a-fA-F0-9]{40}$': ['SHA1', 'MySQL4.1+', 'RIPEMD-160'],
        r'^[a-fA-F0-9]{64}$': ['SHA256', 'SHA3-256'],
        r'^[a-fA-F0-9]{128}$': ['SHA512', 'SHA3-512', 'Whirlpool'],
        r'^\$1\$': ['MD5 Crypt (Linux)'],
        r'^\$2[aby]?\$': ['Bcrypt'],
        r'^\$5\$': ['SHA256 Crypt (Linux)'],
        r'^\$6\$': ['SHA512 Crypt (Linux)'],
        r'^\$y\$': ['Yescrypt'],
        r'^[a-fA-F0-9]{32}:[a-fA-F0-9]+$': ['NTLM with salt', 'MD5 with salt'],
        r'^[^:]+:\d+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}:::$': ['PWDUMP format (LM:NTLM)'],
        r'^\$apr1\$': ['Apache MD5'],
        r'^\{SSHA\}': ['SSHA (LDAP)'],
        r'^\$P\$': ['PHPass (WordPress, phpBB)'],
        r'^\$H\$': ['PHPass'],
        r'^sha1\$': ['Django SHA1'],
        r'^pbkdf2_sha256\$': ['Django PBKDF2'],
        r'^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$': ['NetNTLMv1'],
        r'^[a-zA-Z0-9+/]{27}=$': ['Base64 encoded (potentially)'],
    }
    
    # Hashcat modes
    HASHCAT_MODES = {
        'MD5': 0,
        'SHA1': 100,
        'SHA256': 1400,
        'SHA512': 1700,
        'NTLM': 1000,
        'LM': 3000,
        'MD5 Crypt (Linux)': 500,
        'SHA256 Crypt (Linux)': 7400,
        'SHA512 Crypt (Linux)': 1800,
        'Bcrypt': 3200,
        'MySQL4.1+': 300,
        'MSSQL 2005': 132,
        'MSSQL 2012': 1731,
        'Oracle 11g': 112,
        'PostgreSQL': 12,
        'PHPass (WordPress, phpBB)': 400,
        'Apache MD5': 1600,
        'Kerberos TGS-REP (SPN)': 13100,
        'Kerberos AS-REP': 18200,
        'NetNTLMv1': 5500,
        'NetNTLMv2': 5600,
        'WPA/WPA2': 22000,
        'Django SHA1': 124,
        'Django PBKDF2': 10000,
    }
    
    @classmethod
    def identify(cls, hash_value: str) -> List[str]:
        """Identify hash type."""
        possible_types = []
        
        for pattern, types in cls.HASH_PATTERNS.items():
            if re.match(pattern, hash_value):
                possible_types.extend(types)
        
        return list(set(possible_types))
    
    @classmethod
    def get_hashcat_mode(cls, hash_type: str) -> Optional[int]:
        """Get Hashcat mode for hash type."""
        return cls.HASHCAT_MODES.get(hash_type)
    
    @classmethod
    def identify_with_hashid(cls, hash_value: str) -> str:
        """Use hashid tool for identification."""
        try:
            result = subprocess.run(
                ['hashid', hash_value],
                capture_output=True, text=True, timeout=10
            )
            return result.stdout
        except:
            return ""


class HashcatCracker:
    """
    Hashcat password cracker.
    """
    
    def __init__(self):
        self.results: List[CrackResult] = []
    
    def crack_dictionary(self, hash_file: str, wordlist: str, 
                        hash_mode: int, rules: str = None) -> List[CrackResult]:
        """
        Dictionary attack with Hashcat.
        
        Args:
            hash_file: Path to file containing hashes
            wordlist: Path to wordlist
            hash_mode: Hashcat hash mode
            rules: Optional rules file
        """
        console.print(f"\n[cyan]🔓 Hashcat dictionary attack (mode {hash_mode})...[/cyan]")
        
        cmd = ['hashcat', '-m', str(hash_mode), '-a', '0', hash_file, wordlist, '--force']
        
        if rules:
            cmd.extend(['-r', rules])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            
            # Show cracked
            show_cmd = ['hashcat', '-m', str(hash_mode), hash_file, '--show']
            show_result = subprocess.run(show_cmd, capture_output=True, text=True)
            
            for line in show_result.stdout.strip().split('\n'):
                if ':' in line:
                    parts = line.rsplit(':', 1)
                    if len(parts) == 2:
                        cracked = CrackResult(
                            hash_value=parts[0],
                            password=parts[1],
                            hash_type=str(hash_mode),
                            tool='hashcat'
                        )
                        self.results.append(cracked)
                        console.print(f"[green]✓ Cracked: {parts[0][:20]}... = {parts[1]}[/green]")
            
        except subprocess.TimeoutExpired:
            console.print("[yellow]Timeout - try with longer timeout or smaller wordlist[/yellow]")
        except FileNotFoundError:
            console.print("[red]hashcat not found[/red]")
        
        return self.results
    
    def crack_brute_force(self, hash_file: str, hash_mode: int,
                         mask: str = '?a?a?a?a?a?a') -> List[CrackResult]:
        """
        Brute force attack with Hashcat.
        
        Args:
            hash_file: Path to hash file
            hash_mode: Hashcat mode
            mask: Mask pattern (?l=lowercase, ?u=uppercase, ?d=digit, ?s=special, ?a=all)
        """
        console.print(f"\n[cyan]🔓 Hashcat brute force attack (mask: {mask})...[/cyan]")
        
        cmd = ['hashcat', '-m', str(hash_mode), '-a', '3', hash_file, mask, '--force']
        
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            
            # Show results
            show_cmd = ['hashcat', '-m', str(hash_mode), hash_file, '--show']
            result = subprocess.run(show_cmd, capture_output=True, text=True)
            
            for line in result.stdout.strip().split('\n'):
                if ':' in line:
                    parts = line.rsplit(':', 1)
                    if len(parts) == 2:
                        self.results.append(CrackResult(
                            hash_value=parts[0],
                            password=parts[1],
                            hash_type=str(hash_mode),
                            tool='hashcat'
                        ))
                        console.print(f"[green]✓ Cracked: {parts[1]}[/green]")
                        
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        
        return self.results
    
    def crack_combinator(self, hash_file: str, hash_mode: int,
                        wordlist1: str, wordlist2: str) -> List[CrackResult]:
        """Combinator attack (combine two wordlists)."""
        console.print("\n[cyan]🔓 Hashcat combinator attack...[/cyan]")
        
        cmd = ['hashcat', '-m', str(hash_mode), '-a', '1', 
               hash_file, wordlist1, wordlist2, '--force']
        
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
        except:
            pass
        
        return self.results
    
    def crack_hybrid(self, hash_file: str, hash_mode: int,
                    wordlist: str, mask: str = '?d?d?d?d') -> List[CrackResult]:
        """Hybrid attack (wordlist + mask)."""
        console.print("\n[cyan]🔓 Hashcat hybrid attack...[/cyan]")
        
        # Mode 6: wordlist + mask
        cmd = ['hashcat', '-m', str(hash_mode), '-a', '6', 
               hash_file, wordlist, mask, '--force']
        
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
        except:
            pass
        
        return self.results
    
    @staticmethod
    def generate_masks() -> Dict[str, str]:
        """Generate common masks for brute force."""
        return {
            'lowercase_6': '?l?l?l?l?l?l',
            'lowercase_8': '?l?l?l?l?l?l?l?l',
            'upper_lower_6': '?u?l?l?l?l?l',
            'upper_lower_num': '?u?l?l?l?l?d?d',
            'common_pattern': '?u?l?l?l?l?l?d?d',
            'all_6': '?a?a?a?a?a?a',
            'all_8': '?a?a?a?a?a?a?a?a',
            'numeric_4': '?d?d?d?d',
            'numeric_6': '?d?d?d?d?d?d',
            'year_pattern': '?l?l?l?l?l?l20?d?d',
        }
    
    @staticmethod
    def common_rules() -> List[str]:
        """List common Hashcat rules."""
        return [
            '/usr/share/hashcat/rules/best64.rule',
            '/usr/share/hashcat/rules/rockyou-30000.rule',
            '/usr/share/hashcat/rules/d3ad0ne.rule',
            '/usr/share/hashcat/rules/dive.rule',
            '/usr/share/hashcat/rules/InsidePro-PasswordsPro.rule',
            '/usr/share/hashcat/rules/OneRuleToRuleThemAll.rule',
        ]


class JohnCracker:
    """
    John the Ripper password cracker.
    """
    
    def __init__(self):
        self.results: List[CrackResult] = []
    
    def crack_dictionary(self, hash_file: str, wordlist: str,
                        format: str = None) -> List[CrackResult]:
        """Dictionary attack with John."""
        console.print("\n[cyan]🔓 John dictionary attack...[/cyan]")
        
        cmd = ['john', '--wordlist=' + wordlist, hash_file]
        if format:
            cmd.append(f'--format={format}')
        
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            
            # Show cracked
            show_result = subprocess.run(
                ['john', '--show', hash_file],
                capture_output=True, text=True
            )
            
            for line in show_result.stdout.strip().split('\n'):
                if ':' in line and 'password hashes cracked' not in line:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        self.results.append(CrackResult(
                            hash_value=parts[0],
                            password=parts[1],
                            hash_type=format or 'auto',
                            tool='john'
                        ))
                        console.print(f"[green]✓ Cracked: {parts[0]} = {parts[1]}[/green]")
                        
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        
        return self.results
    
    def crack_incremental(self, hash_file: str, format: str = None,
                         charset: str = 'alnum') -> List[CrackResult]:
        """Incremental (brute force) attack with John."""
        console.print("\n[cyan]🔓 John incremental attack...[/cyan]")
        
        cmd = ['john', f'--incremental={charset}', hash_file]
        if format:
            cmd.append(f'--format={format}')
        
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
        except:
            pass
        
        return self.results
    
    def crack_rules(self, hash_file: str, wordlist: str,
                   rules: str = 'Jumbo') -> List[CrackResult]:
        """Dictionary attack with rules."""
        console.print("\n[cyan]🔓 John with rules...[/cyan]")
        
        cmd = ['john', f'--wordlist={wordlist}', f'--rules={rules}', hash_file]
        
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
        except:
            pass
        
        return self.results
    
    def unshadow(self, passwd_file: str, shadow_file: str,
                output_file: str = '/tmp/unshadowed.txt') -> str:
        """Combine passwd and shadow files for John."""
        console.print("\n[cyan]Unshadowing password files...[/cyan]")
        
        try:
            result = subprocess.run(
                ['unshadow', passwd_file, shadow_file],
                capture_output=True, text=True
            )
            
            with open(output_file, 'w') as f:
                f.write(result.stdout)
            
            return output_file
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            return ""
    
    def zip2john(self, zip_file: str) -> str:
        """Extract hash from ZIP file."""
        try:
            result = subprocess.run(
                ['zip2john', zip_file],
                capture_output=True, text=True
            )
            return result.stdout.strip()
        except:
            return ""
    
    def rar2john(self, rar_file: str) -> str:
        """Extract hash from RAR file."""
        try:
            result = subprocess.run(
                ['rar2john', rar_file],
                capture_output=True, text=True
            )
            return result.stdout.strip()
        except:
            return ""
    
    def pdf2john(self, pdf_file: str) -> str:
        """Extract hash from PDF file."""
        try:
            result = subprocess.run(
                ['pdf2john.pl', pdf_file],
                capture_output=True, text=True
            )
            return result.stdout.strip()
        except:
            return ""
    
    def office2john(self, office_file: str) -> str:
        """Extract hash from Office file."""
        try:
            result = subprocess.run(
                ['office2john.py', office_file],
                capture_output=True, text=True
            )
            return result.stdout.strip()
        except:
            return ""
    
    def ssh2john(self, key_file: str) -> str:
        """Extract hash from SSH private key."""
        try:
            result = subprocess.run(
                ['ssh2john.py', key_file],
                capture_output=True, text=True
            )
            return result.stdout.strip()
        except:
            return ""
    
    def keepass2john(self, kdbx_file: str) -> str:
        """Extract hash from KeePass database."""
        try:
            result = subprocess.run(
                ['keepass2john', kdbx_file],
                capture_output=True, text=True
            )
            return result.stdout.strip()
        except:
            return ""
    
    @staticmethod
    def list_formats() -> str:
        """List all supported John formats."""
        try:
            result = subprocess.run(
                ['john', '--list=formats'],
                capture_output=True, text=True
            )
            return result.stdout
        except:
            return ""


class OnlineCracker:
    """
    Online hash cracking services.
    """
    
    SERVICES = {
        'crackstation': 'https://crackstation.net/',
        'hashes.com': 'https://hashes.com/en/decrypt/hash',
        'cmd5': 'https://www.cmd5.org/',
        'hashkiller': 'https://hashkiller.io/',
        'onlinehashcrack': 'https://www.onlinehashcrack.com/',
    }
    
    @classmethod
    def lookup_crackstation(cls, hash_value: str) -> Optional[str]:
        """Lookup hash on CrackStation API."""
        import requests
        
        try:
            response = requests.post(
                'https://api.crackstation.net/v1/crack',
                data={'hash': hash_value},
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('found'):
                    return data.get('plain')
        except:
            pass
        
        return None
    
    @classmethod
    def display_services(cls):
        """Display online cracking services."""
        console.print("\n[cyan]Online Hash Cracking Services:[/cyan]")
        for name, url in cls.SERVICES.items():
            console.print(f"  • {name}: {url}")


class RainbowTableCracker:
    """
    Rainbow table attacks.
    """
    
    def __init__(self, tables_path: str = '/usr/share/rainbowcrack'):
        self.tables_path = tables_path
    
    def crack_rtgen(self, hash_value: str, hash_type: str = 'ntlm') -> Optional[str]:
        """Crack using rainbow tables with rcrack."""
        console.print("\n[cyan]🌈 Rainbow table attack...[/cyan]")
        
        try:
            result = subprocess.run(
                ['rcrack', self.tables_path, '-h', hash_value],
                capture_output=True, text=True, timeout=300
            )
            
            for line in result.stdout.split('\n'):
                if 'result' in line.lower() and 'hex:' in line:
                    # Extract password
                    match = re.search(r'result: (.+)$', line)
                    if match:
                        return match.group(1)
                        
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        
        return None
    
    @staticmethod
    def generate_tables_cmd(hash_type: str = 'ntlm',
                           charset: str = 'loweralpha-numeric',
                           min_len: int = 1, max_len: int = 7) -> str:
        """Generate command to create rainbow tables."""
        return f'''
# Generate rainbow tables
rtgen {hash_type} {charset} {min_len} {max_len} 0 2400 100000 0

# Sort the tables
rtsort .

# Tables will be created in current directory
'''


class PasswordAnalyzer:
    """
    Password analysis and statistics.
    """
    
    @staticmethod
    def analyze_password(password: str) -> Dict:
        """Analyze password strength."""
        analysis = {
            'length': len(password),
            'has_lower': bool(re.search(r'[a-z]', password)),
            'has_upper': bool(re.search(r'[A-Z]', password)),
            'has_digit': bool(re.search(r'\d', password)),
            'has_special': bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password)),
            'strength': 'weak',
            'score': 0,
        }
        
        # Calculate score
        score = 0
        if analysis['length'] >= 8:
            score += 1
        if analysis['length'] >= 12:
            score += 1
        if analysis['has_lower']:
            score += 1
        if analysis['has_upper']:
            score += 1
        if analysis['has_digit']:
            score += 1
        if analysis['has_special']:
            score += 1
        
        analysis['score'] = score
        
        if score <= 2:
            analysis['strength'] = 'weak'
        elif score <= 4:
            analysis['strength'] = 'medium'
        else:
            analysis['strength'] = 'strong'
        
        return analysis
    
    @staticmethod
    def analyze_wordlist(wordlist_path: str) -> Dict:
        """Analyze a wordlist."""
        stats = {
            'total': 0,
            'unique': 0,
            'avg_length': 0,
            'min_length': float('inf'),
            'max_length': 0,
            'common_patterns': {},
        }
        
        passwords = set()
        total_length = 0
        
        try:
            with open(wordlist_path, 'r', errors='ignore') as f:
                for line in f:
                    pw = line.strip()
                    stats['total'] += 1
                    passwords.add(pw)
                    length = len(pw)
                    total_length += length
                    
                    if length < stats['min_length']:
                        stats['min_length'] = length
                    if length > stats['max_length']:
                        stats['max_length'] = length
            
            stats['unique'] = len(passwords)
            stats['avg_length'] = total_length / stats['total'] if stats['total'] > 0 else 0
            
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        
        return stats
    
    @staticmethod
    def find_patterns(passwords: List[str]) -> Dict:
        """Find common patterns in cracked passwords."""
        patterns = {
            'years': 0,
            'sequential': 0,
            'keyboard_patterns': 0,
            'common_words': 0,
            'length_distribution': {},
        }
        
        year_pattern = re.compile(r'(19|20)\d{2}')
        sequential = ['123', '234', '345', 'abc', 'bcd', 'xyz', 'qwe', 'asd', 'zxc']
        keyboard = ['qwerty', 'asdf', 'zxcv', 'qwer', '1qaz', '2wsx']
        
        for pw in passwords:
            pw_lower = pw.lower()
            
            # Year
            if year_pattern.search(pw):
                patterns['years'] += 1
            
            # Sequential
            if any(seq in pw_lower for seq in sequential):
                patterns['sequential'] += 1
            
            # Keyboard patterns
            if any(kp in pw_lower for kp in keyboard):
                patterns['keyboard_patterns'] += 1
            
            # Length distribution
            length = len(pw)
            patterns['length_distribution'][length] = patterns['length_distribution'].get(length, 0) + 1
        
        return patterns


def display_all_tools():
    """Display all password cracking tools."""
    console.print("\n[bold cyan]═══════════════════════════════════════════════════════════[/bold cyan]")
    console.print("[bold cyan]              PASSWORD CRACKING TOOLS                        [/bold cyan]")
    console.print("[bold cyan]═══════════════════════════════════════════════════════════[/bold cyan]")
    
    table = Table(title="Available Tools", show_header=True,
                 header_style="bold magenta")
    table.add_column("Tool", style="cyan", width=20)
    table.add_column("Type", width=15)
    table.add_column("Best For", style="white")
    
    tools = [
        ('Hashcat', 'GPU Cracker', 'Fast GPU-based cracking'),
        ('John the Ripper', 'CPU Cracker', 'Versatile, many formats'),
        ('Rainbow Tables', 'Precomputed', 'Instant lookup (if table exists)'),
        ('Online Services', 'Cloud', 'Quick lookup of common hashes'),
        ('Hydra', 'Online Brute', 'Network service brute forcing'),
        ('Medusa', 'Online Brute', 'Fast parallel brute forcing'),
        ('CrackMapExec', 'AD Spraying', 'Active Directory attacks'),
    ]
    
    for tool, ttype, desc in tools:
        table.add_row(tool, ttype, desc)
    
    console.print(table)
