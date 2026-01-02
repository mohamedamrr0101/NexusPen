#!/usr/bin/env python3
"""
NexusPen - Credential Utilities Module
=======================================
Credential extraction, wordlist generation, and management.
"""

import os
import re
import hashlib
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console
from rich.table import Table

console = Console()


@dataclass
class Credential:
    """Represents a credential."""
    username: str
    password: Optional[str] = None
    hash_value: Optional[str] = None
    hash_type: Optional[str] = None
    source: Optional[str] = None
    domain: Optional[str] = None


class CredentialManager:
    """
    Manage discovered credentials.
    """
    
    def __init__(self):
        self.credentials: List[Credential] = []
    
    def add(self, username: str, password: str = None, hash_value: str = None,
           source: str = None, domain: str = None):
        """Add a credential."""
        cred = Credential(
            username=username,
            password=password,
            hash_value=hash_value,
            source=source,
            domain=domain
        )
        
        # Identify hash type
        if hash_value:
            cred.hash_type = self._identify_hash_type(hash_value)
        
        self.credentials.append(cred)
    
    def _identify_hash_type(self, hash_value: str) -> str:
        """Identify hash type."""
        if len(hash_value) == 32:
            return 'MD5/NTLM'
        elif len(hash_value) == 40:
            return 'SHA1'
        elif len(hash_value) == 64:
            return 'SHA256'
        elif ':' in hash_value:
            return 'LM:NTLM'
        return 'Unknown'
    
    def get_passwords(self) -> List[str]:
        """Get list of cleared passwords."""
        return [c.password for c in self.credentials if c.password]
    
    def get_hashes(self) -> List[str]:
        """Get list of hashes."""
        return [c.hash_value for c in self.credentials if c.hash_value]
    
    def export_hashcat(self, filename: str):
        """Export hashes for Hashcat."""
        with open(filename, 'w') as f:
            for cred in self.credentials:
                if cred.hash_value:
                    if cred.username:
                        f.write(f"{cred.username}:{cred.hash_value}\n")
                    else:
                        f.write(f"{cred.hash_value}\n")
        
        console.print(f"[green]✓ Exported {len(self.get_hashes())} hashes to {filename}[/green]")
    
    def export_wordlist(self, filename: str):
        """Export passwords as wordlist."""
        passwords = set(self.get_passwords())
        
        with open(filename, 'w') as f:
            for pwd in passwords:
                f.write(f"{pwd}\n")
        
        console.print(f"[green]✓ Exported {len(passwords)} passwords to {filename}[/green]")
    
    def display(self):
        """Display credentials."""
        if not self.credentials:
            console.print("[yellow]No credentials stored[/yellow]")
            return
        
        table = Table(title="Discovered Credentials", show_header=True,
                     header_style="bold magenta")
        table.add_column("Username", style="cyan")
        table.add_column("Password", style="green")
        table.add_column("Hash", style="dim", width=20)
        table.add_column("Type", style="yellow")
        table.add_column("Source", style="white")
        
        for cred in self.credentials:
            table.add_row(
                cred.username or "-",
                cred.password or "-",
                (cred.hash_value[:20] + "...") if cred.hash_value and len(cred.hash_value) > 20 else (cred.hash_value or "-"),
                cred.hash_type or "-",
                cred.source or "-"
            )
        
        console.print(table)


class WordlistGenerator:
    """
    Generate custom wordlists for password attacks.
    """
    
    def __init__(self):
        self.words: Set[str] = set()
    
    def add_word(self, word: str):
        """Add a word to the wordlist."""
        self.words.add(word)
    
    def add_words(self, words: List[str]):
        """Add multiple words."""
        self.words.update(words)
    
    def generate_from_company(self, company_name: str, year: int = 2024) -> Set[str]:
        """Generate passwords from company name."""
        words = set()
        name = company_name.lower()
        Name = company_name.capitalize()
        NAME = company_name.upper()
        
        # Basic variations
        words.update([name, Name, NAME])
        
        # With numbers
        for y in range(year-2, year+1):
            words.update([
                f"{name}{y}",
                f"{Name}{y}",
                f"{name}{y}!",
                f"{Name}{y}!",
                f"{name}@{y}",
                f"{Name}@{y}",
            ])
        
        # With common suffixes
        suffixes = ['123', '1234', '!', '@', '#', '123!', '1234!', '2024', '2024!']
        for suffix in suffixes:
            words.add(f"{name}{suffix}")
            words.add(f"{Name}{suffix}")
        
        # Seasons
        seasons = ['Spring', 'Summer', 'Fall', 'Winter', 'Autumn']
        for season in seasons:
            words.add(f"{season}{year}")
            words.add(f"{season}{year}!")
        
        self.words.update(words)
        return words
    
    def generate_from_usernames(self, usernames: List[str]) -> Set[str]:
        """Generate passwords from usernames."""
        words = set()
        
        for user in usernames:
            # Username variations
            words.update([
                user,
                user.lower(),
                user.capitalize(),
                f"{user}123",
                f"{user}1234",
                f"{user}!",
                f"{user}@123",
                f"{user}#1",
                user[::-1],  # Reversed
            ])
            
            # First letter uppercase + year
            words.add(f"{user.capitalize()}2024")
            words.add(f"{user.capitalize()}2024!")
        
        self.words.update(words)
        return words
    
    def generate_common_patterns(self) -> Set[str]:
        """Generate common password patterns."""
        words = set()
        
        # Common bases
        bases = ['password', 'admin', 'root', 'user', 'test', 'guest', 
                'login', 'welcome', 'letmein', 'changeme', 'qwerty',
                'abc123', 'master', 'monkey', 'dragon', 'shadow']
        
        for base in bases:
            words.update([
                base,
                base.capitalize(),
                f"{base}123",
                f"{base}1234",
                f"{base}!",
                f"{base}@",
                f"{base}#",
                f"{base}2024",
            ])
        
        # Keyboard patterns
        patterns = [
            'qwerty', 'qwerty123', 'asdfgh', 'zxcvbn', '123456', '12345678',
            'qwertyuiop', 'password1', '1q2w3e4r', '1qaz2wsx'
        ]
        words.update(patterns)
        
        self.words.update(words)
        return words
    
    def mutate_wordlist(self, input_file: str) -> Set[str]:
        """Apply mutations to an existing wordlist."""
        words = set()
        
        try:
            with open(input_file, 'r', errors='ignore') as f:
                for line in f:
                    word = line.strip()
                    if word:
                        words.update(self._mutate_word(word))
        except FileNotFoundError:
            console.print(f"[red]File not found: {input_file}[/red]")
        
        self.words.update(words)
        return words
    
    def _mutate_word(self, word: str) -> Set[str]:
        """Apply mutations to a single word."""
        mutations = set([word])
        
        # Case variations
        mutations.add(word.lower())
        mutations.add(word.upper())
        mutations.add(word.capitalize())
        mutations.add(word.swapcase())
        
        # Leet speak
        leet = word.replace('a', '@').replace('e', '3').replace('i', '1').replace('o', '0').replace('s', '$')
        mutations.add(leet)
        
        # Append numbers
        for n in ['1', '12', '123', '1234', '!', '@', '#']:
            mutations.add(f"{word}{n}")
            mutations.add(f"{word.capitalize()}{n}")
        
        # Prepend numbers
        mutations.add(f"1{word}")
        mutations.add(f"123{word}")
        
        return mutations
    
    def save(self, filename: str):
        """Save wordlist to file."""
        with open(filename, 'w') as f:
            for word in sorted(self.words):
                f.write(f"{word}\n")
        
        console.print(f"[green]✓ Saved {len(self.words)} words to {filename}[/green]")
    
    def stats(self):
        """Display wordlist statistics."""
        console.print(f"\n[cyan]📊 Wordlist Statistics[/cyan]")
        console.print(f"[green]Total words: {len(self.words)}[/green]")
        
        if self.words:
            lengths = [len(w) for w in self.words]
            console.print(f"[green]Min length: {min(lengths)}[/green]")
            console.print(f"[green]Max length: {max(lengths)}[/green]")
            console.print(f"[green]Avg length: {sum(lengths)/len(lengths):.1f}[/green]")


class DefaultCredentials:
    """
    Database of default credentials.
    """
    
    CREDENTIALS = {
        'ssh': [
            ('root', 'root'), ('root', 'toor'), ('admin', 'admin'),
            ('user', 'user'), ('ubuntu', 'ubuntu'), ('pi', 'raspberry'),
        ],
        'ftp': [
            ('anonymous', ''), ('ftp', 'ftp'), ('admin', 'admin'),
            ('root', 'root'), ('user', 'user'),
        ],
        'mysql': [
            ('root', ''), ('root', 'root'), ('root', 'mysql'),
            ('admin', 'admin'), ('mysql', 'mysql'),
        ],
        'postgresql': [
            ('postgres', 'postgres'), ('postgres', ''), ('admin', 'admin'),
        ],
        'mssql': [
            ('sa', 'sa'), ('sa', ''), ('admin', 'admin'),
        ],
        'mongodb': [
            ('admin', 'admin'), ('root', 'root'), ('', ''),
        ],
        'redis': [
            ('', ''),  # No auth by default
        ],
        'tomcat': [
            ('admin', 'admin'), ('tomcat', 'tomcat'), ('admin', 'tomcat'),
            ('manager', 'manager'), ('tomcat', 's3cret'),
        ],
        'jenkins': [
            ('admin', 'admin'), ('admin', 'password'), ('jenkins', 'jenkins'),
        ],
        'wordpress': [
            ('admin', 'admin'), ('admin', 'password'), ('admin', 'wordpress'),
        ],
        'phpmyadmin': [
            ('root', ''), ('root', 'root'), ('admin', 'admin'),
        ],
        'cisco': [
            ('cisco', 'cisco'), ('admin', 'admin'), ('admin', 'password'),
        ],
        'juniper': [
            ('root', 'root'), ('admin', 'admin'),
        ],
        'netgear': [
            ('admin', 'password'), ('admin', 'admin'), ('admin', '1234'),
        ],
        'linksys': [
            ('admin', 'admin'), ('', 'admin'),
        ],
        'dlink': [
            ('admin', ''), ('admin', 'admin'), ('admin', 'password'),
        ],
    }
    
    @classmethod
    def get_for_service(cls, service: str) -> List[tuple]:
        """Get default credentials for a service."""
        return cls.CREDENTIALS.get(service.lower(), [])
    
    @classmethod
    def get_all(cls) -> Dict[str, List[tuple]]:
        """Get all default credentials."""
        return cls.CREDENTIALS
    
    @classmethod
    def display(cls, service: str = None):
        """Display default credentials."""
        if service:
            creds = cls.get_for_service(service)
            console.print(f"\n[cyan]Default credentials for {service}:[/cyan]")
            for user, pwd in creds:
                console.print(f"  [yellow]{user}[/yellow] : [green]{pwd or '(empty)'}[/green]")
        else:
            for svc, creds in cls.CREDENTIALS.items():
                console.print(f"\n[cyan]{svc}:[/cyan]")
                for user, pwd in creds[:3]:
                    console.print(f"  [yellow]{user}[/yellow] : [green]{pwd or '(empty)'}[/green]")
