#!/usr/bin/env python3
"""
NexusPen - Wordlist Module
===========================
Wordlist generation and management.
"""

import subprocess
import os
import re
import itertools
from typing import List, Optional, Set
from dataclasses import dataclass

from rich.console import Console
from rich.progress import Progress

console = Console()


@dataclass
class WordlistStats:
    """Wordlist statistics."""
    total_words: int
    unique_words: int
    min_length: int
    max_length: int
    avg_length: float
    file_size: int


class WordlistManager:
    """
    Wordlist management and common wordlists.
    """
    
    # Common wordlist paths on Kali
    WORDLISTS = {
        'rockyou': '/usr/share/wordlists/rockyou.txt',
        'fasttrack': '/usr/share/wordlists/fasttrack.txt',
        'dirb_common': '/usr/share/wordlists/dirb/common.txt',
        'dirb_big': '/usr/share/wordlists/dirb/big.txt',
        'dirbuster_small': '/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt',
        'dirbuster_medium': '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
        'seclists_passwords': '/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt',
        'seclists_usernames': '/usr/share/seclists/Usernames/top-usernames-shortlist.txt',
        'metasploit_users': '/usr/share/metasploit-framework/data/wordlists/unix_users.txt',
        'metasploit_passwords': '/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt',
    }
    
    @classmethod
    def get_wordlist(cls, name: str) -> Optional[str]:
        """Get path to a named wordlist."""
        path = cls.WORDLISTS.get(name)
        if path and os.path.exists(path):
            return path
        return None
    
    @classmethod
    def list_available(cls) -> dict:
        """List available wordlists."""
        available = {}
        for name, path in cls.WORDLISTS.items():
            if os.path.exists(path):
                size = os.path.getsize(path)
                available[name] = {'path': path, 'size': size}
        return available
    
    @staticmethod
    def get_stats(wordlist_path: str) -> WordlistStats:
        """Get wordlist statistics."""
        total = 0
        unique = set()
        min_len = float('inf')
        max_len = 0
        total_len = 0
        
        with open(wordlist_path, 'r', errors='ignore') as f:
            for line in f:
                word = line.strip()
                total += 1
                unique.add(word)
                length = len(word)
                total_len += length
                min_len = min(min_len, length)
                max_len = max(max_len, length)
        
        return WordlistStats(
            total_words=total,
            unique_words=len(unique),
            min_length=min_len if min_len != float('inf') else 0,
            max_length=max_len,
            avg_length=total_len / total if total > 0 else 0,
            file_size=os.path.getsize(wordlist_path)
        )
    
    @staticmethod
    def decompress_rockyou():
        """Decompress rockyou.txt.gz if needed."""
        gz_path = '/usr/share/wordlists/rockyou.txt.gz'
        txt_path = '/usr/share/wordlists/rockyou.txt'
        
        if os.path.exists(gz_path) and not os.path.exists(txt_path):
            console.print("[cyan]Decompressing rockyou.txt.gz...[/cyan]")
            subprocess.run(['gzip', '-dk', gz_path])
            console.print("[green]✓ Done[/green]")


class WordlistGenerator:
    """
    Custom wordlist generation.
    """
    
    @staticmethod
    def generate_from_keywords(keywords: List[str], 
                               add_numbers: bool = True,
                               add_special: bool = False,
                               add_years: bool = True,
                               leet_speak: bool = False) -> Set[str]:
        """
        Generate wordlist from keywords.
        
        Args:
            keywords: Base keywords
            add_numbers: Add numeric suffixes
            add_special: Add special characters
            add_years: Add year suffixes
            leet_speak: Convert to leet speak
        """
        console.print("\n[cyan]🔧 Generating wordlist from keywords...[/cyan]")
        
        words = set()
        numbers = ['1', '12', '123', '1234', '!', '@', '#']
        years = [str(y) for y in range(2020, 2026)]
        specials = ['!', '@', '#', '$', '%', '*']
        
        leet_map = {'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 't': '7'}
        
        for keyword in keywords:
            # Base variations
            words.add(keyword)
            words.add(keyword.lower())
            words.add(keyword.upper())
            words.add(keyword.capitalize())
            words.add(keyword.title())
            
            if add_numbers:
                for num in numbers:
                    words.add(f'{keyword}{num}')
                    words.add(f'{keyword.capitalize()}{num}')
            
            if add_years:
                for year in years:
                    words.add(f'{keyword}{year}')
                    words.add(f'{keyword.capitalize()}{year}')
                    words.add(f'{keyword}{year}!')
            
            if add_special:
                for special in specials:
                    words.add(f'{keyword}{special}')
                    words.add(f'{special}{keyword}')
            
            if leet_speak:
                leet_word = keyword.lower()
                for char, leet_char in leet_map.items():
                    leet_word = leet_word.replace(char, leet_char)
                words.add(leet_word)
        
        console.print(f"[green]✓ Generated {len(words)} words[/green]")
        return words
    
    @staticmethod
    def generate_combinations(base_words: List[str], 
                             separators: List[str] = None) -> Set[str]:
        """Generate combinations of words."""
        separators = separators or ['', '_', '-', '.']
        combinations = set()
        
        for w1, w2 in itertools.product(base_words, repeat=2):
            for sep in separators:
                combinations.add(f'{w1}{sep}{w2}')
        
        return combinations
    
    @staticmethod
    def generate_username_wordlist(first_names: List[str], 
                                   last_names: List[str],
                                   domain: str = None) -> Set[str]:
        """Generate username wordlist from names."""
        usernames = set()
        
        for first in first_names:
            for last in last_names:
                f = first.lower()
                l = last.lower()
                
                # Common patterns
                usernames.update([
                    f'{f}{l}',
                    f'{f}.{l}',
                    f'{f}_{l}',
                    f'{f[0]}{l}',
                    f'{f}{l[0]}',
                    f'{f[0]}.{l}',
                    f'{l}{f}',
                    f'{l}.{f}',
                    f'{l}{f[0]}',
                    f,
                    l,
                ])
                
                if domain:
                    usernames.add(f'{f}.{l}@{domain}')
                    usernames.add(f'{f[0]}{l}@{domain}')
        
        return usernames
    
    @staticmethod
    def save_wordlist(words: Set[str], output_path: str):
        """Save wordlist to file."""
        with open(output_path, 'w') as f:
            for word in sorted(words):
                f.write(f'{word}\n')
        
        console.print(f"[green]✓ Saved {len(words)} words to {output_path}[/green]")


class CeWL:
    """
    CeWL web crawler wordlist generator.
    """
    
    @staticmethod
    def spider(url: str, depth: int = 2, min_word_length: int = 5,
              output_file: str = '/tmp/cewl_wordlist.txt') -> str:
        """
        Spider a website to generate wordlist.
        
        Args:
            url: Target URL
            depth: Spider depth
            min_word_length: Minimum word length
            output_file: Output file path
        """
        console.print(f"\n[cyan]🕷️ Spidering {url} with CeWL...[/cyan]")
        
        cmd = [
            'cewl', url,
            '-d', str(depth),
            '-m', str(min_word_length),
            '-w', output_file
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if os.path.exists(output_file):
                word_count = sum(1 for _ in open(output_file))
                console.print(f"[green]✓ Generated {word_count} words[/green]")
                
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        
        return output_file
    
    @staticmethod
    def with_emails(url: str, output_file: str = '/tmp/cewl_emails.txt') -> str:
        """Spider and extract emails."""
        cmd = ['cewl', url, '-e', '--email_file', output_file]
        
        try:
            subprocess.run(cmd, capture_output=True, timeout=300)
        except:
            pass
        
        return output_file


class CUPP:
    """
    CUPP - Common User Passwords Profiler.
    """
    
    @staticmethod
    def interactive() -> str:
        """Run CUPP in interactive mode."""
        return 'cupp -i'
    
    @staticmethod
    def generate_from_profile(profile: dict, output_file: str = '/tmp/cupp_wordlist.txt') -> Set[str]:
        """
        Generate passwords from user profile.
        
        Args:
            profile: Dict with keys like 'name', 'nickname', 'birthdate', 'pet', etc.
        """
        console.print("\n[cyan]👤 Generating personalized wordlist...[/cyan]")
        
        words = set()
        
        name = profile.get('name', '')
        nickname = profile.get('nickname', '')
        birthdate = profile.get('birthdate', '')  # DDMMYYYY
        pet = profile.get('pet', '')
        partner = profile.get('partner', '')
        company = profile.get('company', '')
        
        base_words = [w for w in [name, nickname, pet, partner, company] if w]
        
        # Add date variations
        if birthdate and len(birthdate) == 8:
            day = birthdate[:2]
            month = birthdate[2:4]
            year = birthdate[4:]
            base_words.extend([day, month, year, year[-2:], f'{day}{month}'])
        
        # Generate with WordlistGenerator
        words = WordlistGenerator.generate_from_keywords(
            base_words,
            add_numbers=True,
            add_special=True,
            add_years=True,
            leet_speak=True
        )
        
        # Save
        WordlistGenerator.save_wordlist(words, output_file)
        
        return words


class Crunch:
    """
    Crunch wordlist generator.
    """
    
    @staticmethod
    def generate(min_len: int, max_len: int, charset: str = None,
                pattern: str = None, output_file: str = None) -> str:
        """
        Generate wordlist with Crunch.
        
        Args:
            min_len: Minimum word length
            max_len: Maximum word length
            charset: Characters to use (default: lowercase)
            pattern: Pattern with placeholders (@=lower, ,=upper, %=numeric, ^=special)
            output_file: Output file
        """
        cmd = ['crunch', str(min_len), str(max_len)]
        
        if charset:
            cmd.append(charset)
        
        if pattern:
            cmd.extend(['-t', pattern])
        
        if output_file:
            cmd.extend(['-o', output_file])
        
        return ' '.join(cmd)
    
    @staticmethod
    def common_patterns() -> dict:
        """Common Crunch patterns."""
        return {
            'lowercase_6': 'crunch 6 6 abcdefghijklmnopqrstuvwxyz',
            'upper_lower_num': 'crunch 8 8 -t @@@@%%%%',
            'name+year': 'crunch 8 12 -t @@@@@@20%%',
            'company+num': 'crunch 10 10 -t Company%%%',
            'phone_us': 'crunch 10 10 -t %%%-%%%-%%%%',
        }


class Hashcat_Utils:
    """
    Hashcat utilities for wordlist manipulation.
    """
    
    @staticmethod
    def apply_rules(wordlist: str, rules_file: str, output: str) -> str:
        """Apply rules to wordlist."""
        return f'hashcat --stdout -r {rules_file} {wordlist} > {output}'
    
    @staticmethod
    def combine_wordlists(wordlist1: str, wordlist2: str, output: str) -> str:
        """Combine two wordlists."""
        return f'combinator {wordlist1} {wordlist2} > {output}'
    
    @staticmethod
    def prince_attack(wordlist: str, output: str) -> str:
        """PRINCE attack wordlist expansion."""
        return f'pp64.bin {wordlist} > {output}'


def merge_wordlists(input_files: List[str], output_file: str, unique: bool = True):
    """Merge multiple wordlists."""
    console.print(f"\n[cyan]📑 Merging {len(input_files)} wordlists...[/cyan]")
    
    words = set() if unique else []
    
    for file_path in input_files:
        if os.path.exists(file_path):
            with open(file_path, 'r', errors='ignore') as f:
                for line in f:
                    word = line.strip()
                    if unique:
                        words.add(word)
                    else:
                        words.append(word)
    
    with open(output_file, 'w') as f:
        for word in sorted(words) if unique else words:
            f.write(f'{word}\n')
    
    count = len(words)
    console.print(f"[green]✓ Merged {count} {'unique ' if unique else ''}words to {output_file}[/green]")


def filter_wordlist(input_file: str, output_file: str,
                   min_length: int = None, max_length: int = None,
                   must_contain: str = None, must_not_contain: str = None):
    """Filter wordlist by criteria."""
    console.print(f"\n[cyan]🔧 Filtering wordlist...[/cyan]")
    
    filtered = []
    
    with open(input_file, 'r', errors='ignore') as f:
        for line in f:
            word = line.strip()
            
            # Length filters
            if min_length and len(word) < min_length:
                continue
            if max_length and len(word) > max_length:
                continue
            
            # Content filters
            if must_contain and must_contain.lower() not in word.lower():
                continue
            if must_not_contain and must_not_contain.lower() in word.lower():
                continue
            
            filtered.append(word)
    
    with open(output_file, 'w') as f:
        for word in filtered:
            f.write(f'{word}\n')
    
    console.print(f"[green]✓ Filtered to {len(filtered)} words[/green]")
