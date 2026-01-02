#!/usr/bin/env python3
"""
NexusPen - Web Fuzzer Module
=============================
Directory, parameter, and subdomain fuzzing.
"""

import subprocess
import requests
from typing import Dict, List, Optional
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

from rich.console import Console
from rich.progress import Progress

console = Console()


@dataclass
class FuzzResult:
    """Fuzzing result."""
    url: str
    status_code: int
    content_length: int
    redirect: Optional[str] = None
    content_type: Optional[str] = None


class DirectoryFuzzer:
    """
    Directory and file fuzzer.
    """
    
    # Common extensions
    EXTENSIONS = [
        '', '.php', '.html', '.js', '.txt', '.xml', '.json',
        '.asp', '.aspx', '.jsp', '.bak', '.old', '.swp',
        '.zip', '.tar', '.gz', '.sql', '.log', '.conf',
    ]
    
    def __init__(self, target_url: str, session: requests.Session = None):
        self.target_url = target_url.rstrip('/')
        self.session = session or requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.results: List[FuzzResult] = []
    
    def fuzz_directories(self, wordlist: List[str], 
                        threads: int = 10,
                        extensions: List[str] = None) -> List[FuzzResult]:
        """Fuzz directories with wordlist."""
        console.print(f"\n[cyan]📂 Fuzzing directories on {self.target_url}...[/cyan]")
        
        extensions = extensions or ['']
        results = []
        
        # Generate all URLs to test
        urls = []
        for word in wordlist:
            for ext in extensions:
                urls.append(f"{self.target_url}/{word}{ext}")
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Fuzzing...", total=len(urls))
            
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {executor.submit(self._check_url, url): url for url in urls}
                
                for future in as_completed(futures):
                    progress.update(task, advance=1)
                    result = future.result()
                    if result:
                        results.append(result)
                        self.results.append(result)
                        
                        if result.status_code == 200:
                            console.print(f"[green]  ✓ {result.url} [{result.status_code}] {result.content_length}B[/green]")
                        elif result.status_code in [301, 302]:
                            console.print(f"[yellow]  → {result.url} [{result.status_code}] -> {result.redirect}[/yellow]")
                        elif result.status_code == 403:
                            console.print(f"[red]  ⛔ {result.url} [{result.status_code}][/red]")
        
        return results
    
    def _check_url(self, url: str) -> Optional[FuzzResult]:
        """Check single URL."""
        try:
            response = self.session.get(url, timeout=5, allow_redirects=False)
            
            if response.status_code in [200, 201, 301, 302, 307, 308, 401, 403]:
                return FuzzResult(
                    url=url,
                    status_code=response.status_code,
                    content_length=len(response.content),
                    redirect=response.headers.get('Location'),
                    content_type=response.headers.get('Content-Type')
                )
                
        except:
            pass
        
        return None
    
    def run_gobuster(self, wordlist: str, mode: str = 'dir',
                    threads: int = 50) -> str:
        """Run Gobuster for directory fuzzing."""
        console.print(f"\n[cyan]🔍 Running Gobuster ({mode} mode)...[/cyan]")
        
        cmd = [
            'gobuster', mode,
            '-u', self.target_url,
            '-w', wordlist,
            '-t', str(threads),
            '-q',
        ]
        
        if mode == 'dir':
            cmd.extend(['-x', 'php,html,txt,asp,aspx,jsp'])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            console.print(result.stdout)
            return result.stdout
        except FileNotFoundError:
            console.print("[yellow]Gobuster not found[/yellow]")
            return ""
        except subprocess.TimeoutExpired:
            return ""
    
    def run_feroxbuster(self, wordlist: str, threads: int = 50) -> str:
        """Run Feroxbuster for recursive directory fuzzing."""
        console.print(f"\n[cyan]🔥 Running Feroxbuster...[/cyan]")
        
        cmd = [
            'feroxbuster',
            '-u', self.target_url,
            '-w', wordlist,
            '-t', str(threads),
            '-x', 'php,html,js,txt',
            '--silent',
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            return result.stdout
        except FileNotFoundError:
            console.print("[yellow]Feroxbuster not found[/yellow]")
            return ""
    
    def run_dirsearch(self, wordlist: str = None, extensions: str = 'php,html,js') -> str:
        """Run Dirsearch."""
        console.print(f"\n[cyan]🔎 Running Dirsearch...[/cyan]")
        
        cmd = ['dirsearch', '-u', self.target_url, '-e', extensions, '-q']
        
        if wordlist:
            cmd.extend(['-w', wordlist])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            return result.stdout
        except FileNotFoundError:
            console.print("[yellow]Dirsearch not found[/yellow]")
            return ""


class SubdomainFuzzer:
    """
    Subdomain enumeration and fuzzing.
    """
    
    def __init__(self, domain: str):
        self.domain = domain
        self.results: List[str] = []
    
    def fuzz_subdomains(self, wordlist: List[str], 
                       threads: int = 20) -> List[str]:
        """Fuzz subdomains with wordlist."""
        console.print(f"\n[cyan]🌐 Fuzzing subdomains of {self.domain}...[/cyan]")
        
        import socket
        
        found = []
        
        def check_subdomain(subdomain: str) -> Optional[str]:
            host = f"{subdomain}.{self.domain}"
            try:
                socket.gethostbyname(host)
                return host
            except socket.gaierror:
                return None
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(check_subdomain, word): word for word in wordlist}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
                    self.results.append(result)
                    console.print(f"[green]  ✓ {result}[/green]")
        
        return found
    
    def run_subfinder(self) -> List[str]:
        """Run Subfinder for passive subdomain enumeration."""
        console.print(f"\n[cyan]🔍 Running Subfinder...[/cyan]")
        
        try:
            result = subprocess.run(
                ['subfinder', '-d', self.domain, '-silent'],
                capture_output=True, text=True, timeout=300
            )
            
            subdomains = result.stdout.strip().split('\n')
            subdomains = [s for s in subdomains if s]
            
            for sub in subdomains[:20]:  # Show first 20
                console.print(f"[green]  ✓ {sub}[/green]")
            
            if len(subdomains) > 20:
                console.print(f"[dim]  ... and {len(subdomains)-20} more[/dim]")
            
            return subdomains
            
        except FileNotFoundError:
            console.print("[yellow]Subfinder not found[/yellow]")
            return []
    
    def run_amass(self, passive: bool = True) -> List[str]:
        """Run Amass for subdomain enumeration."""
        console.print(f"\n[cyan]🗺️ Running Amass...[/cyan]")
        
        cmd = ['amass', 'enum', '-d', self.domain]
        if passive:
            cmd.append('-passive')
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            return result.stdout.strip().split('\n')
        except FileNotFoundError:
            console.print("[yellow]Amass not found[/yellow]")
            return []
    
    def run_sublist3r(self) -> str:
        """Run Sublist3r."""
        console.print(f"\n[cyan]📋 Running Sublist3r...[/cyan]")
        
        try:
            result = subprocess.run(
                ['sublist3r', '-d', self.domain, '-n'],
                capture_output=True, text=True, timeout=300
            )
            return result.stdout
        except FileNotFoundError:
            console.print("[yellow]Sublist3r not found[/yellow]")
            return ""


class ParameterFuzzer:
    """
    Parameter fuzzing and discovery.
    """
    
    # Common parameters
    COMMON_PARAMS = [
        'id', 'page', 'file', 'path', 'url', 'redirect', 'next',
        'query', 'search', 'q', 's', 'keyword', 'name', 'user',
        'username', 'password', 'pass', 'email', 'admin', 'debug',
        'test', 'cmd', 'exec', 'command', 'action', 'callback',
        'api', 'token', 'key', 'secret', 'auth', 'login',
        'category', 'cat', 'type', 'sort', 'order', 'limit',
        'offset', 'start', 'end', 'from', 'to', 'date', 'year',
    ]
    
    def __init__(self, target_url: str, session: requests.Session = None):
        self.target_url = target_url
        self.session = session or requests.Session()
    
    def discover_params(self, wordlist: List[str] = None,
                       method: str = 'GET') -> List[str]:
        """Discover hidden parameters."""
        console.print(f"\n[cyan]🔧 Discovering parameters on {self.target_url}...[/cyan]")
        
        wordlist = wordlist or self.COMMON_PARAMS
        found_params = []
        
        # Get baseline response
        try:
            baseline = self.session.get(self.target_url, timeout=10)
            baseline_length = len(baseline.content)
        except:
            return []
        
        for param in wordlist:
            try:
                if method.upper() == 'GET':
                    response = self.session.get(
                        self.target_url,
                        params={param: 'test'},
                        timeout=5
                    )
                else:
                    response = self.session.post(
                        self.target_url,
                        data={param: 'test'},
                        timeout=5
                    )
                
                # Check if response changed
                if len(response.content) != baseline_length:
                    found_params.append(param)
                    console.print(f"[green]  ✓ Found: {param}[/green]")
                    
                # Check for parameter reflection
                if f'test' in response.text and param in response.text:
                    found_params.append(param)
                    console.print(f"[yellow]  ⚠️ Reflected: {param}[/yellow]")
                    
            except:
                pass
        
        return list(set(found_params))
    
    def run_arjun(self, wordlist: str = None) -> str:
        """Run Arjun for parameter discovery."""
        console.print(f"\n[cyan]🎯 Running Arjun...[/cyan]")
        
        cmd = ['arjun', '-u', self.target_url]
        
        if wordlist:
            cmd.extend(['-w', wordlist])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            console.print(result.stdout)
            return result.stdout
        except FileNotFoundError:
            console.print("[yellow]Arjun not found[/yellow]")
            return ""
    
    def run_paramspider(self) -> str:
        """Run ParamSpider for parameter collection from archives."""
        console.print(f"\n[cyan]🕷️ Running ParamSpider...[/cyan]")
        
        try:
            result = subprocess.run(
                ['paramspider', '-d', self.target_url],
                capture_output=True, text=True, timeout=300
            )
            return result.stdout
        except FileNotFoundError:
            console.print("[yellow]ParamSpider not found[/yellow]")
            return ""


class VHostFuzzer:
    """
    Virtual host fuzzing.
    """
    
    def __init__(self, target_ip: str, target_port: int = 80):
        self.target_ip = target_ip
        self.target_port = target_port
        self.session = requests.Session()
    
    def fuzz_vhosts(self, domain: str, wordlist: List[str],
                   threads: int = 20) -> List[str]:
        """Fuzz virtual hosts."""
        console.print(f"\n[cyan]🏠 Fuzzing virtual hosts on {self.target_ip}...[/cyan]")
        
        found = []
        
        # Get baseline with invalid host
        try:
            baseline = self.session.get(
                f"http://{self.target_ip}:{self.target_port}",
                headers={'Host': 'invalid.host.example.com'},
                timeout=5
            )
            baseline_length = len(baseline.content)
        except:
            return []
        
        for word in wordlist:
            vhost = f"{word}.{domain}"
            try:
                response = self.session.get(
                    f"http://{self.target_ip}:{self.target_port}",
                    headers={'Host': vhost},
                    timeout=5
                )
                
                # Different response = valid vhost
                if len(response.content) != baseline_length:
                    found.append(vhost)
                    console.print(f"[green]  ✓ {vhost} [{response.status_code}] {len(response.content)}B[/green]")
                    
            except:
                pass
        
        return found
    
    def run_ffuf_vhost(self, domain: str, wordlist: str) -> str:
        """Run FFuF for vhost fuzzing."""
        console.print(f"\n[cyan]🔍 Running FFuF for vhost...[/cyan]")
        
        cmd = [
            'ffuf', '-w', f'{wordlist}:FUZZ',
            '-u', f'http://{self.target_ip}',
            '-H', f'Host: FUZZ.{domain}',
            '-mc', 'all',
            '-fs', '0',  # Filter by size
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return result.stdout
        except FileNotFoundError:
            console.print("[yellow]FFuF not found[/yellow]")
            return ""


def run_ffuf(url: str, wordlist: str, position: str = 'FUZZ',
            filters: Dict = None) -> str:
    """
    Run FFuF - versatile fuzzer.
    """
    console.print(f"\n[cyan]⚡ Running FFuF...[/cyan]")
    
    cmd = ['ffuf', '-u', url, '-w', f'{wordlist}:{position}']
    
    if filters:
        if 'fc' in filters:  # Filter codes
            cmd.extend(['-fc', filters['fc']])
        if 'fs' in filters:  # Filter size
            cmd.extend(['-fs', filters['fs']])
        if 'fw' in filters:  # Filter words
            cmd.extend(['-fw', filters['fw']])
        if 'fl' in filters:  # Filter lines
            cmd.extend(['-fl', filters['fl']])
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        console.print(result.stdout)
        return result.stdout
    except FileNotFoundError:
        console.print("[yellow]FFuF not found[/yellow]")
        return ""


def run_wfuzz(url: str, wordlist: str, hide_codes: str = '404') -> str:
    """
    Run WFuzz.
    """
    console.print(f"\n[cyan]🌀 Running WFuzz...[/cyan]")
    
    cmd = [
        'wfuzz', '-c',
        '-w', wordlist,
        '--hc', hide_codes,
        url
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        console.print(result.stdout)
        return result.stdout
    except FileNotFoundError:
        console.print("[yellow]WFuzz not found - install with: pip install wfuzz[/yellow]")
        return ""
