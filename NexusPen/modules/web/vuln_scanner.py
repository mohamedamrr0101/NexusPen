#!/usr/bin/env python3
"""
NexusPen - Web Vulnerability Scanner Module
============================================
Comprehensive web vulnerability detection.
"""

import subprocess
import re
import requests
from typing import Dict, List, Optional
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

from rich.console import Console
from rich.table import Table

console = Console()


@dataclass
class WebVulnerability:
    """Web vulnerability finding."""
    vuln_type: str
    severity: str
    url: str
    parameter: Optional[str]
    payload: Optional[str]
    evidence: Optional[str]
    description: str
    remediation: str
    cwe: Optional[str] = None
    cvss: Optional[float] = None


class WebVulnScanner:
    """
    Comprehensive web vulnerability scanner.
    """
    
    def __init__(self, target_url: str, session: requests.Session = None):
        self.target_url = target_url.rstrip('/')
        self.session = session or requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.findings: List[WebVulnerability] = []
    
    def check_security_headers(self) -> List[WebVulnerability]:
        """Check for missing security headers."""
        console.print("\n[cyan]🔒 Checking security headers...[/cyan]")
        
        vulns = []
        
        required_headers = {
            'X-Frame-Options': {
                'severity': 'medium',
                'description': 'Missing X-Frame-Options allows clickjacking attacks',
                'remediation': 'Set X-Frame-Options: DENY or SAMEORIGIN',
                'cwe': 'CWE-1021',
            },
            'X-Content-Type-Options': {
                'severity': 'low',
                'description': 'Missing X-Content-Type-Options allows MIME sniffing',
                'remediation': 'Set X-Content-Type-Options: nosniff',
                'cwe': 'CWE-16',
            },
            'X-XSS-Protection': {
                'severity': 'low',
                'description': 'Missing XSS protection header',
                'remediation': 'Set X-XSS-Protection: 1; mode=block',
                'cwe': 'CWE-79',
            },
            'Strict-Transport-Security': {
                'severity': 'medium',
                'description': 'Missing HSTS allows MITM attacks',
                'remediation': 'Set Strict-Transport-Security: max-age=31536000; includeSubDomains',
                'cwe': 'CWE-319',
            },
            'Content-Security-Policy': {
                'severity': 'medium',
                'description': 'Missing CSP allows XSS and injection attacks',
                'remediation': 'Implement a strict Content-Security-Policy',
                'cwe': 'CWE-1021',
            },
            'Referrer-Policy': {
                'severity': 'low',
                'description': 'Missing Referrer-Policy may leak sensitive URLs',
                'remediation': 'Set Referrer-Policy: strict-origin-when-cross-origin',
                'cwe': 'CWE-200',
            },
        }
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            
            for header, info in required_headers.items():
                if header.lower() not in [h.lower() for h in response.headers]:
                    vuln = WebVulnerability(
                        vuln_type='Missing Security Header',
                        severity=info['severity'],
                        url=self.target_url,
                        parameter=None,
                        payload=None,
                        evidence=f"Header '{header}' not present",
                        description=info['description'],
                        remediation=info['remediation'],
                        cwe=info['cwe'],
                    )
                    vulns.append(vuln)
                    self.findings.append(vuln)
                    console.print(f"[yellow]  ⚠️ Missing: {header}[/yellow]")
                    
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        
        return vulns
    
    def check_cors(self) -> Optional[WebVulnerability]:
        """Check for CORS misconfiguration."""
        console.print("\n[cyan]🌐 Checking CORS configuration...[/cyan]")
        
        try:
            # Test with arbitrary origin
            response = self.session.get(
                self.target_url,
                headers={'Origin': 'https://evil.com'},
                timeout=10
            )
            
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '')
            
            if acao == '*':
                vuln = WebVulnerability(
                    vuln_type='CORS Misconfiguration',
                    severity='medium',
                    url=self.target_url,
                    parameter=None,
                    payload=None,
                    evidence=f"ACAO: {acao}",
                    description='Wildcard CORS allows any origin',
                    remediation='Restrict CORS to specific trusted origins',
                    cwe='CWE-942',
                )
                self.findings.append(vuln)
                console.print("[yellow]  ⚠️ Wildcard CORS (*)[/yellow]")
                return vuln
            
            if 'evil.com' in acao and acac.lower() == 'true':
                vuln = WebVulnerability(
                    vuln_type='CORS Misconfiguration',
                    severity='high',
                    url=self.target_url,
                    parameter=None,
                    payload=None,
                    evidence=f"ACAO: {acao}, ACAC: {acac}",
                    description='CORS reflects arbitrary origin with credentials',
                    remediation='Validate origin against whitelist',
                    cwe='CWE-942',
                )
                self.findings.append(vuln)
                console.print("[red]  ⚠️ Dangerous CORS configuration![/red]")
                return vuln
                
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        
        return None
    
    def check_ssl_issues(self) -> List[WebVulnerability]:
        """Check for SSL/TLS issues."""
        console.print("\n[cyan]🔐 Checking SSL/TLS...[/cyan]")
        
        vulns = []
        
        if not self.target_url.startswith('https://'):
            vuln = WebVulnerability(
                vuln_type='No HTTPS',
                severity='high',
                url=self.target_url,
                parameter=None,
                payload=None,
                evidence='Site uses HTTP instead of HTTPS',
                description='Traffic is transmitted in cleartext',
                remediation='Enable HTTPS with valid certificate',
                cwe='CWE-319',
            )
            vulns.append(vuln)
            self.findings.append(vuln)
            console.print("[red]  ⚠️ No HTTPS![/red]")
            return vulns
        
        # Check certificate using nmap
        try:
            domain = urlparse(self.target_url).netloc
            result = subprocess.run(
                ['nmap', '--script', 'ssl-cert,ssl-enum-ciphers', '-p', '443', domain],
                capture_output=True, text=True, timeout=60
            )
            
            output = result.stdout.lower()
            
            if 'sslv2' in output or 'sslv3' in output:
                vuln = WebVulnerability(
                    vuln_type='Weak SSL Version',
                    severity='high',
                    url=self.target_url,
                    parameter=None,
                    payload=None,
                    evidence='SSLv2/SSLv3 enabled',
                    description='Weak SSL versions are vulnerable to attacks',
                    remediation='Disable SSLv2 and SSLv3, use TLS 1.2+',
                    cwe='CWE-327',
                )
                vulns.append(vuln)
                self.findings.append(vuln)
                
        except Exception as e:
            console.print(f"[dim]SSL check error: {e}[/dim]")
        
        return vulns
    
    def check_server_info(self) -> List[WebVulnerability]:
        """Check for information disclosure in headers."""
        console.print("\n[cyan]📋 Checking information disclosure...[/cyan]")
        
        vulns = []
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            
            sensitive_headers = {
                'Server': 'Server version disclosed',
                'X-Powered-By': 'Technology stack disclosed',
                'X-AspNet-Version': 'ASP.NET version disclosed',
                'X-AspNetMvc-Version': 'MVC version disclosed',
            }
            
            for header, desc in sensitive_headers.items():
                if header in response.headers:
                    value = response.headers[header]
                    vuln = WebVulnerability(
                        vuln_type='Information Disclosure',
                        severity='low',
                        url=self.target_url,
                        parameter=None,
                        payload=None,
                        evidence=f"{header}: {value}",
                        description=desc,
                        remediation=f'Remove or obfuscate {header} header',
                        cwe='CWE-200',
                    )
                    vulns.append(vuln)
                    self.findings.append(vuln)
                    console.print(f"[yellow]  ⚠️ {header}: {value}[/yellow]")
                    
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        
        return vulns
    
    def check_sensitive_files(self) -> List[WebVulnerability]:
        """Check for sensitive files and directories."""
        console.print("\n[cyan]📁 Checking sensitive files...[/cyan]")
        
        vulns = []
        
        sensitive_paths = [
            '/.git/HEAD', '/.git/config',
            '/.svn/entries', '/.svn/wc.db',
            '/.env', '/wp-config.php.bak',
            '/config.php.bak', '/database.yml',
            '/phpinfo.php', '/info.php',
            '/server-status', '/server-info',
            '/.htaccess', '/.htpasswd',
            '/web.config', '/crossdomain.xml',
            '/robots.txt', '/sitemap.xml',
            '/backup.zip', '/backup.sql',
            '/dump.sql', '/database.sql',
            '/.DS_Store', '/Thumbs.db',
            '/composer.json', '/package.json',
            '/.npmrc', '/.dockerignore',
            '/Dockerfile', '/docker-compose.yml',
        ]
        
        for path in sensitive_paths:
            try:
                url = urljoin(self.target_url, path)
                response = self.session.get(url, timeout=5, allow_redirects=False)
                
                if response.status_code == 200:
                    content_type = response.headers.get('Content-Type', '')
                    
                    # Verify it's not a custom 404
                    if len(response.content) > 0 and 'text/html' not in content_type.lower():
                        vuln = WebVulnerability(
                            vuln_type='Sensitive File Exposure',
                            severity='high' if any(x in path for x in ['.git', '.env', 'config', 'backup', '.sql']) else 'medium',
                            url=url,
                            parameter=None,
                            payload=None,
                            evidence=f"HTTP {response.status_code}, Size: {len(response.content)} bytes",
                            description=f'Sensitive file accessible: {path}',
                            remediation='Remove or restrict access to sensitive files',
                            cwe='CWE-538',
                        )
                        vulns.append(vuln)
                        self.findings.append(vuln)
                        console.print(f"[red]  ⚠️ Found: {path}[/red]")
                        
            except:
                pass
        
        return vulns
    
    def check_open_redirect(self, params: List[str] = None) -> List[WebVulnerability]:
        """Check for open redirect vulnerabilities."""
        console.print("\n[cyan]↪️ Checking open redirect...[/cyan]")
        
        vulns = []
        params = params or ['url', 'redirect', 'next', 'return', 'goto', 'link', 'target', 'dest', 'destination', 'redir', 'redirect_uri', 'return_url', 'continue']
        
        payloads = [
            '//evil.com',
            'https://evil.com',
            '//evil.com/%2f..',
            '/\\evil.com',
            '////evil.com',
        ]
        
        for param in params:
            for payload in payloads:
                try:
                    url = f"{self.target_url}?{param}={payload}"
                    response = self.session.get(url, timeout=5, allow_redirects=False)
                    
                    location = response.headers.get('Location', '')
                    
                    if 'evil.com' in location:
                        vuln = WebVulnerability(
                            vuln_type='Open Redirect',
                            severity='medium',
                            url=url,
                            parameter=param,
                            payload=payload,
                            evidence=f"Redirects to: {location}",
                            description='Open redirect allows phishing attacks',
                            remediation='Validate redirect URLs against whitelist',
                            cwe='CWE-601',
                        )
                        vulns.append(vuln)
                        self.findings.append(vuln)
                        console.print(f"[yellow]  ⚠️ Open redirect via {param}[/yellow]")
                        break
                        
                except:
                    pass
        
        return vulns
    
    def check_http_methods(self) -> List[WebVulnerability]:
        """Check for dangerous HTTP methods."""
        console.print("\n[cyan]📡 Checking HTTP methods...[/cyan]")
        
        vulns = []
        dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
        
        try:
            response = self.session.options(self.target_url, timeout=10)
            allowed = response.headers.get('Allow', '')
            
            for method in dangerous_methods:
                if method in allowed.upper():
                    vuln = WebVulnerability(
                        vuln_type='Dangerous HTTP Method',
                        severity='medium' if method in ['PUT', 'DELETE'] else 'low',
                        url=self.target_url,
                        parameter=None,
                        payload=None,
                        evidence=f"Allowed methods: {allowed}",
                        description=f'{method} method is enabled',
                        remediation=f'Disable {method} method if not required',
                        cwe='CWE-749',
                    )
                    vulns.append(vuln)
                    self.findings.append(vuln)
                    console.print(f"[yellow]  ⚠️ {method} enabled[/yellow]")
                    
        except:
            pass
        
        return vulns
    
    def run_nikto(self) -> str:
        """Run Nikto web scanner."""
        console.print("\n[cyan]🔍 Running Nikto scan...[/cyan]")
        
        try:
            result = subprocess.run(
                ['nikto', '-h', self.target_url, '-Format', 'txt', '-o', '-'],
                capture_output=True, text=True, timeout=600
            )
            return result.stdout
        except FileNotFoundError:
            console.print("[yellow]Nikto not found[/yellow]")
            return ""
        except subprocess.TimeoutExpired:
            console.print("[yellow]Nikto timeout[/yellow]")
            return ""
    
    def run_full_scan(self) -> List[WebVulnerability]:
        """Run comprehensive vulnerability scan."""
        console.print("\n[bold red]═══════════════════════════════════════════════════════════[/bold red]")
        console.print("[bold red]              WEB VULNERABILITY SCAN                        [/bold red]")
        console.print("[bold red]═══════════════════════════════════════════════════════════[/bold red]")
        console.print(f"[cyan]Target: {self.target_url}[/cyan]")
        
        self.check_security_headers()
        self.check_cors()
        self.check_ssl_issues()
        self.check_server_info()
        self.check_sensitive_files()
        self.check_open_redirect()
        self.check_http_methods()
        
        self.display_findings()
        
        return self.findings
    
    def display_findings(self):
        """Display all findings."""
        if not self.findings:
            console.print("\n[green]No vulnerabilities found![/green]")
            return
        
        table = Table(title=f"Vulnerabilities Found ({len(self.findings)})", show_header=True,
                     header_style="bold red")
        table.add_column("Type", style="cyan", width=25)
        table.add_column("Severity", width=10)
        table.add_column("URL/Details", style="white", width=40)
        
        severity_colors = {'critical': 'red', 'high': 'orange1', 'medium': 'yellow', 'low': 'green', 'info': 'blue'}
        
        for vuln in self.findings:
            sev_color = severity_colors.get(vuln.severity, 'white')
            table.add_row(
                vuln.vuln_type,
                f"[{sev_color}]{vuln.severity.upper()}[/{sev_color}]",
                vuln.url[:40] if vuln.url else vuln.evidence[:40]
            )
        
        console.print(table)
