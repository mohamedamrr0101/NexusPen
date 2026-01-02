#!/usr/bin/env python3
"""
NexusPen - Web Application Testing Module
==========================================
Comprehensive web application security testing.

Includes:
- Technology detection
- Directory/file fuzzing
- SQL Injection testing
- XSS detection
- Authentication testing
- API security testing
"""

import subprocess
import re
import json
import requests
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass, field

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

console = Console()


@dataclass
class WebFinding:
    """Represents a web security finding."""
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    url: str
    parameter: Optional[str] = None
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None


class WebRecon:
    """Web application reconnaissance."""
    
    def __init__(self, target: str, config: Dict = None):
        self.target = target
        self.config = config or {}
        self.findings: List[WebFinding] = []
        self.technologies: List[str] = []
        self.cms: Optional[str] = None
        self.waf: Optional[str] = None
        
        # Parse target
        parsed = urlparse(target)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        self.path = parsed.path or "/"
        
        # Session for requests
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': self.config.get('user_agent', 
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
        })
        
        # Get command runner if available
        self.command_runner = self.config.get('command_runner')
        self.tool_manager = self.config.get('tool_manager')
    
    def _execute(self, cmd: List[str], timeout: int = 60) -> tuple:
        """Execute command using CommandRunner if available, else subprocess."""
        if self.command_runner:
            result = self.command_runner.execute(cmd, timeout=timeout)
            return result.return_code == 0 if result.return_code is not None else False, result.stdout
        else:
            # Fallback to direct subprocess
            if self.config.get('verbosity', 0) > 0:
                console.print(f"[grey50]$ {' '.join(cmd)}[/grey50]")
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
                return result.returncode == 0, result.stdout
            except (subprocess.TimeoutExpired, FileNotFoundError):
                return False, ""
    
    def _execute_live(self, cmd: List[str]) -> tuple:
        """Execute with live streaming output (no timeout, Ctrl+C to skip)."""
        if self.command_runner and self.config.get('verbosity', 0) >= 2:
            result = self.command_runner.execute_streaming(cmd)
            return result.return_code == 0 if result.return_code is not None else False, result.stdout
        else:
            return self._execute(cmd)
    
    def run_full_recon(self) -> Dict:
        """Run comprehensive web reconnaissance."""
        console.print(f"\n[cyan]🌐 Starting Web Reconnaissance: {self.target}[/cyan]")
        
        results = {
            'target': self.target,
            'technologies': [],
            'cms': None,
            'waf': None,
            'ssl_info': None,
            'headers': {},
            'robots_txt': None,
            'security_headers': {},
            'findings': []
        }
        
        # Determine if we should use spinner or streaming
        use_streaming = self.config.get('verbosity', 0) >= 2 and self.command_runner
        
        if use_streaming:
            # Run without Progress context to allow streaming output
            console.print("[dim]Running in streaming mode - live command output enabled[/dim]")
            
            console.print("\n[yellow]🔍 Detecting technologies...[/yellow]")
            results['technologies'], results['cms'] = self.detect_technologies()
            
            console.print("\n[yellow]🛡️ Detecting WAF...[/yellow]")
            results['waf'] = self.detect_waf()
            
            console.print("\n[yellow]🔒 Analyzing SSL/TLS...[/yellow]")
            results['ssl_info'] = self.analyze_ssl()
            
            console.print("\n[yellow]🔐 Checking security headers...[/yellow]")
            results['headers'], results['security_headers'] = self.check_security_headers()
            
            console.print("\n[yellow]🤖 Fetching robots.txt...[/yellow]")
            results['robots_txt'] = self.get_robots_txt()
        else:
            # Use Progress spinner for non-verbose mode
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                
                task = progress.add_task("Detecting technologies...", total=None)
                results['technologies'], results['cms'] = self.detect_technologies()
                progress.update(task, completed=True)
                
                task = progress.add_task("Detecting WAF...", total=None)
                results['waf'] = self.detect_waf()
                progress.update(task, completed=True)
                
                task = progress.add_task("Analyzing SSL/TLS...", total=None)
                results['ssl_info'] = self.analyze_ssl()
                progress.update(task, completed=True)
                
                task = progress.add_task("Checking security headers...", total=None)
                results['headers'], results['security_headers'] = self.check_security_headers()
                progress.update(task, completed=True)
                
                task = progress.add_task("Fetching robots.txt...", total=None)
                results['robots_txt'] = self.get_robots_txt()
                progress.update(task, completed=True)
        
        # Display results
        self._display_results(results)
        
        results['findings'] = [f.__dict__ for f in self.findings]
        return results
    
    def detect_technologies(self) -> Tuple[List[str], Optional[str]]:
        """Detect web technologies using multiple methods."""
        technologies = []
        cms = None
        
        try:
            # Method 1: WhatWeb
            cmd = ['whatweb', '--color=never', '-q', '-a', '3', self.target]
            if self.config.get('verbosity', 0) > 0:
                console.print(f"[grey50]$ {' '.join(cmd)}[/grey50]")
                
            result = subprocess.run(
                cmd,
                capture_output=True, text=True, timeout=120
            )
            
            if result.returncode == 0:
                output = result.stdout.lower()
                
                # Debug: show raw output
                if self.config.get('verbosity', 0) >= 2 and result.stdout.strip():
                    console.print(f"[dim]   → {result.stdout.strip()[:200]}[/dim]")
                
                # Extract technologies
                tech_patterns = {
                    'apache': 'Apache',
                    'nginx': 'Nginx',
                    'iis': 'Microsoft IIS',
                    'php': 'PHP',
                    'asp.net': 'ASP.NET',
                    'python': 'Python',
                    'ruby': 'Ruby',
                    'node': 'Node.js',
                    'tomcat': 'Apache Tomcat',
                    'jquery': 'jQuery',
                    'bootstrap': 'Bootstrap',
                    'react': 'React',
                    'angular': 'Angular',
                    'vue': 'Vue.js',
                    'laravel': 'Laravel',
                    'django': 'Django',
                    'flask': 'Flask',
                    'express': 'Express.js',
                }
                
                for key, name in tech_patterns.items():
                    if key in output:
                        technologies.append(name)
                
                # CMS detection
                cms_patterns = {
                    'wordpress': 'WordPress',
                    'joomla': 'Joomla',
                    'drupal': 'Drupal',
                    'magento': 'Magento',
                    'prestashop': 'PrestaShop',
                    'opencart': 'OpenCart',
                    'shopify': 'Shopify',
                    'wix': 'Wix',
                    'squarespace': 'Squarespace',
                }
                
                for key, name in cms_patterns.items():
                    if key in output:
                        cms = name
                        break
                        
        except subprocess.TimeoutExpired:
            if self.config.get('verbosity', 0) > 0:
                console.print(f"[yellow]⚠ whatweb timed out[/yellow]")
        except FileNotFoundError:
            if self.config.get('verbosity', 0) > 0:
                console.print(f"[yellow]⚠ whatweb not installed (apt install whatweb)[/yellow]")
        
        # Method 2: Manual header analysis
        try:
            response = self.session.get(self.target, timeout=10, verify=False)
            
            # Server header
            server = response.headers.get('Server', '').lower()
            if 'apache' in server and 'Apache' not in technologies:
                technologies.append('Apache')
            elif 'nginx' in server and 'Nginx' not in technologies:
                technologies.append('Nginx')
            elif 'iis' in server and 'Microsoft IIS' not in technologies:
                technologies.append('Microsoft IIS')
            
            # X-Powered-By
            powered_by = response.headers.get('X-Powered-By', '').lower()
            if 'php' in powered_by and 'PHP' not in technologies:
                technologies.append('PHP')
            elif 'asp.net' in powered_by and 'ASP.NET' not in technologies:
                technologies.append('ASP.NET')
            
            # Check HTML for CMS indicators
            html = response.text.lower()
            if not cms:
                if 'wp-content' in html or 'wp-includes' in html:
                    cms = 'WordPress'
                elif 'joomla' in html:
                    cms = 'Joomla'
                elif 'drupal' in html:
                    cms = 'Drupal'
                    
        except requests.RequestException:
            pass
        
        return list(set(technologies)), cms
    
    def detect_waf(self) -> Optional[str]:
        """Detect Web Application Firewall."""
        try:
            # Use wafw00f
            cmd = ['wafw00f', '-a', self.target]
            if self.config.get('verbosity', 0) > 0:
                console.print(f"[grey50]$ {' '.join(cmd)}[/grey50]")
                
            result = subprocess.run(
                cmd,
                capture_output=True, text=True, timeout=120
            )
            
            if result.returncode == 0:
                output = result.stdout
                
                # Debug: show raw output
                if self.config.get('verbosity', 0) >= 2 and result.stdout.strip():
                    console.print(f"[dim]   → {result.stdout.strip()[:200]}[/dim]")
                
                # Parse output for WAF name
                waf_match = re.search(r'is behind (.+)', output)
                if waf_match:
                    return waf_match.group(1).strip()
                
        except subprocess.TimeoutExpired:
            if self.config.get('verbosity', 0) > 0:
                console.print(f"[yellow]⚠ wafw00f timed out[/yellow]")
        except FileNotFoundError:
            if self.config.get('verbosity', 0) > 0:
                console.print(f"[yellow]⚠ wafw00f not installed (pip install wafw00f)[/yellow]")
        
        # Manual WAF detection
        try:
            # Test with suspicious payload
            test_url = f"{self.target}/?test=<script>alert(1)</script>"
            response = self.session.get(test_url, timeout=10, verify=False)
            
            headers_str = str(response.headers).lower()
            
            waf_signatures = {
                'cloudflare': 'Cloudflare',
                'akamai': 'Akamai',
                'incapsula': 'Imperva Incapsula',
                'sucuri': 'Sucuri',
                'aws': 'AWS WAF',
                'f5': 'F5 BIG-IP',
                'modsecurity': 'ModSecurity',
                'barracuda': 'Barracuda',
            }
            
            for sig, name in waf_signatures.items():
                if sig in headers_str:
                    return name
                    
        except requests.RequestException:
            pass
        
        return None
    
    def analyze_ssl(self) -> Dict:
        """Analyze SSL/TLS configuration."""
        ssl_info = {
            'enabled': False,
            'valid': False,
            'issuer': None,
            'subject': None,
            'expires': None,
            'protocols': [],
            'ciphers': [],
            'vulnerabilities': []
        }
        
        if not self.target.startswith('https'):
            return ssl_info
        
        try:
            import ssl
            import socket
            
            parsed = urlparse(self.target)
            hostname = parsed.netloc.split(':')[0]
            port = parsed.port or 443
            
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    ssl_info['enabled'] = True
                    ssl_info['valid'] = True
                    ssl_info['issuer'] = dict(x[0] for x in cert.get('issuer', []))
                    ssl_info['subject'] = dict(x[0] for x in cert.get('subject', []))
                    ssl_info['expires'] = cert.get('notAfter')
                    ssl_info['protocols'] = [ssock.version()]
                    
        except ssl.SSLError as e:
            ssl_info['vulnerabilities'].append(f"SSL Error: {str(e)}")
        except Exception:
            pass
        
        # Check for SSLyze if available
        try:
            cmd = ['sslyze', '--regular', self.target.replace('https://', '').split('/')[0]]
            if self.config.get('verbosity', 0) > 0:
                console.print(f"[grey50]$ {' '.join(cmd)}[/grey50]")
                
            result = subprocess.run(
                cmd,
                capture_output=True, text=True, timeout=120
            )
            
            if result.returncode == 0:
                output = result.stdout
                
                # Check for vulnerabilities
                if 'VULNERABLE' in output:
                    if 'heartbleed' in output.lower():
                        ssl_info['vulnerabilities'].append('Heartbleed')
                        self.findings.append(WebFinding(
                            severity='critical',
                            title='Heartbleed Vulnerability (CVE-2014-0160)',
                            description='Server is vulnerable to Heartbleed attack',
                            url=self.target,
                            cve_id='CVE-2014-0160',
                            cvss_score=9.8
                        ))
                        
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        return ssl_info
    
    def check_security_headers(self) -> Tuple[Dict, Dict]:
        """Check HTTP response headers for security issues."""
        all_headers = {}
        security_analysis = {
            'present': [],
            'missing': [],
            'misconfigured': []
        }
        
        required_headers = {
            'Strict-Transport-Security': 'HSTS - Enforces HTTPS',
            'X-Content-Type-Options': 'Prevents MIME type sniffing',
            'X-Frame-Options': 'Prevents clickjacking',
            'Content-Security-Policy': 'Prevents XSS and injection attacks',
            'X-XSS-Protection': 'XSS filter (legacy)',
            'Referrer-Policy': 'Controls referrer information',
            'Permissions-Policy': 'Controls browser features',
        }
        
        try:
            response = self.session.get(self.target, timeout=10, verify=False)
            all_headers = dict(response.headers)
            
            for header, description in required_headers.items():
                if header in response.headers:
                    security_analysis['present'].append({
                        'header': header,
                        'value': response.headers[header],
                        'description': description
                    })
                else:
                    security_analysis['missing'].append({
                        'header': header,
                        'description': description
                    })
                    
                    self.findings.append(WebFinding(
                        severity='low' if header == 'X-XSS-Protection' else 'medium',
                        title=f'Missing Security Header: {header}',
                        description=f'{description} header is not set',
                        url=self.target,
                        remediation=f'Add the {header} header to HTTP responses'
                    ))
            
            # Check for information disclosure
            sensitive_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version']
            for header in sensitive_headers:
                if header in response.headers:
                    self.findings.append(WebFinding(
                        severity='info',
                        title=f'Information Disclosure: {header}',
                        description=f'{header}: {response.headers[header]}',
                        url=self.target,
                        remediation=f'Consider removing or obfuscating the {header} header'
                    ))
                    
        except requests.RequestException:
            pass
        
        return all_headers, security_analysis
    
    def get_robots_txt(self) -> Optional[Dict]:
        """Fetch and parse robots.txt."""
        robots_info = {
            'exists': False,
            'content': None,
            'disallowed': [],
            'sitemaps': [],
            'interesting_paths': []
        }
        
        try:
            robots_url = urljoin(self.base_url, '/robots.txt')
            response = self.session.get(robots_url, timeout=10, verify=False)
            
            if response.status_code == 200:
                robots_info['exists'] = True
                robots_info['content'] = response.text
                
                for line in response.text.split('\n'):
                    line = line.strip().lower()
                    
                    if line.startswith('disallow:'):
                        path = line.replace('disallow:', '').strip()
                        if path:
                            robots_info['disallowed'].append(path)
                            
                            # Check for interesting paths
                            interesting = ['admin', 'backup', 'config', 'database', 
                                         'private', 'secret', 'test', 'dev', 'api']
                            for keyword in interesting:
                                if keyword in path.lower():
                                    robots_info['interesting_paths'].append(path)
                                    break
                    
                    elif line.startswith('sitemap:'):
                        sitemap = line.replace('sitemap:', '').strip()
                        robots_info['sitemaps'].append(sitemap)
                        
        except requests.RequestException:
            pass
        
        return robots_info
    
    def _display_results(self, results: Dict):
        """Display reconnaissance results in a nice format."""
        console.print("\n[bold green]╔══════════════════════════════════════════════════════════════╗[/bold green]")
        console.print("[bold green]║           WEB RECONNAISSANCE RESULTS                          ║[/bold green]")
        console.print("[bold green]╚══════════════════════════════════════════════════════════════╝[/bold green]\n")
        
        # Technologies
        if results['technologies']:
            console.print("[cyan]📦 Technologies Detected:[/cyan]")
            for tech in results['technologies']:
                console.print(f"   • {tech}")
        
        # CMS
        if results['cms']:
            console.print(f"\n[cyan]📝 CMS:[/cyan] {results['cms']}")
        
        # WAF
        if results['waf']:
            console.print(f"[cyan]🛡️ WAF Detected:[/cyan] {results['waf']}")
        
        # Security Headers
        if results['security_headers']:
            console.print("\n[cyan]🔒 Security Headers:[/cyan]")
            present = results['security_headers'].get('present', [])
            missing = results['security_headers'].get('missing', [])
            
            for h in present[:5]:
                console.print(f"   [green]✔[/green] {h['header']}")
            for h in missing[:5]:
                console.print(f"   [red]✘[/red] {h['header']}")
        
        # Findings summary
        if self.findings:
            console.print(f"\n[yellow]⚠️ Findings: {len(self.findings)}[/yellow]")


class WebScanner:
    """Web vulnerability scanner."""
    
    def __init__(self, target: str, config: Dict = None):
        self.target = target
        self.config = config or {}
        self.findings: List[WebFinding] = []
    
    def run_nikto(self) -> List[Dict]:
        """Run Nikto web scanner."""
        console.print(f"\n[cyan]🔍 Running Nikto against {self.target}[/cyan]")
        
        findings = []
        
        try:
            cmd = ['nikto', '-h', self.target, '-Format', 'json', '-o', '-']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            if result.returncode == 0:
                try:
                    data = json.loads(result.stdout)
                    for vuln in data.get('vulnerabilities', []):
                        findings.append({
                            'title': vuln.get('msg', 'Unknown'),
                            'severity': 'medium',
                            'url': vuln.get('url', self.target),
                            'id': vuln.get('id')
                        })
                except json.JSONDecodeError:
                    # Parse text output if JSON fails
                    for line in result.stdout.split('\n'):
                        if '+ ' in line and 'OSVDB' in line:
                            findings.append({
                                'title': line.strip(),
                                'severity': 'medium',
                                'url': self.target
                            })
                            
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            console.print(f"[yellow]⚠️ Nikto: {e}[/yellow]")
        
        console.print(f"[green]✓ Nikto found {len(findings)} potential issues[/green]")
        return findings
    
    def run_nuclei(self, templates: List[str] = None) -> List[Dict]:
        """Run Nuclei template scanner."""
        console.print(f"\n[cyan]🔍 Running Nuclei against {self.target}[/cyan]")
        
        findings = []
        
        try:
            cmd = ['nuclei', '-u', self.target, '-j', '-silent']
            
            if templates:
                cmd.extend(['-t', ','.join(templates)])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            for line in result.stdout.split('\n'):
                if line.strip():
                    try:
                        finding = json.loads(line)
                        findings.append({
                            'title': finding.get('info', {}).get('name', 'Unknown'),
                            'severity': finding.get('info', {}).get('severity', 'unknown'),
                            'url': finding.get('matched-at', self.target),
                            'template': finding.get('template-id'),
                            'description': finding.get('info', {}).get('description', '')
                        })
                    except json.JSONDecodeError:
                        continue
                        
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            console.print(f"[yellow]⚠️ Nuclei: {e}[/yellow]")
        
        console.print(f"[green]✓ Nuclei found {len(findings)} potential issues[/green]")
        return findings


class DirectoryFuzzer:
    """Directory and file fuzzer."""
    
    def __init__(self, target: str, wordlist: str = None, config: Dict = None):
        self.target = target
        self.wordlist = wordlist or "/usr/share/wordlists/dirb/common.txt"
        self.config = config or {}
        self.found_paths: List[Dict] = []
    
    def run_gobuster(self, extensions: List[str] = None) -> List[Dict]:
        """Run Gobuster for directory fuzzing."""
        console.print(f"\n[cyan]🔍 Running Gobuster against {self.target}[/cyan]")
        
        try:
            cmd = [
                'gobuster', 'dir',
                '-u', self.target,
                '-w', self.wordlist,
                '-t', str(self.config.get('threads', 50)),
                '-q',
                '--no-error'
            ]
            
            if extensions:
                cmd.extend(['-x', ','.join(extensions)])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            for line in result.stdout.split('\n'):
                if line.strip() and '(Status:' in line:
                    # Parse: /path (Status: 200) [Size: 1234]
                    match = re.match(r'(/\S+)\s+\(Status:\s*(\d+)\)', line)
                    if match:
                        self.found_paths.append({
                            'path': match.group(1),
                            'status': int(match.group(2)),
                            'url': urljoin(self.target, match.group(1))
                        })
                        
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            console.print(f"[yellow]⚠️ Gobuster: {e}[/yellow]")
        
        console.print(f"[green]✓ Found {len(self.found_paths)} paths[/green]")
        return self.found_paths


# Module entry points
# Module entry points
def run(target: str, profile, results: list, config: Dict = None):
    """Main entry point for web recon module."""
    recon = WebRecon(target, config)
    web_results = recon.run_full_recon()
    results.append({
        'module': 'web.recon',
        'phase': 'recon',
        'findings': web_results
    })
