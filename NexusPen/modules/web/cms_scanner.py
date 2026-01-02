#!/usr/bin/env python3
"""
NexusPen - CMS Scanner Module
=============================
Content Management System vulnerability scanning.
Supports: WordPress, Joomla, Drupal, Magento
"""

import subprocess
import re
import json
from typing import Dict, List, Optional
from urllib.parse import urljoin
from dataclasses import dataclass

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

console = Console()


@dataclass
class CMSFinding:
    """Represents a CMS security finding."""
    cms: str
    severity: str
    title: str
    description: str
    url: str
    version: Optional[str] = None
    cve_id: Optional[str] = None


class CMSScanner:
    """CMS vulnerability scanner."""
    
    def __init__(self, target: str, config: Dict = None):
        self.target = target
        self.config = config or {}
        self.findings: List[CMSFinding] = []
        self.cms_type: Optional[str] = None
        self.cms_version: Optional[str] = None
        
        import requests
        self.session = requests.Session()
        self.session.verify = False
    
    def detect_cms(self) -> Optional[str]:
        """Detect CMS type."""
        console.print(f"\n[cyan]🔍 Detecting CMS type...[/cyan]")
        
        cms_signatures = {
            'wordpress': [
                '/wp-login.php',
                '/wp-admin/',
                '/wp-content/',
                '/wp-includes/',
                'WordPress',
            ],
            'joomla': [
                '/administrator/',
                '/components/',
                '/modules/',
                'Joomla!',
                '/media/jui/',
            ],
            'drupal': [
                '/sites/default/',
                '/modules/',
                '/core/',
                'Drupal',
                '/misc/drupal.js',
            ],
            'magento': [
                '/skin/frontend/',
                '/js/mage/',
                '/app/design/',
                'Magento',
            ],
        }
        
        try:
            response = self.session.get(self.target, timeout=10)
            content = response.text.lower()
            
            for cms, signatures in cms_signatures.items():
                for sig in signatures:
                    if sig.lower() in content:
                        self.cms_type = cms
                        console.print(f"[green]✓ Detected: {cms.upper()}[/green]")
                        return cms
                        
            # Check specific paths
            for cms, signatures in cms_signatures.items():
                for sig in signatures:
                    if sig.startswith('/'):
                        try:
                            test_url = urljoin(self.target, sig)
                            test_response = self.session.get(test_url, timeout=5)
                            if test_response.status_code in [200, 301, 302, 403]:
                                self.cms_type = cms
                                console.print(f"[green]✓ Detected: {cms.upper()}[/green]")
                                return cms
                        except:
                            continue
                            
        except Exception as e:
            console.print(f"[yellow]Warning: {e}[/yellow]")
        
        console.print("[yellow]No known CMS detected[/yellow]")
        return None
    
    def scan(self) -> List[CMSFinding]:
        """Scan CMS for vulnerabilities."""
        if not self.cms_type:
            self.detect_cms()
        
        if self.cms_type == 'wordpress':
            return self.scan_wordpress()
        elif self.cms_type == 'joomla':
            return self.scan_joomla()
        elif self.cms_type == 'drupal':
            return self.scan_drupal()
        elif self.cms_type == 'magento':
            return self.scan_magento()
        else:
            console.print("[yellow]Unknown CMS, running generic scan[/yellow]")
            return self.scan_generic()
    
    def scan_wordpress(self) -> List[CMSFinding]:
        """Scan WordPress for vulnerabilities."""
        console.print(f"\n[cyan]📝 Scanning WordPress: {self.target}[/cyan]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            # Version detection
            task = progress.add_task("Detecting version...", total=None)
            self._detect_wp_version()
            progress.update(task, completed=True)
            
            # User enumeration
            task = progress.add_task("Enumerating users...", total=None)
            users = self._enumerate_wp_users()
            progress.update(task, completed=True)
            
            # Plugin enumeration
            task = progress.add_task("Scanning plugins...", total=None)
            self._scan_wp_plugins()
            progress.update(task, completed=True)
            
            # Theme enumeration
            task = progress.add_task("Scanning themes...", total=None)
            self._scan_wp_themes()
            progress.update(task, completed=True)
            
            # Common vulnerabilities
            task = progress.add_task("Checking common vulnerabilities...", total=None)
            self._check_wp_vulnerabilities()
            progress.update(task, completed=True)
        
        # Try WPScan if available
        self._run_wpscan()
        
        self._display_results()
        return self.findings
    
    def _detect_wp_version(self):
        """Detect WordPress version."""
        version_locations = [
            '/readme.html',
            '/wp-includes/version.php',
            '/',  # Meta generator
        ]
        
        for loc in version_locations:
            try:
                url = urljoin(self.target, loc)
                response = self.session.get(url, timeout=10)
                
                # Check meta generator
                match = re.search(r'WordPress\s*([\d.]+)', response.text)
                if match:
                    self.cms_version = match.group(1)
                    console.print(f"[cyan]Version: {self.cms_version}[/cyan]")
                    return
                    
            except:
                continue
    
    def _enumerate_wp_users(self) -> List[str]:
        """Enumerate WordPress users."""
        users = []
        
        # Method 1: Author archives
        for i in range(1, 10):
            try:
                url = urljoin(self.target, f'/?author={i}')
                response = self.session.get(url, timeout=5, allow_redirects=True)
                
                # Extract username from redirect URL
                if 'author/' in response.url:
                    match = re.search(r'/author/([^/]+)/', response.url)
                    if match:
                        users.append(match.group(1))
            except:
                continue
        
        # Method 2: REST API
        try:
            url = urljoin(self.target, '/wp-json/wp/v2/users')
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                for user in data:
                    username = user.get('slug')
                    if username and username not in users:
                        users.append(username)
                        
                if users:
                    self.findings.append(CMSFinding(
                        cms='wordpress',
                        severity='medium',
                        title='User Enumeration via REST API',
                        description=f'Found users: {", ".join(users[:5])}',
                        url=url
                    ))
        except:
            pass
        
        return users
    
    def _scan_wp_plugins(self):
        """Scan for vulnerable WordPress plugins."""
        common_plugins = [
            'akismet', 'contact-form-7', 'yoast-seo', 'jetpack',
            'wordfence', 'wp-super-cache', 'woocommerce', 'elementor',
            'really-simple-captcha', 'duplicator', 'updraftplus',
            'revslider', 'gravityforms', 'all-in-one-seo-pack'
        ]
        
        for plugin in common_plugins:
            try:
                url = urljoin(self.target, f'/wp-content/plugins/{plugin}/')
                response = self.session.get(url, timeout=5)
                
                if response.status_code in [200, 403]:
                    # Check readme for version
                    readme_url = urljoin(self.target, f'/wp-content/plugins/{plugin}/readme.txt')
                    readme_response = self.session.get(readme_url, timeout=5)
                    
                    version = None
                    if readme_response.status_code == 200:
                        match = re.search(r'Stable tag:\s*([\d.]+)', readme_response.text)
                        if match:
                            version = match.group(1)
                    
                    # Check known vulnerable versions
                    self._check_plugin_vulnerabilities(plugin, version)
                    
            except:
                continue
    
    def _scan_wp_themes(self):
        """Scan for WordPress themes."""
        try:
            response = self.session.get(self.target, timeout=10)
            
            # Extract theme from content
            match = re.search(r'/wp-content/themes/([^/]+)/', response.text)
            if match:
                theme = match.group(1)
                console.print(f"[cyan]Active theme: {theme}[/cyan]")
        except:
            pass
    
    def _check_wp_vulnerabilities(self):
        """Check for common WordPress vulnerabilities."""
        vuln_paths = [
            ('/xmlrpc.php', 'XML-RPC Enabled', 'XML-RPC can be used for bruteforce'),
            ('/wp-config.php~', 'Backup Config File', 'Config backup file accessible'),
            ('/wp-config.php.bak', 'Backup Config File', 'Config backup file accessible'),
            ('/.git/', 'Git Repository Exposed', '.git directory accessible'),
            ('/debug.log', 'Debug Log Exposed', 'WP debug log file accessible'),
            ('/wp-content/uploads/', 'Uploads Browsable', 'Uploads directory listing enabled'),
        ]
        
        for path, title, desc in vuln_paths:
            try:
                url = urljoin(self.target, path)
                response = self.session.get(url, timeout=5)
                
                if response.status_code == 200:
                    self.findings.append(CMSFinding(
                        cms='wordpress',
                        severity='medium' if 'config' not in path else 'critical',
                        title=title,
                        description=desc,
                        url=url
                    ))
            except:
                continue
    
    def _check_plugin_vulnerabilities(self, plugin: str, version: str):
        """Check for known plugin vulnerabilities."""
        # Simple version-based vulnerability check
        vulnerable_plugins = {
            'revslider': {'below': '5.4.8', 'cve': 'CVE-2014-9734'},
            'duplicator': {'below': '1.3.28', 'cve': 'CVE-2020-11738'},
            'contact-form-7': {'below': '5.3.2', 'cve': 'CVE-2020-35489'},
        }
        
        if plugin in vulnerable_plugins and version:
            vuln_info = vulnerable_plugins[plugin]
            if self._version_compare(version, vuln_info['below']) < 0:
                self.findings.append(CMSFinding(
                    cms='wordpress',
                    severity='high',
                    title=f'Vulnerable Plugin: {plugin}',
                    description=f'Version {version} vulnerable to {vuln_info["cve"]}',
                    url=self.target,
                    version=version,
                    cve_id=vuln_info['cve']
                ))
    
    def _run_wpscan(self):
        """Run WPScan for comprehensive scanning."""
        try:
            cmd = [
                'wpscan',
                '--url', self.target,
                '--enumerate', 'vp,vt,u',  # Vulnerable plugins, themes, users
                '--format', 'json',
                '--no-banner'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                try:
                    data = json.loads(result.stdout)
                    # Parse WPScan results
                    for vuln in data.get('plugins', {}).values():
                        for v in vuln.get('vulnerabilities', []):
                            self.findings.append(CMSFinding(
                                cms='wordpress',
                                severity='high',
                                title=v.get('title', 'Unknown'),
                                description='Found by WPScan',
                                url=self.target,
                                cve_id=v.get('references', {}).get('cve', [None])[0]
                            ))
                except json.JSONDecodeError:
                    pass
                    
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
    
    def scan_joomla(self) -> List[CMSFinding]:
        """Scan Joomla for vulnerabilities."""
        console.print(f"\n[cyan]📝 Scanning Joomla: {self.target}[/cyan]")
        
        # Version detection
        version_paths = [
            '/administrator/manifests/files/joomla.xml',
            '/language/en-GB/en-GB.xml',
        ]
        
        for path in version_paths:
            try:
                url = urljoin(self.target, path)
                response = self.session.get(url, timeout=10)
                
                if response.status_code == 200:
                    match = re.search(r'<version>([\d.]+)</version>', response.text)
                    if match:
                        self.cms_version = match.group(1)
                        console.print(f"[cyan]Version: {self.cms_version}[/cyan]")
                        break
            except:
                continue
        
        # Try joomscan
        try:
            cmd = ['joomscan', '-u', self.target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            # Parse results
            for line in result.stdout.split('\n'):
                if 'vulnerability' in line.lower():
                    self.findings.append(CMSFinding(
                        cms='joomla',
                        severity='medium',
                        title='Joomscan Finding',
                        description=line.strip(),
                        url=self.target
                    ))
                    
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        self._display_results()
        return self.findings
    
    def scan_drupal(self) -> List[CMSFinding]:
        """Scan Drupal for vulnerabilities."""
        console.print(f"\n[cyan]📝 Scanning Drupal: {self.target}[/cyan]")
        
        # Version detection
        try:
            url = urljoin(self.target, '/core/modules/system/system.info.yml')
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                match = re.search(r"version:\s*'?([\d.]+)'?", response.text)
                if match:
                    self.cms_version = match.group(1)
                    console.print(f"[cyan]Version: {self.cms_version}[/cyan]")
        except:
            pass
        
        # Check for Drupalgeddon
        drupalgeddon_paths = [
            '/user/register?element_parents=account/mail/%23value&ajax_form=1',
        ]
        
        for path in drupalgeddon_paths:
            try:
                url = urljoin(self.target, path)
                response = self.session.post(url, timeout=10)
                
                if response.status_code == 200 and 'form_build_id' in response.text:
                    self.findings.append(CMSFinding(
                        cms='drupal',
                        severity='critical',
                        title='Drupalgeddon2 (CVE-2018-7600)',
                        description='Site vulnerable to Drupalgeddon2 RCE',
                        url=url,
                        cve_id='CVE-2018-7600'
                    ))
            except:
                continue
        
        # Try droopescan
        try:
            cmd = ['droopescan', 'scan', 'drupal', '-u', self.target]
            subprocess.run(cmd, capture_output=True, timeout=300)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        self._display_results()
        return self.findings
    
    def scan_magento(self) -> List[CMSFinding]:
        """Scan Magento for vulnerabilities."""
        console.print(f"\n[cyan]🛒 Scanning Magento: {self.target}[/cyan]")
        
        # Version detection
        try:
            url = urljoin(self.target, '/magento_version')
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                self.cms_version = response.text.strip()
                
        except:
            pass
        
        # Try magescan
        try:
            cmd = ['magescan', 'scan:all', self.target]
            subprocess.run(cmd, capture_output=True, timeout=300)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        self._display_results()
        return self.findings
    
    def scan_generic(self) -> List[CMSFinding]:
        """Generic CMS scanning."""
        return self.findings
    
    def _version_compare(self, v1: str, v2: str) -> int:
        """Compare version strings."""
        try:
            v1_parts = [int(x) for x in v1.split('.')]
            v2_parts = [int(x) for x in v2.split('.')]
            
            for i in range(max(len(v1_parts), len(v2_parts))):
                p1 = v1_parts[i] if i < len(v1_parts) else 0
                p2 = v2_parts[i] if i < len(v2_parts) else 0
                
                if p1 < p2:
                    return -1
                elif p1 > p2:
                    return 1
            return 0
        except:
            return 0
    
    def _display_results(self):
        """Display CMS scan results."""
        if not self.findings:
            console.print("[green]✓ No CMS vulnerabilities found[/green]")
            return
        
        table = Table(title=f"{self.cms_type.upper()} Findings", header_style="bold red")
        table.add_column("Severity", style="yellow", width=10)
        table.add_column("Title", style="cyan")
        table.add_column("CVE", style="dim")
        
        for f in self.findings:
            table.add_row(f.severity.upper(), f.title, f.cve_id or "-")
        
        console.print(table)
        console.print(f"\n[red]⚠️ Found {len(self.findings)} CMS vulnerabilities[/red]")
