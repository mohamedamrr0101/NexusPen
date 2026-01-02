#!/usr/bin/env python3
"""
NexusPen - Shodan CVE Intelligence Module
==========================================
Smart CVE lookup and vulnerability intelligence using Shodan CVEDB API.

API Documentation: https://cvedb.shodan.io/
- Free for non-commercial use
- No API key required
- Updated daily
"""

import requests
import json
from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


@dataclass
class CVEIntelligence:
    """CVE intelligence data from Shodan."""
    cve_id: str
    summary: str
    cvss: float
    cvss_v2: Optional[float] = None
    cvss_v3: Optional[float] = None
    epss: Optional[float] = None  # Exploit Prediction Scoring System
    ranking_epss: Optional[float] = None
    kev: bool = False  # Known Exploited Vulnerability
    ransomware_campaign: Optional[str] = None
    propose_action: Optional[str] = None
    published_time: Optional[str] = None
    cpes: List[str] = None
    references: List[str] = None


class ShodanCVEDB:
    """
    Shodan CVE Database API integration.
    Provides smart vulnerability intelligence and CVE lookups.
    """
    
    BASE_URL = "https://cvedb.shodan.io"
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'NexusPen/1.0',
            'Accept': 'application/json'
        })
        self.cache: Dict[str, CVEIntelligence] = {}
    
    def get_cve(self, cve_id: str) -> Optional[CVEIntelligence]:
        """
        Get detailed information about a specific CVE.
        
        Args:
            cve_id: CVE identifier (e.g., CVE-2021-44228)
        """
        console.print(f"\n[cyan]🔍 Looking up {cve_id}...[/cyan]")
        
        # Check cache
        if cve_id in self.cache:
            console.print("[dim]Using cached data[/dim]")
            return self.cache[cve_id]
        
        try:
            url = f"{self.BASE_URL}/cve/{cve_id}"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                cve_intel = CVEIntelligence(
                    cve_id=data.get('cve', cve_id),
                    summary=data.get('summary', ''),
                    cvss=data.get('cvss', 0),
                    cvss_v2=data.get('cvss_v2'),
                    cvss_v3=data.get('cvss_v3'),
                    epss=data.get('epss'),
                    ranking_epss=data.get('ranking_epss'),
                    kev=data.get('kev', False),
                    ransomware_campaign=data.get('ransomware_campaign'),
                    propose_action=data.get('propose_action'),
                    published_time=data.get('published_time'),
                    cpes=data.get('cpes', []),
                    references=data.get('references', [])
                )
                
                self.cache[cve_id] = cve_intel
                self._display_cve(cve_intel)
                return cve_intel
            else:
                console.print(f"[yellow]CVE not found or API error: {response.status_code}[/yellow]")
                
        except requests.exceptions.RequestException as e:
            console.print(f"[red]Network error: {e}[/red]")
        except json.JSONDecodeError:
            console.print("[red]Invalid response from API[/red]")
        
        return None
    
    def get_cves_by_product(self, product: str, limit: int = 20) -> List[CVEIntelligence]:
        """
        Get CVEs affecting a specific product.
        
        Args:
            product: Product name (e.g., "apache", "nginx", "php")
            limit: Maximum number of results
        """
        console.print(f"\n[cyan]🔍 Searching CVEs for product: {product}[/cyan]")
        
        cves = []
        
        try:
            url = f"{self.BASE_URL}/cves"
            params = {'product': product}
            
            response = self.session.get(url, params=params, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                
                if isinstance(data, list):
                    for item in data[:limit]:
                        cves.append(CVEIntelligence(
                            cve_id=item.get('cve', ''),
                            summary=item.get('summary', ''),
                            cvss=item.get('cvss', 0),
                            cvss_v3=item.get('cvss_v3'),
                            epss=item.get('epss'),
                            kev=item.get('kev', False),
                        ))
                
                console.print(f"[green]✓ Found {len(cves)} CVEs for {product}[/green]")
                
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        
        return cves
    
    def get_cves_by_cpe(self, cpe23: str) -> List[CVEIntelligence]:
        """
        Get CVEs for a specific CPE (Common Platform Enumeration).
        
        Args:
            cpe23: CPE 2.3 string (e.g., cpe:2.3:a:apache:http_server:2.4.49)
        """
        console.print(f"\n[cyan]🔍 Searching CVEs for CPE: {cpe23}[/cyan]")
        
        cves = []
        
        try:
            url = f"{self.BASE_URL}/cves"
            params = {'cpe23': cpe23}
            
            response = self.session.get(url, params=params, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                
                if isinstance(data, list):
                    for item in data:
                        cves.append(CVEIntelligence(
                            cve_id=item.get('cve', ''),
                            summary=item.get('summary', ''),
                            cvss=item.get('cvss', 0),
                            cvss_v3=item.get('cvss_v3'),
                            epss=item.get('epss'),
                            kev=item.get('kev', False),
                        ))
                
                console.print(f"[green]✓ Found {len(cves)} CVEs[/green]")
                
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        
        return cves
    
    def get_kev_cves(self, limit: int = 50) -> List[CVEIntelligence]:
        """
        Get Known Exploited Vulnerabilities (KEV).
        These are CVEs with confirmed active exploitation.
        
        Args:
            limit: Maximum number of results
        """
        console.print("\n[cyan]🔍 Fetching Known Exploited Vulnerabilities (KEV)...[/cyan]")
        
        cves = []
        
        try:
            url = f"{self.BASE_URL}/cves"
            params = {'is_kev': 'true'}
            
            response = self.session.get(url, params=params, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                
                if isinstance(data, list):
                    for item in data[:limit]:
                        cves.append(CVEIntelligence(
                            cve_id=item.get('cve', ''),
                            summary=item.get('summary', ''),
                            cvss=item.get('cvss', 0),
                            cvss_v3=item.get('cvss_v3'),
                            epss=item.get('epss'),
                            kev=True,
                            ransomware_campaign=item.get('ransomware_campaign')
                        ))
                
                console.print(f"[red]⚠️ Found {len(cves)} Known Exploited Vulnerabilities![/red]")
                
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        
        return cves
    
    def get_trending_cves(self) -> List[CVEIntelligence]:
        """
        Get CVEs sorted by EPSS (Exploit Prediction Scoring System).
        Higher EPSS = higher probability of exploitation.
        """
        console.print("\n[cyan]🔥 Fetching trending CVEs (high EPSS)...[/cyan]")
        
        cves = []
        
        try:
            url = f"{self.BASE_URL}/cves"
            params = {'sort_by_epss': 'true'}
            
            response = self.session.get(url, params=params, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                
                if isinstance(data, list):
                    for item in data[:30]:
                        cves.append(CVEIntelligence(
                            cve_id=item.get('cve', ''),
                            summary=item.get('summary', ''),
                            cvss=item.get('cvss', 0),
                            epss=item.get('epss'),
                            ranking_epss=item.get('ranking_epss'),
                            kev=item.get('kev', False),
                        ))
                
                console.print(f"[green]✓ Found {len(cves)} trending CVEs[/green]")
                
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        
        return cves
    
    def get_recent_cves(self, days: int = 7) -> List[CVEIntelligence]:
        """
        Get CVEs published in the last N days.
        
        Args:
            days: Number of days to look back
        """
        console.print(f"\n[cyan]📅 Fetching CVEs from last {days} days...[/cyan]")
        
        cves = []
        
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        try:
            url = f"{self.BASE_URL}/cves"
            params = {
                'start_date': start_date.strftime('%Y-%m-%d'),
                'end_date': end_date.strftime('%Y-%m-%d')
            }
            
            response = self.session.get(url, params=params, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                
                if isinstance(data, list):
                    for item in data:
                        cves.append(CVEIntelligence(
                            cve_id=item.get('cve', ''),
                            summary=item.get('summary', ''),
                            cvss=item.get('cvss', 0),
                            cvss_v3=item.get('cvss_v3'),
                            epss=item.get('epss'),
                            kev=item.get('kev', False),
                            published_time=item.get('published_time')
                        ))
                
                console.print(f"[green]✓ Found {len(cves)} new CVEs[/green]")
                
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        
        return cves
    
    def search_cpes(self, product: str) -> List[str]:
        """
        Search for CPEs matching a product name.
        
        Args:
            product: Product name to search
        """
        console.print(f"\n[cyan]🔍 Searching CPEs for: {product}[/cyan]")
        
        cpes = []
        
        try:
            url = f"{self.BASE_URL}/cpes"
            params = {'product': product}
            
            response = self.session.get(url, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                if isinstance(data, list):
                    cpes = data
                    console.print(f"[green]✓ Found {len(cpes)} CPEs[/green]")
                
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        
        return cpes
    
    def _display_cve(self, cve: CVEIntelligence):
        """Display CVE information in a rich panel."""
        severity_color = self._get_severity_color(cve.cvss)
        kev_badge = "[bold red]⚠️ KEV - ACTIVELY EXPLOITED[/bold red]" if cve.kev else ""
        
        info = f"""[bold]{cve.cve_id}[/bold] {kev_badge}

[cyan]Summary:[/cyan]
{cve.summary[:500]}{'...' if len(cve.summary) > 500 else ''}

[cyan]CVSS Score:[/cyan] [{severity_color}]{cve.cvss}[/{severity_color}] {'(Critical)' if cve.cvss >= 9 else '(High)' if cve.cvss >= 7 else '(Medium)' if cve.cvss >= 4 else '(Low)'}

[cyan]EPSS:[/cyan] {cve.epss or 'N/A'} ({f"{cve.ranking_epss*100:.1f}% likely to be exploited" if cve.ranking_epss else ''})

[cyan]Recommended Action:[/cyan]
{cve.propose_action or 'Apply vendor patches'}
"""
        
        if cve.ransomware_campaign and cve.ransomware_campaign != 'Unknown':
            info += f"\n[red]🔴 Used in ransomware: {cve.ransomware_campaign}[/red]"
        
        console.print(Panel(info, title=f"CVE Intelligence", border_style=severity_color))
    
    def _get_severity_color(self, cvss: float) -> str:
        """Get color based on CVSS score."""
        if cvss >= 9:
            return "red"
        elif cvss >= 7:
            return "yellow"
        elif cvss >= 4:
            return "cyan"
        else:
            return "green"
    
    def display_cves(self, cves: List[CVEIntelligence], title: str = "CVE Results"):
        """Display a list of CVEs in a table."""
        if not cves:
            console.print("[yellow]No CVEs found[/yellow]")
            return
        
        table = Table(title=title, show_header=True, header_style="bold magenta")
        table.add_column("CVE ID", style="cyan", width=18)
        table.add_column("CVSS", justify="center", width=6)
        table.add_column("EPSS", justify="center", width=8)
        table.add_column("KEV", justify="center", width=4)
        table.add_column("Summary", width=50)
        
        for cve in cves:
            cvss_color = self._get_severity_color(cve.cvss)
            kev_icon = "[red]⚠️[/red]" if cve.kev else ""
            epss_str = f"{cve.epss:.4f}" if cve.epss else "-"
            
            table.add_row(
                cve.cve_id,
                f"[{cvss_color}]{cve.cvss}[/{cvss_color}]",
                epss_str,
                kev_icon,
                cve.summary[:50] + "..." if len(cve.summary) > 50 else cve.summary
            )
        
        console.print(table)


class SmartVulnScanner:
    """
    Smart vulnerability scanner that uses Shodan CVEDB
    to identify vulnerabilities based on detected services.
    """
    
    def __init__(self):
        self.cvedb = ShodanCVEDB()
        self.findings: List[Dict] = []
    
    def scan_by_service(self, service: str, version: str = None) -> List[CVEIntelligence]:
        """
        Scan for vulnerabilities based on detected service.
        
        Args:
            service: Service name (e.g., "apache", "nginx")
            version: Service version
        """
        console.print(f"\n[bold cyan]═══ Smart Vulnerability Scan: {service} {version or ''} ═══[/bold cyan]")
        
        cves = []
        
        # Build CPE if version is known
        if version:
            # Try to build CPE23
            product = service.lower().replace(' ', '_')
            cpe = f"cpe:2.3:a:*:{product}:{version}"
            cves = self.cvedb.get_cves_by_cpe(cpe)
        
        # Fallback to product search
        if not cves:
            cves = self.cvedb.get_cves_by_product(service)
        
        # Filter high severity
        critical_cves = [c for c in cves if c.cvss >= 7]
        kev_cves = [c for c in cves if c.kev]
        
        if kev_cves:
            console.print(f"\n[red]⚠️ {len(kev_cves)} KNOWN EXPLOITED VULNERABILITIES FOUND![/red]")
            self.cvedb.display_cves(kev_cves, "Known Exploited Vulnerabilities")
        
        if critical_cves:
            console.print(f"\n[yellow]Found {len(critical_cves)} critical/high CVEs[/yellow]")
            self.cvedb.display_cves(critical_cves[:10], "Critical Vulnerabilities")
        
        return cves
    
    def scan_services(self, services: List[Dict]) -> Dict:
        """
        Scan multiple services for vulnerabilities.
        
        Args:
            services: List of dicts with 'name' and 'version' keys
        """
        console.print("\n[bold red]═══════════════════════════════════════════════════════════[/bold red]")
        console.print("[bold red]          SMART VULNERABILITY INTELLIGENCE SCAN             [/bold red]")
        console.print("[bold red]═══════════════════════════════════════════════════════════[/bold red]")
        
        all_cves = []
        
        for service in services:
            name = service.get('name', '')
            version = service.get('version')
            
            cves = self.scan_by_service(name, version)
            
            for cve in cves:
                self.findings.append({
                    'service': name,
                    'version': version,
                    'cve': cve.cve_id,
                    'cvss': cve.cvss,
                    'kev': cve.kev
                })
            
            all_cves.extend(cves)
        
        # Summary
        kev_count = len([c for c in all_cves if c.kev])
        critical_count = len([c for c in all_cves if c.cvss >= 9])
        high_count = len([c for c in all_cves if 7 <= c.cvss < 9])
        
        console.print("\n[bold cyan]═══ SCAN SUMMARY ═══[/bold cyan]")
        console.print(f"[red]Known Exploited (KEV): {kev_count}[/red]")
        console.print(f"[red]Critical (CVSS ≥ 9): {critical_count}[/red]")
        console.print(f"[yellow]High (CVSS ≥ 7): {high_count}[/yellow]")
        console.print(f"[white]Total CVEs: {len(all_cves)}[/white]")
        
        return {
            'total': len(all_cves),
            'kev': kev_count,
            'critical': critical_count,
            'high': high_count,
            'findings': self.findings
        }
    
    def get_exploit_priority(self) -> List[Dict]:
        """
        Get prioritized list of vulnerabilities to exploit.
        Sorted by: KEV first, then EPSS, then CVSS.
        """
        # Sort by priority
        priority_list = sorted(
            self.findings,
            key=lambda x: (x.get('kev', False), x.get('cvss', 0)),
            reverse=True
        )
        
        return priority_list[:10]  # Top 10


# Convenience functions
def lookup_cve(cve_id: str) -> Optional[CVEIntelligence]:
    """Quick CVE lookup."""
    db = ShodanCVEDB()
    return db.get_cve(cve_id)


def get_kev_list() -> List[CVEIntelligence]:
    """Get list of known exploited vulnerabilities."""
    db = ShodanCVEDB()
    return db.get_kev_cves()


def scan_product(product: str) -> List[CVEIntelligence]:
    """Scan a product for known vulnerabilities."""
    db = ShodanCVEDB()
    return db.get_cves_by_product(product)
