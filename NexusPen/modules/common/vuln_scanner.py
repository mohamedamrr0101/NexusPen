#!/usr/bin/env python3
"""
NexusPen - Vulnerability Database Module
=========================================
CVE lookup and vulnerability database integration.
"""

import subprocess
import re
import json
from typing import Dict, List, Optional
from dataclasses import dataclass

from rich.console import Console
from rich.table import Table

console = Console()


@dataclass
class CVEInfo:
    """CVE information."""
    cve_id: str
    description: str
    severity: str
    cvss_score: float
    affected_products: List[str]
    references: List[str]
    exploits_available: bool = False
    exploit_db_id: Optional[str] = None


class VulnDatabase:
    """
    Vulnerability database lookup.
    Integrates with searchsploit and online databases.
    """
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
    
    def search_exploits(self, query: str, exact: bool = False) -> List[Dict]:
        """
        Search for exploits using searchsploit.
        
        Args:
            query: Search query (e.g., "Apache 2.4.49")
            exact: Exact match only
        """
        console.print(f"\n[cyan]🔍 Searching exploits for: {query}[/cyan]")
        
        exploits = []
        
        try:
            cmd = ['searchsploit', '--json']
            
            if exact:
                cmd.append('-e')
            
            cmd.append(query)
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                data = json.loads(result.stdout)
                
                for exploit in data.get('RESULTS_EXPLOIT', []):
                    exploits.append({
                        'title': exploit.get('Title', ''),
                        'edb_id': exploit.get('EDB-ID', ''),
                        'path': exploit.get('Path', ''),
                        'type': exploit.get('Type', ''),
                        'platform': exploit.get('Platform', ''),
                        'date': exploit.get('Date', ''),
                    })
                
                console.print(f"[green]✓ Found {len(exploits)} exploits[/green]")
                
        except json.JSONDecodeError:
            # Fallback to text parsing
            result = subprocess.run(
                ['searchsploit', query],
                capture_output=True, text=True, timeout=60
            )
            
            for line in result.stdout.split('\n'):
                if '/' in line and '|' in line:
                    parts = line.split('|')
                    if len(parts) >= 2:
                        exploits.append({
                            'title': parts[0].strip(),
                            'path': parts[1].strip()
                        })
                        
        except FileNotFoundError:
            console.print("[yellow]searchsploit not found[/yellow]")
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        
        return exploits
    
    def get_exploit_code(self, edb_id: str) -> Optional[str]:
        """Get exploit code from ExploitDB."""
        try:
            cmd = ['searchsploit', '-m', edb_id]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                console.print(f"[green]✓ Exploit {edb_id} copied to current directory[/green]")
                return result.stdout
                
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        
        return None
    
    def search_cve(self, cve_id: str) -> Optional[CVEInfo]:
        """
        Search for CVE information.
        Uses nmap scripts or online lookup.
        """
        console.print(f"\n[cyan]🔍 Looking up {cve_id}...[/cyan]")
        
        # Try to get info from searchsploit
        exploits = self.search_exploits(cve_id)
        
        cve_info = CVEInfo(
            cve_id=cve_id,
            description="",
            severity="Unknown",
            cvss_score=0.0,
            affected_products=[],
            references=[],
            exploits_available=len(exploits) > 0
        )
        
        if exploits:
            cve_info.exploit_db_id = exploits[0].get('edb_id')
            cve_info.description = exploits[0].get('title', '')
        
        return cve_info
    
    def check_service_vulns(self, service: str, version: str) -> List[Dict]:
        """
        Check for vulnerabilities in a specific service version.
        
        Args:
            service: Service name (e.g., "Apache", "OpenSSH")
            version: Version string (e.g., "2.4.49", "8.2p1")
        """
        console.print(f"\n[cyan]🔍 Checking vulns for {service} {version}...[/cyan]")
        
        query = f"{service} {version}"
        return self.search_exploits(query)
    
    def display_exploits(self, exploits: List[Dict]):
        """Display exploits in a table."""
        if not exploits:
            console.print("[yellow]No exploits found[/yellow]")
            return
        
        table = Table(title="Available Exploits", show_header=True,
                     header_style="bold red")
        table.add_column("EDB-ID", style="cyan", width=8)
        table.add_column("Title", style="yellow", width=50)
        table.add_column("Type", style="white", width=10)
        table.add_column("Platform", style="green", width=10)
        
        for exp in exploits[:20]:  # Limit to 20
            table.add_row(
                exp.get('edb_id', '-'),
                exp.get('title', '')[:50],
                exp.get('type', '-'),
                exp.get('platform', '-')
            )
        
        console.print(table)


class NmapVulnScanner:
    """
    Nmap vulnerability scanning integration.
    """
    
    def __init__(self, target: str):
        self.target = target
    
    def run_vuln_scan(self, ports: str = None) -> Dict:
        """
        Run Nmap vulnerability scripts.
        
        Args:
            ports: Ports to scan (e.g., "22,80,443")
        """
        console.print(f"\n[cyan]🔍 Running Nmap vuln scan on {self.target}...[/cyan]")
        
        results = {
            'target': self.target,
            'vulnerabilities': []
        }
        
        cmd = [
            'nmap',
            '--script', 'vuln',
            '-sV',
            self.target
        ]
        
        if ports:
            cmd.extend(['-p', ports])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            # Parse vulnerabilities from output
            vuln_patterns = [
                r'(CVE-\d{4}-\d+)',
                r'(MS\d{2}-\d{3})',
                r'VULNERABLE:',
            ]
            
            for line in result.stdout.split('\n'):
                for pattern in vuln_patterns:
                    match = re.search(pattern, line)
                    if match or 'VULNERABLE' in line.upper():
                        results['vulnerabilities'].append(line.strip())
            
            console.print(f"[green]✓ Scan complete. Found {len(results['vulnerabilities'])} potential vulnerabilities[/green]")
            
        except subprocess.TimeoutExpired:
            console.print("[yellow]Scan timed out[/yellow]")
        except FileNotFoundError:
            console.print("[red]nmap not found[/red]")
        
        return results
    
    def run_specific_scripts(self, scripts: List[str], ports: str = None) -> Dict:
        """
        Run specific Nmap scripts.
        
        Args:
            scripts: List of script names (e.g., ["smb-vuln-ms17-010", "http-vuln-cve2017-5638"])
            ports: Ports to scan
        """
        console.print(f"\n[cyan]🔍 Running Nmap scripts: {', '.join(scripts)}[/cyan]")
        
        results = {'scripts': {}}
        
        for script in scripts:
            cmd = [
                'nmap',
                '--script', script,
                self.target
            ]
            
            if ports:
                cmd.extend(['-p', ports])
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                
                if 'VULNERABLE' in result.stdout.upper():
                    results['scripts'][script] = {
                        'vulnerable': True,
                        'output': result.stdout
                    }
                    console.print(f"[red]⚠️ {script}: VULNERABLE[/red]")
                else:
                    results['scripts'][script] = {'vulnerable': False}
                    console.print(f"[green]✓ {script}: Not vulnerable[/green]")
                    
            except Exception as e:
                results['scripts'][script] = {'error': str(e)}
        
        return results


class NucleiScanner:
    """
    Nuclei vulnerability scanner integration.
    """
    
    def __init__(self, target: str, config: Dict = None):
        self.target = target
        self.config = config or {}
    
    def scan(self, templates: str = None, severity: str = None,
            tags: str = None) -> List[Dict]:
        """
        Run Nuclei scan.
        
        Args:
            templates: Specific templates to use
            severity: Filter by severity (critical,high,medium,low)
            tags: Filter by tags (e.g., "cve,rce")
        """
        console.print(f"\n[cyan]🔍 Running Nuclei scan on {self.target}...[/cyan]")
        
        findings = []
        
        cmd = [
            'nuclei',
            '-u', self.target,
            '-json',
            '-silent'
        ]
        
        if templates:
            cmd.extend(['-t', templates])
        if severity:
            cmd.extend(['-severity', severity])
        if tags:
            cmd.extend(['-tags', tags])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            for line in result.stdout.split('\n'):
                if line.strip():
                    try:
                        finding = json.loads(line)
                        findings.append({
                            'template': finding.get('template-id'),
                            'name': finding.get('info', {}).get('name'),
                            'severity': finding.get('info', {}).get('severity'),
                            'matched': finding.get('matched-at'),
                            'description': finding.get('info', {}).get('description', '')
                        })
                    except json.JSONDecodeError:
                        continue
            
            # Display results
            critical = len([f for f in findings if f.get('severity') == 'critical'])
            high = len([f for f in findings if f.get('severity') == 'high'])
            
            console.print(f"[green]✓ Found {len(findings)} vulnerabilities ({critical} critical, {high} high)[/green]")
            
        except FileNotFoundError:
            console.print("[red]nuclei not found[/red]")
        except subprocess.TimeoutExpired:
            console.print("[yellow]Scan timed out[/yellow]")
        
        return findings
    
    def scan_cves(self) -> List[Dict]:
        """Scan for known CVEs."""
        return self.scan(tags='cve')
    
    def scan_critical(self) -> List[Dict]:
        """Scan for critical vulnerabilities only."""
        return self.scan(severity='critical,high')
