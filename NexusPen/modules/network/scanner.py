#!/usr/bin/env python3
"""
NexusPen - Network Infrastructure Module
=========================================
Network device discovery and vulnerability assessment.
"""

import subprocess
import re
import socket
from typing import Dict, List, Optional
from dataclasses import dataclass

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

console = Console()


@dataclass
class NetworkFinding:
    """Represents a network security finding."""
    host: str
    severity: str
    title: str
    description: str
    port: Optional[int] = None
    service: Optional[str] = None
    cve_id: Optional[str] = None


class NetworkScanner:
    """Network infrastructure scanner."""
    
    def __init__(self, target: str, config: Dict = None):
        self.target = target
        self.config = config or {}
        self.findings: List[NetworkFinding] = []
        self.hosts: List[Dict] = []
    
    def discover_hosts(self, network: str = None) -> List[Dict]:
        """
        Discover live hosts on the network.
        
        Args:
            network: Network CIDR (e.g., 192.168.1.0/24)
        """
        console.print(f"\n[cyan]🌐 Discovering hosts on {network or self.target}[/cyan]")
        
        target = network or self.target
        
        # Method 1: Nmap ping sweep
        try:
            cmd = ['nmap', '-sn', '-PE', '-PP', '--min-rate', '500', target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            # Parse hosts
            host_pattern = r'Nmap scan report for (?:(\S+) \()?(\d+\.\d+\.\d+\.\d+)'
            for match in re.finditer(host_pattern, result.stdout):
                hostname = match.group(1) or ''
                ip = match.group(2)
                self.hosts.append({
                    'ip': ip,
                    'hostname': hostname,
                    'mac': None,
                    'vendor': None
                })
            
            # Extract MAC addresses
            mac_pattern = r'MAC Address: ([0-9A-F:]+) \(([^)]+)\)'
            for match in re.finditer(mac_pattern, result.stdout):
                mac = match.group(1)
                vendor = match.group(2)
                # Associate with last host
                if self.hosts:
                    self.hosts[-1]['mac'] = mac
                    self.hosts[-1]['vendor'] = vendor
                    
        except (subprocess.TimeoutExpired, FileNotFoundError):
            # Fallback: ARP scan
            try:
                cmd = ['arp-scan', '-l']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                
                for line in result.stdout.split('\n'):
                    match = re.match(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f:]+)\s+(.+)', line)
                    if match:
                        self.hosts.append({
                            'ip': match.group(1),
                            'mac': match.group(2),
                            'vendor': match.group(3)
                        })
                        
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
        
        console.print(f"[green]✓ Found {len(self.hosts)} live hosts[/green]")
        return self.hosts
    
    def scan_network_devices(self) -> Dict:
        """Scan for network devices (routers, switches, firewalls)."""
        console.print(f"\n[cyan]🔧 Scanning network devices[/cyan]")
        
        results = {
            'routers': [],
            'switches': [],
            'firewalls': [],
            'printers': [],
            'cameras': []
        }
        
        # Common network device ports
        device_ports = {
            'router': [22, 23, 80, 443, 161, 8080],
            'switch': [22, 23, 161, 443],
            'firewall': [22, 443, 4444, 8443],
            'printer': [9100, 515, 631, 80],
            'camera': [80, 554, 8080, 443]
        }
        
        for host in self.hosts:
            ip = host['ip']
            device_type = self._identify_device_type(ip, host.get('vendor', ''))
            
            if device_type:
                results[f'{device_type}s'].append({
                    'ip': ip,
                    'vendor': host.get('vendor'),
                    'mac': host.get('mac')
                })
        
        return results
    
    def check_snmp(self, community: str = 'public') -> List[Dict]:
        """Check for SNMP with default community strings."""
        console.print(f"\n[cyan]📡 Checking SNMP[/cyan]")
        
        snmp_hosts = []
        communities = ['public', 'private', 'community', 'admin']
        
        for host in self.hosts:
            ip = host['ip']
            
            for community in communities:
                try:
                    cmd = ['snmpwalk', '-v2c', '-c', community, ip, 'system', '-t', '2']
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    
                    if result.returncode == 0 and 'SNMPv2' in result.stdout:
                        snmp_hosts.append({
                            'ip': ip,
                            'community': community,
                            'info': result.stdout[:200]
                        })
                        
                        self.findings.append(NetworkFinding(
                            host=ip,
                            severity='high' if community == 'public' else 'medium',
                            title=f'SNMP Community String: {community}',
                            description=f'SNMP accessible with community string "{community}"',
                            port=161,
                            service='snmp'
                        ))
                        break
                        
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    continue
        
        return snmp_hosts
    
    def check_telnet(self) -> List[Dict]:
        """Check for open Telnet services."""
        telnet_hosts = []
        
        for host in self.hosts:
            ip = host['ip']
            
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip, 23))
                
                if result == 0:
                    telnet_hosts.append({'ip': ip})
                    self.findings.append(NetworkFinding(
                        host=ip,
                        severity='high',
                        title='Telnet Service Enabled',
                        description='Telnet transmits credentials in plaintext',
                        port=23,
                        service='telnet'
                    ))
                
                sock.close()
            except:
                pass
        
        return telnet_hosts
    
    def check_default_credentials(self) -> List[Dict]:
        """Check for default credentials on network devices."""
        console.print(f"\n[cyan]🔑 Checking default credentials[/cyan]")
        
        default_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', ''),
            ('cisco', 'cisco'),
            ('root', 'root'),
            ('user', 'user'),
        ]
        
        found = []
        
        # Check HTTP/HTTPS management interfaces
        for host in self.hosts:
            ip = host['ip']
            
            for port in [80, 443, 8080, 8443]:
                for username, password in default_creds:
                    if self._test_http_auth(ip, port, username, password):
                        found.append({
                            'ip': ip,
                            'port': port,
                            'username': username,
                            'password': password
                        })
                        
                        self.findings.append(NetworkFinding(
                            host=ip,
                            severity='critical',
                            title='Default Credentials Found',
                            description=f'Device accepts default credentials: {username}/{password}',
                            port=port
                        ))
                        break
        
        return found
    
    def _identify_device_type(self, ip: str, vendor: str) -> Optional[str]:
        """Identify device type from vendor or fingerprint."""
        vendor = vendor.lower()
        
        router_vendors = ['cisco', 'juniper', 'mikrotik', 'ubiquiti', 'netgear', 'linksys']
        switch_vendors = ['cisco', 'hp', 'aruba', 'dell']
        firewall_vendors = ['palo alto', 'fortinet', 'sonicwall', 'watchguard']
        printer_vendors = ['hp', 'canon', 'epson', 'brother', 'xerox']
        camera_vendors = ['hikvision', 'dahua', 'axis', 'vivotek']
        
        for v in camera_vendors:
            if v in vendor:
                return 'camera'
        for v in printer_vendors:
            if v in vendor:
                return 'printer'
        for v in firewall_vendors:
            if v in vendor:
                return 'firewall'
        for v in router_vendors:
            if v in vendor:
                return 'router'
        
        return None
    
    def _test_http_auth(self, ip: str, port: int, username: str, password: str) -> bool:
        """Test HTTP basic authentication."""
        try:
            import requests
            scheme = 'https' if port in [443, 8443] else 'http'
            url = f"{scheme}://{ip}:{port}/"
            
            response = requests.get(url, auth=(username, password), 
                                  timeout=5, verify=False)
            return response.status_code in [200, 301, 302]
        except:
            return False
    
    def run_full_scan(self, network: str = None) -> Dict:
        """Run full network assessment."""
        results = {
            'hosts': [],
            'devices': {},
            'snmp': [],
            'telnet': [],
            'default_creds': [],
            'findings': []
        }
        
        results['hosts'] = self.discover_hosts(network)
        results['devices'] = self.scan_network_devices()
        results['snmp'] = self.check_snmp()
        results['telnet'] = self.check_telnet()
        results['findings'] = [f.__dict__ for f in self.findings]
        
        self._display_results(results)
        return results
    
    def _display_results(self, results: Dict):
        """Display scan results."""
        console.print("\n[bold green]╔══════════════════════════════════════════════════════════════╗[/bold green]")
        console.print("[bold green]║           NETWORK INFRASTRUCTURE SCAN RESULTS                ║[/bold green]")
        console.print("[bold green]╚══════════════════════════════════════════════════════════════╝[/bold green]\n")
        
        console.print(f"[cyan]🌐 Live Hosts:[/cyan] {len(results['hosts'])}")
        console.print(f"[cyan]📡 SNMP Accessible:[/cyan] {len(results['snmp'])}")
        console.print(f"[cyan]📟 Telnet Open:[/cyan] {len(results['telnet'])}")
        console.print(f"\n[yellow]⚠️ Findings: {len(self.findings)}[/yellow]")


class ARPScanner:
    """ARP-based network scanner."""
    
    def __init__(self, interface: str = 'eth0'):
        self.interface = interface
    
    def scan(self, network: str) -> List[Dict]:
        """Perform ARP scan."""
        try:
            from scapy.all import ARP, Ether, srp
            
            arp = ARP(pdst=network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            
            result = srp(packet, timeout=3, verbose=0, iface=self.interface)[0]
            
            hosts = []
            for sent, received in result:
                hosts.append({
                    'ip': received.psrc,
                    'mac': received.hwsrc
                })
            
            return hosts
            
        except ImportError:
            console.print("[yellow]Scapy not installed[/yellow]")
            return []


# Module entry point
def run(target: str, profile, results: list):
    """Main entry point for network module."""
    scanner = NetworkScanner(target)
    network_results = scanner.run_full_scan()
    results.append({
        'module': 'network.recon',
        'phase': 'recon',
        'findings': network_results
    })
