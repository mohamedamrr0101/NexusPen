#!/usr/bin/env python3
"""
NexusPen - Common Port Scanner Module
=====================================
Shared port scanning functionality for all platforms.
"""

import subprocess
import re
import socket
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table

console = Console()


@dataclass
class PortScanResult:
    """Result of a port scan."""
    port: int
    protocol: str
    state: str
    service: str
    version: str
    banner: str


class PortScanner:
    """
    Advanced port scanner with multiple scanning techniques.
    Integrates with Nmap, Masscan, and provides fallback Python scanning.
    """
    
    # Common port groupings
    QUICK_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 
                   443, 445, 993, 995, 1433, 3306, 3389, 5432, 8080]
    
    TOP_100 = "7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,8888,9100,9999-10000,32768,49152-49157"
    
    def __init__(self, target: str, config: Dict = None):
        self.target = target
        self.config = config or {}
        self.nmap_path = config.get('nmap_path', '/usr/bin/nmap')
        self.masscan_path = config.get('masscan_path', '/usr/bin/masscan')
    
    def scan(self, ports: str = None, technique: str = 'nmap', 
             timing: str = 'T3', service_detection: bool = True) -> Tuple[List[int], Dict]:
        """
        Perform port scan.
        
        Args:
            ports: Port specification (e.g., "22,80,443" or "1-1000")
            technique: Scan technique ('nmap', 'masscan', 'socket')
            timing: Nmap timing template (T0-T5)
            service_detection: Enable service/version detection
            
        Returns:
            Tuple of (open_ports, services_dict)
        """
        if technique == 'nmap':
            return self._nmap_scan(ports, timing, service_detection)
        elif technique == 'masscan':
            return self._masscan_scan(ports)
        else:
            return self._socket_scan(ports)
    
    def quick_scan(self) -> Tuple[List[int], Dict]:
        """Quick scan of most common ports."""
        return self.scan(ports=','.join(map(str, self.QUICK_PORTS)), timing='T4')
    
    def full_scan(self) -> Tuple[List[int], Dict]:
        """Full scan of all 65535 ports."""
        return self.scan(ports='1-65535', technique='masscan')
    
    def _nmap_scan(self, ports: str = None, timing: str = 'T3', 
                   service_detection: bool = True) -> Tuple[List[int], Dict]:
        """Perform Nmap scan."""
        console.print(f"[cyan]🔍 Running Nmap scan on {self.target}...[/cyan]")
        
        cmd = [self.nmap_path, '-sS', f'-{timing}', '--open', '-oX', '-']
        
        if service_detection:
            cmd.append('-sV')
        
        if ports:
            cmd.extend(['-p', ports])
        else:
            cmd.append('--top-ports=1000')
        
        cmd.append(self.target)
        
        if self.config.get('verbosity', 0) > 0:
            console.print(f"[grey50]$ {' '.join(cmd)}[/grey50]")
            
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            if result.returncode == 0:
                return self._parse_nmap_xml(result.stdout)
                
        except subprocess.TimeoutExpired:
            console.print("[yellow]⚠️ Nmap scan timed out[/yellow]")
        except FileNotFoundError:
            console.print("[yellow]⚠️ Nmap not found, using socket scan[/yellow]")
            return self._socket_scan(ports)
        
        return [], {}
    
    def _masscan_scan(self, ports: str = None) -> Tuple[List[int], Dict]:
        """Perform Masscan for fast port discovery."""
        console.print(f"[cyan]🚀 Running Masscan on {self.target}...[/cyan]")
        
        port_spec = ports or '1-65535'
        
        cmd = [
            self.masscan_path,
            self.target,
            '-p', port_spec,
            '--rate=1000',
            '-oJ', '-'
        ]
        
        if self.config.get('verbosity', 0) > 0:
            console.print(f"[grey50]$ {' '.join(cmd)}[/grey50]")
            
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            open_ports = []
            for line in result.stdout.split('\n'):
                if '"port":' in line:
                    port_match = re.search(r'"port":\s*(\d+)', line)
                    if port_match:
                        open_ports.append(int(port_match.group(1)))
            
            # Run Nmap for service detection on discovered ports
            if open_ports:
                console.print(f"[cyan]Detecting services on {len(open_ports)} ports...[/cyan]")
                port_list = ','.join(map(str, sorted(open_ports)[:100]))  # Limit to 100
                return self._nmap_scan(ports=port_list, timing='T4', service_detection=True)
            
            return open_ports, {}
            
        except subprocess.TimeoutExpired:
            console.print("[yellow]⚠️ Masscan timed out[/yellow]")
        except FileNotFoundError:
            console.print("[yellow]⚠️ Masscan not found[/yellow]")
        
        return [], {}
    
    def _socket_scan(self, ports: str = None) -> Tuple[List[int], Dict]:
        """Fallback socket-based port scan."""
        console.print(f"[cyan]🔌 Running socket scan on {self.target}...[/cyan]")
        
        # Parse ports
        if ports:
            port_list = self._parse_ports(ports)
        else:
            port_list = self.QUICK_PORTS
        
        open_ports = []
        services = {}
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            console=console
        ) as progress:
            task = progress.add_task("Scanning ports...", total=len(port_list))
            
            for port in port_list:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((self.target, port))
                    
                    if result == 0:
                        open_ports.append(port)
                        
                        # Try banner grab
                        banner = self._grab_banner(port)
                        services[port] = {
                            'name': self._guess_service(port),
                            'product': banner,
                            'version': '',
                            'protocol': 'tcp'
                        }
                    
                    sock.close()
                except socket.error:
                    pass
                
                progress.update(task, advance=1)
        
        return open_ports, services
    
    def _parse_nmap_xml(self, xml_output: str) -> Tuple[List[int], Dict]:
        """Parse Nmap XML output."""
        import xml.etree.ElementTree as ET
        
        ports = []
        services = {}
        
        try:
            root = ET.fromstring(xml_output)
            
            for port in root.findall('.//port'):
                portid = int(port.get('portid'))
                protocol = port.get('protocol')
                
                state = port.find('state')
                if state is not None and state.get('state') == 'open':
                    ports.append(portid)
                    
                    service = port.find('service')
                    if service is not None:
                        services[portid] = {
                            'name': service.get('name', 'unknown'),
                            'product': service.get('product', ''),
                            'version': service.get('version', ''),
                            'extrainfo': service.get('extrainfo', ''),
                            'protocol': protocol
                        }
                    else:
                        services[portid] = {
                            'name': self._guess_service(portid),
                            'product': '',
                            'version': '',
                            'protocol': protocol
                        }
                        
        except ET.ParseError:
            pass
        
        return ports, services
    
    def _parse_ports(self, port_spec: str) -> List[int]:
        """Parse port specification string."""
        ports = set()
        
        for part in port_spec.split(','):
            part = part.strip()
            if '-' in part:
                try:
                    start, end = part.split('-')
                    ports.update(range(int(start), int(end) + 1))
                except ValueError:
                    continue
            else:
                try:
                    ports.add(int(part))
                except ValueError:
                    continue
        
        return sorted([p for p in ports if 1 <= p <= 65535])
    
    def _grab_banner(self, port: int) -> str:
        """Attempt to grab service banner."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((self.target, port))
            
            # Send probe based on port
            if port in [80, 8080, 8000, 8888]:
                sock.send(b"HEAD / HTTP/1.1\r\nHost: " + 
                         self.target.encode() + b"\r\n\r\n")
            else:
                sock.send(b"\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner[:200]
        except:
            return ""
    
    def _guess_service(self, port: int) -> str:
        """Guess service name from port number."""
        common_ports = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
            80: 'http', 110: 'pop3', 111: 'rpcbind', 135: 'msrpc',
            139: 'netbios-ssn', 143: 'imap', 443: 'https', 445: 'microsoft-ds',
            993: 'imaps', 995: 'pop3s', 1433: 'mssql', 1521: 'oracle',
            3306: 'mysql', 3389: 'rdp', 5432: 'postgresql', 5900: 'vnc',
            5985: 'winrm', 6379: 'redis', 8080: 'http-proxy', 27017: 'mongodb'
        }
        return common_ports.get(port, 'unknown')
    
    def display_results(self, ports: List[int], services: Dict):
        """Display scan results in a table."""
        if not ports:
            console.print("[yellow]No open ports found.[/yellow]")
            return
        
        table = Table(title=f"Open Ports on {self.target}", show_header=True, 
                     header_style="bold magenta")
        table.add_column("Port", style="cyan", width=8)
        table.add_column("State", style="green", width=8)
        table.add_column("Service", style="yellow", width=15)
        table.add_column("Version", style="white")
        
        for port in sorted(ports):
            service = services.get(port, {})
            table.add_row(
                str(port),
                "open",
                service.get('name', 'unknown'),
                f"{service.get('product', '')} {service.get('version', '')}".strip()
            )
        
        console.print(table)
        console.print(f"\n[green]Total: {len(ports)} open ports[/green]")
