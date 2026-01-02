#!/usr/bin/env python3
"""
NexusPen - Service Scanner Module
=================================
Comprehensive service detection and fingerprinting.
"""

import socket
import ssl
import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


@dataclass
class ServiceInfo:
    """Service detection result."""
    port: int
    protocol: str
    service: str
    version: Optional[str] = None
    banner: Optional[str] = None
    product: Optional[str] = None
    os_hint: Optional[str] = None
    ssl: bool = False
    vulnerabilities: List[str] = None


class ServiceScanner:
    """
    Advanced service detection and fingerprinting.
    """
    
    # Service signatures for fingerprinting
    SERVICE_SIGNATURES = {
        'ssh': [
            (r'SSH-(\d+\.\d+)-OpenSSH_(\S+)', 'OpenSSH'),
            (r'SSH-(\d+\.\d+)-dropbear_(\S+)', 'Dropbear'),
            (r'SSH-(\d+\.\d+)-libssh[\-_](\S+)', 'libssh'),
            (r'SSH-(\d+\.\d+)-Cisco', 'Cisco SSH'),
        ],
        'http': [
            (r'Server:\s*Apache/([\d.]+)', 'Apache'),
            (r'Server:\s*nginx/([\d.]+)', 'nginx'),
            (r'Server:\s*Microsoft-IIS/([\d.]+)', 'IIS'),
            (r'Server:\s*lighttpd/([\d.]+)', 'lighttpd'),
            (r'Server:\s*LiteSpeed', 'LiteSpeed'),
            (r'X-Powered-By:\s*PHP/([\d.]+)', 'PHP'),
            (r'X-Powered-By:\s*ASP\.NET', 'ASP.NET'),
        ],
        'ftp': [
            (r'220.*vsftpd\s*([\d.]+)', 'vsftpd'),
            (r'220.*ProFTPD\s*([\d.]+)', 'ProFTPD'),
            (r'220.*FileZilla\s*Server\s*([\d.]+)', 'FileZilla'),
            (r'220.*Pure-FTPd', 'Pure-FTPd'),
            (r'220.*Microsoft FTP', 'Microsoft FTP'),
        ],
        'smtp': [
            (r'220.*Postfix', 'Postfix'),
            (r'220.*Exim\s*([\d.]+)', 'Exim'),
            (r'220.*Sendmail', 'Sendmail'),
            (r'220.*Microsoft ESMTP', 'Microsoft Exchange'),
        ],
        'mysql': [
            (r'([\d.]+)-MariaDB', 'MariaDB'),
            (r'([\d.]+).*MySQL', 'MySQL'),
        ],
        'postgresql': [
            (r'PostgreSQL\s*([\d.]+)', 'PostgreSQL'),
        ],
        'rdp': [
            (r'\x03\x00\x00', 'RDP'),
        ],
        'smb': [
            (r'SMBr', 'SMB'),
        ],
    }
    
    # Default port to service mapping
    PORT_SERVICES = {
        21: 'ftp',
        22: 'ssh',
        23: 'telnet',
        25: 'smtp',
        53: 'dns',
        80: 'http',
        110: 'pop3',
        111: 'rpcbind',
        135: 'msrpc',
        139: 'netbios-ssn',
        143: 'imap',
        443: 'https',
        445: 'smb',
        465: 'smtps',
        587: 'submission',
        993: 'imaps',
        995: 'pop3s',
        1433: 'mssql',
        1521: 'oracle',
        3306: 'mysql',
        3389: 'rdp',
        5432: 'postgresql',
        5900: 'vnc',
        6379: 'redis',
        8080: 'http-proxy',
        8443: 'https-alt',
        27017: 'mongodb',
    }
    
    def __init__(self, target: str, config: Dict = None):
        self.target = target
        self.config = config or {}
        self.timeout = config.get('timeout', 5)
        self.services: List[ServiceInfo] = []
    
    def scan_port(self, port: int) -> Optional[ServiceInfo]:
        """
        Scan a single port and identify the service.
        """
        service_info = ServiceInfo(
            port=port,
            protocol='tcp',
            service=self.PORT_SERVICES.get(port, 'unknown'),
            vulnerabilities=[]
        )
        
        try:
            # Connect to port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            result = sock.connect_ex((self.target, port))
            
            if result != 0:
                sock.close()
                return None
            
            # Try to get banner
            banner = self._grab_banner(sock, port)
            if banner:
                service_info.banner = banner[:500]  # Limit banner size
                
                # Fingerprint service
                detected = self._fingerprint_service(banner, port)
                if detected:
                    service_info.service = detected.get('service', service_info.service)
                    service_info.version = detected.get('version')
                    service_info.product = detected.get('product')
            
            # Check for SSL
            if port in [443, 465, 636, 993, 995, 8443]:
                service_info.ssl = True
                ssl_info = self._check_ssl(port)
                if ssl_info:
                    service_info.version = ssl_info.get('version', service_info.version)
            
            sock.close()
            return service_info
            
        except socket.timeout:
            return None
        except Exception as e:
            return None
    
    def scan_ports(self, ports: List[int], threads: int = 50) -> List[ServiceInfo]:
        """
        Scan multiple ports concurrently.
        """
        console.print(f"\n[cyan]🔍 Scanning {len(ports)} ports on {self.target}...[/cyan]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Scanning...", total=None)
            
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {executor.submit(self.scan_port, port): port for port in ports}
                
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        self.services.append(result)
            
            progress.update(task, completed=True)
        
        console.print(f"[green]✓ Found {len(self.services)} open ports[/green]")
        return self.services
    
    def _grab_banner(self, sock: socket.socket, port: int) -> Optional[str]:
        """Grab service banner."""
        try:
            # Some services need a probe
            probes = {
                80: b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
                443: b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
                8080: b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
                25: b"EHLO test\r\n",
                110: b"",
                143: b"",
                21: b"",
                22: b"",
            }
            
            probe = probes.get(port, b"")
            
            if probe:
                sock.send(probe)
            
            sock.settimeout(3)
            banner = sock.recv(4096)
            
            # Try to decode
            try:
                return banner.decode('utf-8', errors='ignore').strip()
            except:
                return banner.decode('latin-1', errors='ignore').strip()
                
        except:
            return None
    
    def _fingerprint_service(self, banner: str, port: int) -> Optional[Dict]:
        """Fingerprint service from banner."""
        result = {}
        
        # Check all service signatures
        for service, patterns in self.SERVICE_SIGNATURES.items():
            for pattern, product in patterns:
                match = re.search(pattern, banner, re.IGNORECASE)
                if match:
                    result['service'] = service
                    result['product'] = product
                    if match.groups():
                        result['version'] = match.group(1) if len(match.groups()) >= 1 else None
                    return result
        
        # Fallback detection based on keywords
        keywords = {
            'SSH-': 'ssh',
            'HTTP/': 'http',
            '220 ': 'ftp',
            '250 ': 'smtp',
            'MySQL': 'mysql',
            'PostgreSQL': 'postgresql',
            'Redis': 'redis',
            'MongoDB': 'mongodb',
            '+OK': 'pop3',
            '* OK': 'imap',
        }
        
        for keyword, service in keywords.items():
            if keyword in banner:
                result['service'] = service
                return result
        
        return None
    
    def _check_ssl(self, port: int) -> Optional[Dict]:
        """Check SSL/TLS configuration."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.target, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    return {
                        'version': version,
                        'cipher': cipher[0] if cipher else None,
                        'has_cert': bool(cert)
                    }
                    
        except Exception as e:
            return None
    
    def display_results(self):
        """Display scan results."""
        if not self.services:
            console.print("[yellow]No open ports found[/yellow]")
            return
        
        table = Table(title=f"Services on {self.target}", show_header=True,
                     header_style="bold magenta")
        table.add_column("Port", style="cyan", width=6)
        table.add_column("Service", style="yellow", width=12)
        table.add_column("Product", style="green", width=15)
        table.add_column("Version", style="white", width=12)
        table.add_column("SSL", width=4)
        
        for svc in sorted(self.services, key=lambda x: x.port):
            table.add_row(
                str(svc.port),
                svc.service,
                svc.product or "-",
                svc.version or "-",
                "✓" if svc.ssl else "-"
            )
        
        console.print(table)


class BannerGrabber:
    """
    Multi-protocol banner grabbing utility.
    """
    
    def __init__(self, target: str, timeout: int = 5):
        self.target = target
        self.timeout = timeout
    
    def grab(self, port: int, protocol: str = 'tcp') -> Optional[str]:
        """Grab banner from a specific port."""
        try:
            if protocol == 'tcp':
                return self._grab_tcp(port)
            elif protocol == 'udp':
                return self._grab_udp(port)
        except:
            return None
    
    def _grab_tcp(self, port: int) -> Optional[str]:
        """Grab TCP banner."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        
        try:
            sock.connect((self.target, port))
            
            # Send probe based on port
            if port in [80, 443, 8080, 8443]:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port == 25:
                sock.send(b"EHLO test\r\n")
            elif port == 21:
                pass  # FTP sends banner immediately
            
            banner = sock.recv(4096)
            sock.close()
            
            return banner.decode('utf-8', errors='ignore')
            
        except Exception as e:
            return None
        finally:
            sock.close()
    
    def _grab_udp(self, port: int) -> Optional[str]:
        """Grab UDP banner."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        
        try:
            # UDP probes
            probes = {
                53: b"\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00",  # DNS
                161: b"\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63",  # SNMP
                123: b"\x1b" + b"\x00" * 47,  # NTP
            }
            
            probe = probes.get(port, b"\x00")
            sock.sendto(probe, (self.target, port))
            
            data, addr = sock.recvfrom(4096)
            return data.decode('utf-8', errors='ignore')
            
        except:
            return None
        finally:
            sock.close()
    
    def grab_all(self, ports: List[int]) -> Dict[int, str]:
        """Grab banners from multiple ports."""
        console.print(f"\n[cyan]📡 Grabbing banners from {len(ports)} ports...[/cyan]")
        
        banners = {}
        
        for port in ports:
            banner = self.grab(port)
            if banner:
                banners[port] = banner
                console.print(f"[green]Port {port}:[/green] {banner[:50]}...")
        
        return banners
