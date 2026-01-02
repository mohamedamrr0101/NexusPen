#!/usr/bin/env python3
"""
NexusPen - Network Utilities Module
====================================
Network tools and utilities.
"""

import socket
import subprocess
import struct
import ipaddress
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

console = Console()


@dataclass
class HostInfo:
    """Host information."""
    ip: str
    hostname: Optional[str] = None
    mac: Optional[str] = None
    vendor: Optional[str] = None
    os: Optional[str] = None
    is_alive: bool = False


class NetworkScanner:
    """
    Network discovery and scanning utilities.
    """
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.timeout = config.get('timeout', 2)
    
    def ping_sweep(self, network: str, threads: int = 100) -> List[HostInfo]:
        """
        Ping sweep a network to find live hosts.
        
        Args:
            network: Network in CIDR notation (e.g., 192.168.1.0/24)
            threads: Number of concurrent threads
        """
        console.print(f"\n[cyan]🔍 Ping sweeping {network}...[/cyan]")
        
        live_hosts = []
        
        try:
            net = ipaddress.ip_network(network, strict=False)
        except ValueError as e:
            console.print(f"[red]Invalid network: {e}[/red]")
            return []
        
        hosts = list(net.hosts())
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task(f"Scanning {len(hosts)} hosts...", total=None)
            
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {executor.submit(self._ping_host, str(ip)): ip 
                          for ip in hosts}
                
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        live_hosts.append(result)
            
            progress.update(task, completed=True)
        
        console.print(f"[green]✓ Found {len(live_hosts)} live hosts[/green]")
        return live_hosts
    
    def _ping_host(self, ip: str) -> Optional[HostInfo]:
        """Ping a single host."""
        try:
            # Use subprocess for cross-platform compatibility
            param = '-n' if subprocess.sys.platform == 'win32' else '-c'
            cmd = ['ping', param, '1', '-W', '1', ip]
            
            result = subprocess.run(cmd, capture_output=True, timeout=3)
            
            if result.returncode == 0:
                return HostInfo(ip=ip, is_alive=True)
                
        except:
            pass
        
        return None
    
    def arp_scan(self, interface: str = None) -> List[HostInfo]:
        """
        ARP scan local network.
        
        Args:
            interface: Network interface to use
        """
        console.print(f"\n[cyan]🔍 Running ARP scan...[/cyan]")
        
        hosts = []
        
        cmd = ['arp-scan', '-l']
        if interface:
            cmd.extend(['-I', interface])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            import re
            pattern = r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f:]+)\s+(.+)'
            
            for match in re.finditer(pattern, result.stdout, re.IGNORECASE):
                hosts.append(HostInfo(
                    ip=match.group(1),
                    mac=match.group(2),
                    vendor=match.group(3).strip(),
                    is_alive=True
                ))
            
            console.print(f"[green]✓ Found {len(hosts)} hosts[/green]")
            
        except FileNotFoundError:
            console.print("[yellow]arp-scan not found, trying with scapy...[/yellow]")
            hosts = self._arp_scan_scapy()
        except subprocess.TimeoutExpired:
            console.print("[yellow]ARP scan timed out[/yellow]")
        
        return hosts
    
    def _arp_scan_scapy(self) -> List[HostInfo]:
        """ARP scan using Scapy."""
        try:
            from scapy.all import ARP, Ether, srp
            
            # Get local network
            import netifaces
            gateways = netifaces.gateways()
            default_gw = gateways['default'][netifaces.AF_INET]
            iface = default_gw[1]
            
            addrs = netifaces.ifaddresses(iface)
            ip_info = addrs[netifaces.AF_INET][0]
            network = f"{ip_info['addr']}/24"
            
            arp = ARP(pdst=network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            
            result = srp(packet, timeout=3, verbose=0)[0]
            
            hosts = []
            for sent, received in result:
                hosts.append(HostInfo(
                    ip=received.psrc,
                    mac=received.hwsrc,
                    is_alive=True
                ))
            
            return hosts
            
        except ImportError:
            console.print("[red]scapy not installed[/red]")
            return []
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            return []
    
    def resolve_hostname(self, ip: str) -> Optional[str]:
        """Resolve IP to hostname."""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return None
    
    def resolve_ip(self, hostname: str) -> Optional[str]:
        """Resolve hostname to IP."""
        try:
            ip = socket.gethostbyname(hostname)
            return ip
        except:
            return None
    
    def display_hosts(self, hosts: List[HostInfo]):
        """Display discovered hosts."""
        if not hosts:
            return
        
        table = Table(title="Discovered Hosts", show_header=True,
                     header_style="bold magenta")
        table.add_column("IP", style="cyan")
        table.add_column("MAC", style="yellow")
        table.add_column("Vendor", style="green")
        table.add_column("Hostname", style="white")
        
        for host in hosts:
            table.add_row(
                host.ip,
                host.mac or "-",
                host.vendor or "-",
                host.hostname or "-"
            )
        
        console.print(table)


class DNSTools:
    """
    DNS enumeration and utilities.
    """
    
    def __init__(self, target: str):
        self.target = target
    
    def query_record(self, record_type: str) -> List[str]:
        """Query DNS record."""
        try:
            import dns.resolver
            
            answers = dns.resolver.resolve(self.target, record_type)
            return [str(rdata) for rdata in answers]
            
        except ImportError:
            # Fallback to dig
            result = subprocess.run(
                ['dig', '+short', record_type, self.target],
                capture_output=True, text=True
            )
            return result.stdout.strip().split('\n')
        except:
            return []
    
    def enumerate_subdomains(self, wordlist: str = None) -> List[str]:
        """Enumerate subdomains."""
        console.print(f"\n[cyan]🔍 Enumerating subdomains for {self.target}...[/cyan]")
        
        subdomains = []
        
        # Try subfinder first
        try:
            result = subprocess.run(
                ['subfinder', '-d', self.target, '-silent'],
                capture_output=True, text=True, timeout=120
            )
            subdomains.extend(result.stdout.strip().split('\n'))
        except:
            pass
        
        # Try amass
        try:
            result = subprocess.run(
                ['amass', 'enum', '-passive', '-d', self.target],
                capture_output=True, text=True, timeout=300
            )
            subdomains.extend(result.stdout.strip().split('\n'))
        except:
            pass
        
        # Manual bruteforce if wordlist provided
        if wordlist:
            subdomains.extend(self._bruteforce_subdomains(wordlist))
        
        # Deduplicate
        subdomains = list(set(s for s in subdomains if s))
        
        console.print(f"[green]✓ Found {len(subdomains)} subdomains[/green]")
        return subdomains
    
    def _bruteforce_subdomains(self, wordlist: str) -> List[str]:
        """Bruteforce subdomains using wordlist."""
        found = []
        
        try:
            with open(wordlist, 'r') as f:
                for line in f:
                    subdomain = line.strip()
                    if subdomain:
                        fqdn = f"{subdomain}.{self.target}"
                        try:
                            socket.gethostbyname(fqdn)
                            found.append(fqdn)
                        except:
                            pass
        except FileNotFoundError:
            console.print(f"[red]Wordlist not found: {wordlist}[/red]")
        
        return found
    
    def zone_transfer(self, nameserver: str = None) -> List[str]:
        """Attempt DNS zone transfer."""
        console.print(f"\n[cyan]🔍 Attempting zone transfer for {self.target}...[/cyan]")
        
        records = []
        
        # Get nameservers if not provided
        nameservers = [nameserver] if nameserver else self.query_record('NS')
        
        for ns in nameservers:
            ns = ns.rstrip('.')
            try:
                result = subprocess.run(
                    ['dig', '@' + ns, self.target, 'AXFR'],
                    capture_output=True, text=True, timeout=30
                )
                
                if 'Transfer failed' not in result.stdout:
                    console.print(f"[green]✓ Zone transfer successful from {ns}![/green]")
                    records.extend(result.stdout.split('\n'))
                else:
                    console.print(f"[yellow]Zone transfer denied by {ns}[/yellow]")
                    
            except:
                continue
        
        return records
    
    def get_all_records(self) -> Dict[str, List[str]]:
        """Get all common DNS records."""
        console.print(f"\n[cyan]📋 Getting DNS records for {self.target}...[/cyan]")
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        records = {}
        
        for rtype in record_types:
            result = self.query_record(rtype)
            if result and result[0]:
                records[rtype] = result
                console.print(f"[green]{rtype}:[/green] {', '.join(result[:3])}")
        
        return records


class ProxyHandler:
    """
    Proxy configuration and tunneling.
    """
    
    def __init__(self):
        self.proxies = {}
    
    def set_socks(self, host: str, port: int, version: int = 5):
        """Configure SOCKS proxy."""
        self.proxies = {
            'http': f'socks{version}://{host}:{port}',
            'https': f'socks{version}://{host}:{port}'
        }
        console.print(f"[green]✓ SOCKS{version} proxy set: {host}:{port}[/green]")
    
    def set_http(self, host: str, port: int):
        """Configure HTTP proxy."""
        self.proxies = {
            'http': f'http://{host}:{port}',
            'https': f'http://{host}:{port}'
        }
        console.print(f"[green]✓ HTTP proxy set: {host}:{port}[/green]")
    
    def get_proxies(self) -> Dict:
        """Get proxy configuration for requests."""
        return self.proxies
    
    def setup_proxychains(self, proxy_list: List[Tuple[str, str, int]]):
        """Generate proxychains configuration."""
        config = """# proxychains.conf
strict_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
"""
        for proto, host, port in proxy_list:
            config += f"{proto} {host} {port}\n"
        
        with open('/tmp/proxychains.conf', 'w') as f:
            f.write(config)
        
        console.print("[green]✓ Proxychains config written to /tmp/proxychains.conf[/green]")
        console.print("[yellow]Usage: proxychains -f /tmp/proxychains.conf <command>[/yellow]")
    
    def start_ssh_tunnel(self, ssh_host: str, ssh_user: str, 
                        local_port: int, remote_host: str, remote_port: int) -> str:
        """Generate SSH tunnel command."""
        cmd = f"ssh -L {local_port}:{remote_host}:{remote_port} {ssh_user}@{ssh_host} -N"
        console.print(f"[yellow]Run: {cmd}[/yellow]")
        return cmd
    
    def start_dynamic_tunnel(self, ssh_host: str, ssh_user: str,
                            local_port: int = 1080) -> str:
        """Generate SSH dynamic tunnel (SOCKS proxy) command."""
        cmd = f"ssh -D {local_port} {ssh_user}@{ssh_host} -N"
        console.print(f"[yellow]Run: {cmd}[/yellow]")
        console.print(f"[yellow]Then configure SOCKS proxy: 127.0.0.1:{local_port}[/yellow]")
        return cmd


class ConnectionCheck:
    """
    Check connectivity to targets.
    """
    
    @staticmethod
    def check_tcp(host: str, port: int, timeout: int = 3) -> bool:
        """Check TCP connectivity."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False
    
    @staticmethod
    def check_udp(host: str, port: int, timeout: int = 3) -> bool:
        """Check UDP connectivity (best effort)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(b'', (host, port))
            return True
        except:
            return False
    
    @staticmethod
    def check_icmp(host: str) -> bool:
        """Check ICMP connectivity."""
        try:
            param = '-n' if subprocess.sys.platform == 'win32' else '-c'
            result = subprocess.run(
                ['ping', param, '1', '-W', '1', host],
                capture_output=True, timeout=5
            )
            return result.returncode == 0
        except:
            return False
    
    @staticmethod
    def traceroute(host: str) -> List[str]:
        """Run traceroute."""
        hops = []
        
        try:
            cmd = 'tracert' if subprocess.sys.platform == 'win32' else 'traceroute'
            result = subprocess.run(
                [cmd, host],
                capture_output=True, text=True, timeout=60
            )
            
            import re
            for line in result.stdout.split('\n'):
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    hops.append(ip_match.group(1))
                    
        except:
            pass
        
        return hops
