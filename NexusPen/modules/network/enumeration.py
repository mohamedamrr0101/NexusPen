#!/usr/bin/env python3
"""
NexusPen - Network Enumeration Module
======================================
Comprehensive network device and service enumeration.
"""

import subprocess
import socket
import struct
from typing import Dict, List, Optional
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor

from rich.console import Console
from rich.table import Table

console = Console()


@dataclass
class NetworkDevice:
    """Network device information."""
    ip: str
    mac: str
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    os_guess: Optional[str] = None
    open_ports: List[int] = None


@dataclass 
class ServiceInfo:
    """Service information."""
    port: int
    protocol: str
    service: str
    version: Optional[str] = None
    banner: Optional[str] = None


class NetworkEnumerator:
    """
    Network enumeration utilities.
    """
    
    def __init__(self, interface: str = None):
        self.interface = interface
    
    def get_local_ip(self) -> str:
        """Get local IP address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def get_subnet(self) -> str:
        """Get local subnet."""
        local_ip = self.get_local_ip()
        parts = local_ip.split('.')
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    
    def arp_scan(self, subnet: str = None) -> List[NetworkDevice]:
        """Perform ARP scan to discover hosts."""
        console.print("\n[cyan]🔍 Running ARP scan...[/cyan]")
        
        subnet = subnet or self.get_subnet()
        devices = []
        
        # Try arp-scan first
        cmd = ['arp-scan', '-l']
        if self.interface:
            cmd.extend(['-I', self.interface])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            for line in result.stdout.split('\n'):
                parts = line.split()
                if len(parts) >= 3 and '.' in parts[0]:
                    devices.append(NetworkDevice(
                        ip=parts[0],
                        mac=parts[1],
                        vendor=' '.join(parts[2:]) if len(parts) > 2 else None
                    ))
            
            console.print(f"[green]✓ Found {len(devices)} devices[/green]")
            
        except FileNotFoundError:
            console.print("[yellow]arp-scan not found, trying nmap...[/yellow]")
            return self.nmap_host_discovery(subnet)
        
        return devices
    
    def nmap_host_discovery(self, subnet: str = None) -> List[NetworkDevice]:
        """Use Nmap for host discovery."""
        console.print("\n[cyan]🔍 Running Nmap host discovery...[/cyan]")
        
        subnet = subnet or self.get_subnet()
        devices = []
        
        try:
            result = subprocess.run(
                ['nmap', '-sn', '-PR', subnet],
                capture_output=True, text=True, timeout=120
            )
            
            current_ip = None
            current_mac = None
            
            for line in result.stdout.split('\n'):
                if 'Nmap scan report for' in line:
                    parts = line.split()
                    current_ip = parts[-1].strip('()')
                elif 'MAC Address:' in line:
                    parts = line.split()
                    current_mac = parts[2]
                    vendor = ' '.join(parts[3:]).strip('()')
                    
                    if current_ip:
                        devices.append(NetworkDevice(
                            ip=current_ip,
                            mac=current_mac,
                            vendor=vendor
                        ))
            
            console.print(f"[green]✓ Found {len(devices)} devices[/green]")
            
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        
        return devices
    
    def ping_sweep(self, subnet: str = None) -> List[str]:
        """Perform ICMP ping sweep."""
        console.print("\n[cyan]🔍 Running ping sweep...[/cyan]")
        
        subnet = subnet or self.get_subnet()
        alive_hosts = []
        
        # Extract base IP
        base = '.'.join(subnet.split('.')[:3])
        
        def ping_host(ip):
            try:
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', '1', ip],
                    capture_output=True, timeout=2
                )
                if result.returncode == 0:
                    return ip
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            ips = [f"{base}.{i}" for i in range(1, 255)]
            results = executor.map(ping_host, ips)
            
            for ip in results:
                if ip:
                    alive_hosts.append(ip)
        
        console.print(f"[green]✓ Found {len(alive_hosts)} alive hosts[/green]")
        return alive_hosts
    
    def get_routing_table(self) -> str:
        """Get routing table."""
        result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
        return result.stdout
    
    def get_arp_table(self) -> str:
        """Get ARP table."""
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
        return result.stdout
    
    def traceroute(self, target: str) -> str:
        """Perform traceroute."""
        console.print(f"\n[cyan]📍 Traceroute to {target}...[/cyan]")
        
        result = subprocess.run(
            ['traceroute', '-n', target],
            capture_output=True, text=True, timeout=60
        )
        return result.stdout
    
    def dns_lookup(self, hostname: str) -> Dict:
        """Perform DNS lookups."""
        console.print(f"\n[cyan]🔍 DNS lookup for {hostname}...[/cyan]")
        
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        for rtype in record_types:
            try:
                result = subprocess.run(
                    ['dig', '+short', rtype, hostname],
                    capture_output=True, text=True, timeout=10
                )
                if result.stdout.strip():
                    records[rtype] = result.stdout.strip().split('\n')
            except:
                pass
        
        return records
    
    def reverse_dns(self, ip: str) -> Optional[str]:
        """Perform reverse DNS lookup."""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return None


class SNMPEnumerator:
    """
    SNMP enumeration utilities.
    """
    
    COMMON_COMMUNITIES = ['public', 'private', 'manager', 'admin', 'cisco', 'community']
    
    def __init__(self, target: str):
        self.target = target
    
    def walk(self, community: str = 'public', oid: str = '1') -> str:
        """SNMP walk."""
        console.print(f"\n[cyan]🔍 SNMP walk {self.target}...[/cyan]")
        
        try:
            result = subprocess.run(
                ['snmpwalk', '-v2c', '-c', community, self.target, oid],
                capture_output=True, text=True, timeout=60
            )
            return result.stdout
        except FileNotFoundError:
            console.print("[red]snmpwalk not found[/red]")
            return ""
    
    def brute_community(self) -> List[str]:
        """Brute force SNMP community strings."""
        console.print(f"\n[cyan]🔑 Brute forcing SNMP communities on {self.target}...[/cyan]")
        
        valid = []
        
        for community in self.COMMON_COMMUNITIES:
            try:
                result = subprocess.run(
                    ['snmpwalk', '-v2c', '-c', community, '-t', '2', self.target, '1.3.6.1.2.1.1.1'],
                    capture_output=True, text=True, timeout=5
                )
                
                if result.returncode == 0 and result.stdout:
                    valid.append(community)
                    console.print(f"[green]  ✓ {community}[/green]")
            except:
                pass
        
        return valid
    
    def get_system_info(self, community: str = 'public') -> Dict:
        """Get system info via SNMP."""
        oids = {
            'sysDescr': '1.3.6.1.2.1.1.1.0',
            'sysObjectID': '1.3.6.1.2.1.1.2.0',
            'sysUpTime': '1.3.6.1.2.1.1.3.0',
            'sysContact': '1.3.6.1.2.1.1.4.0',
            'sysName': '1.3.6.1.2.1.1.5.0',
            'sysLocation': '1.3.6.1.2.1.1.6.0',
        }
        
        info = {}
        for name, oid in oids.items():
            try:
                result = subprocess.run(
                    ['snmpget', '-v2c', '-c', community, self.target, oid],
                    capture_output=True, text=True, timeout=5
                )
                if result.stdout:
                    info[name] = result.stdout.split('=')[-1].strip()
            except:
                pass
        
        return info
    
    def enum_users(self, community: str = 'public') -> List[str]:
        """Enumerate users via SNMP (Windows)."""
        output = self.walk(community, '1.3.6.1.4.1.77.1.2.25')
        
        users = []
        for line in output.split('\n'):
            if 'STRING' in line:
                user = line.split('"')[1] if '"' in line else None
                if user:
                    users.append(user)
        
        return users
    
    def enum_processes(self, community: str = 'public') -> List[str]:
        """Enumerate running processes via SNMP."""
        output = self.walk(community, '1.3.6.1.2.1.25.4.2.1.2')
        
        processes = []
        for line in output.split('\n'):
            if 'STRING' in line:
                proc = line.split('"')[1] if '"' in line else None
                if proc:
                    processes.append(proc)
        
        return processes


class SMBEnumerator:
    """
    SMB/CIFS enumeration.
    """
    
    def __init__(self, target: str):
        self.target = target
    
    def list_shares(self, username: str = '', password: str = '') -> List[Dict]:
        """List SMB shares."""
        console.print(f"\n[cyan]📂 Listing SMB shares on {self.target}...[/cyan]")
        
        shares = []
        
        cmd = ['smbclient', '-L', self.target, '-N']
        if username:
            cmd = ['smbclient', '-L', self.target, '-U', f'{username}%{password}']
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            for line in result.stdout.split('\n'):
                if 'Disk' in line or 'IPC' in line or 'Printer' in line:
                    parts = line.split()
                    if parts:
                        shares.append({
                            'name': parts[0],
                            'type': parts[1] if len(parts) > 1 else '',
                            'comment': ' '.join(parts[2:]) if len(parts) > 2 else ''
                        })
                        console.print(f"[green]  📁 {parts[0]}[/green]")
            
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        
        return shares
    
    def enum4linux(self) -> str:
        """Run enum4linux for comprehensive enumeration."""
        console.print(f"\n[cyan]🔍 Running enum4linux on {self.target}...[/cyan]")
        
        try:
            result = subprocess.run(
                ['enum4linux', '-a', self.target],
                capture_output=True, text=True, timeout=300
            )
            return result.stdout
        except FileNotFoundError:
            console.print("[red]enum4linux not found[/red]")
            return ""
    
    def check_null_session(self) -> bool:
        """Check if null session is allowed."""
        console.print(f"\n[cyan]🔓 Checking null session on {self.target}...[/cyan]")
        
        try:
            result = subprocess.run(
                ['smbclient', '-L', self.target, '-N'],
                capture_output=True, text=True, timeout=10
            )
            
            if 'Sharename' in result.stdout:
                console.print("[green]  ✓ Null session allowed![/green]")
                return True
        except:
            pass
        
        console.print("[yellow]  ✗ Null session not allowed[/yellow]")
        return False
    
    def get_users_rpc(self) -> List[str]:
        """Enumerate users via RPC."""
        console.print(f"\n[cyan]👤 Enumerating users via RPC...[/cyan]")
        
        users = []
        
        try:
            result = subprocess.run(
                ['rpcclient', '-U', '', '-N', self.target, '-c', 'enumdomusers'],
                capture_output=True, text=True, timeout=30
            )
            
            for line in result.stdout.split('\n'):
                if 'user:' in line:
                    user = line.split('[')[1].split(']')[0] if '[' in line else None
                    if user:
                        users.append(user)
                        console.print(f"[green]  👤 {user}[/green]")
        except:
            pass
        
        return users


class LDAPEnumerator:
    """
    LDAP enumeration.
    """
    
    def __init__(self, target: str, port: int = 389):
        self.target = target
        self.port = port
    
    def anonymous_bind(self) -> bool:
        """Check if anonymous bind is allowed."""
        console.print(f"\n[cyan]🔓 Checking anonymous LDAP bind on {self.target}...[/cyan]")
        
        try:
            result = subprocess.run(
                ['ldapsearch', '-x', '-H', f'ldap://{self.target}:{self.port}',
                 '-b', '', '-s', 'base', 'namingContexts'],
                capture_output=True, text=True, timeout=10
            )
            
            if 'namingContexts' in result.stdout:
                console.print("[green]  ✓ Anonymous bind allowed![/green]")
                return True
        except:
            pass
        
        return False
    
    def get_base_dn(self) -> Optional[str]:
        """Get base DN."""
        try:
            result = subprocess.run(
                ['ldapsearch', '-x', '-H', f'ldap://{self.target}:{self.port}',
                 '-b', '', '-s', 'base', 'namingContexts'],
                capture_output=True, text=True, timeout=10
            )
            
            for line in result.stdout.split('\n'):
                if 'namingContexts:' in line:
                    return line.split(':')[1].strip()
        except:
            pass
        
        return None
    
    def search(self, base_dn: str, filter: str = '(objectClass=*)') -> str:
        """Perform LDAP search."""
        try:
            result = subprocess.run(
                ['ldapsearch', '-x', '-H', f'ldap://{self.target}:{self.port}',
                 '-b', base_dn, filter],
                capture_output=True, text=True, timeout=60
            )
            return result.stdout
        except:
            return ""
    
    def enum_users(self, base_dn: str) -> List[str]:
        """Enumerate LDAP users."""
        console.print(f"\n[cyan]👤 Enumerating LDAP users...[/cyan]")
        
        users = []
        output = self.search(base_dn, '(objectClass=person)')
        
        for line in output.split('\n'):
            if 'sAMAccountName:' in line or 'uid:' in line:
                user = line.split(':')[1].strip()
                users.append(user)
        
        console.print(f"[green]✓ Found {len(users)} users[/green]")
        return users


class NetBIOSEnumerator:
    """
    NetBIOS enumeration.
    """
    
    def __init__(self, target: str):
        self.target = target
    
    def nbtscan(self, subnet: str = None) -> str:
        """Run nbtscan."""
        console.print(f"\n[cyan]🔍 Running nbtscan...[/cyan]")
        
        target = subnet or self.target
        
        try:
            result = subprocess.run(
                ['nbtscan', target],
                capture_output=True, text=True, timeout=60
            )
            return result.stdout
        except FileNotFoundError:
            console.print("[red]nbtscan not found[/red]")
            return ""
    
    def nbtstat(self) -> Dict:
        """Get NetBIOS name table."""
        console.print(f"\n[cyan]🔍 Getting NetBIOS info for {self.target}...[/cyan]")
        
        info = {}
        
        try:
            result = subprocess.run(
                ['nmblookup', '-A', self.target],
                capture_output=True, text=True, timeout=10
            )
            
            for line in result.stdout.split('\n'):
                if '<' in line and '>' in line:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        name = parts[0]
                        ntype = parts[1]
                        info[name] = ntype
            
        except:
            pass
        
        return info
