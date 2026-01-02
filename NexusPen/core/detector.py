#!/usr/bin/env python3
"""
NexusPen - Smart Target Detector
================================
Automatically detects target type (Windows, Linux, Web, AD, Network Device)
and suggests the appropriate testing modules.

This is the "brain" of NexusPen that makes intelligent decisions.
"""

import socket
import subprocess
import re
import json
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from rich.console import Console
from rich.table import Table

console = Console()


class TargetType(Enum):
    """Enumeration of target types."""
    UNKNOWN = "unknown"
    LINUX = "linux"
    WINDOWS = "windows"
    ACTIVE_DIRECTORY = "active_directory"
    WEB_APPLICATION = "web_application"
    NETWORK_DEVICE = "network_device"
    WIRELESS = "wireless"
    DATABASE = "database"
    CONTAINER = "container"


@dataclass
class TargetProfile:
    """Profile containing all information about a target."""
    ip: str
    hostname: Optional[str] = None
    target_type: TargetType = TargetType.UNKNOWN
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, Dict] = field(default_factory=dict)
    is_domain_controller: bool = False
    is_web_server: bool = False
    is_database_server: bool = False
    cms_detected: Optional[str] = None
    technologies: List[str] = field(default_factory=list)
    confidence: float = 0.0
    recommended_modules: List[str] = field(default_factory=list)
    

class TargetDetector:
    """
    Smart Target Detection Engine
    
    Uses multiple techniques to identify the target:
    1. Port scanning - Open ports reveal OS hints
    2. Service detection - Banner grabbing and version detection
    3. OS fingerprinting - TCP/IP stack analysis
    4. Web technology detection - CMS, frameworks, servers
    5. Network behavior analysis - TTL, window size, etc.
    """
    
    # Port signatures for different systems
    WINDOWS_PORTS = {135, 139, 445, 3389, 5985, 5986, 1433, 3306}
    LINUX_PORTS = {22, 111, 2049}
    WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888}
    AD_PORTS = {53, 88, 389, 636, 3268, 3269, 464, 593}
    DATABASE_PORTS = {1433, 1521, 3306, 5432, 27017, 6379, 9200}
    
    # Service signatures for OS detection
    WINDOWS_SERVICES = [
        'microsoft', 'windows', 'iis', 'smb', 'netbios', 'rdp', 
        'mssql', 'exchange', 'sharepoint', 'asp.net'
    ]
    LINUX_SERVICES = [
        'openssh', 'apache', 'nginx', 'ubuntu', 'debian', 'centos',
        'fedora', 'red hat', 'mysql', 'postgresql', 'proftpd', 'vsftpd'
    ]
    AD_SERVICES = [
        'kerberos', 'ldap', 'active directory', 'domain', 'dc',
        'global catalog', 'adws'
    ]
    
    # TTL-based OS detection
    TTL_SIGNATURES = {
        (60, 70): 'linux',      # Linux default TTL ~64
        (120, 130): 'windows',  # Windows default TTL ~128
        (250, 260): 'network',  # Network devices TTL ~255
    }
    
    def __init__(self, nmap_path: str = "/usr/bin/nmap"):
        self.nmap_path = nmap_path
        
    def detect(self, target: str, quick: bool = True) -> TargetProfile:
        """
        Main detection method.
        
        Args:
            target: IP address or hostname
            quick: If True, use quick scan; if False, comprehensive scan
            
        Returns:
            TargetProfile with all detected information
        """
        console.print(f"\n[bold cyan]🔍 Analyzing target: {target}[/bold cyan]")
        
        profile = TargetProfile(ip=target)
        
        # Step 1: Resolve hostname
        profile.hostname = self._resolve_hostname(target)
        
        # Step 2: Quick port scan
        profile.open_ports, profile.services = self._scan_ports(target, quick)
        
        # Step 3: TTL-based OS detection
        ttl_os = self._detect_os_by_ttl(target)
        
        # Step 4: Service-based OS detection
        service_os = self._detect_os_by_services(profile.services)
        
        # Step 5: Nmap OS detection (if available)
        nmap_os = self._nmap_os_detection(target) if not quick else None
        
        # Step 6: Determine final OS
        profile.target_type, profile.os_name, profile.confidence = self._determine_os(
            ttl_os, service_os, nmap_os, profile.open_ports
        )
        
        # Step 7: Check for special roles
        profile.is_domain_controller = self._check_domain_controller(profile)
        profile.is_web_server = self._check_web_server(profile)
        profile.is_database_server = self._check_database_server(profile)
        
        # Step 8: Web technology detection
        if profile.is_web_server:
            profile.technologies, profile.cms_detected = self._detect_web_tech(target, profile.open_ports)
        
        # Step 9: Recommend modules
        profile.recommended_modules = self._recommend_modules(profile)
        
        # Display results
        self._display_profile(profile)
        
        return profile
    
    def _resolve_hostname(self, target: str) -> Optional[str]:
        """Resolve IP to hostname or vice versa."""
        try:
            if self._is_ip(target):
                return socket.gethostbyaddr(target)[0]
            else:
                return socket.gethostbyname(target)
        except socket.herror:
            return None
        except socket.gaierror:
            return None
    
    def _is_ip(self, target: str) -> bool:
        """Check if target is an IP address."""
        try:
            socket.inet_aton(target)
            return True
        except socket.error:
            return False
    
    def _scan_ports(self, target: str, quick: bool = True) -> Tuple[List[int], Dict]:
        """
        Scan for open ports using Nmap.
        
        Returns:
            Tuple of (open_ports list, services dict)
        """
        ports = []
        services = {}
        
        try:
            # Quick scan: top 1000 ports
            # Full scan: all ports with version detection
            if quick:
                cmd = [self.nmap_path, '-sS', '-sV', '--top-ports', '1000', 
                       '-T4', '--open', '-oX', '-', target]
            else:
                cmd = [self.nmap_path, '-sS', '-sV', '-p-', '-T4', 
                       '--open', '-oX', '-', target]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                ports, services = self._parse_nmap_xml(result.stdout)
                
        except subprocess.TimeoutExpired:
            console.print("[yellow]⚠️  Port scan timed out[/yellow]")
        except FileNotFoundError:
            console.print("[red]❌ Nmap not found. Using fallback method.[/red]")
            ports, services = self._fallback_port_scan(target)
        except Exception as e:
            console.print(f"[red]❌ Port scan error: {e}[/red]")
            
        return ports, services
    
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
                            'name': 'unknown',
                            'product': '',
                            'version': '',
                            'protocol': protocol
                        }
                        
        except ET.ParseError:
            pass
            
        return ports, services
    
    def _fallback_port_scan(self, target: str, ports: List[int] = None) -> Tuple[List[int], Dict]:
        """Fallback port scanner using Python sockets."""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 
                    443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 
                    5900, 5985, 6379, 8080, 8443, 27017]
        
        open_ports = []
        services = {}
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                
                if result == 0:
                    open_ports.append(port)
                    banner = self._grab_banner(target, port)
                    services[port] = {
                        'name': self._guess_service(port),
                        'product': banner,
                        'version': '',
                        'protocol': 'tcp'
                    }
                sock.close()
            except:
                pass
                
        return open_ports, services
    
    def _grab_banner(self, target: str, port: int) -> str:
        """Attempt to grab service banner."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target, port))
            
            # Send probe for HTTP
            if port in [80, 8080, 8000, 8888]:
                sock.send(b"HEAD / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
            else:
                sock.send(b"\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner[:200]  # Limit banner length
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
    
    def _detect_os_by_ttl(self, target: str) -> Optional[str]:
        """Detect OS based on TTL value from ping."""
        try:
            # Use ping to get TTL
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '2', target],
                capture_output=True, text=True, timeout=5
            )
            
            if result.returncode == 0:
                # Extract TTL from output
                ttl_match = re.search(r'ttl[=:](\d+)', result.stdout, re.IGNORECASE)
                if ttl_match:
                    ttl = int(ttl_match.group(1))
                    
                    for (low, high), os_type in self.TTL_SIGNATURES.items():
                        if low <= ttl <= high:
                            return os_type
                    
                    # Handle intermediate values
                    if ttl < 100:
                        return 'linux'
                    elif ttl < 200:
                        return 'windows'
                    else:
                        return 'network'
                        
        except Exception:
            pass
            
        return None
    
    def _detect_os_by_services(self, services: Dict) -> Optional[str]:
        """Detect OS based on running services."""
        windows_score = 0
        linux_score = 0
        ad_score = 0
        
        for port, service_info in services.items():
            service_str = ' '.join([
                str(service_info.get('name', '')),
                str(service_info.get('product', '')),
                str(service_info.get('extrainfo', ''))
            ]).lower()
            
            # Check Windows signatures
            for sig in self.WINDOWS_SERVICES:
                if sig in service_str:
                    windows_score += 1
            
            # Check Linux signatures
            for sig in self.LINUX_SERVICES:
                if sig in service_str:
                    linux_score += 1
            
            # Check AD signatures
            for sig in self.AD_SERVICES:
                if sig in service_str:
                    ad_score += 1
        
        # Determine winner
        if ad_score >= 2:
            return 'active_directory'
        elif windows_score > linux_score:
            return 'windows'
        elif linux_score > windows_score:
            return 'linux'
        
        return None
    
    def _nmap_os_detection(self, target: str) -> Optional[str]:
        """Use Nmap's OS detection (-O flag)."""
        try:
            cmd = [self.nmap_path, '-O', '--osscan-guess', target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                output = result.stdout.lower()
                
                if 'windows' in output:
                    return 'windows'
                elif 'linux' in output:
                    return 'linux'
                elif 'freebsd' in output or 'openbsd' in output:
                    return 'bsd'
                elif 'cisco' in output or 'juniper' in output:
                    return 'network'
                    
        except Exception:
            pass
            
        return None
    
    def _determine_os(self, ttl_os: Optional[str], service_os: Optional[str], 
                     nmap_os: Optional[str], open_ports: List[int]) -> Tuple[TargetType, str, float]:
        """
        Combine all detection methods to determine final OS.
        
        Returns:
            Tuple of (TargetType, OS name, confidence)
        """
        votes = {'windows': 0, 'linux': 0, 'active_directory': 0, 'network': 0}
        
        # Weight: TTL = 1, Services = 2, Nmap = 3
        if ttl_os:
            votes[ttl_os] = votes.get(ttl_os, 0) + 1
        if service_os:
            votes[service_os] = votes.get(service_os, 0) + 2
        if nmap_os:
            votes[nmap_os] = votes.get(nmap_os, 0) + 3
        
        # Port-based voting
        windows_port_match = len(set(open_ports) & self.WINDOWS_PORTS)
        linux_port_match = len(set(open_ports) & self.LINUX_PORTS)
        ad_port_match = len(set(open_ports) & self.AD_PORTS)
        
        votes['windows'] += windows_port_match
        votes['linux'] += linux_port_match
        votes['active_directory'] += ad_port_match * 2  # AD gets higher weight
        
        # Get winner
        winner = max(votes, key=votes.get)
        total_votes = sum(votes.values())
        confidence = votes[winner] / max(total_votes, 1)
        
        # Map to TargetType
        type_mapping = {
            'windows': TargetType.WINDOWS,
            'linux': TargetType.LINUX,
            'active_directory': TargetType.ACTIVE_DIRECTORY,
            'network': TargetType.NETWORK_DEVICE
        }
        
        target_type = type_mapping.get(winner, TargetType.UNKNOWN)
        
        return target_type, winner, confidence
    
    def _check_domain_controller(self, profile: TargetProfile) -> bool:
        """Check if target is a Domain Controller."""
        ad_ports = {88, 389, 636, 3268, 3269}
        
        # Must have Kerberos (88) and LDAP (389)
        if 88 in profile.open_ports and 389 in profile.open_ports:
            return True
        
        # Check service banners
        for port, service in profile.services.items():
            service_str = str(service).lower()
            if 'domain controller' in service_str or 'active directory' in service_str:
                return True
        
        return False
    
    def _check_web_server(self, profile: TargetProfile) -> bool:
        """Check if target has web services."""
        return bool(set(profile.open_ports) & self.WEB_PORTS)
    
    def _check_database_server(self, profile: TargetProfile) -> bool:
        """Check if target has database services."""
        return bool(set(profile.open_ports) & self.DATABASE_PORTS)
    
    def _detect_web_tech(self, target: str, open_ports: List[int]) -> Tuple[List[str], Optional[str]]:
        """Detect web technologies and CMS."""
        technologies = []
        cms = None
        
        web_ports = set(open_ports) & self.WEB_PORTS
        
        for port in web_ports:
            try:
                protocol = 'https' if port in [443, 8443] else 'http'
                url = f"{protocol}://{target}:{port}/"
                
                # Try WhatWeb or manual detection
                tech, detected_cms = self._whatweb_scan(url)
                technologies.extend(tech)
                if detected_cms:
                    cms = detected_cms
                    
            except Exception:
                pass
        
        return list(set(technologies)), cms
    
    def _whatweb_scan(self, url: str) -> Tuple[List[str], Optional[str]]:
        """Use WhatWeb for technology detection."""
        technologies = []
        cms = None
        
        try:
            result = subprocess.run(
                ['whatweb', '--color=never', '-q', url],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                output = result.stdout.lower()
                
                # Extract technologies
                tech_patterns = {
                    'apache': 'Apache',
                    'nginx': 'Nginx',
                    'iis': 'IIS',
                    'php': 'PHP',
                    'asp.net': 'ASP.NET',
                    'jquery': 'jQuery',
                    'bootstrap': 'Bootstrap',
                    'react': 'React',
                    'angular': 'Angular',
                    'vue': 'Vue.js'
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
                    'shopify': 'Shopify',
                    'wix': 'Wix'
                }
                
                for key, name in cms_patterns.items():
                    if key in output:
                        cms = name
                        break
                        
        except Exception:
            pass
        
        return technologies, cms
    
    def _recommend_modules(self, profile: TargetProfile) -> List[str]:
        """Recommend testing modules based on target profile."""
        modules = []
        
        # Always start with common recon
        modules.append("modules.common.recon")
        modules.append("modules.common.port_scanner")
        
        # OS-specific modules
        if profile.target_type == TargetType.WINDOWS:
            modules.extend([
                "modules.windows.smb_enum",
                "modules.windows.rpc_enum",
                "modules.windows.privesc",
                "modules.windows.exploits"
            ])
            if 3389 in profile.open_ports:
                modules.append("modules.windows.rdp")
            if 1433 in profile.open_ports:
                modules.append("modules.windows.mssql")
            if 5985 in profile.open_ports or 5986 in profile.open_ports:
                modules.append("modules.windows.winrm")
                
        elif profile.target_type == TargetType.LINUX:
            modules.extend([
                "modules.linux.ssh_enum",
                "modules.linux.linpeas",
                "modules.linux.privesc",
                "modules.linux.exploits"
            ])
            if 21 in profile.open_ports:
                modules.append("modules.linux.ftp_enum")
            if 111 in profile.open_ports or 2049 in profile.open_ports:
                modules.append("modules.linux.nfs_enum")
            if 3306 in profile.open_ports:
                modules.append("modules.linux.mysql_enum")
                
        elif profile.target_type == TargetType.ACTIVE_DIRECTORY:
            modules.extend([
                "modules.ad.ldap_enum",
                "modules.ad.kerberos",
                "modules.ad.bloodhound",
                "modules.ad.gpp",
                "modules.ad.dcsync",
                "modules.ad.exploits"
            ])
        
        # Web modules
        if profile.is_web_server:
            modules.extend([
                "modules.web.recon",
                "modules.web.scanner",
                "modules.web.fuzzer",
                "modules.web.sqli",
                "modules.web.xss"
            ])
            
            if profile.cms_detected == 'WordPress':
                modules.append("modules.web.cms.wordpress")
            elif profile.cms_detected == 'Joomla':
                modules.append("modules.web.cms.joomla")
        
        # Database modules
        if profile.is_database_server:
            modules.append("modules.password.bruteforce")
        
        # Password attacks
        modules.append("modules.password.spray")
        
        # Reporting
        modules.append("modules.report.html_report")
        
        return modules
    
    def _display_profile(self, profile: TargetProfile):
        """Display target profile in a nice table."""
        table = Table(title="🎯 Target Profile", show_header=True, header_style="bold magenta")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="white")
        
        table.add_row("IP Address", profile.ip)
        table.add_row("Hostname", profile.hostname or "N/A")
        table.add_row("Target Type", f"[bold]{profile.target_type.value.upper()}[/bold]")
        table.add_row("OS Detection", profile.os_name or "Unknown")
        table.add_row("Confidence", f"{profile.confidence:.0%}")
        table.add_row("Open Ports", ", ".join(map(str, profile.open_ports[:15])) + ("..." if len(profile.open_ports) > 15 else ""))
        table.add_row("Is Domain Controller", "✅ Yes" if profile.is_domain_controller else "❌ No")
        table.add_row("Is Web Server", "✅ Yes" if profile.is_web_server else "❌ No")
        table.add_row("Is Database Server", "✅ Yes" if profile.is_database_server else "❌ No")
        
        if profile.cms_detected:
            table.add_row("CMS Detected", profile.cms_detected)
        
        if profile.technologies:
            table.add_row("Technologies", ", ".join(profile.technologies[:10]))
        
        console.print(table)
        
        # Recommended modules
        console.print("\n[bold green]📦 Recommended Modules:[/bold green]")
        for i, module in enumerate(profile.recommended_modules, 1):
            console.print(f"  {i}. {module}")
