#!/usr/bin/env python3
"""
NexusPen - Utility Functions
============================
Common utility functions used across the framework.
"""

import os
import re
import socket
import subprocess
import hashlib
import ipaddress
from pathlib import Path
from typing import List, Optional, Tuple, Union
from urllib.parse import urlparse

from rich.console import Console

console = Console()


def print_banner():
    """Print NexusPen banner."""
    banner = """
    ███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗██████╗ ███████╗███╗   ██╗
    ████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝██╔══██╗██╔════╝████╗  ██║
    ██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗██████╔╝█████╗  ██╔██╗ ██║
    ██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║██╔═══╝ ██╔══╝  ██║╚██╗██║
    ██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║██║     ███████╗██║ ╚████║
    ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝     ╚══════╝╚═╝  ╚═══╝
    """
    console.print(f"[bold red]{banner}[/bold red]")


def check_root() -> bool:
    """Check if running as root."""
    return os.geteuid() == 0


def validate_target(target: str) -> Tuple[bool, str]:
    """
    Validate target format.
    
    Returns:
        Tuple of (is_valid, target_type)
        target_type: 'ip', 'cidr', 'hostname', 'url'
    """
    # Check if URL
    if target.startswith(('http://', 'https://')):
        try:
            result = urlparse(target)
            if result.netloc:
                return True, 'url'
        except:
            pass
        return False, 'invalid'
    
    # Check if CIDR
    try:
        ipaddress.ip_network(target, strict=False)
        return True, 'cidr'
    except ValueError:
        pass
    
    # Check if IP
    try:
        ipaddress.ip_address(target)
        return True, 'ip'
    except ValueError:
        pass
    
    # Check if hostname
    hostname_pattern = re.compile(
        r'^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*$'
    )
    if hostname_pattern.match(target):
        return True, 'hostname'
    
    return False, 'invalid'


def expand_cidr(cidr: str) -> List[str]:
    """Expand CIDR notation to list of IPs."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return []


def resolve_hostname(hostname: str) -> Optional[str]:
    """Resolve hostname to IP address."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def reverse_dns(ip: str) -> Optional[str]:
    """Perform reverse DNS lookup."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None


def is_port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    """Check if a port is open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False


def run_command(
    cmd: Union[str, List[str]],
    timeout: int = 300,
    shell: bool = False,
    capture_output: bool = True
) -> Tuple[int, str, str]:
    """
    Run a shell command.
    
    Returns:
        Tuple of (return_code, stdout, stderr)
    """
    try:
        if isinstance(cmd, str) and not shell:
            cmd = cmd.split()
        
        result = subprocess.run(
            cmd,
            shell=shell,
            capture_output=capture_output,
            text=True,
            timeout=timeout
        )
        
        return result.returncode, result.stdout, result.stderr
        
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except FileNotFoundError:
        return -1, "", "Command not found"
    except Exception as e:
        return -1, "", str(e)


def check_tool(tool_name: str) -> bool:
    """Check if a tool is installed and accessible."""
    try:
        result = subprocess.run(
            ['which', tool_name],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except:
        return False


def get_tool_version(tool_name: str) -> Optional[str]:
    """Get version of an installed tool."""
    version_flags = ['--version', '-V', '-v', 'version']
    
    for flag in version_flags:
        try:
            result = subprocess.run(
                [tool_name, flag],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                # Extract version number
                version_match = re.search(r'[\d]+\.[\d]+(?:\.[\d]+)?', result.stdout)
                if version_match:
                    return version_match.group()
        except:
            continue
    
    return None


def sanitize_filename(filename: str) -> str:
    """Sanitize a string for use as a filename."""
    # Remove invalid characters
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Remove leading/trailing spaces and dots
    sanitized = sanitized.strip('. ')
    # Limit length
    return sanitized[:200]


def calculate_hash(data: Union[str, bytes], algorithm: str = 'sha256') -> str:
    """Calculate hash of data."""
    if isinstance(data, str):
        data = data.encode()
    
    hash_funcs = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha256': hashlib.sha256,
        'sha512': hashlib.sha512
    }
    
    hash_func = hash_funcs.get(algorithm, hashlib.sha256)
    return hash_func(data).hexdigest()


def parse_ports(port_string: str) -> List[int]:
    """
    Parse port specification string.
    
    Examples:
        "80" -> [80]
        "80,443" -> [80, 443]
        "80-85" -> [80, 81, 82, 83, 84, 85]
        "80,443,8000-8100" -> [80, 443, 8000, 8001, ..., 8100]
    """
    ports = set()
    
    for part in port_string.split(','):
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
    
    # Filter valid ports
    return sorted([p for p in ports if 1 <= p <= 65535])


def format_bytes(size: int) -> str:
    """Format bytes to human readable string."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} PB"


def format_duration(seconds: float) -> str:
    """Format seconds to human readable duration."""
    if seconds < 60:
        return f"{seconds:.2f}s"
    elif seconds < 3600:
        minutes = seconds // 60
        secs = seconds % 60
        return f"{int(minutes)}m {int(secs)}s"
    else:
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        return f"{int(hours)}h {int(minutes)}m"


def extract_urls(text: str) -> List[str]:
    """Extract URLs from text."""
    url_pattern = re.compile(
        r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\.-]*(?:\?\S*)?'
    )
    return url_pattern.findall(text)


def extract_emails(text: str) -> List[str]:
    """Extract email addresses from text."""
    email_pattern = re.compile(
        r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    )
    return email_pattern.findall(text)


def extract_ips(text: str) -> List[str]:
    """Extract IP addresses from text."""
    ip_pattern = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    )
    return ip_pattern.findall(text)


def get_common_ports() -> dict:
    """Return dictionary of common ports and services."""
    return {
        21: ('FTP', 'File Transfer Protocol'),
        22: ('SSH', 'Secure Shell'),
        23: ('Telnet', 'Telnet'),
        25: ('SMTP', 'Simple Mail Transfer'),
        53: ('DNS', 'Domain Name System'),
        80: ('HTTP', 'Web Server'),
        88: ('Kerberos', 'Kerberos Authentication'),
        110: ('POP3', 'Post Office Protocol'),
        111: ('RPCBind', 'RPC Port Mapper'),
        135: ('MSRPC', 'Microsoft RPC'),
        139: ('NetBIOS', 'NetBIOS Session Service'),
        143: ('IMAP', 'Internet Message Access'),
        389: ('LDAP', 'Lightweight Directory Access'),
        443: ('HTTPS', 'Secure Web Server'),
        445: ('SMB', 'Server Message Block'),
        464: ('Kerberos', 'Kerberos Password Change'),
        465: ('SMTPS', 'Secure SMTP'),
        587: ('SMTP', 'SMTP Submission'),
        593: ('HTTP-RPC', 'HTTP RPC Endpoint Mapper'),
        636: ('LDAPS', 'Secure LDAP'),
        993: ('IMAPS', 'Secure IMAP'),
        995: ('POP3S', 'Secure POP3'),
        1433: ('MSSQL', 'Microsoft SQL Server'),
        1521: ('Oracle', 'Oracle Database'),
        2049: ('NFS', 'Network File System'),
        3268: ('LDAP GC', 'Global Catalog'),
        3269: ('LDAPS GC', 'Secure Global Catalog'),
        3306: ('MySQL', 'MySQL Database'),
        3389: ('RDP', 'Remote Desktop Protocol'),
        5432: ('PostgreSQL', 'PostgreSQL Database'),
        5900: ('VNC', 'Virtual Network Computing'),
        5985: ('WinRM', 'Windows Remote Management'),
        5986: ('WinRM-S', 'Secure WinRM'),
        6379: ('Redis', 'Redis Database'),
        8080: ('HTTP-Proxy', 'HTTP Proxy/Alt HTTP'),
        8443: ('HTTPS-Alt', 'Alternate HTTPS'),
        27017: ('MongoDB', 'MongoDB Database'),
    }
