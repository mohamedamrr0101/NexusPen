#!/usr/bin/env python3
"""
NexusPen - Tool Manager
=======================
Smart tool detection, discovery, and auto-installation.
"""

import subprocess
import shutil
import os
from typing import Dict, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

from rich.console import Console
from rich.prompt import Confirm

console = Console()


class InstallMethod(Enum):
    APT = "apt"
    PIP = "pip"
    GEM = "gem"
    GO = "go"
    MANUAL = "manual"


@dataclass
class ToolInfo:
    """Information about a tool."""
    name: str
    install_method: InstallMethod
    package_name: str
    description: str = ""
    alternatives: list = None
    
    def __post_init__(self):
        if self.alternatives is None:
            self.alternatives = []


# Tool registry - maps tool names to installation info
TOOL_REGISTRY: Dict[str, ToolInfo] = {
    # Network Tools
    'nmap': ToolInfo('nmap', InstallMethod.APT, 'nmap', 'Network scanner'),
    'masscan': ToolInfo('masscan', InstallMethod.APT, 'masscan', 'Fast port scanner'),
    'nc': ToolInfo('nc', InstallMethod.APT, 'netcat-openbsd', 'Network utility', ['netcat', 'ncat']),
    'netcat': ToolInfo('netcat', InstallMethod.APT, 'netcat-openbsd', 'Network utility'),
    
    # Web Tools
    'whatweb': ToolInfo('whatweb', InstallMethod.APT, 'whatweb', 'Web technology detector'),
    'wafw00f': ToolInfo('wafw00f', InstallMethod.PIP, 'wafw00f', 'WAF detector'),
    'nikto': ToolInfo('nikto', InstallMethod.APT, 'nikto', 'Web vulnerability scanner'),
    'gobuster': ToolInfo('gobuster', InstallMethod.APT, 'gobuster', 'Directory bruteforcer'),
    'dirb': ToolInfo('dirb', InstallMethod.APT, 'dirb', 'Directory scanner'),
    'wfuzz': ToolInfo('wfuzz', InstallMethod.PIP, 'wfuzz', 'Web fuzzer'),
    'sqlmap': ToolInfo('sqlmap', InstallMethod.APT, 'sqlmap', 'SQL injection tool'),
    'sslyze': ToolInfo('sslyze', InstallMethod.PIP, 'sslyze', 'SSL/TLS analyzer'),
    
    # SSH Tools
    'ssh-audit': ToolInfo('ssh-audit', InstallMethod.PIP, 'ssh-audit', 'SSH security auditor'),
    
    # SMB/Windows Tools
    'enum4linux': ToolInfo('enum4linux', InstallMethod.APT, 'enum4linux', 'SMB enumerator'),
    'smbclient': ToolInfo('smbclient', InstallMethod.APT, 'smbclient', 'SMB client'),
    'rpcclient': ToolInfo('rpcclient', InstallMethod.APT, 'smbclient', 'RPC client'),
    'crackmapexec': ToolInfo('crackmapexec', InstallMethod.APT, 'crackmapexec', 'Network pentesting tool'),
    
    # AD Tools
    'ldapsearch': ToolInfo('ldapsearch', InstallMethod.APT, 'ldap-utils', 'LDAP query tool'),
    'ldapdomaindump': ToolInfo('ldapdomaindump', InstallMethod.PIP, 'ldapdomaindump', 'LDAP dumper'),
    'bloodhound-python': ToolInfo('bloodhound-python', InstallMethod.PIP, 'bloodhound', 'BloodHound collector'),
    'certipy': ToolInfo('certipy', InstallMethod.PIP, 'certipy-ad', 'ADCS exploitation'),
    
    # Impacket Tools
    'GetUserSPNs.py': ToolInfo('GetUserSPNs.py', InstallMethod.PIP, 'impacket', 'Kerberoasting'),
    'GetNPUsers.py': ToolInfo('GetNPUsers.py', InstallMethod.PIP, 'impacket', 'AS-REP Roasting'),
    'secretsdump.py': ToolInfo('secretsdump.py', InstallMethod.PIP, 'impacket', 'Credential dumping'),
    
    # NFS Tools
    'showmount': ToolInfo('showmount', InstallMethod.APT, 'nfs-common', 'NFS share lister'),
    
    # Password Tools
    'john': ToolInfo('john', InstallMethod.APT, 'john', 'Password cracker'),
    'hashcat': ToolInfo('hashcat', InstallMethod.APT, 'hashcat', 'GPU password cracker'),
    'hydra': ToolInfo('hydra', InstallMethod.APT, 'hydra', 'Login bruteforcer'),
    
    # Wireless Tools
    'aircrack-ng': ToolInfo('aircrack-ng', InstallMethod.APT, 'aircrack-ng', 'Wireless security'),
    'reaver': ToolInfo('reaver', InstallMethod.APT, 'reaver', 'WPS cracker'),
    
    # Misc
    'searchsploit': ToolInfo('searchsploit', InstallMethod.APT, 'exploitdb', 'Exploit database'),
    'msfconsole': ToolInfo('msfconsole', InstallMethod.APT, 'metasploit-framework', 'Metasploit'),
}

# Common search paths on Kali
SEARCH_PATHS = [
    '/usr/bin',
    '/usr/sbin',
    '/usr/local/bin',
    '/usr/local/sbin',
    '/opt',
    os.path.expanduser('~/.local/bin'),
    '/usr/share',
]


class ToolManager:
    """Manages tool detection, discovery, and installation."""
    
    def __init__(self, auto_install: bool = False, verbosity: int = 0):
        self.auto_install = auto_install
        self.verbosity = verbosity
        self._cache: Dict[str, Optional[str]] = {}
    
    def check_tool(self, name: str) -> Optional[str]:
        """
        Check if a tool is available.
        Returns the path if found, None if not found.
        """
        # Check cache first
        if name in self._cache:
            return self._cache[name]
        
        # Use shutil.which for standard path lookup
        path = shutil.which(name)
        if path:
            self._cache[name] = path
            return path
        
        # Try to find the tool in common locations
        path = self.find_tool(name)
        if path:
            self._cache[name] = path
            return path
        
        self._cache[name] = None
        return None
    
    def find_tool(self, name: str) -> Optional[str]:
        """Search for a tool in common Kali paths."""
        for base_path in SEARCH_PATHS:
            if not os.path.exists(base_path):
                continue
            
            # Direct check
            full_path = os.path.join(base_path, name)
            if os.path.isfile(full_path) and os.access(full_path, os.X_OK):
                return full_path
            
            # Check in subdirectories (e.g., /opt/tool/bin/tool)
            if base_path == '/opt':
                for item in os.listdir(base_path):
                    item_path = os.path.join(base_path, item)
                    if os.path.isdir(item_path):
                        bin_path = os.path.join(item_path, 'bin', name)
                        if os.path.isfile(bin_path) and os.access(bin_path, os.X_OK):
                            return bin_path
                        direct_path = os.path.join(item_path, name)
                        if os.path.isfile(direct_path) and os.access(direct_path, os.X_OK):
                            return direct_path
        
        # Check alternatives
        if name in TOOL_REGISTRY:
            for alt in TOOL_REGISTRY[name].alternatives:
                alt_path = shutil.which(alt)
                if alt_path:
                    return alt_path
        
        return None
    
    def get_install_command(self, name: str) -> Optional[str]:
        """Get the command to install a tool."""
        if name not in TOOL_REGISTRY:
            return None
        
        tool_info = TOOL_REGISTRY[name]
        
        if tool_info.install_method == InstallMethod.APT:
            return f"sudo apt install -y {tool_info.package_name}"
        elif tool_info.install_method == InstallMethod.PIP:
            return f"pip install {tool_info.package_name}"
        elif tool_info.install_method == InstallMethod.GEM:
            return f"gem install {tool_info.package_name}"
        elif tool_info.install_method == InstallMethod.GO:
            return f"go install {tool_info.package_name}"
        else:
            return None
    
    def install_tool(self, name: str, prompt: bool = True) -> bool:
        """
        Attempt to install a missing tool.
        Returns True if installation was successful.
        """
        if name not in TOOL_REGISTRY:
            if self.verbosity > 0:
                console.print(f"[yellow]⚠ Unknown tool: {name}[/yellow]")
            return False
        
        tool_info = TOOL_REGISTRY[name]
        install_cmd = self.get_install_command(name)
        
        if not install_cmd:
            return False
        
        # Prompt user if not auto-install
        if prompt and not self.auto_install:
            console.print(f"[yellow]⚠ Tool not found: {name}[/yellow]")
            console.print(f"[dim]Install command: {install_cmd}[/dim]")
            
            if not Confirm.ask(f"Install {name}?", default=False):
                return False
        
        # Run installation
        if self.verbosity > 0:
            console.print(f"[cyan]📦 Installing {name}...[/cyan]")
        
        try:
            if tool_info.install_method == InstallMethod.APT:
                # APT needs sudo
                result = subprocess.run(
                    ['sudo', 'apt', 'install', '-y', tool_info.package_name],
                    capture_output=True, text=True, timeout=300
                )
            elif tool_info.install_method == InstallMethod.PIP:
                result = subprocess.run(
                    ['pip', 'install', tool_info.package_name],
                    capture_output=True, text=True, timeout=300
                )
            else:
                return False
            
            if result.returncode == 0:
                console.print(f"[green]✅ {name} installed successfully[/green]")
                # Clear cache
                self._cache.pop(name, None)
                return True
            else:
                if self.verbosity > 0:
                    console.print(f"[red]❌ Failed to install {name}[/red]")
                    if self.verbosity > 1:
                        console.print(f"[dim]{result.stderr}[/dim]")
                return False
                
        except subprocess.TimeoutExpired:
            console.print(f"[red]❌ Installation timed out[/red]")
            return False
        except Exception as e:
            if self.verbosity > 0:
                console.print(f"[red]❌ Installation error: {e}[/red]")
            return False
    
    def ensure_tool(self, name: str) -> Tuple[bool, Optional[str]]:
        """
        Ensure a tool is available, attempting installation if needed.
        Returns (success, path).
        """
        path = self.check_tool(name)
        if path:
            return True, path
        
        # Try to install
        if self.auto_install:
            if self.install_tool(name, prompt=False):
                path = self.check_tool(name)
                return path is not None, path
        
        return False, None
    
    def check_all_tools(self) -> Dict[str, bool]:
        """Check availability of all registered tools."""
        results = {}
        for name in TOOL_REGISTRY:
            results[name] = self.check_tool(name) is not None
        return results
    
    def print_tool_status(self):
        """Print a formatted status of all tools."""
        from rich.table import Table
        
        table = Table(title="Tool Status")
        table.add_column("Tool", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Install Command", style="dim")
        
        for name, info in TOOL_REGISTRY.items():
            path = self.check_tool(name)
            status = "✅ Found" if path else "❌ Missing"
            status_style = "green" if path else "red"
            install_cmd = self.get_install_command(name) or "N/A"
            
            table.add_row(name, f"[{status_style}]{status}[/{status_style}]", install_cmd)
        
        console.print(table)


# Global instance
_tool_manager: Optional[ToolManager] = None


def get_tool_manager(auto_install: bool = False, verbosity: int = 0) -> ToolManager:
    """Get or create the global ToolManager instance."""
    global _tool_manager
    if _tool_manager is None:
        _tool_manager = ToolManager(auto_install=auto_install, verbosity=verbosity)
    return _tool_manager
