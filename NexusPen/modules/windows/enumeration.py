#!/usr/bin/env python3
"""
NexusPen - Windows Enumeration Module
======================================
Comprehensive Windows system enumeration.
"""

import subprocess
from typing import Dict, List, Optional
from dataclasses import dataclass

from rich.console import Console
from rich.table import Table

console = Console()


@dataclass
class WindowsSystemInfo:
    """Windows system information."""
    hostname: str
    os_version: str
    os_build: str
    architecture: str
    domain: str
    users: List[str]
    groups: List[str]
    network_interfaces: List[Dict]


class WindowsEnumerator:
    """
    Windows system enumeration.
    """
    
    def __init__(self, target: str = None, username: str = None,
                 password: str = None, domain: str = None):
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain or '.'
    
    def _run_cmd(self, cmd: List[str], timeout: int = 30) -> str:
        """Run command and return output."""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return result.stdout
        except Exception as e:
            return f"Error: {e}"
    
    def get_system_info(self) -> Dict:
        """Get system information."""
        console.print("\n[cyan]💻 Getting system information...[/cyan]")
        
        info = {}
        
        # systeminfo
        output = self._run_cmd(['systeminfo'])
        
        for line in output.split('\n'):
            if 'Host Name:' in line:
                info['hostname'] = line.split(':')[1].strip()
            elif 'OS Name:' in line:
                info['os_name'] = line.split(':')[1].strip()
            elif 'OS Version:' in line:
                info['os_version'] = line.split(':')[1].strip()
            elif 'System Type:' in line:
                info['architecture'] = line.split(':')[1].strip()
            elif 'Domain:' in line:
                info['domain'] = line.split(':')[1].strip()
        
        return info
    
    def get_users(self) -> List[Dict]:
        """Enumerate local users."""
        console.print("\n[cyan]👥 Enumerating users...[/cyan]")
        
        users = []
        
        # net user
        output = self._run_cmd(['net', 'user'])
        
        # Parse users
        in_user_section = False
        for line in output.split('\n'):
            if '---' in line:
                in_user_section = True
                continue
            if in_user_section and line.strip() and 'successfully' not in line.lower():
                for user in line.split():
                    if user:
                        users.append({'name': user, 'type': 'local'})
                        console.print(f"[green]  ✓ {user}[/green]")
        
        return users
    
    def get_groups(self) -> List[Dict]:
        """Enumerate local groups."""
        console.print("\n[cyan]👥 Enumerating groups...[/cyan]")
        
        groups = []
        
        output = self._run_cmd(['net', 'localgroup'])
        
        for line in output.split('\n'):
            if line.startswith('*'):
                group_name = line[1:].strip()
                groups.append({'name': group_name})
                console.print(f"[green]  ✓ {group_name}[/green]")
        
        return groups
    
    def get_group_members(self, group: str) -> List[str]:
        """Get members of a group."""
        output = self._run_cmd(['net', 'localgroup', group])
        
        members = []
        in_members = False
        
        for line in output.split('\n'):
            if '---' in line:
                in_members = True
                continue
            if in_members and line.strip() and 'successfully' not in line.lower():
                members.append(line.strip())
        
        return members
    
    def get_network_info(self) -> Dict:
        """Get network configuration."""
        console.print("\n[cyan]🌐 Getting network information...[/cyan]")
        
        info = {
            'interfaces': [],
            'routes': [],
            'arp': [],
            'connections': [],
        }
        
        # ipconfig
        output = self._run_cmd(['ipconfig', '/all'])
        info['ipconfig'] = output
        
        # netstat
        output = self._run_cmd(['netstat', '-ano'])
        for line in output.split('\n'):
            if 'LISTENING' in line or 'ESTABLISHED' in line:
                info['connections'].append(line.strip())
        
        # arp
        output = self._run_cmd(['arp', '-a'])
        info['arp_table'] = output
        
        # route
        output = self._run_cmd(['route', 'print'])
        info['routes'] = output
        
        return info
    
    def get_services(self) -> List[Dict]:
        """Enumerate running services."""
        console.print("\n[cyan]⚙️ Enumerating services...[/cyan]")
        
        services = []
        
        output = self._run_cmd(['wmic', 'service', 'get', 'name,displayname,state,startmode,pathname'])
        
        for line in output.split('\n')[1:]:
            if line.strip():
                parts = line.split()
                if len(parts) >= 4:
                    services.append({
                        'name': parts[0],
                        'state': parts[-2] if len(parts) > 2 else 'unknown',
                    })
        
        return services
    
    def get_processes(self) -> List[Dict]:
        """Enumerate running processes."""
        console.print("\n[cyan]📊 Enumerating processes...[/cyan]")
        
        processes = []
        
        output = self._run_cmd(['tasklist', '/v'])
        
        for line in output.split('\n')[3:]:
            if line.strip():
                parts = line.split()
                if len(parts) >= 2:
                    processes.append({
                        'name': parts[0],
                        'pid': parts[1] if len(parts) > 1 else '',
                    })
        
        return processes
    
    def get_installed_software(self) -> List[Dict]:
        """Get installed software."""
        console.print("\n[cyan]📦 Getting installed software...[/cyan]")
        
        software = []
        
        output = self._run_cmd([
            'wmic', 'product', 'get', 'name,version'
        ], timeout=120)
        
        for line in output.split('\n')[1:]:
            if line.strip():
                software.append({'name': line.strip()})
        
        return software
    
    def get_scheduled_tasks(self) -> List[Dict]:
        """Get scheduled tasks."""
        console.print("\n[cyan]📅 Getting scheduled tasks...[/cyan]")
        
        tasks = []
        
        output = self._run_cmd(['schtasks', '/query', '/fo', 'LIST', '/v'])
        
        current_task = {}
        for line in output.split('\n'):
            if 'TaskName:' in line:
                if current_task:
                    tasks.append(current_task)
                current_task = {'name': line.split(':')[1].strip()}
            elif 'Task To Run:' in line:
                current_task['command'] = line.split(':')[1].strip()
            elif 'Run As User:' in line:
                current_task['user'] = line.split(':')[1].strip()
        
        if current_task:
            tasks.append(current_task)
        
        return tasks
    
    def check_antivirus(self) -> Dict:
        """Check installed antivirus."""
        console.print("\n[cyan]🛡️ Checking antivirus...[/cyan]")
        
        av_info = {}
        
        # Windows Defender
        output = self._run_cmd([
            'powershell', '-c',
            'Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled'
        ])
        
        if 'True' in output:
            av_info['defender_enabled'] = True
            console.print("[yellow]  ⚠️ Windows Defender enabled[/yellow]")
        else:
            av_info['defender_enabled'] = False
            console.print("[green]  ✓ Windows Defender disabled[/green]")
        
        # Check for other AV
        av_processes = ['avp.exe', 'avgui.exe', 'avguard.exe', 'mcshield.exe', 
                       'bdagent.exe', 'mbam.exe', 'SavService.exe']
        
        output = self._run_cmd(['tasklist'])
        
        for av in av_processes:
            if av.lower() in output.lower():
                av_info['third_party_av'] = av
                console.print(f"[yellow]  ⚠️ Third-party AV detected: {av}[/yellow]")
        
        return av_info
    
    def get_firewall_status(self) -> Dict:
        """Get firewall status."""
        console.print("\n[cyan]🔥 Checking firewall...[/cyan]")
        
        output = self._run_cmd(['netsh', 'advfirewall', 'show', 'allprofiles'])
        
        return {'status': output}
    
    def get_shares(self) -> List[Dict]:
        """Get network shares."""
        console.print("\n[cyan]📁 Getting network shares...[/cyan]")
        
        shares = []
        
        output = self._run_cmd(['net', 'share'])
        
        for line in output.split('\n')[4:]:
            if line.strip() and 'successfully' not in line.lower():
                parts = line.split()
                if parts:
                    shares.append({'name': parts[0]})
                    console.print(f"[green]  ✓ {parts[0]}[/green]")
        
        return shares


class RemoteWindowsEnumerator:
    """
    Remote Windows enumeration using Impacket tools.
    """
    
    def __init__(self, target: str, username: str, password: str = None,
                 hashes: str = None, domain: str = '.'):
        self.target = target
        self.username = username
        self.password = password
        self.hashes = hashes
        self.domain = domain
    
    def _build_auth(self) -> str:
        """Build authentication string."""
        if self.hashes:
            return f'{self.domain}/{self.username}@{self.target} -hashes {self.hashes}'
        else:
            return f'{self.domain}/{self.username}:{self.password}@{self.target}'
    
    def enum_users_rpcclient(self) -> List[str]:
        """Enumerate users via RPC."""
        console.print("\n[cyan]👥 Enumerating users via RPC...[/cyan]")
        
        users = []
        
        cmd = ['rpcclient', '-U', f'{self.username}%{self.password}', self.target, '-c', 'enumdomusers']
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            for line in result.stdout.split('\n'):
                if 'user:' in line:
                    user = line.split('[')[1].split(']')[0]
                    users.append(user)
                    console.print(f"[green]  ✓ {user}[/green]")
                    
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        
        return users
    
    def enum_shares_smbclient(self) -> List[Dict]:
        """Enumerate shares via SMB."""
        console.print("\n[cyan]📁 Enumerating shares via SMB...[/cyan]")
        
        shares = []
        
        cmd = ['smbclient', '-L', self.target, '-U', f'{self.username}%{self.password}']
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            for line in result.stdout.split('\n'):
                if 'Disk' in line or 'IPC' in line:
                    parts = line.split()
                    if parts:
                        shares.append({'name': parts[0], 'type': parts[1] if len(parts) > 1 else ''})
                        console.print(f"[green]  ✓ {parts[0]}[/green]")
                        
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        
        return shares
    
    def run_crackmapexec(self, module: str = None) -> str:
        """Run CrackMapExec."""
        console.print(f"\n[cyan]🔧 Running CrackMapExec...[/cyan]")
        
        cmd = ['crackmapexec', 'smb', self.target, '-u', self.username]
        
        if self.password:
            cmd.extend(['-p', self.password])
        elif self.hashes:
            cmd.extend(['-H', self.hashes])
        
        if module:
            cmd.extend(['-M', module])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            console.print(result.stdout)
            return result.stdout
        except FileNotFoundError:
            console.print("[yellow]CrackMapExec not found[/yellow]")
            return ""
    
    def run_enum4linux(self) -> str:
        """Run enum4linux."""
        console.print("\n[cyan]🔍 Running enum4linux...[/cyan]")
        
        cmd = ['enum4linux', '-a', self.target]
        
        if self.username and self.password:
            cmd.extend(['-u', self.username, '-p', self.password])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return result.stdout
        except FileNotFoundError:
            console.print("[yellow]enum4linux not found[/yellow]")
            return ""
