"""
NexusPen - Windows Module
==========================
Complete Windows penetration testing module.

Includes:
- recon: Windows reconnaissance
- enumeration: System, user, service enumeration
- privesc: Privilege escalation vectors
- vulnerabilities: Windows CVE detection
- persistence: Persistence techniques
- lateral_movement: Lateral movement methods
- evasion: Defense evasion techniques
- credential_access: Credential extraction
"""

# Reconnaissance
from .recon import (
    WindowsRecon,
    SMBRecon,
)

# Enumeration
from .enumeration import (
    WindowsEnumerator,
    WindowsSystemInfo,
    RemoteWindowsEnumerator,
)

# Privilege Escalation
from .privesc import (
    WindowsPrivEsc,
    PrivEscVector,
    PotatoExploits,
)

# Vulnerabilities
from .vulnerabilities import (
    WindowsVulnScanner,
    WindowsVulnerability,
)

# Persistence
from .persistence import (
    WindowsPersistence,
    PersistenceMethod,
)

# Lateral Movement
from .lateral_movement import (
    WindowsLateralMovement,
    LateralMethod,
    PassTheHash,
    PassTheTicket,
    OverpassTheHash,
)

# Defense Evasion
from .evasion import (
    AMSIBypass,
    DefenderBypass,
    ETWBypass,
    UACBypass,
    AppLockerBypass,
    CLMBypass,
    LogEvasion,
)

# Credential Access
from .credential_access import (
    Mimikatz,
    LaZagne,
    WindowsCredentialExtractor,
    ExtractedCredential,
    Kerberoast,
    ASREPRoast,
)

__all__ = [
    # Recon
    'WindowsRecon', 'SMBRecon',
    
    # Enumeration
    'WindowsEnumerator', 'WindowsSystemInfo', 'RemoteWindowsEnumerator',
    
    # PrivEsc
    'WindowsPrivEsc', 'PrivEscVector', 'PotatoExploits',
    
    # Vulnerabilities
    'WindowsVulnScanner', 'WindowsVulnerability',
    
    # Persistence
    'WindowsPersistence', 'PersistenceMethod',
    
    # Lateral Movement
    'WindowsLateralMovement', 'LateralMethod',
    'PassTheHash', 'PassTheTicket', 'OverpassTheHash',
    
    # Evasion
    'AMSIBypass', 'DefenderBypass', 'ETWBypass',
    'UACBypass', 'AppLockerBypass', 'CLMBypass', 'LogEvasion',
    
    # Credential Access
    'Mimikatz', 'LaZagne', 'WindowsCredentialExtractor',
    'ExtractedCredential', 'Kerberoast', 'ASREPRoast',
]


def run_full_assessment(target: str = None, local: bool = True) -> dict:
    """
    Run comprehensive Windows security assessment.
    
    Args:
        target: Remote target IP (optional)
        local: Run local checks
    """
    from rich.console import Console
    console = Console()
    
    console.print("\n[bold red]═══════════════════════════════════════════════════════════[/bold red]")
    console.print("[bold red]              WINDOWS SECURITY ASSESSMENT                   [/bold red]")
    console.print("[bold red]═══════════════════════════════════════════════════════════[/bold red]")
    
    results = {
        'system_info': {},
        'users': [],
        'services': [],
        'privesc_vectors': [],
        'vulnerabilities': [],
        'credentials': [],
    }
    
    if local:
        # Local enumeration
        console.print("\n[cyan]━━━ Phase 1: Local Enumeration ━━━[/cyan]")
        try:
            enumerator = WindowsEnumerator()
            results['system_info'] = enumerator.get_system_info()
            results['users'] = enumerator.get_users()
            results['services'] = enumerator.get_services()
        except Exception as e:
            console.print(f"[red]Enumeration error: {e}[/red]")
        
        # Privilege escalation check
        console.print("\n[cyan]━━━ Phase 2: Privilege Escalation Check ━━━[/cyan]")
        try:
            privesc = WindowsPrivEsc()
            results['privesc_vectors'] = privesc.check_all()
        except Exception as e:
            console.print(f"[red]PrivEsc check error: {e}[/red]")
    
    if target:
        # Remote vulnerability scan
        console.print("\n[cyan]━━━ Phase 3: Remote Vulnerability Scan ━━━[/cyan]")
        try:
            vuln_scanner = WindowsVulnScanner(target)
            results['vulnerabilities'] = vuln_scanner.run_full_scan()
        except Exception as e:
            console.print(f"[red]Vuln scan error: {e}[/red]")
    
    # Summary
    console.print("\n[bold cyan]═══ ASSESSMENT SUMMARY ═══[/bold cyan]")
    console.print(f"[cyan]PrivEsc Vectors: {len(results['privesc_vectors'])}[/cyan]")
    console.print(f"[cyan]Vulnerabilities: {len(results['vulnerabilities'])}[/cyan]")
    
    return results


# MITRE ATT&CK Mapping
MITRE_ATTACK_MAPPING = {
    'T1003': {
        'name': 'OS Credential Dumping',
        'techniques': ['Mimikatz', 'LSASS dump', 'SAM dump', 'DCSync'],
    },
    'T1003.001': {
        'name': 'LSASS Memory',
        'techniques': ['Mimikatz sekurlsa::logonpasswords', 'ProcDump', 'comsvcs.dll'],
    },
    'T1003.002': {
        'name': 'Security Account Manager',
        'techniques': ['reg save', 'secretsdump', 'Mimikatz lsadump::sam'],
    },
    'T1003.003': {
        'name': 'NTDS',
        'techniques': ['DCSync', 'VSS shadow copy', 'ntdsutil'],
    },
    'T1003.006': {
        'name': 'DCSync',
        'techniques': ['Mimikatz lsadump::dcsync', 'secretsdump'],
    },
    'T1558.003': {
        'name': 'Kerberoasting',
        'techniques': ['Rubeus kerberoast', 'GetUserSPNs'],
    },
    'T1558.004': {
        'name': 'AS-REP Roasting',
        'techniques': ['Rubeus asreproast', 'GetNPUsers'],
    },
    'T1021': {
        'name': 'Remote Services',
        'techniques': ['PSExec', 'WMIExec', 'WinRM', 'RDP'],
    },
    'T1053': {
        'name': 'Scheduled Task',
        'techniques': ['schtasks', 'ATExec'],
    },
    'T1547.001': {
        'name': 'Registry Run Keys',
        'techniques': ['Run/RunOnce keys', 'Startup folder'],
    },
    'T1548.002': {
        'name': 'UAC Bypass',
        'techniques': ['fodhelper', 'eventvwr', 'sdclt', 'cmstp'],
    },
    'T1562.001': {
        'name': 'Disable Security Tools',
        'techniques': ['Defender disable', 'AMSI bypass', 'ETW bypass'],
    },
    'T1134': {
        'name': 'Access Token Manipulation',
        'techniques': ['Token impersonation', 'Potato attacks'],
    },
}


# Cheat sheet
WINDOWS_PENTEST_CHEATSHEET = '''
# Windows Pentesting Cheat Sheet

## Initial Enumeration
- systeminfo
- whoami /all
- net user / net localgroup
- netstat -ano
- tasklist /v

## Check Privileges
- whoami /priv
- accesschk.exe -uwcqv *

## Credential Extraction
- mimikatz: sekurlsa::logonpasswords
- reg save HKLM\\SAM sam
- secretsdump.py

## Lateral Movement
- psexec.py domain/user:pass@target
- wmiexec.py domain/user:pass@target
- evil-winrm -i target -u user -p pass

## Persistence
- reg add HKCU\\...\\Run
- schtasks /create
- sc create

## Evasion
- AMSI bypass (reflection)
- Defender exclusions
- UAC bypass (fodhelper)
'''
