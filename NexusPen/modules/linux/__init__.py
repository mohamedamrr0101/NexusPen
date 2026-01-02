"""
NexusPen - Linux Module
=======================
Complete Linux penetration testing module.

Includes:
- recon: Basic Linux reconnaissance
- enumeration: Comprehensive system enumeration
- vulnerabilities: Kernel and service vulnerability scanning
- privesc: Privilege escalation techniques
- persistence: Maintaining access
"""

# Reconnaissance
from .recon import LinuxRecon, LinuxFinding

# Enumeration
from .enumeration import (
    LinuxEnumerator,
    LinuxSystemInfo,
    SSHEnumerator,
    NFSEnumerator,
)

# Vulnerability scanning
from .vulnerabilities import (
    LinuxVulnScanner,
    LinuxVulnerability,
)

# Privilege escalation
from .privesc import (
    LinuxPrivEsc,
    PrivEscVector,
)

# Persistence
from .persistence import (
    LinuxPersistence,
    PersistenceMethod,
)

__all__ = [
    # Recon
    'LinuxRecon', 'LinuxFinding',
    
    # Enumeration
    'LinuxEnumerator', 'LinuxSystemInfo', 'SSHEnumerator', 'NFSEnumerator',
    
    # Vulnerabilities
    'LinuxVulnScanner', 'LinuxVulnerability',
    
    # Privilege Escalation
    'LinuxPrivEsc', 'PrivEscVector',
    
    # Persistence
    'LinuxPersistence', 'PersistenceMethod',
]


def run_full_assessment(target: str = None, ssh_creds: dict = None) -> dict:
    """
    Run complete Linux security assessment.
    
    Args:
        target: Target IP (for remote assessment)
        ssh_creds: SSH credentials {'username': '', 'password'/'key': ''}
    """
    from rich.console import Console
    console = Console()
    
    console.print("\n[bold red]═══════════════════════════════════════════════════════════[/bold red]")
    console.print("[bold red]              LINUX SECURITY ASSESSMENT                      [/bold red]")
    console.print("[bold red]═══════════════════════════════════════════════════════════[/bold red]")
    
    results = {
        'enumeration': {},
        'vulnerabilities': [],
        'privesc_vectors': [],
        'persistence_options': []
    }
    
    # 1. Enumeration
    console.print("\n[cyan]━━━ Phase 1: Enumeration ━━━[/cyan]")
    enumerator = LinuxEnumerator(target, ssh_creds)
    results['enumeration'] = enumerator.run_full_enumeration()
    
    # 2. Vulnerability Scanning
    console.print("\n[cyan]━━━ Phase 2: Vulnerability Scanning ━━━[/cyan]")
    vuln_scanner = LinuxVulnScanner(target)
    results['vulnerabilities'] = vuln_scanner.run_full_scan()
    
    # 3. Privilege Escalation
    console.print("\n[cyan]━━━ Phase 3: Privilege Escalation ━━━[/cyan]")
    privesc = LinuxPrivEsc()
    results['privesc_vectors'] = privesc.run_full_check()
    
    # Summary
    console.print("\n[bold cyan]═══ ASSESSMENT SUMMARY ═══[/bold cyan]")
    console.print(f"[yellow]Users Found: {len(results['enumeration'].get('users', []))}[/yellow]")
    console.print(f"[yellow]SUID Binaries: {len(results['enumeration'].get('suid', []))}[/yellow]")
    console.print(f"[red]Vulnerabilities: {len(results['vulnerabilities'])}[/red]")
    console.print(f"[red]PrivEsc Vectors: {len(results['privesc_vectors'])}[/red]")
    
    return results
