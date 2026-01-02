"""
NexusPen - Active Directory Module
===================================
Complete AD testing capabilities.

Modules:
- recon: Basic AD reconnaissance
- attacks: Impacket attacks, tickets, NTLM relay, ADCS
- enumeration: LDAP enumeration (users, groups, SPNs, delegations)
- vulnerabilities: CVE checks (Zerologon, noPac, PrintNightmare, etc.)
- persistence: AD persistence techniques
- bloodhound: BloodHound data collection and analysis
"""

# Basic recon
from .recon import ADRecon, KerberosAttacks, BloodHound as BHLegacy, ADFinding, run

# Advanced attacks
from .attacks import (
    ImpacketAttacks,
    TicketAttacks,
    NTLMRelayAttacks,
    ADAttackResult,
)

# Enumeration
from .enumeration import (
    LDAPEnumerator,
    PowerViewEnumerator,
    ADObject,
)

# Vulnerability scanning
from .vulnerabilities import (
    ADVulnerabilityScanner,
    ADVulnerability,
)

# Persistence and lateral movement
from .persistence import (
    ADPersistence,
    LateralMovement,
    PersistenceResult,
)

# BloodHound integration
from .bloodhound import (
    BloodHoundCollector,
    BloodHoundAnalyzer,
    ADPathFinder,
    BloodHoundResult,
)

__all__ = [
    # Recon
    'ADRecon', 'KerberosAttacks', 'BHLegacy', 'ADFinding', 'run',
    
    # Attacks
    'ImpacketAttacks', 'TicketAttacks', 'NTLMRelayAttacks', 'ADAttackResult',
    
    # Enumeration
    'LDAPEnumerator', 'PowerViewEnumerator', 'ADObject',
    
    # Vulnerabilities
    'ADVulnerabilityScanner', 'ADVulnerability',
    
    # Persistence
    'ADPersistence', 'LateralMovement', 'PersistenceResult',
    
    # BloodHound
    'BloodHoundCollector', 'BloodHoundAnalyzer', 
    'ADPathFinder', 'BloodHoundResult',
]


# Convenience function for full AD assessment
def run_full_assessment(dc_ip: str, domain: str, username: str, 
                       password: str, output_dir: str = None) -> dict:
    """
    Run comprehensive AD assessment.
    
    Args:
        dc_ip: Domain Controller IP
        domain: Domain name (e.g., corp.local)
        username: Username for authentication
        password: Password
        output_dir: Output directory for results
        
    Returns:
        Dictionary with all assessment results
    """
    from rich.console import Console
    console = Console()
    
    console.print("\n[bold red]╔═══════════════════════════════════════════════════════════════╗[/bold red]")
    console.print("[bold red]║     NEXUSPEN - ACTIVE DIRECTORY FULL ASSESSMENT              ║[/bold red]")
    console.print("[bold red]╚═══════════════════════════════════════════════════════════════╝[/bold red]")
    console.print(f"\n[cyan]Target: {domain} ({dc_ip})[/cyan]")
    console.print(f"[cyan]User: {username}[/cyan]\n")
    
    results = {
        'domain': domain,
        'dc_ip': dc_ip,
        'enumeration': {},
        'vulnerabilities': [],
        'kerberoastable': [],
        'asrep_roastable': [],
        'delegations': {},
        'bloodhound': None
    }
    
    # 1. LDAP Enumeration
    console.print("\n[bold yellow]═══ PHASE 1: ENUMERATION ═══[/bold yellow]")
    enumerator = LDAPEnumerator(dc_ip, domain, username, password)
    results['enumeration'] = enumerator.run_full_enumeration()
    
    # 2. Vulnerability Scanning
    console.print("\n[bold yellow]═══ PHASE 2: VULNERABILITY SCAN ═══[/bold yellow]")
    vuln_scanner = ADVulnerabilityScanner(dc_ip, domain)
    results['vulnerabilities'] = vuln_scanner.scan_all(username, password)
    
    # 3. BloodHound Collection
    console.print("\n[bold yellow]═══ PHASE 3: BLOODHOUND COLLECTION ═══[/bold yellow]")
    bh_collector = BloodHoundCollector(domain, dc_ip, username, password)
    results['bloodhound'] = bh_collector.collect_all(output_dir)
    
    # Summary
    console.print("\n[bold green]═══ ASSESSMENT COMPLETE ═══[/bold green]")
    console.print(f"[green]Users: {len(results['enumeration'].get('users', []))}[/green]")
    console.print(f"[green]Computers: {len(results['enumeration'].get('computers', []))}[/green]")
    console.print(f"[red]Vulnerabilities: {len(results['vulnerabilities'])}[/red]")
    
    return results
