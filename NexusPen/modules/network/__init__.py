"""
NexusPen - Network Module
=========================
Complete network penetration testing module.

Includes:
- scanner: Port scanning and service detection
- enumeration: Network device enumeration (SNMP, SMB, LDAP)
- vulnerabilities: Network vulnerability scanning
- attacks: Network attack techniques (MITM, ARP, DNS)
"""

# Scanner
from .scanner import NetworkScanner

# Enumeration
from .enumeration import (
    NetworkEnumerator,
    NetworkDevice,
    ServiceInfo,
    SNMPEnumerator,
    SMBEnumerator,
    LDAPEnumerator,
    NetBIOSEnumerator
)

# Vulnerability scanning
from .vulnerabilities import (
    NetworkVulnScanner,
    NetworkVulnerability
)

# Attacks
from .attacks import (
    ARPAttacks,
    DNSAttacks,
    MITMAttacks,
    SniffingAttacks,
    VLANAttacks,
    STPAttacks,
    DHCPAttacks,
    NetworkDoS,
    WirelessAttacks,
    display_all_attacks
)

__all__ = [
    # Scanner
    'NetworkScanner',
    
    # Enumeration
    'NetworkEnumerator', 'NetworkDevice', 'ServiceInfo',
    'SNMPEnumerator', 'SMBEnumerator', 'LDAPEnumerator', 'NetBIOSEnumerator',
    
    # Vulnerabilities
    'NetworkVulnScanner', 'NetworkVulnerability',
    
    # Attacks
    'ARPAttacks', 'DNSAttacks', 'MITMAttacks', 'SniffingAttacks',
    'VLANAttacks', 'STPAttacks', 'DHCPAttacks', 'NetworkDoS',
    'WirelessAttacks', 'display_all_attacks',
]


def run_full_assessment(target: str, interface: str = 'eth0') -> dict:
    """
    Run complete network security assessment.
    
    Args:
        target: Target IP or subnet
        interface: Network interface to use
    """
    from rich.console import Console
    console = Console()
    
    console.print("\n[bold red]═══════════════════════════════════════════════════════════[/bold red]")
    console.print("[bold red]              NETWORK SECURITY ASSESSMENT                   [/bold red]")
    console.print("[bold red]═══════════════════════════════════════════════════════════[/bold red]")
    
    results = {
        'enumeration': {},
        'vulnerabilities': [],
        'available_attacks': []
    }
    
    # 1. Network Enumeration
    console.print("\n[cyan]━━━ Phase 1: Network Enumeration ━━━[/cyan]")
    enumerator = NetworkEnumerator(interface)
    
    # Host discovery
    if '/' in target:
        devices = enumerator.arp_scan(target)
        results['enumeration']['devices'] = [d.__dict__ for d in devices]
    else:
        results['enumeration']['target'] = target
    
    # SNMP enumeration
    snmp = SNMPEnumerator(target)
    communities = snmp.brute_community()
    if communities:
        results['enumeration']['snmp_communities'] = communities
        results['enumeration']['snmp_info'] = snmp.get_system_info(communities[0])
    
    # SMB enumeration
    smb = SMBEnumerator(target)
    if smb.check_null_session():
        results['enumeration']['smb_shares'] = smb.list_shares()
        results['enumeration']['smb_users'] = smb.get_users_rpc()
    
    # 2. Vulnerability Scanning
    console.print("\n[cyan]━━━ Phase 2: Vulnerability Scanning ━━━[/cyan]")
    vuln_scanner = NetworkVulnScanner(target)
    results['vulnerabilities'] = [v.__dict__ for v in vuln_scanner.run_full_scan()]
    
    # 3. Available Attacks
    console.print("\n[cyan]━━━ Phase 3: Attack Recommendations ━━━[/cyan]")
    display_all_attacks()
    
    # Summary
    console.print("\n[bold cyan]═══ ASSESSMENT SUMMARY ═══[/bold cyan]")
    console.print(f"[yellow]SNMP Communities: {len(results['enumeration'].get('snmp_communities', []))}[/yellow]")
    console.print(f"[yellow]SMB Shares: {len(results['enumeration'].get('smb_shares', []))}[/yellow]")
    console.print(f"[red]Vulnerabilities: {len(results['vulnerabilities'])}[/red]")
    
    return results
