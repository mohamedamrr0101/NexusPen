#!/usr/bin/env python3
"""
NexusPen - Wireless Network Testing Module
===========================================
WiFi security assessment and attacks.
"""

import subprocess
import re
import os
import time
from typing import Dict, List, Optional
from dataclasses import dataclass

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

console = Console()


@dataclass
class WirelessNetwork:
    """Represents a wireless network."""
    bssid: str
    essid: str
    channel: int
    encryption: str
    cipher: Optional[str] = None
    auth: Optional[str] = None
    power: int = 0
    clients: int = 0


@dataclass 
class WirelessFinding:
    """Represents a wireless security finding."""
    bssid: str
    essid: str
    severity: str
    title: str
    description: str


class WirelessScanner:
    """Wireless network scanner."""
    
    def __init__(self, interface: str = 'wlan0', config: Dict = None):
        self.interface = interface
        self.config = config or {}
        self.networks: List[WirelessNetwork] = []
        self.findings: List[WirelessFinding] = []
        self.monitor_interface = None
    
    def enable_monitor_mode(self) -> bool:
        """Enable monitor mode on wireless interface."""
        console.print(f"[cyan]📡 Enabling monitor mode on {self.interface}[/cyan]")
        
        try:
            # Kill interfering processes
            subprocess.run(['airmon-ng', 'check', 'kill'], 
                         capture_output=True, timeout=30)
            
            # Enable monitor mode
            result = subprocess.run(
                ['airmon-ng', 'start', self.interface],
                capture_output=True, text=True, timeout=30
            )
            
            # Find monitor interface name
            if 'monitor mode' in result.stdout.lower():
                # Usually becomes wlan0mon
                self.monitor_interface = f"{self.interface}mon"
                
                # Check if interface exists
                result2 = subprocess.run(['iwconfig', self.monitor_interface],
                                       capture_output=True, text=True)
                if result2.returncode == 0:
                    console.print(f"[green]✓ Monitor mode enabled: {self.monitor_interface}[/green]")
                    return True
            
            return False
            
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            console.print(f"[red]❌ Failed to enable monitor mode: {e}[/red]")
            return False
    
    def disable_monitor_mode(self):
        """Disable monitor mode."""
        if self.monitor_interface:
            try:
                subprocess.run(['airmon-ng', 'stop', self.monitor_interface],
                             capture_output=True, timeout=30)
                console.print("[green]✓ Monitor mode disabled[/green]")
            except:
                pass
    
    def scan_networks(self, duration: int = 30) -> List[WirelessNetwork]:
        """
        Scan for wireless networks.
        
        Args:
            duration: Scan duration in seconds
        """
        console.print(f"\n[cyan]🔍 Scanning wireless networks for {duration}s...[/cyan]")
        
        interface = self.monitor_interface or self.interface
        output_file = '/tmp/airodump_scan'
        
        try:
            # Run airodump-ng
            cmd = [
                'airodump-ng',
                interface,
                '-w', output_file,
                '--output-format', 'csv',
                '--write-interval', '2'
            ]
            
            # Run for specified duration
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, 
                                   stderr=subprocess.DEVNULL)
            time.sleep(duration)
            proc.terminate()
            proc.wait()
            
            # Parse results
            csv_file = f"{output_file}-01.csv"
            if os.path.exists(csv_file):
                self._parse_airodump_csv(csv_file)
                os.remove(csv_file)
            
        except FileNotFoundError:
            console.print("[red]❌ airodump-ng not found[/red]")
            # Fallback to iwlist
            self._scan_with_iwlist()
        
        self._display_networks()
        return self.networks
    
    def _scan_with_iwlist(self):
        """Fallback scan using iwlist."""
        try:
            result = subprocess.run(
                ['iwlist', self.interface, 'scan'],
                capture_output=True, text=True, timeout=30
            )
            
            current_network = None
            
            for line in result.stdout.split('\n'):
                if 'Cell' in line and 'Address:' in line:
                    bssid = re.search(r'Address:\s*([0-9A-F:]+)', line)
                    if bssid:
                        if current_network:
                            self.networks.append(current_network)
                        current_network = WirelessNetwork(
                            bssid=bssid.group(1),
                            essid='',
                            channel=0,
                            encryption='Unknown'
                        )
                
                elif current_network:
                    if 'ESSID:' in line:
                        essid = re.search(r'ESSID:"([^"]*)"', line)
                        if essid:
                            current_network.essid = essid.group(1)
                    
                    elif 'Channel:' in line:
                        channel = re.search(r'Channel:(\d+)', line)
                        if channel:
                            current_network.channel = int(channel.group(1))
                    
                    elif 'Encryption key:' in line:
                        if 'on' in line:
                            current_network.encryption = 'WEP/WPA'
                        else:
                            current_network.encryption = 'Open'
                    
                    elif 'WPA2' in line:
                        current_network.encryption = 'WPA2'
                    elif 'WPA' in line:
                        current_network.encryption = 'WPA'
            
            if current_network:
                self.networks.append(current_network)
                
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
    
    def _parse_airodump_csv(self, csv_file: str):
        """Parse airodump-ng CSV output."""
        try:
            with open(csv_file, 'r', errors='ignore') as f:
                lines = f.readlines()
            
            parsing_aps = False
            parsing_clients = False
            
            for line in lines:
                line = line.strip()
                
                if 'BSSID' in line and 'ESSID' in line:
                    parsing_aps = True
                    parsing_clients = False
                    continue
                
                if 'Station MAC' in line:
                    parsing_aps = False
                    parsing_clients = True
                    continue
                
                if parsing_aps and line:
                    parts = [p.strip() for p in line.split(',')]
                    if len(parts) >= 14:
                        try:
                            self.networks.append(WirelessNetwork(
                                bssid=parts[0],
                                essid=parts[13] if len(parts) > 13 else '',
                                channel=int(parts[3]) if parts[3].strip().isdigit() else 0,
                                encryption=parts[5],
                                cipher=parts[6] if len(parts) > 6 else None,
                                auth=parts[7] if len(parts) > 7 else None,
                                power=int(parts[8]) if parts[8].strip().lstrip('-').isdigit() else 0
                            ))
                        except (ValueError, IndexError):
                            continue
                            
        except Exception as e:
            console.print(f"[yellow]Warning parsing CSV: {e}[/yellow]")
    
    def check_vulnerabilities(self):
        """Check for wireless security vulnerabilities."""
        console.print("\n[cyan]🔓 Checking wireless vulnerabilities...[/cyan]")
        
        for network in self.networks:
            # Open network
            if network.encryption.lower() == 'open' or network.encryption.lower() == 'opn':
                self.findings.append(WirelessFinding(
                    bssid=network.bssid,
                    essid=network.essid,
                    severity='high',
                    title='Open Wireless Network',
                    description='Network has no encryption, traffic can be sniffed'
                ))
            
            # WEP
            elif 'wep' in network.encryption.lower():
                self.findings.append(WirelessFinding(
                    bssid=network.bssid,
                    essid=network.essid,
                    severity='critical',
                    title='WEP Encryption (Deprecated)',
                    description='WEP can be cracked in minutes, use WPA2/WPA3'
                ))
            
            # WPA (not WPA2)
            elif network.encryption.lower() == 'wpa' and 'wpa2' not in network.encryption.lower():
                self.findings.append(WirelessFinding(
                    bssid=network.bssid,
                    essid=network.essid,
                    severity='medium',
                    title='WPA Encryption (Weak)',
                    description='WPA is deprecated, use WPA2/WPA3'
                ))
            
            # TKIP
            if network.cipher and 'tkip' in network.cipher.lower():
                self.findings.append(WirelessFinding(
                    bssid=network.bssid,
                    essid=network.essid,
                    severity='medium',
                    title='TKIP Cipher (Weak)',
                    description='TKIP has known vulnerabilities, use AES/CCMP'
                ))
        
        console.print(f"[yellow]⚠️ Found {len(self.findings)} wireless security issues[/yellow]")
    
    def capture_handshake(self, bssid: str, channel: int, 
                         output_file: str = '/tmp/handshake',
                         timeout: int = 120) -> bool:
        """
        Capture WPA handshake for offline cracking.
        
        Args:
            bssid: Target AP BSSID
            channel: Target channel
            output_file: Output file path
            timeout: Capture timeout
        """
        console.print(f"\n[cyan]🤝 Capturing handshake for {bssid}...[/cyan]")
        
        interface = self.monitor_interface or self.interface
        
        try:
            # Set channel
            subprocess.run(['iwconfig', interface, 'channel', str(channel)],
                         capture_output=True, timeout=5)
            
            # Start capture
            cmd = [
                'airodump-ng',
                '-c', str(channel),
                '--bssid', bssid,
                '-w', output_file,
                interface
            ]
            
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
            
            # Wait for handshake or timeout
            start_time = time.time()
            cap_file = f"{output_file}-01.cap"
            
            while time.time() - start_time < timeout:
                if os.path.exists(cap_file):
                    # Check if handshake captured
                    result = subprocess.run(
                        ['aircrack-ng', cap_file],
                        capture_output=True, text=True, timeout=10
                    )
                    
                    if 'handshake' in result.stdout.lower():
                        proc.terminate()
                        console.print(f"[green]✓ Handshake captured: {cap_file}[/green]")
                        return True
                
                time.sleep(5)
            
            proc.terminate()
            console.print("[yellow]⚠️ Handshake capture timeout[/yellow]")
            return False
            
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            console.print(f"[red]❌ Error: {e}[/red]")
            return False
    
    def deauth_attack(self, bssid: str, client: str = None, 
                     packets: int = 10) -> bool:
        """
        Send deauthentication packets.
        
        Args:
            bssid: Target AP BSSID
            client: Specific client MAC (or broadcast)
            packets: Number of deauth packets
        """
        console.print(f"\n[cyan]💀 Sending deauth to {bssid}...[/cyan]")
        
        interface = self.monitor_interface or self.interface
        
        try:
            cmd = [
                'aireplay-ng',
                '-0', str(packets),  # Deauth
                '-a', bssid,
                interface
            ]
            
            if client:
                cmd.extend(['-c', client])
            
            subprocess.run(cmd, capture_output=True, timeout=30)
            console.print("[green]✓ Deauth packets sent[/green]")
            return True
            
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            console.print(f"[red]❌ Error: {e}[/red]")
            return False
    
    def crack_handshake(self, cap_file: str, wordlist: str) -> Optional[str]:
        """
        Crack WPA handshake.
        
        Args:
            cap_file: Capture file with handshake
            wordlist: Wordlist file
        """
        console.print(f"\n[cyan]🔓 Cracking handshake...[/cyan]")
        
        try:
            cmd = ['aircrack-ng', '-w', wordlist, cap_file]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            
            # Parse password
            match = re.search(r'KEY FOUND!\s*\[\s*(.+?)\s*\]', result.stdout)
            if match:
                password = match.group(1)
                console.print(f"[green]✓ Password found: {password}[/green]")
                return password
            else:
                console.print("[yellow]⚠️ Password not found[/yellow]")
                return None
                
        except subprocess.TimeoutExpired:
            console.print("[yellow]⚠️ Cracking timeout[/yellow]")
            return None
        except FileNotFoundError:
            console.print("[red]❌ aircrack-ng not found[/red]")
            return None
    
    def _display_networks(self):
        """Display discovered networks."""
        if not self.networks:
            console.print("[yellow]No wireless networks found[/yellow]")
            return
        
        table = Table(title="Wireless Networks", show_header=True,
                     header_style="bold magenta")
        table.add_column("ESSID", style="cyan")
        table.add_column("BSSID", style="dim")
        table.add_column("CH", style="yellow", width=4)
        table.add_column("Encryption", style="white")
        table.add_column("Power", width=6)
        
        for net in sorted(self.networks, key=lambda x: x.power, reverse=True)[:20]:
            enc_style = "red" if 'wep' in net.encryption.lower() or net.encryption.lower() == 'open' else "green"
            table.add_row(
                net.essid or '<hidden>',
                net.bssid,
                str(net.channel),
                f"[{enc_style}]{net.encryption}[/{enc_style}]",
                str(net.power)
            )
        
        console.print(table)
        console.print(f"\n[green]Total: {len(self.networks)} networks[/green]")


# Module entry point
def run(interface: str = 'wlan0', results: list = None):
    """Main entry point for wireless module."""
    scanner = WirelessScanner(interface)
    
    if scanner.enable_monitor_mode():
        scanner.scan_networks(duration=30)
        scanner.check_vulnerabilities()
        scanner.disable_monitor_mode()
        
        if results is not None:
            results.append({
                'module': 'wireless.scan',
                'phase': 'recon',
                'networks': [n.__dict__ for n in scanner.networks],
                'findings': [f.__dict__ for f in scanner.findings]
            })
