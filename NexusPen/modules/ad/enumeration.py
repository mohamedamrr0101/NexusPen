#!/usr/bin/env python3
"""
NexusPen - Active Directory Enumeration Module
===============================================
Comprehensive AD enumeration using multiple tools.

Includes:
- LDAP enumeration
- GPO enumeration
- ACL enumeration
- Trust enumeration
- SPN enumeration
- Delegation enumeration
"""

import subprocess
import re
import json
import ldap3
from typing import Dict, List, Optional
from dataclasses import dataclass, field

from rich.console import Console
from rich.table import Table
from rich.tree import Tree

console = Console()


@dataclass
class ADObject:
    """Represents an AD object."""
    dn: str
    name: str
    object_class: str
    attributes: Dict = field(default_factory=dict)


class LDAPEnumerator:
    """
    Advanced LDAP enumeration.
    """
    
    def __init__(self, dc_ip: str, domain: str, username: str = None, 
                 password: str = None, use_ssl: bool = False):
        self.dc_ip = dc_ip
        self.domain = domain
        self.username = username
        self.password = password
        self.use_ssl = use_ssl
        self.connection = None
        self.base_dn = ','.join([f'DC={part}' for part in domain.split('.')])
    
    def connect(self) -> bool:
        """Establish LDAP connection."""
        try:
            server = ldap3.Server(
                self.dc_ip,
                port=636 if self.use_ssl else 389,
                use_ssl=self.use_ssl,
                get_info=ldap3.ALL
            )
            
            if self.username and self.password:
                self.connection = ldap3.Connection(
                    server,
                    user=f'{self.domain}\\{self.username}',
                    password=self.password,
                    authentication=ldap3.NTLM
                )
            else:
                self.connection = ldap3.Connection(server)
            
            if self.connection.bind():
                console.print("[green]✓ LDAP connection established[/green]")
                return True
            else:
                console.print(f"[red]LDAP bind failed: {self.connection.last_error}[/red]")
                return False
                
        except Exception as e:
            console.print(f"[red]LDAP error: {e}[/red]")
            return False
    
    def get_domain_info(self) -> Dict:
        """Get domain information."""
        console.print("\n[cyan]📋 Getting domain information...[/cyan]")
        
        info = {
            'domain': self.domain,
            'base_dn': self.base_dn,
            'functional_level': None,
            'domain_controllers': [],
            'forest_name': None,
        }
        
        if not self.connection:
            return info
        
        try:
            # Query domain object
            self.connection.search(
                self.base_dn,
                '(objectClass=domain)',
                attributes=['*']
            )
            
            if self.connection.entries:
                entry = self.connection.entries[0]
                info['functional_level'] = str(entry.get('msDS-Behavior-Version', ''))
                
        except Exception as e:
            console.print(f"[yellow]Warning: {e}[/yellow]")
        
        return info
    
    def enumerate_users(self, detailed: bool = False) -> List[Dict]:
        """Enumerate all domain users."""
        console.print("\n[cyan]👥 Enumerating users...[/cyan]")
        
        users = []
        
        if not self.connection:
            return users
        
        try:
            attributes = ['sAMAccountName', 'displayName', 'mail', 'memberOf',
                         'userAccountControl', 'lastLogon', 'pwdLastSet',
                         'description', 'adminCount']
            
            self.connection.search(
                self.base_dn,
                '(&(objectClass=user)(objectCategory=person))',
                attributes=attributes
            )
            
            for entry in self.connection.entries:
                user = {
                    'username': str(entry.sAMAccountName),
                    'display_name': str(entry.displayName) if entry.displayName else '',
                    'email': str(entry.mail) if entry.mail else '',
                    'groups': [str(g) for g in entry.memberOf] if entry.memberOf else [],
                    'uac': int(entry.userAccountControl) if entry.userAccountControl else 0,
                    'admin_count': bool(entry.adminCount) if entry.adminCount else False,
                    'description': str(entry.description) if entry.description else '',
                }
                
                # Parse UAC flags
                uac = user['uac']
                user['disabled'] = bool(uac & 0x0002)
                user['password_not_required'] = bool(uac & 0x0020)
                user['password_never_expires'] = bool(uac & 0x10000)
                user['dont_require_preauth'] = bool(uac & 0x400000)  # AS-REP roastable
                
                users.append(user)
            
            console.print(f"[green]✓ Found {len(users)} users[/green]")
            
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        
        return users
    
    def enumerate_groups(self) -> List[Dict]:
        """Enumerate all domain groups."""
        console.print("\n[cyan]👪 Enumerating groups...[/cyan]")
        
        groups = []
        
        if not self.connection:
            return groups
        
        try:
            self.connection.search(
                self.base_dn,
                '(objectClass=group)',
                attributes=['sAMAccountName', 'description', 'member', 'adminCount']
            )
            
            for entry in self.connection.entries:
                group = {
                    'name': str(entry.sAMAccountName),
                    'description': str(entry.description) if entry.description else '',
                    'members': len(entry.member) if entry.member else 0,
                    'admin_count': bool(entry.adminCount) if entry.adminCount else False,
                }
                groups.append(group)
            
            console.print(f"[green]✓ Found {len(groups)} groups[/green]")
            
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        
        return groups
    
    def enumerate_computers(self) -> List[Dict]:
        """Enumerate all domain computers."""
        console.print("\n[cyan]💻 Enumerating computers...[/cyan]")
        
        computers = []
        
        if not self.connection:
            return computers
        
        try:
            self.connection.search(
                self.base_dn,
                '(objectClass=computer)',
                attributes=['sAMAccountName', 'dNSHostName', 'operatingSystem',
                           'operatingSystemVersion', 'lastLogon', 'userAccountControl']
            )
            
            for entry in self.connection.entries:
                computer = {
                    'name': str(entry.sAMAccountName).rstrip('$'),
                    'dns_name': str(entry.dNSHostName) if entry.dNSHostName else '',
                    'os': str(entry.operatingSystem) if entry.operatingSystem else '',
                    'os_version': str(entry.operatingSystemVersion) if entry.operatingSystemVersion else '',
                }
                
                # Check if it's a DC
                uac = int(entry.userAccountControl) if entry.userAccountControl else 0
                computer['is_dc'] = bool(uac & 0x2000)
                
                computers.append(computer)
            
            console.print(f"[green]✓ Found {len(computers)} computers[/green]")
            
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        
        return computers
    
    def enumerate_domain_admins(self) -> List[str]:
        """Enumerate Domain Admins group members."""
        console.print("\n[cyan]👑 Enumerating Domain Admins...[/cyan]")
        
        admins = []
        
        if not self.connection:
            return admins
        
        try:
            # Find Domain Admins group
            self.connection.search(
                self.base_dn,
                '(&(objectClass=group)(sAMAccountName=Domain Admins))',
                attributes=['member']
            )
            
            if self.connection.entries:
                members = self.connection.entries[0].member
                if members:
                    for member_dn in members:
                        # Get username from DN
                        match = re.search(r'CN=([^,]+)', str(member_dn))
                        if match:
                            admins.append(match.group(1))
            
            console.print(f"[red]⚠️ Domain Admins: {', '.join(admins)}[/red]")
            
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        
        return admins
    
    def enumerate_spns(self) -> List[Dict]:
        """Find accounts with SPNs (Kerberoastable)."""
        console.print("\n[cyan]🎫 Finding Kerberoastable accounts...[/cyan]")
        
        spn_accounts = []
        
        if not self.connection:
            return spn_accounts
        
        try:
            self.connection.search(
                self.base_dn,
                '(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer)))',
                attributes=['sAMAccountName', 'servicePrincipalName', 'adminCount']
            )
            
            for entry in self.connection.entries:
                account = {
                    'username': str(entry.sAMAccountName),
                    'spns': [str(s) for s in entry.servicePrincipalName] if entry.servicePrincipalName else [],
                    'admin_count': bool(entry.adminCount) if entry.adminCount else False,
                }
                spn_accounts.append(account)
            
            console.print(f"[yellow]⚠️ Found {len(spn_accounts)} Kerberoastable accounts[/yellow]")
            
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        
        return spn_accounts
    
    def enumerate_asreproastable(self) -> List[str]:
        """Find accounts with PreAuth disabled (AS-REP roastable)."""
        console.print("\n[cyan]🎫 Finding AS-REP Roastable accounts...[/cyan]")
        
        accounts = []
        
        if not self.connection:
            return accounts
        
        try:
            # UAC flag 0x400000 = DONT_REQUIRE_PREAUTH
            self.connection.search(
                self.base_dn,
                '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))',
                attributes=['sAMAccountName']
            )
            
            accounts = [str(e.sAMAccountName) for e in self.connection.entries]
            
            if accounts:
                console.print(f"[yellow]⚠️ AS-REP Roastable: {', '.join(accounts)}[/yellow]")
            else:
                console.print("[green]✓ No AS-REP Roastable accounts found[/green]")
                
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        
        return accounts
    
    def enumerate_delegations(self) -> Dict:
        """Find accounts with delegation configured."""
        console.print("\n[cyan]🔗 Finding delegation configurations...[/cyan]")
        
        delegations = {
            'unconstrained': [],
            'constrained': [],
            'rbcd': []
        }
        
        if not self.connection:
            return delegations
        
        try:
            # Unconstrained delegation (UAC 0x80000)
            self.connection.search(
                self.base_dn,
                '(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))',
                attributes=['sAMAccountName']
            )
            delegations['unconstrained'] = [str(e.sAMAccountName) for e in self.connection.entries]
            
            # Constrained delegation
            self.connection.search(
                self.base_dn,
                '(msDS-AllowedToDelegateTo=*)',
                attributes=['sAMAccountName', 'msDS-AllowedToDelegateTo']
            )
            for entry in self.connection.entries:
                delegations['constrained'].append({
                    'account': str(entry.sAMAccountName),
                    'targets': [str(t) for t in entry['msDS-AllowedToDelegateTo']]
                })
            
            # Resource-Based Constrained Delegation (RBCD)
            self.connection.search(
                self.base_dn,
                '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)',
                attributes=['sAMAccountName', 'msDS-AllowedToActOnBehalfOfOtherIdentity']
            )
            delegations['rbcd'] = [str(e.sAMAccountName) for e in self.connection.entries]
            
            # Display findings
            if delegations['unconstrained']:
                console.print(f"[red]⚠️ Unconstrained Delegation: {delegations['unconstrained']}[/red]")
            if delegations['constrained']:
                console.print(f"[yellow]⚠️ Constrained Delegation: {len(delegations['constrained'])} accounts[/yellow]")
            if delegations['rbcd']:
                console.print(f"[yellow]⚠️ RBCD configured: {delegations['rbcd']}[/yellow]")
                
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        
        return delegations
    
    def enumerate_gpos(self) -> List[Dict]:
        """Enumerate Group Policy Objects."""
        console.print("\n[cyan]📜 Enumerating GPOs...[/cyan]")
        
        gpos = []
        
        if not self.connection:
            return gpos
        
        try:
            self.connection.search(
                f'CN=Policies,CN=System,{self.base_dn}',
                '(objectClass=groupPolicyContainer)',
                attributes=['displayName', 'gPCFileSysPath', 'gPCMachineExtensionNames']
            )
            
            for entry in self.connection.entries:
                gpo = {
                    'name': str(entry.displayName) if entry.displayName else 'Unknown',
                    'path': str(entry.gPCFileSysPath) if entry.gPCFileSysPath else '',
                }
                gpos.append(gpo)
            
            console.print(f"[green]✓ Found {len(gpos)} GPOs[/green]")
            
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        
        return gpos
    
    def enumerate_trusts(self) -> List[Dict]:
        """Enumerate domain trusts."""
        console.print("\n[cyan]🤝 Enumerating trusts...[/cyan]")
        
        trusts = []
        
        if not self.connection:
            return trusts
        
        try:
            self.connection.search(
                f'CN=System,{self.base_dn}',
                '(objectClass=trustedDomain)',
                attributes=['name', 'trustDirection', 'trustType', 'trustAttributes']
            )
            
            for entry in self.connection.entries:
                direction = int(entry.trustDirection) if entry.trustDirection else 0
                trust = {
                    'name': str(entry.name),
                    'direction': 'Bidirectional' if direction == 3 else 
                                ('Outbound' if direction == 2 else 
                                ('Inbound' if direction == 1 else 'Unknown')),
                    'type': str(entry.trustType) if entry.trustType else '',
                }
                trusts.append(trust)
            
            console.print(f"[green]✓ Found {len(trusts)} trusts[/green]")
            
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        
        return trusts
    
    def enumerate_laps(self) -> List[Dict]:
        """Find computers with LAPS configured."""
        console.print("\n[cyan]🔐 Checking LAPS...[/cyan]")
        
        laps_computers = []
        
        if not self.connection:
            return laps_computers
        
        try:
            self.connection.search(
                self.base_dn,
                '(&(objectClass=computer)(ms-Mcs-AdmPwd=*))',
                attributes=['sAMAccountName', 'ms-Mcs-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime']
            )
            
            for entry in self.connection.entries:
                laps_computers.append({
                    'computer': str(entry.sAMAccountName),
                    'password': str(entry['ms-Mcs-AdmPwd']) if entry['ms-Mcs-AdmPwd'] else 'Access Denied'
                })
            
            if laps_computers:
                console.print(f"[green]✓ Found {len(laps_computers)} computers with readable LAPS passwords![/green]")
                
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        
        return laps_computers
    
    def run_full_enumeration(self) -> Dict:
        """Run comprehensive AD enumeration."""
        console.print("\n[bold cyan]═══════════════════════════════════════════════════════════[/bold cyan]")
        console.print("[bold cyan]         ACTIVE DIRECTORY ENUMERATION                       [/bold cyan]")
        console.print("[bold cyan]═══════════════════════════════════════════════════════════[/bold cyan]")
        
        if not self.connect():
            return {}
        
        results = {
            'domain_info': self.get_domain_info(),
            'users': self.enumerate_users(),
            'groups': self.enumerate_groups(),
            'computers': self.enumerate_computers(),
            'domain_admins': self.enumerate_domain_admins(),
            'spn_accounts': self.enumerate_spns(),
            'asrep_accounts': self.enumerate_asreproastable(),
            'delegations': self.enumerate_delegations(),
            'gpos': self.enumerate_gpos(),
            'trusts': self.enumerate_trusts(),
            'laps': self.enumerate_laps(),
        }
        
        return results


class PowerViewEnumerator:
    """
    PowerView-style enumeration using native tools.
    """
    
    def __init__(self, domain: str, dc_ip: str, username: str, password: str):
        self.domain = domain
        self.dc_ip = dc_ip
        self.username = username
        self.password = password
    
    def find_local_admin_access(self, computers: List[str]) -> List[str]:
        """Find computers where current user has local admin access."""
        console.print("\n[cyan]🔍 Finding local admin access...[/cyan]")
        
        admin_access = []
        
        for computer in computers:
            try:
                cmd = [
                    'cme', 'smb', computer,
                    '-u', self.username,
                    '-p', self.password,
                    '-d', self.domain
                ]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                
                if '(Pwn3d!)' in result.stdout:
                    admin_access.append(computer)
                    console.print(f"[green]✓ Admin on: {computer}[/green]")
                    
            except Exception:
                continue
        
        return admin_access
    
    def find_domain_shares(self) -> List[Dict]:
        """Find accessible shares across the domain."""
        console.print("\n[cyan]📁 Finding domain shares...[/cyan]")
        
        shares = []
        
        try:
            cmd = [
                'cme', 'smb', self.dc_ip,
                '-u', self.username,
                '-p', self.password,
                '-d', self.domain,
                '--shares'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            for line in result.stdout.split('\n'):
                if 'READ' in line or 'WRITE' in line:
                    shares.append({'share': line.strip()})
                    
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        
        return shares
