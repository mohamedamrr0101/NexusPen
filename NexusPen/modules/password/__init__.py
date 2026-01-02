"""
NexusPen - Password Module
==========================
Complete password attack module.

Includes:
- bruteforce: Online password brute forcing (Hydra, Medusa)
- cracking: Offline hash cracking (Hashcat, John)
- spraying: Password spraying attacks
- dumping: Credential extraction (secretsdump, Mimikatz)
- wordlists: Wordlist generation and management
"""

# Brute forcing
from .bruteforce import PasswordBruteforcer

# Hash cracking
from .cracking import (
    HashIdentifier,
    HashcatCracker,
    JohnCracker,
    OnlineCracker,
    RainbowTableCracker,
    PasswordAnalyzer,
    CrackResult,
    display_all_tools,
)

# Password spraying
from .spraying import (
    PasswordSprayer,
    CredentialStuffer,
    SeasonalPasswordGenerator,
    SprayResult,
)

# Credential dumping
from .dumping import (
    WindowsHashDumper,
    LinuxHashDumper,
    BrowserCredentialDumper,
    CredentialFileParser,
    DumpedHash,
    display_dump_methods,
)

# Wordlist management
from .wordlists import (
    WordlistManager,
    WordlistGenerator,
    WordlistStats,
    CeWL,
    CUPP,
    Crunch,
)

# Alias for backwards compatibility
HashCracker = HashcatCracker

__all__ = [
    # Brute force
    'PasswordBruteforcer',
    
    # Cracking
    'HashIdentifier', 'HashcatCracker', 'JohnCracker', 'HashCracker',
    'OnlineCracker', 'RainbowTableCracker', 'PasswordAnalyzer',
    'CrackResult', 'display_all_tools',
    
    # Spraying
    'PasswordSprayer', 'CredentialStuffer', 'SeasonalPasswordGenerator',
    'SprayResult',
    
    # Dumping
    'WindowsHashDumper', 'LinuxHashDumper', 'BrowserCredentialDumper',
    'CredentialFileParser', 'DumpedHash', 'display_dump_methods',
    
    # Wordlists
    'WordlistManager', 'WordlistGenerator', 'WordlistStats',
    'CeWL', 'CUPP', 'Crunch',
]


def run_full_assessment(target: str, userlist: str = None, 
                       wordlist: str = None, protocol: str = 'smb') -> dict:
    """
    Run complete password attack assessment.
    
    Args:
        target: Target IP
        userlist: Path to user list file
        wordlist: Path to password wordlist
        protocol: Protocol to attack (smb, ssh, rdp, etc.)
    """
    from rich.console import Console
    console = Console()
    
    console.print("\n[bold red]═══════════════════════════════════════════════════════════[/bold red]")
    console.print("[bold red]              PASSWORD ATTACK ASSESSMENT                    [/bold red]")
    console.print("[bold red]═══════════════════════════════════════════════════════════[/bold red]")
    
    results = {
        'cracked_hashes': [],
        'valid_credentials': [],
        'dumped_hashes': [],
    }
    
    # 1. Password Spraying
    console.print("\n[cyan]━━━ Phase 1: Password Spraying ━━━[/cyan]")
    
    if userlist:
        with open(userlist, 'r') as f:
            users = [line.strip() for line in f]
        
        sprayer = PasswordSprayer(target)
        spray_results = sprayer.smart_spray(users, protocol=protocol)
        results['valid_credentials'] = [r.__dict__ for r in spray_results]
    
    # 2. Brute Force (if spraying fails)
    if not results['valid_credentials'] and wordlist:
        console.print("\n[cyan]━━━ Phase 2: Brute Force ━━━[/cyan]")
        bruteforcer = PasswordBruteforcer(target)
        # Add brute force logic here
    
    # Summary
    console.print("\n[bold cyan]═══ ASSESSMENT SUMMARY ═══[/bold cyan]")
    console.print(f"[green]Valid Credentials: {len(results['valid_credentials'])}[/green]")
    console.print(f"[yellow]Cracked Hashes: {len(results['cracked_hashes'])}[/yellow]")
    console.print(f"[yellow]Dumped Hashes: {len(results['dumped_hashes'])}[/yellow]")
    
    return results
