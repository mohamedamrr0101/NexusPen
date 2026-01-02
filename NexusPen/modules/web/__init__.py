"""
NexusPen - Web Module
======================
Complete web application security testing module.

Includes:
- recon: Web reconnaissance and information gathering
- cms_scanner: WordPress, Joomla, Drupal scanning
- sqli: SQL injection detection and exploitation
- xss: Cross-site scripting testing
- lfi_rfi: Local/Remote file inclusion
- vuln_scanner: Security headers, CORS, SSL, sensitive files
- ssrf: Server-side request forgery
- xxe_ssti: XXE injection and SSTI
- api_scanner: REST API and GraphQL security
- command_injection: OS command injection
- jwt_session: JWT and session security
- fuzzer: Directory, subdomain, and parameter fuzzing
"""

# Reconnaissance
from .recon import (
    WebRecon,
    WebScanner,
    DirectoryFuzzer as ReconDirectoryFuzzer,
    WebFinding,
)

# CMS Scanning
from .cms_scanner import (
    CMSScanner,
    CMSFinding,
)

# SQL Injection
from .sqli import (
    SQLiScanner,
    SQLMapWrapper,
)

# XSS
from .xss import (
    XSSScanner,
)

# LFI/RFI
from .lfi_rfi import (
    LFIScanner,
    RFIScanner,
)

# Vulnerability Scanner
from .vuln_scanner import (
    WebVulnScanner,
    WebVulnerability,
)

# SSRF
from .ssrf import (
    SSRFScanner,
    BlindSSRFScanner,
    SSRFResult,
)

# XXE & SSTI
from .xxe_ssti import (
    XXEScanner,
    XXEResult,
    STTIScanner,
    IDORScanner,
)

# API Security
from .api_scanner import (
    RESTAPIScanner,
    GraphQLScanner,
    APIVulnerability,
)

# Command Injection
from .command_injection import (
    CommandInjectionScanner,
    CommandInjectionResult,
    UploadVulnScanner,
    PathTraversalScanner,
)

# JWT & Session
from .jwt_session import (
    JWTAnalyzer,
    JWTVulnerability,
    SessionAnalyzer,
    CookieAnalyzer,
)

# Fuzzing
from .fuzzer import (
    DirectoryFuzzer,
    SubdomainFuzzer,
    ParameterFuzzer,
    VHostFuzzer,
    FuzzResult,
    run_ffuf,
    run_wfuzz,
)

__all__ = [
    # Recon
    'WebRecon', 'WebScanner', 'WebFinding',
    
    # CMS
    'CMSScanner', 'CMSFinding',
    
    # SQLi
    'SQLiScanner', 'SQLMapWrapper',
    
    # XSS
    'XSSScanner',
    
    # LFI/RFI
    'LFIScanner', 'RFIScanner',
    
    # Vuln Scanner
    'WebVulnScanner', 'WebVulnerability',
    
    # SSRF
    'SSRFScanner', 'BlindSSRFScanner', 'SSRFResult',
    
    # XXE/SSTI
    'XXEScanner', 'XXEResult', 'STTIScanner', 'IDORScanner',
    
    # API
    'RESTAPIScanner', 'GraphQLScanner', 'APIVulnerability',
    
    # Command Injection
    'CommandInjectionScanner', 'CommandInjectionResult',
    'UploadVulnScanner', 'PathTraversalScanner',
    
    # JWT/Session
    'JWTAnalyzer', 'JWTVulnerability', 'SessionAnalyzer', 'CookieAnalyzer',
    
    # Fuzzing
    'DirectoryFuzzer', 'SubdomainFuzzer', 'ParameterFuzzer',
    'VHostFuzzer', 'FuzzResult', 'run_ffuf', 'run_wfuzz',
]


def run_full_assessment(target_url: str, depth: str = 'standard') -> dict:
    """
    Run comprehensive web application assessment.
    
    Args:
        target_url: Target URL
        depth: Assessment depth ('quick', 'standard', 'deep')
    """
    from rich.console import Console
    console = Console()
    
    console.print("\n[bold red]═══════════════════════════════════════════════════════════[/bold red]")
    console.print("[bold red]              WEB APPLICATION ASSESSMENT                    [/bold red]")
    console.print("[bold red]═══════════════════════════════════════════════════════════[/bold red]")
    console.print(f"[cyan]Target: {target_url}[/cyan]")
    console.print(f"[cyan]Depth: {depth}[/cyan]")
    
    results = {
        'vulnerabilities': [],
        'info': [],
    }
    
    # 1. Reconnaissance
    console.print("\n[cyan]━━━ Phase 1: Reconnaissance ━━━[/cyan]")
    try:
        recon = WebRecon(target_url)
        recon.run_full_recon()
        results['info'].append({'phase': 'recon', 'data': recon.results})
    except Exception as e:
        console.print(f"[red]Recon error: {e}[/red]")
    
    # 2. CMS Detection
    console.print("\n[cyan]━━━ Phase 2: CMS Detection ━━━[/cyan]")
    try:
        cms = CMSScanner(target_url)
        cms_result = cms.detect_cms()
        if cms_result:
            results['info'].append({'phase': 'cms', 'type': cms_result})
    except Exception as e:
        console.print(f"[red]CMS detection error: {e}[/red]")
    
    # 3. Vulnerability Scanning
    console.print("\n[cyan]━━━ Phase 3: Vulnerability Scan ━━━[/cyan]")
    try:
        vuln_scanner = WebVulnScanner(target_url)
        vulns = vuln_scanner.run_full_scan()
        for v in vulns:
            results['vulnerabilities'].append(v.__dict__)
    except Exception as e:
        console.print(f"[red]Vuln scan error: {e}[/red]")
    
    # 4. Injection Testing (if deep)
    if depth in ['standard', 'deep']:
        console.print("\n[cyan]━━━ Phase 4: Injection Testing ━━━[/cyan]")
        
        # SQLi
        try:
            sqli = SQLiScanner(target_url)
            sqli_results = sqli.test_all_params()
            results['vulnerabilities'].extend(sqli_results)
        except Exception as e:
            console.print(f"[red]SQLi test error: {e}[/red]")
        
        # XSS
        try:
            xss = XSSScanner(target_url)
            xss_results = xss.scan_reflected()
            results['vulnerabilities'].extend(xss_results)
        except Exception as e:
            console.print(f"[red]XSS test error: {e}[/red]")
    
    # Summary
    console.print("\n[bold cyan]═══ ASSESSMENT SUMMARY ═══[/bold cyan]")
    vuln_count = len(results['vulnerabilities'])
    console.print(f"[{'red' if vuln_count > 0 else 'green'}]Vulnerabilities Found: {vuln_count}[/]")
    
    return results


# OWASP Top 10 coverage reference
OWASP_TOP_10 = {
    'A01:2021 - Broken Access Control': [
        'IDORScanner', 'RESTAPIScanner.check_bola'
    ],
    'A02:2021 - Cryptographic Failures': [
        'SSLAnalyzer', 'WebVulnScanner.check_ssl_issues'
    ],
    'A03:2021 - Injection': [
        'SQLiScanner', 'XSSScanner', 'CommandInjectionScanner',
        'XXEScanner', 'STTIScanner', 'LFIScanner'
    ],
    'A04:2021 - Insecure Design': [
        'RESTAPIScanner.check_rate_limiting'
    ],
    'A05:2021 - Security Misconfiguration': [
        'WebVulnScanner.check_security_headers',
        'WebVulnScanner.check_cors',
        'WebVulnScanner.check_sensitive_files'
    ],
    'A06:2021 - Vulnerable Components': [
        'CMSScanner'
    ],
    'A07:2021 - Authentication Failures': [
        'JWTAnalyzer', 'SessionAnalyzer', 'CookieAnalyzer'
    ],
    'A08:2021 - Integrity Failures': [
        'JWTAnalyzer.generate_none_attack'
    ],
    'A09:2021 - Logging Failures': [
        'RESTAPIScanner.check_verbose_errors'
    ],
    'A10:2021 - SSRF': [
        'SSRFScanner', 'BlindSSRFScanner'
    ],
}
