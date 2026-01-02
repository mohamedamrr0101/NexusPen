"""
NexusPen - Common Module
========================
Shared utilities and tools used across all modules.

Includes:
- Port scanning (Nmap, Masscan, socket)
- Service detection and fingerprinting
- Banner grabbing
- Vulnerability database (searchsploit, Nuclei)
- Payload generation (reverse shells, web shells)
- Encoding/hashing utilities
- Credential management
- Wordlist generation
- Network utilities (ping sweep, ARP scan, DNS)
- Proxy and tunneling tools
"""

# Port scanning
from .port_scanner import PortScanner

# Service detection
from .service_scanner import (
    ServiceScanner,
    ServiceInfo,
    BannerGrabber
)

# Vulnerability scanning
from .vuln_scanner import (
    VulnDatabase,
    NmapVulnScanner,
    NucleiScanner,
    CVEInfo
)

# Payload generation
from .payloads import (
    PayloadGenerator,
    WebShellGenerator,
    BindShellGenerator,
    Payload
)

# Encoding utilities
from .encoders import (
    Encoder,
    Hasher,
    SQLiPayloadEncoder,
    XSSPayloadEncoder,
    encode_payload,
    hash_string
)

# Credential management
from .credentials import (
    CredentialManager,
    Credential,
    WordlistGenerator,
    DefaultCredentials
)

# Network utilities
from .network_utils import (
    NetworkScanner,
    HostInfo,
    DNSTools,
    ProxyHandler,
    ConnectionCheck
)

# CVE Intelligence (Shodan CVEDB)
from .cve_intel import (
    ShodanCVEDB,
    CVEIntelligence,
    SmartVulnScanner,
    lookup_cve,
    get_kev_list,
    scan_product
)

# AI Assistant (OpenRouter/DeepSeek)
from .ai_assistant import (
    AIAssistant,
    AIConfig,
    CVEResearcher,
    setup_ai,
    research_cve
)

__all__ = [
    # Port scanning
    'PortScanner',
    
    # Service detection
    'ServiceScanner', 'ServiceInfo', 'BannerGrabber',
    
    # Vulnerability scanning
    'VulnDatabase', 'NmapVulnScanner', 'NucleiScanner', 'CVEInfo',
    
    # Payloads
    'PayloadGenerator', 'WebShellGenerator', 'BindShellGenerator', 'Payload',
    
    # Encoding
    'Encoder', 'Hasher', 'SQLiPayloadEncoder', 'XSSPayloadEncoder',
    'encode_payload', 'hash_string',
    
    # Credentials
    'CredentialManager', 'Credential', 'WordlistGenerator', 'DefaultCredentials',
    
    # Network
    'NetworkScanner', 'HostInfo', 'DNSTools', 'ProxyHandler', 'ConnectionCheck',
    
    # CVE Intelligence
    'ShodanCVEDB', 'CVEIntelligence', 'SmartVulnScanner',
    'lookup_cve', 'get_kev_list', 'scan_product',
    
    # AI Assistant
    'AIAssistant', 'AIConfig', 'CVEResearcher',
    'setup_ai', 'research_cve',
]
