#!/usr/bin/env python3
"""
NexusPen - API Security Testing Module
========================================
REST API and GraphQL security testing.
"""

import requests
import json
from typing import Dict, List, Optional
from dataclasses import dataclass

from rich.console import Console
from rich.table import Table

console = Console()


@dataclass
class APIVulnerability:
    """API vulnerability finding."""
    endpoint: str
    method: str
    vuln_type: str
    severity: str
    description: str
    evidence: Optional[str] = None


class RESTAPIScanner:
    """
    REST API security scanner.
    """
    
    def __init__(self, base_url: str, auth_token: str = None):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        
        if auth_token:
            self.session.headers.update({
                'Authorization': f'Bearer {auth_token}'
            })
        
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'NexusPen API Scanner'
        })
        
        self.findings: List[APIVulnerability] = []
    
    def check_authentication(self, endpoints: List[str]) -> List[APIVulnerability]:
        """Check for authentication bypass."""
        console.print("\n[cyan]🔐 Testing authentication...[/cyan]")
        
        vulns = []
        
        # Test without auth
        no_auth_session = requests.Session()
        no_auth_session.headers.update({'Content-Type': 'application/json'})
        
        for endpoint in endpoints:
            url = f"{self.base_url}{endpoint}"
            
            try:
                response = no_auth_session.get(url, timeout=10)
                
                if response.status_code == 200:
                    vuln = APIVulnerability(
                        endpoint=endpoint,
                        method='GET',
                        vuln_type='Authentication Bypass',
                        severity='critical',
                        description='Endpoint accessible without authentication',
                        evidence=f"Status: {response.status_code}"
                    )
                    vulns.append(vuln)
                    self.findings.append(vuln)
                    console.print(f"[red]  ⚠️ No auth required: {endpoint}[/red]")
                    
            except:
                pass
        
        return vulns
    
    def check_bola(self, endpoint: str, id_param: str,
                  test_ids: List = None) -> List[APIVulnerability]:
        """Check for Broken Object Level Authorization (BOLA/IDOR)."""
        console.print(f"\n[cyan]🔑 Testing BOLA on {endpoint}...[/cyan]")
        
        vulns = []
        test_ids = test_ids or [1, 2, 3, 0, -1, 999999]
        
        for test_id in test_ids:
            url = endpoint.replace(f'{{{id_param}}}', str(test_id))
            url = f"{self.base_url}{url}"
            
            try:
                response = self.session.get(url, timeout=10)
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        vuln = APIVulnerability(
                            endpoint=url,
                            method='GET',
                            vuln_type='BOLA/IDOR',
                            severity='high',
                            description=f'Accessible object ID: {test_id}',
                            evidence=json.dumps(data)[:200]
                        )
                        vulns.append(vuln)
                        self.findings.append(vuln)
                        console.print(f"[yellow]  ⚠️ Accessible: ID {test_id}[/yellow]")
                    except:
                        pass
                    
            except:
                pass
        
        return vulns
    
    def check_mass_assignment(self, endpoint: str, 
                             sensitive_fields: List[str] = None) -> List[APIVulnerability]:
        """Check for mass assignment vulnerabilities."""
        console.print(f"\n[cyan]📝 Testing mass assignment on {endpoint}...[/cyan]")
        
        vulns = []
        sensitive_fields = sensitive_fields or [
            'role', 'admin', 'is_admin', 'isAdmin', 'is_superuser',
            'verified', 'email_verified', 'active', 'status',
            'balance', 'credits', 'permissions', 'group_id',
        ]
        
        url = f"{self.base_url}{endpoint}"
        
        for field in sensitive_fields:
            payload = {field: True}
            
            try:
                # Test with PUT
                response = self.session.put(url, json=payload, timeout=10)
                
                if response.status_code in [200, 201]:
                    try:
                        data = response.json()
                        if data.get(field) == True:
                            vuln = APIVulnerability(
                                endpoint=endpoint,
                                method='PUT',
                                vuln_type='Mass Assignment',
                                severity='critical',
                                description=f'Field "{field}" can be modified',
                                evidence=json.dumps(data)[:200]
                            )
                            vulns.append(vuln)
                            self.findings.append(vuln)
                            console.print(f"[red]  ⚠️ Mass assignment: {field}[/red]")
                    except:
                        pass
                        
            except:
                pass
        
        return vulns
    
    def check_rate_limiting(self, endpoint: str, 
                           requests_count: int = 100) -> Optional[APIVulnerability]:
        """Check for missing rate limiting."""
        console.print(f"\n[cyan]⚡ Testing rate limiting on {endpoint}...[/cyan]")
        
        url = f"{self.base_url}{endpoint}"
        success_count = 0
        
        for i in range(requests_count):
            try:
                response = self.session.get(url, timeout=5)
                if response.status_code == 200:
                    success_count += 1
            except:
                break
        
        if success_count >= requests_count * 0.9:  # 90% success rate
            vuln = APIVulnerability(
                endpoint=endpoint,
                method='GET',
                vuln_type='Missing Rate Limiting',
                severity='medium',
                description=f'{success_count}/{requests_count} requests succeeded without rate limit'
            )
            self.findings.append(vuln)
            console.print(f"[yellow]  ⚠️ No rate limiting detected[/yellow]")
            return vuln
        
        return None
    
    def check_injection(self, endpoint: str, param: str) -> List[APIVulnerability]:
        """Check for injection vulnerabilities."""
        console.print(f"\n[cyan]💉 Testing injection on {endpoint}...[/cyan]")
        
        vulns = []
        
        injection_payloads = {
            'sqli': ["' OR '1'='1", "1; DROP TABLE users--", "1 UNION SELECT 1,2,3--"],
            'nosql': ['{"$gt": ""}', '{"$ne": null}', '{"$where": "1==1"}'],
            'command': ['; ls', '| cat /etc/passwd', '`id`'],
        }
        
        url = f"{self.base_url}{endpoint}"
        
        for inj_type, payloads in injection_payloads.items():
            for payload in payloads:
                try:
                    response = self.session.get(
                        url,
                        params={param: payload},
                        timeout=10
                    )
                    
                    # Check for error-based indicators
                    error_indicators = [
                        'sql', 'syntax', 'mysql', 'postgresql', 'oracle',
                        'root:', 'uid=', 'mongodb',
                    ]
                    
                    for indicator in error_indicators:
                        if indicator in response.text.lower():
                            vuln = APIVulnerability(
                                endpoint=endpoint,
                                method='GET',
                                vuln_type=f'{inj_type.upper()} Injection',
                                severity='critical',
                                description=f'Injection via {param}',
                                evidence=f"Payload: {payload}"
                            )
                            vulns.append(vuln)
                            self.findings.append(vuln)
                            console.print(f"[red]  ⚠️ {inj_type.upper()} injection![/red]")
                            break
                            
                except:
                    pass
        
        return vulns
    
    def check_verbose_errors(self, endpoint: str) -> Optional[APIVulnerability]:
        """Check for verbose error messages."""
        console.print(f"\n[cyan]📋 Testing error handling on {endpoint}...[/cyan]")
        
        url = f"{self.base_url}{endpoint}"
        
        # Trigger errors
        error_triggers = [
            {'method': 'POST', 'data': 'invalid json'},
            {'method': 'GET', 'params': {'id': 'invalid'}},
            {'method': 'PUT', 'data': None},
        ]
        
        for trigger in error_triggers:
            try:
                if trigger['method'] == 'POST':
                    response = self.session.post(url, data=trigger.get('data'), timeout=10)
                elif trigger['method'] == 'GET':
                    response = self.session.get(url, params=trigger.get('params'), timeout=10)
                else:
                    response = self.session.put(url, data=trigger.get('data'), timeout=10)
                
                # Check for stack traces
                verbose_indicators = [
                    'traceback', 'stack trace', 'exception', 'error in',
                    'line ', 'at com.', 'at org.', 'file "',
                ]
                
                for indicator in verbose_indicators:
                    if indicator in response.text.lower():
                        vuln = APIVulnerability(
                            endpoint=endpoint,
                            method=trigger['method'],
                            vuln_type='Verbose Error Message',
                            severity='low',
                            description='Stack trace or detailed error exposed',
                            evidence=response.text[:300]
                        )
                        self.findings.append(vuln)
                        console.print(f"[yellow]  ⚠️ Verbose errors exposed[/yellow]")
                        return vuln
                        
            except:
                pass
        
        return None
    
    def display_findings(self):
        """Display all findings."""
        if not self.findings:
            console.print("\n[green]No vulnerabilities found![/green]")
            return
        
        table = Table(title="API Vulnerabilities", show_header=True,
                     header_style="bold red")
        table.add_column("Endpoint", style="cyan", width=30)
        table.add_column("Type", width=20)
        table.add_column("Severity", width=10)
        
        for vuln in self.findings:
            sev_color = {'critical': 'red', 'high': 'orange1', 'medium': 'yellow', 'low': 'green'}.get(vuln.severity, 'white')
            table.add_row(
                vuln.endpoint[:30],
                vuln.vuln_type,
                f"[{sev_color}]{vuln.severity.upper()}[/{sev_color}]"
            )
        
        console.print(table)


class GraphQLScanner:
    """
    GraphQL API security scanner.
    """
    
    def __init__(self, endpoint: str, auth_token: str = None):
        self.endpoint = endpoint
        self.session = requests.Session()
        
        if auth_token:
            self.session.headers.update({
                'Authorization': f'Bearer {auth_token}'
            })
        
        self.session.headers.update({
            'Content-Type': 'application/json'
        })
        
        self.findings = []
    
    def introspection_query(self) -> Optional[Dict]:
        """Try GraphQL introspection."""
        console.print("\n[cyan]🔍 Testing GraphQL introspection...[/cyan]")
        
        query = '''
        query IntrospectionQuery {
            __schema {
                types {
                    name
                    fields {
                        name
                        type {
                            name
                            kind
                        }
                    }
                }
            }
        }
        '''
        
        try:
            response = self.session.post(
                self.endpoint,
                json={'query': query},
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                if 'data' in data and data['data'].get('__schema'):
                    console.print("[yellow]  ⚠️ Introspection enabled![/yellow]")
                    return data['data']['__schema']
                    
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        
        return None
    
    def check_query_complexity(self) -> bool:
        """Check for query complexity limits."""
        console.print("\n[cyan]🔄 Testing query complexity...[/cyan]")
        
        # Deep nested query
        deep_query = '''
        query {
            users {
                posts {
                    comments {
                        author {
                            posts {
                                comments {
                                    author {
                                        posts {
                                            title
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        '''
        
        try:
            response = self.session.post(
                self.endpoint,
                json={'query': deep_query},
                timeout=30
            )
            
            if response.status_code == 200:
                errors = response.json().get('errors', [])
                if not any('complexity' in str(e).lower() or 'depth' in str(e).lower() for e in errors):
                    console.print("[yellow]  ⚠️ No query complexity limits![/yellow]")
                    return True
                    
        except:
            pass
        
        return False
    
    def check_batching(self) -> bool:
        """Check for query batching abuse."""
        console.print("\n[cyan]📦 Testing query batching...[/cyan]")
        
        # Batch query
        batch = [
            {'query': 'query { __typename }'},
            {'query': 'query { __typename }'},
            {'query': 'query { __typename }'},
        ]
        
        try:
            response = self.session.post(
                self.endpoint,
                json=batch,
                timeout=10
            )
            
            if response.status_code == 200 and isinstance(response.json(), list):
                console.print("[yellow]  ⚠️ Query batching allowed![/yellow]")
                return True
                
        except:
            pass
        
        return False
    
    def check_injection(self, field: str) -> bool:
        """Check for GraphQL injection."""
        console.print(f"\n[cyan]💉 Testing GraphQL injection...[/cyan]")
        
        injection_payloads = [
            f'query {{ {field}(id: "1\' OR \'1\'=\'1") {{ id }} }}',
            f'query {{ {field}(id: 1) {{ id __typename }} }}',
        ]
        
        for payload in injection_payloads:
            try:
                response = self.session.post(
                    self.endpoint,
                    json={'query': payload},
                    timeout=10
                )
                
                if 'sql' in response.text.lower() or 'syntax' in response.text.lower():
                    console.print("[red]  ⚠️ GraphQL injection possible![/red]")
                    return True
                    
            except:
                pass
        
        return False
    
    @staticmethod
    def common_queries() -> List[str]:
        """Get common GraphQL queries for testing."""
        return [
            'query { users { id email password } }',
            'query { user(id: 1) { id email role } }',
            'query { allUsers { nodes { id admin } } }',
            'mutation { deleteUser(id: 1) { success } }',
            'subscription { newMessages { content } }',
        ]
