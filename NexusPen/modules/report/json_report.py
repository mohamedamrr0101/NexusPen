#!/usr/bin/env python3
"""
NexusPen - JSON Report Generator
=================================
Machine-readable JSON report generation.
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

from rich.console import Console

console = Console()


@dataclass
class JSONReportConfig:
    """JSON report configuration."""
    output_path: str
    include_raw_data: bool = True
    include_evidence: bool = True
    pretty_print: bool = True
    indent: int = 2


class JSONReportGenerator:
    """
    JSON report generator for machine-readable output.
    """
    
    def __init__(self, config: JSONReportConfig = None):
        self.config = config or JSONReportConfig(output_path='/tmp/nexuspen_report.json')
        self.report_data = {}
    
    def initialize_report(self, scan_info: Dict):
        """Initialize report structure."""
        self.report_data = {
            'meta': {
                'report_type': 'penetration_test',
                'generator': 'NexusPen Framework',
                'version': '1.0.0',
                'generated_at': datetime.now().isoformat(),
                'format_version': '1.0',
            },
            'engagement': {
                'start_time': scan_info.get('start_time', datetime.now().isoformat()),
                'end_time': None,
                'target': scan_info.get('target', ''),
                'scope': scan_info.get('scope', []),
                'methodology': scan_info.get('methodology', 'OWASP/PTES'),
            },
            'executive_summary': {
                'total_hosts': 0,
                'total_vulnerabilities': 0,
                'critical_count': 0,
                'high_count': 0,
                'medium_count': 0,
                'low_count': 0,
                'info_count': 0,
                'overall_risk': 'Unknown',
            },
            'hosts': [],
            'vulnerabilities': [],
            'credentials': [],
            'findings': [],
            'recommendations': [],
            'raw_data': {} if self.config.include_raw_data else None,
        }
    
    def add_host(self, host_data: Dict):
        """Add discovered host."""
        host_entry = {
            'ip': host_data.get('ip', ''),
            'hostname': host_data.get('hostname', ''),
            'os': host_data.get('os', ''),
            'mac': host_data.get('mac', ''),
            'status': host_data.get('status', 'up'),
            'ports': host_data.get('ports', []),
            'services': host_data.get('services', []),
            'discovered_at': datetime.now().isoformat(),
        }
        self.report_data['hosts'].append(host_entry)
        self.report_data['executive_summary']['total_hosts'] = len(self.report_data['hosts'])
    
    def add_vulnerability(self, vuln_data: Dict):
        """Add vulnerability finding."""
        vuln_entry = {
            'id': vuln_data.get('id', f"VULN-{len(self.report_data['vulnerabilities'])+1:04d}"),
            'title': vuln_data.get('title', ''),
            'description': vuln_data.get('description', ''),
            'severity': vuln_data.get('severity', 'medium'),
            'cvss_score': vuln_data.get('cvss', 0.0),
            'cvss_vector': vuln_data.get('cvss_vector', ''),
            'cve': vuln_data.get('cve', []),
            'cwe': vuln_data.get('cwe', ''),
            'affected_hosts': vuln_data.get('affected_hosts', []),
            'affected_port': vuln_data.get('port', ''),
            'affected_service': vuln_data.get('service', ''),
            'evidence': vuln_data.get('evidence', '') if self.config.include_evidence else '',
            'proof_of_concept': vuln_data.get('poc', ''),
            'remediation': vuln_data.get('remediation', ''),
            'references': vuln_data.get('references', []),
            'exploit_available': vuln_data.get('exploit_available', False),
            'exploited': vuln_data.get('exploited', False),
            'discovered_at': datetime.now().isoformat(),
        }
        
        self.report_data['vulnerabilities'].append(vuln_entry)
        self._update_vuln_counts()
    
    def add_credential(self, cred_data: Dict):
        """Add discovered credential."""
        cred_entry = {
            'type': cred_data.get('type', 'password'),
            'username': cred_data.get('username', ''),
            'password': cred_data.get('password', ''),
            'hash': cred_data.get('hash', ''),
            'domain': cred_data.get('domain', ''),
            'host': cred_data.get('host', ''),
            'service': cred_data.get('service', ''),
            'source': cred_data.get('source', ''),
            'cracked': cred_data.get('cracked', False),
            'discovered_at': datetime.now().isoformat(),
        }
        self.report_data['credentials'].append(cred_entry)
    
    def add_finding(self, finding_data: Dict):
        """Add general finding."""
        finding_entry = {
            'id': f"FIND-{len(self.report_data['findings'])+1:04d}",
            'category': finding_data.get('category', 'general'),
            'title': finding_data.get('title', ''),
            'description': finding_data.get('description', ''),
            'impact': finding_data.get('impact', ''),
            'likelihood': finding_data.get('likelihood', 'medium'),
            'risk_rating': finding_data.get('risk_rating', 'medium'),
            'affected_assets': finding_data.get('affected_assets', []),
            'evidence': finding_data.get('evidence', ''),
            'recommendation': finding_data.get('recommendation', ''),
        }
        self.report_data['findings'].append(finding_entry)
    
    def add_recommendation(self, rec_data: Dict):
        """Add recommendation."""
        rec_entry = {
            'id': f"REC-{len(self.report_data['recommendations'])+1:03d}",
            'priority': rec_data.get('priority', 'medium'),
            'title': rec_data.get('title', ''),
            'description': rec_data.get('description', ''),
            'affected_vulnerabilities': rec_data.get('affected_vulns', []),
            'effort': rec_data.get('effort', 'medium'),
            'impact': rec_data.get('impact', 'high'),
        }
        self.report_data['recommendations'].append(rec_entry)
    
    def add_raw_data(self, key: str, data: Any):
        """Add raw scan data."""
        if self.config.include_raw_data and self.report_data.get('raw_data') is not None:
            self.report_data['raw_data'][key] = data
    
    def _update_vuln_counts(self):
        """Update vulnerability counts in summary."""
        summary = self.report_data['executive_summary']
        vulns = self.report_data['vulnerabilities']
        
        summary['total_vulnerabilities'] = len(vulns)
        summary['critical_count'] = sum(1 for v in vulns if v['severity'] == 'critical')
        summary['high_count'] = sum(1 for v in vulns if v['severity'] == 'high')
        summary['medium_count'] = sum(1 for v in vulns if v['severity'] == 'medium')
        summary['low_count'] = sum(1 for v in vulns if v['severity'] == 'low')
        summary['info_count'] = sum(1 for v in vulns if v['severity'] == 'info')
        
        # Calculate overall risk
        if summary['critical_count'] > 0:
            summary['overall_risk'] = 'Critical'
        elif summary['high_count'] > 0:
            summary['overall_risk'] = 'High'
        elif summary['medium_count'] > 0:
            summary['overall_risk'] = 'Medium'
        elif summary['low_count'] > 0:
            summary['overall_risk'] = 'Low'
        else:
            summary['overall_risk'] = 'Informational'
    
    def finalize_report(self, end_time: str = None):
        """Finalize the report."""
        self.report_data['engagement']['end_time'] = end_time or datetime.now().isoformat()
        self._update_vuln_counts()
    
    def generate(self, output_path: str = None) -> str:
        """Generate JSON report file."""
        output_path = output_path or self.config.output_path
        
        console.print(f"\n[cyan]📄 Generating JSON report...[/cyan]")
        
        self.finalize_report()
        
        with open(output_path, 'w') as f:
            if self.config.pretty_print:
                json.dump(self.report_data, f, indent=self.config.indent, default=str)
            else:
                json.dump(self.report_data, f, default=str)
        
        console.print(f"[green]✓ Report saved to {output_path}[/green]")
        return output_path
    
    def get_report_data(self) -> Dict:
        """Get report data as dictionary."""
        return self.report_data
    
    def load_from_file(self, file_path: str):
        """Load existing report from file."""
        with open(file_path, 'r') as f:
            self.report_data = json.load(f)


class JSONLReportGenerator:
    """
    JSON Lines (JSONL) report generator.
    Each line is a separate JSON object for streaming processing.
    """
    
    def __init__(self, output_path: str):
        self.output_path = output_path
        self.file = None
    
    def open(self):
        """Open file for writing."""
        self.file = open(self.output_path, 'w')
    
    def close(self):
        """Close file."""
        if self.file:
            self.file.close()
    
    def write_entry(self, entry_type: str, data: Dict):
        """Write a single entry."""
        entry = {
            'type': entry_type,
            'timestamp': datetime.now().isoformat(),
            'data': data
        }
        self.file.write(json.dumps(entry) + '\n')
    
    def __enter__(self):
        self.open()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def convert_to_sarif(json_report: Dict) -> Dict:
    """
    Convert JSON report to SARIF format.
    SARIF = Static Analysis Results Interchange Format
    """
    sarif = {
        '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
        'version': '2.1.0',
        'runs': [{
            'tool': {
                'driver': {
                    'name': 'NexusPen',
                    'version': '1.0.0',
                    'informationUri': 'https://nexuspen.example.com',
                    'rules': []
                }
            },
            'results': []
        }]
    }
    
    rules = {}
    results = []
    
    for vuln in json_report.get('vulnerabilities', []):
        rule_id = vuln.get('id', '')
        
        # Add rule
        if rule_id not in rules:
            rules[rule_id] = {
                'id': rule_id,
                'name': vuln.get('title', ''),
                'shortDescription': {'text': vuln.get('title', '')},
                'fullDescription': {'text': vuln.get('description', '')},
                'defaultConfiguration': {
                    'level': _severity_to_sarif_level(vuln.get('severity', 'medium'))
                },
                'properties': {
                    'security-severity': str(vuln.get('cvss_score', 0.0))
                }
            }
        
        # Add result
        result = {
            'ruleId': rule_id,
            'level': _severity_to_sarif_level(vuln.get('severity', 'medium')),
            'message': {'text': vuln.get('description', '')},
            'locations': [{
                'physicalLocation': {
                    'artifactLocation': {
                        'uri': vuln.get('affected_hosts', ['unknown'])[0]
                    }
                }
            }]
        }
        results.append(result)
    
    sarif['runs'][0]['tool']['driver']['rules'] = list(rules.values())
    sarif['runs'][0]['results'] = results
    
    return sarif


def _severity_to_sarif_level(severity: str) -> str:
    """Convert severity to SARIF level."""
    mapping = {
        'critical': 'error',
        'high': 'error',
        'medium': 'warning',
        'low': 'note',
        'info': 'none',
    }
    return mapping.get(severity.lower(), 'warning')
