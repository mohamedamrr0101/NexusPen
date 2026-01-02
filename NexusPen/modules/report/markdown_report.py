#!/usr/bin/env python3
"""
NexusPen - Markdown Report Generator
=====================================
Markdown and text-based report generation.
"""

from datetime import datetime
from typing import Dict, List, Optional
import os

from rich.console import Console

console = Console()


class MarkdownReportGenerator:
    """
    Markdown report generator.
    """
    
    def __init__(self, output_path: str = '/tmp/nexuspen_report.md'):
        self.output_path = output_path
        self.content = []
    
    def add_header(self, title: str, level: int = 1):
        """Add header."""
        self.content.append(f"{'#' * level} {title}\n")
    
    def add_paragraph(self, text: str):
        """Add paragraph."""
        self.content.append(f"{text}\n")
    
    def add_table(self, headers: List[str], rows: List[List[str]]):
        """Add markdown table."""
        # Header row
        self.content.append('| ' + ' | '.join(headers) + ' |')
        # Separator
        self.content.append('| ' + ' | '.join(['---'] * len(headers)) + ' |')
        # Data rows
        for row in rows:
            self.content.append('| ' + ' | '.join(str(cell) for cell in row) + ' |')
        self.content.append('')
    
    def add_code_block(self, code: str, language: str = ''):
        """Add code block."""
        self.content.append(f'```{language}')
        self.content.append(code)
        self.content.append('```\n')
    
    def add_list(self, items: List[str], ordered: bool = False):
        """Add list."""
        for i, item in enumerate(items):
            if ordered:
                self.content.append(f'{i+1}. {item}')
            else:
                self.content.append(f'- {item}')
        self.content.append('')
    
    def add_quote(self, text: str):
        """Add blockquote."""
        lines = text.split('\n')
        for line in lines:
            self.content.append(f'> {line}')
        self.content.append('')
    
    def add_badge(self, label: str, value: str, color: str = 'blue') -> str:
        """Generate badge markdown (for GitHub README style)."""
        return f'![{label}](https://img.shields.io/badge/{label}-{value}-{color})'
    
    def generate_executive_summary(self, data: Dict):
        """Generate executive summary section."""
        self.add_header('Executive Summary', 1)
        
        # Overview
        self.add_paragraph(f"**Assessment Date:** {data.get('date', datetime.now().strftime('%Y-%m-%d'))}")
        self.add_paragraph(f"**Target:** {data.get('target', 'N/A')}")
        self.add_paragraph(f"**Scope:** {data.get('scope', 'N/A')}")
        
        # Risk summary
        self.add_header('Risk Summary', 2)
        
        summary = data.get('summary', {})
        self.add_table(
            ['Severity', 'Count'],
            [
                ['🔴 Critical', str(summary.get('critical', 0))],
                ['🟠 High', str(summary.get('high', 0))],
                ['🟡 Medium', str(summary.get('medium', 0))],
                ['🟢 Low', str(summary.get('low', 0))],
                ['🔵 Informational', str(summary.get('info', 0))],
            ]
        )
        
        self.add_paragraph(f"**Overall Risk Rating:** {data.get('overall_risk', 'N/A')}")
    
    def generate_findings_section(self, vulnerabilities: List[Dict]):
        """Generate findings section."""
        self.add_header('Detailed Findings', 1)
        
        severity_order = ['critical', 'high', 'medium', 'low', 'info']
        
        for severity in severity_order:
            vulns = [v for v in vulnerabilities if v.get('severity', '').lower() == severity]
            
            if not vulns:
                continue
            
            severity_emoji = {
                'critical': '🔴', 'high': '🟠', 'medium': '🟡',
                'low': '🟢', 'info': '🔵'
            }.get(severity, '⚪')
            
            self.add_header(f'{severity_emoji} {severity.upper()} Severity', 2)
            
            for vuln in vulns:
                self.add_header(vuln.get('title', 'Unknown'), 3)
                
                # Info table
                self.add_table(
                    ['Field', 'Value'],
                    [
                        ['CVE', ', '.join(vuln.get('cve', [])) or 'N/A'],
                        ['CVSS', str(vuln.get('cvss', 'N/A'))],
                        ['Affected', ', '.join(vuln.get('affected_hosts', []))],
                    ]
                )
                
                # Description
                self.add_header('Description', 4)
                self.add_paragraph(vuln.get('description', ''))
                
                # Evidence
                if vuln.get('evidence'):
                    self.add_header('Evidence', 4)
                    self.add_code_block(vuln['evidence'])
                
                # Remediation
                self.add_header('Remediation', 4)
                self.add_paragraph(vuln.get('remediation', 'N/A'))
                
                self.add_paragraph('---')
    
    def generate_recommendations_section(self, recommendations: List[Dict]):
        """Generate recommendations section."""
        self.add_header('Recommendations', 1)
        
        # Priority table
        self.add_table(
            ['Priority', 'Recommendation', 'Effort'],
            [[r.get('priority', ''), r.get('title', ''), r.get('effort', '')] for r in recommendations]
        )
        
        # Detailed recommendations
        for i, rec in enumerate(recommendations, 1):
            self.add_header(f'{i}. {rec.get("title", "")}', 3)
            self.add_paragraph(rec.get('description', ''))
    
    def generate_credentials_section(self, credentials: List[Dict], redact: bool = True):
        """Generate credentials section."""
        self.add_header('Discovered Credentials', 1)
        
        rows = []
        for cred in credentials:
            password = cred.get('password', '')
            if redact and password:
                password = password[:2] + '*' * (len(password) - 2)
            
            rows.append([
                cred.get('username', ''),
                password,
                cred.get('host', ''),
                cred.get('source', ''),
            ])
        
        self.add_table(['Username', 'Password', 'Host', 'Source'], rows)
    
    def generate_full_report(self, report_data: Dict):
        """Generate complete markdown report."""
        # Title
        self.add_header('Penetration Test Report', 1)
        self.add_paragraph(f"*Generated by NexusPen Framework on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")
        self.add_paragraph('')
        
        # Table of Contents
        self.add_header('Table of Contents', 2)
        self.add_list([
            '[Executive Summary](#executive-summary)',
            '[Detailed Findings](#detailed-findings)',
            '[Recommendations](#recommendations)',
            '[Appendix](#appendix)',
        ])
        
        # Executive Summary
        self.generate_executive_summary(report_data.get('executive_summary', {}))
        
        # Findings
        self.generate_findings_section(report_data.get('vulnerabilities', []))
        
        # Recommendations
        self.generate_recommendations_section(report_data.get('recommendations', []))
        
        # Credentials
        if report_data.get('credentials'):
            self.generate_credentials_section(report_data['credentials'])
    
    def generate(self, output_path: str = None) -> str:
        """Generate markdown file."""
        output_path = output_path or self.output_path
        
        console.print(f"\n[cyan]📄 Generating Markdown report...[/cyan]")
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(self.content))
        
        console.print(f"[green]✓ Report saved to {output_path}[/green]")
        return output_path
    
    def get_content(self) -> str:
        """Get markdown content as string."""
        return '\n'.join(self.content)


class TextReportGenerator:
    """
    Plain text report generator.
    """
    
    def __init__(self, output_path: str = '/tmp/nexuspen_report.txt', width: int = 80):
        self.output_path = output_path
        self.width = width
        self.content = []
    
    def add_title(self, title: str):
        """Add centered title with border."""
        border = '=' * self.width
        self.content.append(border)
        self.content.append(title.center(self.width))
        self.content.append(border)
        self.content.append('')
    
    def add_section(self, title: str):
        """Add section header."""
        self.content.append('')
        self.content.append('-' * self.width)
        self.content.append(title.upper())
        self.content.append('-' * self.width)
        self.content.append('')
    
    def add_subsection(self, title: str):
        """Add subsection header."""
        self.content.append('')
        self.content.append(f'[{title}]')
        self.content.append('-' * len(title))
    
    def add_line(self, text: str):
        """Add line of text."""
        self.content.append(text)
    
    def add_key_value(self, key: str, value: str, separator: str = ':'):
        """Add key-value pair."""
        self.content.append(f'{key}{separator} {value}')
    
    def add_table(self, headers: List[str], rows: List[List[str]]):
        """Add ASCII table."""
        # Calculate column widths
        widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                widths[i] = max(widths[i], len(str(cell)))
        
        # Border
        border = '+' + '+'.join('-' * (w + 2) for w in widths) + '+'
        
        # Header
        self.content.append(border)
        header_row = '|' + '|'.join(f' {h.ljust(widths[i])} ' for i, h in enumerate(headers)) + '|'
        self.content.append(header_row)
        self.content.append(border)
        
        # Data
        for row in rows:
            data_row = '|' + '|'.join(f' {str(cell).ljust(widths[i])} ' for i, cell in enumerate(row)) + '|'
            self.content.append(data_row)
        
        self.content.append(border)
        self.content.append('')
    
    def add_box(self, text: str, char: str = '*'):
        """Add text in a box."""
        lines = text.split('\n')
        max_len = max(len(line) for line in lines)
        
        border = char * (max_len + 4)
        self.content.append(border)
        for line in lines:
            self.content.append(f'{char} {line.ljust(max_len)} {char}')
        self.content.append(border)
        self.content.append('')
    
    def generate_full_report(self, report_data: Dict):
        """Generate complete text report."""
        self.add_title('PENETRATION TEST REPORT')
        self.add_line(f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
        self.add_line(f'Generator: NexusPen Framework')
        
        # Executive Summary
        self.add_section('EXECUTIVE SUMMARY')
        
        summary = report_data.get('executive_summary', {})
        self.add_key_value('Target', summary.get('target', 'N/A'))
        self.add_key_value('Total Hosts', str(summary.get('total_hosts', 0)))
        self.add_key_value('Total Vulnerabilities', str(summary.get('total_vulnerabilities', 0)))
        self.add_line('')
        
        self.add_table(
            ['Severity', 'Count'],
            [
                ['Critical', str(summary.get('critical_count', 0))],
                ['High', str(summary.get('high_count', 0))],
                ['Medium', str(summary.get('medium_count', 0))],
                ['Low', str(summary.get('low_count', 0))],
            ]
        )
        
        # Findings
        self.add_section('FINDINGS')
        
        for vuln in report_data.get('vulnerabilities', []):
            self.add_subsection(vuln.get('title', ''))
            self.add_key_value('Severity', vuln.get('severity', '').upper())
            self.add_key_value('CVSS', str(vuln.get('cvss', 'N/A')))
            self.add_key_value('CVE', ', '.join(vuln.get('cve', [])) or 'N/A')
            self.add_line('')
            self.add_line('Description:')
            self.add_line(vuln.get('description', ''))
            self.add_line('')
            self.add_line('Remediation:')
            self.add_line(vuln.get('remediation', ''))
            self.add_line('')
    
    def generate(self, output_path: str = None) -> str:
        """Generate text file."""
        output_path = output_path or self.output_path
        
        console.print(f"\n[cyan]📄 Generating text report...[/cyan]")
        
        with open(output_path, 'w') as f:
            f.write('\n'.join(self.content))
        
        console.print(f"[green]✓ Report saved to {output_path}[/green]")
        return output_path


class CSVReportGenerator:
    """
    CSV report generator for spreadsheet import.
    """
    
    def __init__(self, output_path: str = '/tmp/nexuspen_report.csv'):
        self.output_path = output_path
    
    def generate_vulnerabilities_csv(self, vulnerabilities: List[Dict], output_path: str = None) -> str:
        """Generate vulnerabilities CSV."""
        import csv
        
        output_path = output_path or self.output_path
        
        headers = [
            'ID', 'Title', 'Severity', 'CVSS', 'CVE', 'Affected Hosts',
            'Port', 'Service', 'Description', 'Remediation', 'References'
        ]
        
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            
            for vuln in vulnerabilities:
                writer.writerow([
                    vuln.get('id', ''),
                    vuln.get('title', ''),
                    vuln.get('severity', ''),
                    vuln.get('cvss', ''),
                    '; '.join(vuln.get('cve', [])),
                    '; '.join(vuln.get('affected_hosts', [])),
                    vuln.get('port', ''),
                    vuln.get('service', ''),
                    vuln.get('description', ''),
                    vuln.get('remediation', ''),
                    '; '.join(vuln.get('references', [])),
                ])
        
        console.print(f"[green]✓ CSV report saved to {output_path}[/green]")
        return output_path
    
    def generate_credentials_csv(self, credentials: List[Dict], output_path: str = None) -> str:
        """Generate credentials CSV."""
        import csv
        
        output_path = output_path or self.output_path.replace('.csv', '_credentials.csv')
        
        headers = ['Username', 'Password', 'Hash', 'Domain', 'Host', 'Service', 'Source']
        
        with open(output_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            
            for cred in credentials:
                writer.writerow([
                    cred.get('username', ''),
                    cred.get('password', ''),
                    cred.get('hash', ''),
                    cred.get('domain', ''),
                    cred.get('host', ''),
                    cred.get('service', ''),
                    cred.get('source', ''),
                ])
        
        return output_path
    
    def generate_hosts_csv(self, hosts: List[Dict], output_path: str = None) -> str:
        """Generate hosts CSV."""
        import csv
        
        output_path = output_path or self.output_path.replace('.csv', '_hosts.csv')
        
        headers = ['IP', 'Hostname', 'OS', 'Status', 'Open Ports', 'Services']
        
        with open(output_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            
            for host in hosts:
                ports = [str(p.get('port', '')) for p in host.get('ports', [])]
                services = [p.get('service', '') for p in host.get('ports', [])]
                
                writer.writerow([
                    host.get('ip', ''),
                    host.get('hostname', ''),
                    host.get('os', ''),
                    host.get('status', ''),
                    '; '.join(ports),
                    '; '.join(services),
                ])
        
        return output_path
