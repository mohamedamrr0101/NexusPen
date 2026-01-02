#!/usr/bin/env python3
"""
NexusPen - Executive Summary Generator
=======================================
AI-powered executive summary generation.
"""

from datetime import datetime
from typing import Dict, List, Optional
import textwrap

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


class ExecutiveSummaryGenerator:
    """
    Generate professional executive summaries.
    """
    
    RISK_LEVELS = {
        'critical': {
            'color': 'red',
            'description': 'Immediate action required. Systems are at imminent risk of compromise.',
            'action': 'Engage incident response team and implement emergency remediation.',
        },
        'high': {
            'color': 'orange',
            'description': 'Significant vulnerabilities present. High likelihood of exploitation.',
            'action': 'Prioritize remediation within 7 days.',
        },
        'medium': {
            'color': 'yellow',
            'description': 'Moderate risk. Vulnerabilities should be addressed in regular patching cycle.',
            'action': 'Schedule remediation within 30 days.',
        },
        'low': {
            'color': 'green',
            'description': 'Minor issues identified. Low risk to the organization.',
            'action': 'Address during next maintenance window.',
        },
    }
    
    def __init__(self):
        self.summary_data = {}
    
    def analyze_findings(self, vulnerabilities: List[Dict], 
                        credentials: List[Dict] = None,
                        hosts: List[Dict] = None) -> Dict:
        """Analyze findings and generate summary data."""
        
        # Count by severity
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for vuln in vulnerabilities:
            sev = vuln.get('severity', 'medium').lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        # Calculate risk score (weighted)
        risk_score = (
            severity_counts['critical'] * 10 +
            severity_counts['high'] * 7 +
            severity_counts['medium'] * 4 +
            severity_counts['low'] * 1
        )
        
        # Determine overall risk
        if severity_counts['critical'] > 0:
            overall_risk = 'critical'
        elif severity_counts['high'] >= 3:
            overall_risk = 'critical'
        elif severity_counts['high'] > 0:
            overall_risk = 'high'
        elif severity_counts['medium'] >= 5:
            overall_risk = 'high'
        elif severity_counts['medium'] > 0:
            overall_risk = 'medium'
        else:
            overall_risk = 'low'
        
        # Identify key findings
        key_findings = []
        for vuln in sorted(vulnerabilities, key=lambda x: 
                          {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
                          .get(x.get('severity', 'medium').lower(), 5))[:5]:
            key_findings.append({
                'title': vuln.get('title', ''),
                'severity': vuln.get('severity', ''),
                'impact': vuln.get('description', '')[:200] + '...' if len(vuln.get('description', '')) > 200 else vuln.get('description', ''),
            })
        
        self.summary_data = {
            'severity_counts': severity_counts,
            'total_vulnerabilities': len(vulnerabilities),
            'total_hosts': len(hosts) if hosts else 0,
            'total_credentials': len(credentials) if credentials else 0,
            'risk_score': risk_score,
            'overall_risk': overall_risk,
            'key_findings': key_findings,
            'exploitable_count': sum(1 for v in vulnerabilities if v.get('exploit_available')),
            'has_credentials': bool(credentials),
        }
        
        return self.summary_data
    
    def generate_text_summary(self) -> str:
        """Generate text executive summary."""
        data = self.summary_data
        risk_info = self.RISK_LEVELS.get(data['overall_risk'], self.RISK_LEVELS['medium'])
        
        summary = f"""
EXECUTIVE SUMMARY
=================

Assessment Overview
-------------------
This penetration testing assessment was conducted to evaluate the security posture 
of the target environment. The assessment identified a total of {data['total_vulnerabilities']} 
vulnerabilities across {data['total_hosts']} hosts.

Overall Risk Rating: {data['overall_risk'].upper()}
{risk_info['description']}

Vulnerability Breakdown
-----------------------
• Critical: {data['severity_counts']['critical']}
• High: {data['severity_counts']['high']}
• Medium: {data['severity_counts']['medium']}
• Low: {data['severity_counts']['low']}
• Informational: {data['severity_counts']['info']}

Key Findings
------------
"""
        for i, finding in enumerate(data['key_findings'], 1):
            summary += f"\n{i}. [{finding['severity'].upper()}] {finding['title']}"
        
        if data['has_credentials']:
            summary += f"""

Credential Exposure
------------------
The assessment revealed {data['total_credentials']} exposed credentials, indicating 
potential unauthorized access risks.
"""
        
        summary += f"""

Recommended Actions
-------------------
{risk_info['action']}

Immediate priorities:
1. Address all critical and high severity vulnerabilities
2. Implement network segmentation to limit lateral movement
3. Review and strengthen access controls
4. Enable comprehensive logging and monitoring
"""
        
        return summary.strip()
    
    def generate_html_summary(self) -> str:
        """Generate HTML executive summary widget."""
        data = self.summary_data
        risk_info = self.RISK_LEVELS.get(data['overall_risk'], self.RISK_LEVELS['medium'])
        
        html = f"""
<div class="executive-summary">
    <div class="risk-badge risk-{data['overall_risk']}">
        <span class="risk-label">Overall Risk</span>
        <span class="risk-value">{data['overall_risk'].upper()}</span>
    </div>
    
    <div class="summary-stats">
        <div class="stat">
            <span class="stat-value">{data['total_vulnerabilities']}</span>
            <span class="stat-label">Vulnerabilities</span>
        </div>
        <div class="stat">
            <span class="stat-value">{data['total_hosts']}</span>
            <span class="stat-label">Hosts</span>
        </div>
        <div class="stat stat-critical">
            <span class="stat-value">{data['severity_counts']['critical']}</span>
            <span class="stat-label">Critical</span>
        </div>
        <div class="stat stat-high">
            <span class="stat-value">{data['severity_counts']['high']}</span>
            <span class="stat-label">High</span>
        </div>
    </div>
    
    <div class="risk-description">
        <p>{risk_info['description']}</p>
        <p><strong>Action Required:</strong> {risk_info['action']}</p>
    </div>
    
    <div class="key-findings">
        <h3>Key Findings</h3>
        <ul>
"""
        for finding in data['key_findings']:
            html += f"""            <li class="finding finding-{finding['severity'].lower()}">
                <span class="severity">{finding['severity'].upper()}</span>
                {finding['title']}
            </li>
"""
        
        html += """        </ul>
    </div>
</div>
"""
        return html
    
    def generate_metrics_dashboard(self) -> str:
        """Generate metrics for dashboard display."""
        data = self.summary_data
        
        return f"""
╔══════════════════════════════════════════════════════════════╗
║                    SECURITY METRICS DASHBOARD                 ║
╠══════════════════════════════════════════════════════════════╣
║                                                               ║
║   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          ║
║   │   RISK      │  │   VULNS     │  │   HOSTS     │          ║
║   │  {data['overall_risk'].upper():^9}  │  │    {data['total_vulnerabilities']:^5}    │  │    {data['total_hosts']:^5}    │          ║
║   └─────────────┘  └─────────────┘  └─────────────┘          ║
║                                                               ║
║   Severity Distribution:                                      ║
║   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━    ║
║   🔴 Critical: {data['severity_counts']['critical']:>3}    🟠 High: {data['severity_counts']['high']:>3}    🟡 Medium: {data['severity_counts']['medium']:>3}         ║
║   🟢 Low: {data['severity_counts']['low']:>3}         🔵 Info: {data['severity_counts']['info']:>3}                              ║
║                                                               ║
║   Exploitable: {data['exploitable_count']:>3}    Credentials Found: {data['total_credentials']:>3}              ║
║                                                               ║
╚══════════════════════════════════════════════════════════════╝
"""
    
    def display_console_summary(self):
        """Display summary in console with rich formatting."""
        data = self.summary_data
        
        # Risk panel
        risk_color = {'critical': 'red', 'high': 'orange1', 'medium': 'yellow', 'low': 'green'}
        
        console.print(Panel(
            f"[bold {risk_color.get(data['overall_risk'], 'white')}]{data['overall_risk'].upper()}[/]",
            title="Overall Risk",
            border_style=risk_color.get(data['overall_risk'], 'white'),
        ))
        
        # Stats table
        table = Table(title="Vulnerability Summary", show_header=True)
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="center")
        
        table.add_row("[red]Critical[/red]", str(data['severity_counts']['critical']))
        table.add_row("[orange1]High[/orange1]", str(data['severity_counts']['high']))
        table.add_row("[yellow]Medium[/yellow]", str(data['severity_counts']['medium']))
        table.add_row("[green]Low[/green]", str(data['severity_counts']['low']))
        table.add_row("[blue]Info[/blue]", str(data['severity_counts']['info']))
        
        console.print(table)
        
        # Key findings
        console.print("\n[bold]Key Findings:[/bold]")
        for finding in data['key_findings']:
            sev_color = {'critical': 'red', 'high': 'orange1', 'medium': 'yellow', 'low': 'green'}.get(finding['severity'].lower(), 'white')
            console.print(f"  [{sev_color}]•[/{sev_color}] [{sev_color}][{finding['severity'].upper()}][/{sev_color}] {finding['title']}")


class ReportTemplateEngine:
    """
    Template engine for report generation.
    """
    
    def __init__(self):
        self.templates = {}
    
    def load_template(self, name: str, template: str):
        """Load a template."""
        self.templates[name] = template
    
    def render(self, template_name: str, data: Dict) -> str:
        """Render template with data."""
        template = self.templates.get(template_name, '')
        
        # Simple variable substitution
        for key, value in data.items():
            template = template.replace(f'{{{{{key}}}}}', str(value))
        
        return template
    
    @staticmethod
    def default_html_template() -> str:
        """Get default HTML report template."""
        return """
<!DOCTYPE html>
<html>
<head>
    <title>Penetration Test Report - {{target}}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { text-align: center; border-bottom: 2px solid #333; padding-bottom: 20px; }
        .section { margin: 30px 0; }
        .vulnerability { border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .severity-critical { border-left: 5px solid #dc3545; }
        .severity-high { border-left: 5px solid #fd7e14; }
        .severity-medium { border-left: 5px solid #ffc107; }
        .severity-low { border-left: 5px solid #28a745; }
        .badge { padding: 3px 8px; border-radius: 3px; color: white; font-size: 12px; }
        .badge-critical { background: #dc3545; }
        .badge-high { background: #fd7e14; }
        .badge-medium { background: #ffc107; color: black; }
        .badge-low { background: #28a745; }
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
        th { background: #f5f5f5; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Penetration Test Report</h1>
        <p>Target: {{target}}</p>
        <p>Date: {{date}}</p>
    </div>
    
    <div class="section">
        <h2>Executive Summary</h2>
        {{executive_summary}}
    </div>
    
    <div class="section">
        <h2>Findings</h2>
        {{findings}}
    </div>
    
    <div class="section">
        <h2>Recommendations</h2>
        {{recommendations}}
    </div>
    
    <div class="footer">
        <p><em>Generated by NexusPen Framework</em></p>
    </div>
</body>
</html>
"""
