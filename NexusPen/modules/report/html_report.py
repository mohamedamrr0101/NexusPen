#!/usr/bin/env python3
"""
NexusPen - HTML Report Generator
================================
Professional penetration testing report generator.
"""

import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from jinja2 import Template

from rich.console import Console

console = Console()


# Professional HTML Report Template
REPORT_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NexusPen - Penetration Test Report</title>
    <style>
        :root {
            --primary: #1a1a2e;
            --secondary: #16213e;
            --accent: #0f3460;
            --danger: #e94560;
            --warning: #f39c12;
            --success: #27ae60;
            --info: #3498db;
            --light: #ecf0f1;
            --text: #2c3e50;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: var(--light);
            color: var(--text);
            line-height: 1.6;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        /* Header */
        .header {
            background: linear-gradient(135deg, var(--primary), var(--accent));
            color: white;
            padding: 40px;
            text-align: center;
            margin-bottom: 30px;
            border-radius: 10px;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header .subtitle {
            opacity: 0.9;
            font-size: 1.2em;
        }
        
        /* Executive Summary */
        .summary-card {
            background: white;
            border-radius: 10px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        
        .summary-card h2 {
            color: var(--primary);
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid var(--accent);
        }
        
        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 3px 10px rgba(0,0,0,0.1);
        }
        
        .stat-card.critical { border-top: 4px solid var(--danger); }
        .stat-card.high { border-top: 4px solid var(--warning); }
        .stat-card.medium { border-top: 4px solid #f1c40f; }
        .stat-card.low { border-top: 4px solid var(--info); }
        .stat-card.info { border-top: 4px solid var(--success); }
        
        .stat-number {
            font-size: 3em;
            font-weight: bold;
            line-height: 1;
        }
        
        .stat-label {
            font-size: 0.9em;
            color: #666;
            text-transform: uppercase;
            margin-top: 5px;
        }
        
        /* Findings Table */
        .findings-table {
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        
        .findings-table th,
        .findings-table td {
            padding: 15px;
            text-align: left;
            border-bottom: 1px solid #eee;
        }
        
        .findings-table th {
            background: var(--primary);
            color: white;
            font-weight: 600;
        }
        
        .findings-table tr:hover {
            background: #f5f5f5;
        }
        
        /* Severity Badges */
        .badge {
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: 600;
            color: white;
        }
        
        .badge-critical { background: var(--danger); }
        .badge-high { background: var(--warning); }
        .badge-medium { background: #f1c40f; color: #333; }
        .badge-low { background: var(--info); }
        .badge-info { background: var(--success); }
        
        /* Finding Cards */
        .finding-card {
            background: white;
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 3px 10px rgba(0,0,0,0.1);
            border-left: 4px solid var(--accent);
        }
        
        .finding-card.critical { border-left-color: var(--danger); }
        .finding-card.high { border-left-color: var(--warning); }
        .finding-card.medium { border-left-color: #f1c40f; }
        .finding-card.low { border-left-color: var(--info); }
        
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .finding-title {
            font-size: 1.2em;
            font-weight: 600;
            color: var(--primary);
        }
        
        .finding-section {
            margin: 15px 0;
        }
        
        .finding-section h4 {
            color: var(--accent);
            margin-bottom: 8px;
            font-size: 0.9em;
            text-transform: uppercase;
        }
        
        .evidence-box {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 5px;
            padding: 15px;
            font-family: 'Consolas', monospace;
            font-size: 0.85em;
            overflow-x: auto;
        }
        
        /* Target Info */
        .target-info {
            background: var(--secondary);
            color: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 30px;
        }
        
        .target-info h3 {
            margin-bottom: 15px;
        }
        
        .target-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }
        
        .target-item {
            padding: 10px;
            background: rgba(255,255,255,0.1);
            border-radius: 5px;
        }
        
        .target-item label {
            font-size: 0.85em;
            opacity: 0.8;
            display: block;
        }
        
        /* Services Table */
        .services-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        
        .services-table th,
        .services-table td {
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid rgba(255,255,255,0.2);
        }
        
        /* Footer */
        .footer {
            text-align: center;
            padding: 30px;
            margin-top: 40px;
            color: #666;
            font-size: 0.9em;
        }
        
        /* Print Styles */
        @media print {
            body { background: white; }
            .container { max-width: 100%; }
            .header { break-after: avoid; }
            .finding-card { break-inside: avoid; }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>🔐 Penetration Test Report</h1>
            <p class="subtitle">Generated by NexusPen Framework</p>
            <p style="margin-top: 10px; opacity: 0.8;">{{ report_date }}</p>
        </div>
        
        <!-- Target Information -->
        <div class="target-info">
            <h3>🎯 Target Information</h3>
            <div class="target-grid">
                <div class="target-item">
                    <label>Target</label>
                    <strong>{{ target }}</strong>
                </div>
                <div class="target-item">
                    <label>OS Type</label>
                    <strong>{{ target_type }}</strong>
                </div>
                <div class="target-item">
                    <label>Scan Duration</label>
                    <strong>{{ duration }}</strong>
                </div>
                <div class="target-item">
                    <label>Session ID</label>
                    <strong>{{ session_id }}</strong>
                </div>
            </div>
            
            {% if open_ports %}
            <h4 style="margin-top: 20px;">Open Ports</h4>
            <table class="services-table">
                <tr>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Version</th>
                </tr>
                {% for port, service in services.items() %}
                <tr>
                    <td>{{ port }}</td>
                    <td>{{ service.name }}</td>
                    <td>{{ service.product }} {{ service.version }}</td>
                </tr>
                {% endfor %}
            </table>
            {% endif %}
        </div>
        
        <!-- Executive Summary -->
        <div class="summary-card">
            <h2>📋 Executive Summary</h2>
            <p>
                This penetration test was conducted against <strong>{{ target }}</strong> 
                to identify security vulnerabilities and assess the overall security posture.
                The assessment identified <strong>{{ total_findings }} findings</strong> 
                across various severity levels.
            </p>
            
            <!-- Stats Grid -->
            <div class="stats-grid" style="margin-top: 20px;">
                <div class="stat-card critical">
                    <div class="stat-number" style="color: var(--danger);">{{ critical_count }}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat-card high">
                    <div class="stat-number" style="color: var(--warning);">{{ high_count }}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat-card medium">
                    <div class="stat-number" style="color: #f1c40f;">{{ medium_count }}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat-card low">
                    <div class="stat-number" style="color: var(--info);">{{ low_count }}</div>
                    <div class="stat-label">Low</div>
                </div>
                <div class="stat-card info">
                    <div class="stat-number" style="color: var(--success);">{{ info_count }}</div>
                    <div class="stat-label">Informational</div>
                </div>
            </div>
        </div>
        
        <!-- Findings Summary Table -->
        <div class="summary-card">
            <h2>📊 Findings Overview</h2>
            <table class="findings-table">
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Severity</th>
                        <th>Finding</th>
                        <th>CVSS</th>
                        <th>CVE</th>
                    </tr>
                </thead>
                <tbody>
                    {% for finding in findings %}
                    <tr>
                        <td>{{ loop.index }}</td>
                        <td><span class="badge badge-{{ finding.severity }}">{{ finding.severity|upper }}</span></td>
                        <td>{{ finding.title }}</td>
                        <td>{{ finding.cvss_score or 'N/A' }}</td>
                        <td>{{ finding.cve_id or 'N/A' }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        
        <!-- Detailed Findings -->
        <div class="summary-card">
            <h2>🔍 Detailed Findings</h2>
            
            {% for finding in findings %}
            <div class="finding-card {{ finding.severity }}">
                <div class="finding-header">
                    <span class="finding-title">{{ finding.title }}</span>
                    <span class="badge badge-{{ finding.severity }}">{{ finding.severity|upper }}</span>
                </div>
                
                <div class="finding-section">
                    <h4>Description</h4>
                    <p>{{ finding.description }}</p>
                </div>
                
                {% if finding.evidence %}
                <div class="finding-section">
                    <h4>Evidence</h4>
                    <div class="evidence-box">{{ finding.evidence }}</div>
                </div>
                {% endif %}
                
                {% if finding.remediation %}
                <div class="finding-section">
                    <h4>Remediation</h4>
                    <p>{{ finding.remediation }}</p>
                </div>
                {% endif %}
                
                <div style="display: flex; gap: 20px; margin-top: 15px; font-size: 0.9em; color: #666;">
                    {% if finding.cvss_score %}
                    <span>CVSS: {{ finding.cvss_score }}</span>
                    {% endif %}
                    {% if finding.cve_id %}
                    <span>CVE: {{ finding.cve_id }}</span>
                    {% endif %}
                </div>
            </div>
            {% endfor %}
        </div>
        
        <!-- Footer -->
        <div class="footer">
            <p>Report generated by <strong>NexusPen</strong> - Professional Penetration Testing Framework</p>
            <p>{{ report_date }}</p>
        </div>
    </div>
</body>
</html>
'''


def generate(session, profile, results: List, output_dir: Path) -> str:
    """
    Generate HTML report.
    
    Args:
        session: Session data
        profile: Target profile
        results: Scan results
        output_dir: Output directory for report
        
    Returns:
        Path to generated report
    """
    console.print("\n[cyan]📄 Generating HTML Report...[/cyan]")
    
    # Collect all findings from results
    all_findings = []
    for result in results:
        if isinstance(result, dict) and 'findings' in result:
            findings_data = result['findings']
            if isinstance(findings_data, dict) and 'findings' in findings_data:
                all_findings.extend(findings_data['findings'])
            elif isinstance(findings_data, list):
                all_findings.extend(findings_data)
    
    # Count by severity
    severity_counts = {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'info': 0
    }
    
    for finding in all_findings:
        severity = finding.get('severity', 'info').lower()
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    # Calculate duration
    duration = "N/A"
    if hasattr(session, 'start_time') and hasattr(session, 'end_time'):
        if session.end_time:
            try:
                start = datetime.fromisoformat(session.start_time)
                end = datetime.fromisoformat(session.end_time)
                delta = end - start
                duration = str(delta).split('.')[0]  # Remove microseconds
            except:
                pass
    
    # Get services from profile
    services = {}
    open_ports = []
    if profile:
        if hasattr(profile, 'services'):
            services = profile.services if isinstance(profile.services, dict) else {}
        if hasattr(profile, 'open_ports'):
            open_ports = profile.open_ports if isinstance(profile.open_ports, list) else []
    
    # Prepare template data
    template_data = {
        'report_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'target': session.target if hasattr(session, 'target') else 'Unknown',
        'target_type': profile.target_type.value if profile and hasattr(profile, 'target_type') else 'Unknown',
        'session_id': session.session_id if hasattr(session, 'session_id') else 'Unknown',
        'duration': duration,
        'total_findings': len(all_findings),
        'critical_count': severity_counts['critical'],
        'high_count': severity_counts['high'],
        'medium_count': severity_counts['medium'],
        'low_count': severity_counts['low'],
        'info_count': severity_counts['info'],
        'findings': all_findings,
        'services': services,
        'open_ports': open_ports
    }
    
    # Render template
    template = Template(REPORT_TEMPLATE)
    html_content = template.render(**template_data)
    
    # Write report
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_filename = f"nexuspen_report_{timestamp}.html"
    report_path = output_dir / report_filename
    
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    console.print(f"[green]✅ Report saved to: {report_path}[/green]")
    
    return str(report_path)
