#!/usr/bin/env python3
"""
NexusPen - PDF Report Generator
===============================
Generate professional PDF reports using WeasyPrint.
"""

import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from rich.console import Console

console = Console()


def generate_pdf(session, profile, results: List, output_dir: Path) -> str:
    """
    Generate PDF report from HTML.
    
    Args:
        session: Session data
        profile: Target profile
        results: Scan results
        output_dir: Output directory
        
    Returns:
        Path to generated PDF
    """
    console.print("\n[cyan]📄 Generating PDF Report...[/cyan]")
    
    try:
        from .html_report import generate as generate_html
        from weasyprint import HTML, CSS
        
        # First generate HTML
        html_path = generate_html(session, profile, results, output_dir)
        
        # Convert to PDF
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        pdf_filename = f"nexuspen_report_{timestamp}.pdf"
        pdf_path = Path(output_dir) / pdf_filename
        
        # Add print-friendly CSS
        print_css = CSS(string='''
            @page {
                size: A4;
                margin: 2cm;
            }
            body {
                font-size: 11pt;
            }
            .finding-card {
                page-break-inside: avoid;
            }
        ''')
        
        HTML(filename=html_path).write_pdf(str(pdf_path), stylesheets=[print_css])
        
        console.print(f"[green]✅ PDF saved to: {pdf_path}[/green]")
        return str(pdf_path)
        
    except ImportError:
        console.print("[yellow]WeasyPrint not installed, skipping PDF generation[/yellow]")
        return ""
    except Exception as e:
        console.print(f"[red]PDF generation failed: {e}[/red]")
        return ""


def generate_json(session, profile, results: List, output_dir: Path) -> str:
    """
    Generate JSON export.
    
    Args:
        session: Session data
        profile: Target profile
        results: Scan results
        output_dir: Output directory
        
    Returns:
        Path to generated JSON file
    """
    import json
    
    console.print("\n[cyan]📄 Generating JSON Export...[/cyan]")
    
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    json_filename = f"nexuspen_export_{timestamp}.json"
    json_path = output_dir / json_filename
    
    export_data = {
        'report_date': datetime.now().isoformat(),
        'target': session.target if hasattr(session, 'target') else 'Unknown',
        'session_id': session.session_id if hasattr(session, 'session_id') else None,
        'target_profile': {
            'target_type': profile.target_type.value if profile else None,
            'os_name': profile.os_name if profile else None,
            'open_ports': profile.open_ports if profile else [],
            'services': profile.services if profile else {},
        } if profile else None,
        'results': results,
        'findings': [],
    }
    
    # Extract all findings
    for result in results:
        if isinstance(result, dict) and 'findings' in result:
            findings = result['findings']
            if isinstance(findings, dict) and 'findings' in findings:
                export_data['findings'].extend(findings['findings'])
            elif isinstance(findings, list):
                export_data['findings'].extend(findings)
    
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(export_data, f, indent=2, default=str)
    
    console.print(f"[green]✅ JSON saved to: {json_path}[/green]")
    return str(json_path)


def generate_xml(session, profile, results: List, output_dir: Path) -> str:
    """
    Generate XML export.
    
    Args:
        session: Session data  
        profile: Target profile
        results: Scan results
        output_dir: Output directory
        
    Returns:
        Path to generated XML file
    """
    import xml.etree.ElementTree as ET
    from xml.dom import minidom
    
    console.print("\n[cyan]📄 Generating XML Export...[/cyan]")
    
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    xml_filename = f"nexuspen_export_{timestamp}.xml"
    xml_path = output_dir / xml_filename
    
    # Build XML structure
    root = ET.Element('NexusPenReport')
    root.set('date', datetime.now().isoformat())
    
    # Target info
    target_elem = ET.SubElement(root, 'Target')
    ET.SubElement(target_elem, 'Address').text = session.target if hasattr(session, 'target') else 'Unknown'
    ET.SubElement(target_elem, 'SessionID').text = session.session_id if hasattr(session, 'session_id') else ''
    
    if profile:
        ET.SubElement(target_elem, 'Type').text = profile.target_type.value if hasattr(profile, 'target_type') else ''
        ET.SubElement(target_elem, 'OS').text = profile.os_name or ''
    
    # Findings
    findings_elem = ET.SubElement(root, 'Findings')
    
    for result in results:
        if isinstance(result, dict) and 'findings' in result:
            findings = result['findings']
            if isinstance(findings, dict) and 'findings' in findings:
                findings_list = findings['findings']
            elif isinstance(findings, list):
                findings_list = findings
            else:
                continue
                
            for finding in findings_list:
                if isinstance(finding, dict):
                    finding_elem = ET.SubElement(findings_elem, 'Finding')
                    finding_elem.set('severity', finding.get('severity', 'info'))
                    
                    ET.SubElement(finding_elem, 'Title').text = finding.get('title', 'Unknown')
                    ET.SubElement(finding_elem, 'Description').text = finding.get('description', '')
                    
                    if finding.get('cve_id'):
                        ET.SubElement(finding_elem, 'CVE').text = finding.get('cve_id')
                    if finding.get('cvss_score'):
                        ET.SubElement(finding_elem, 'CVSS').text = str(finding.get('cvss_score'))
    
    # Pretty print
    xml_str = minidom.parseString(ET.tostring(root)).toprettyxml(indent="  ")
    
    with open(xml_path, 'w', encoding='utf-8') as f:
        f.write(xml_str)
    
    console.print(f"[green]✅ XML saved to: {xml_path}[/green]")
    return str(xml_path)
