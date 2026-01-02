"""
NexusPen - Report Module
========================
Complete reporting module with multiple format support.

Includes:
- html_report: Professional HTML reports
- pdf_report: PDF document generation
- json_report: Machine-readable JSON/SARIF
- xml_report: Nessus, OpenVAS, JUnit XML formats
- markdown_report: Markdown, Text, CSV exports
- executive_summary: AI-powered summary generation
"""

# HTML Report
from .html_report import HTMLReportGenerator

# PDF Report
from .pdf_report import PDFReport

# JSON Report
from .json_report import (
    JSONReportGenerator,
    JSONReportConfig,
    JSONLReportGenerator,
    convert_to_sarif
)

# XML Report
from .xml_report import (
    XMLReportGenerator,
    NessusXMLGenerator,
    OpenVASXMLGenerator,
    JUnitXMLGenerator
)

# Markdown/Text/CSV Report
from .markdown_report import (
    MarkdownReportGenerator,
    TextReportGenerator,
    CSVReportGenerator
)

# Executive Summary
from .executive_summary import (
    ExecutiveSummaryGenerator,
    ReportTemplateEngine
)

__all__ = [
    # HTML
    'HTMLReportGenerator',
    
    # PDF
    'PDFReport',
    
    # JSON
    'JSONReportGenerator', 'JSONReportConfig', 'JSONLReportGenerator',
    'convert_to_sarif',
    
    # XML
    'XMLReportGenerator', 'NessusXMLGenerator', 
    'OpenVASXMLGenerator', 'JUnitXMLGenerator',
    
    # Markdown/Text/CSV
    'MarkdownReportGenerator', 'TextReportGenerator', 'CSVReportGenerator',
    
    # Executive Summary
    'ExecutiveSummaryGenerator', 'ReportTemplateEngine',
]


class ReportManager:
    """
    Unified report manager for generating reports in multiple formats.
    """
    
    def __init__(self, output_dir: str = '/tmp/nexuspen_reports'):
        self.output_dir = output_dir
        self.report_data = {}
        
        import os
        os.makedirs(output_dir, exist_ok=True)
    
    def set_data(self, report_data: dict):
        """Set report data."""
        self.report_data = report_data
    
    def generate_all(self, basename: str = 'report') -> dict:
        """Generate reports in all formats."""
        from rich.console import Console
        console = Console()
        
        console.print("\n[bold cyan]═══════════════════════════════════════════════════════════[/bold cyan]")
        console.print("[bold cyan]              GENERATING ALL REPORTS                        [/bold cyan]")
        console.print("[bold cyan]═══════════════════════════════════════════════════════════[/bold cyan]")
        
        generated = {}
        
        # HTML
        try:
            html_gen = HTMLReportGenerator()
            html_gen.set_findings(self.report_data.get('vulnerabilities', []))
            html_path = f"{self.output_dir}/{basename}.html"
            html_gen.generate(html_path)
            generated['html'] = html_path
        except Exception as e:
            console.print(f"[red]HTML generation failed: {e}[/red]")
        
        # JSON
        try:
            json_gen = JSONReportGenerator(JSONReportConfig(
                output_path=f"{self.output_dir}/{basename}.json"
            ))
            json_gen.initialize_report({
                'target': self.report_data.get('target', ''),
                'start_time': self.report_data.get('start_time', ''),
            })
            for vuln in self.report_data.get('vulnerabilities', []):
                json_gen.add_vulnerability(vuln)
            for host in self.report_data.get('hosts', []):
                json_gen.add_host(host)
            json_path = json_gen.generate()
            generated['json'] = json_path
        except Exception as e:
            console.print(f"[red]JSON generation failed: {e}[/red]")
        
        # Markdown
        try:
            md_gen = MarkdownReportGenerator(f"{self.output_dir}/{basename}.md")
            md_gen.generate_full_report(self.report_data)
            md_path = md_gen.generate()
            generated['markdown'] = md_path
        except Exception as e:
            console.print(f"[red]Markdown generation failed: {e}[/red]")
        
        # CSV
        try:
            csv_gen = CSVReportGenerator(f"{self.output_dir}/{basename}.csv")
            csv_path = csv_gen.generate_vulnerabilities_csv(
                self.report_data.get('vulnerabilities', [])
            )
            generated['csv'] = csv_path
        except Exception as e:
            console.print(f"[red]CSV generation failed: {e}[/red]")
        
        # XML
        try:
            xml_gen = XMLReportGenerator(f"{self.output_dir}/{basename}.xml")
            xml_gen.initialize_report({'target': self.report_data.get('target', '')})
            for vuln in self.report_data.get('vulnerabilities', []):
                xml_gen.add_vulnerability(vuln)
            xml_path = xml_gen.generate()
            generated['xml'] = xml_path
        except Exception as e:
            console.print(f"[red]XML generation failed: {e}[/red]")
        
        # JUnit (for CI/CD)
        try:
            junit_gen = JUnitXMLGenerator(f"{self.output_dir}/{basename}_junit.xml")
            junit_gen.initialize()
            for vuln in self.report_data.get('vulnerabilities', []):
                junit_gen.add_vulnerability_as_test(vuln)
            junit_path = junit_gen.generate()
            generated['junit'] = junit_path
        except Exception as e:
            console.print(f"[red]JUnit generation failed: {e}[/red]")
        
        # Executive Summary
        try:
            summary_gen = ExecutiveSummaryGenerator()
            summary_gen.analyze_findings(
                self.report_data.get('vulnerabilities', []),
                self.report_data.get('credentials', []),
                self.report_data.get('hosts', [])
            )
            summary_text = summary_gen.generate_text_summary()
            
            summary_path = f"{self.output_dir}/{basename}_executive_summary.txt"
            with open(summary_path, 'w') as f:
                f.write(summary_text)
            generated['executive_summary'] = summary_path
        except Exception as e:
            console.print(f"[red]Executive summary generation failed: {e}[/red]")
        
        # Summary
        console.print("\n[bold green]Generated Reports:[/bold green]")
        for format_type, path in generated.items():
            console.print(f"  [green]✓[/green] {format_type}: {path}")
        
        return generated
    
    def generate_html(self, output_path: str = None) -> str:
        """Generate HTML report only."""
        output_path = output_path or f"{self.output_dir}/report.html"
        html_gen = HTMLReportGenerator()
        html_gen.set_findings(self.report_data.get('vulnerabilities', []))
        return html_gen.generate(output_path)
    
    def generate_json(self, output_path: str = None) -> str:
        """Generate JSON report only."""
        output_path = output_path or f"{self.output_dir}/report.json"
        json_gen = JSONReportGenerator(JSONReportConfig(output_path=output_path))
        json_gen.initialize_report({'target': self.report_data.get('target', '')})
        for vuln in self.report_data.get('vulnerabilities', []):
            json_gen.add_vulnerability(vuln)
        return json_gen.generate()
    
    def generate_markdown(self, output_path: str = None) -> str:
        """Generate Markdown report only."""
        output_path = output_path or f"{self.output_dir}/report.md"
        md_gen = MarkdownReportGenerator(output_path)
        md_gen.generate_full_report(self.report_data)
        return md_gen.generate()


def generate_report(report_data: dict, output_dir: str = '/tmp/nexuspen_reports',
                   formats: list = None) -> dict:
    """
    Quick function to generate reports.
    
    Args:
        report_data: Dictionary with vulnerabilities, hosts, credentials
        output_dir: Output directory for reports
        formats: List of formats ['html', 'json', 'markdown', 'csv', 'xml']
    
    Returns:
        Dictionary with paths to generated reports
    """
    manager = ReportManager(output_dir)
    manager.set_data(report_data)
    
    if formats is None:
        return manager.generate_all()
    
    generated = {}
    
    if 'html' in formats:
        generated['html'] = manager.generate_html()
    if 'json' in formats:
        generated['json'] = manager.generate_json()
    if 'markdown' in formats:
        generated['markdown'] = manager.generate_markdown()
    
    return generated
