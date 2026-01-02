#!/usr/bin/env python3
"""
NexusPen - XML Report Generator
================================
XML/OWASP format report generation.
"""

import xml.etree.ElementTree as ET
from xml.dom import minidom
from datetime import datetime
from typing import Dict, List, Optional
import os

from rich.console import Console

console = Console()


class XMLReportGenerator:
    """
    XML report generator with multiple format support.
    """
    
    def __init__(self, output_path: str = '/tmp/nexuspen_report.xml'):
        self.output_path = output_path
        self.root = None
    
    def initialize_report(self, scan_info: Dict):
        """Initialize XML report structure."""
        self.root = ET.Element('PenetrationTestReport')
        self.root.set('generator', 'NexusPen Framework')
        self.root.set('version', '1.0.0')
        self.root.set('generated', datetime.now().isoformat())
        
        # Meta info
        meta = ET.SubElement(self.root, 'MetaData')
        ET.SubElement(meta, 'Target').text = scan_info.get('target', '')
        ET.SubElement(meta, 'StartTime').text = scan_info.get('start_time', datetime.now().isoformat())
        ET.SubElement(meta, 'Methodology').text = scan_info.get('methodology', 'OWASP/PTES')
        
        # Sections
        ET.SubElement(self.root, 'ExecutiveSummary')
        ET.SubElement(self.root, 'Hosts')
        ET.SubElement(self.root, 'Vulnerabilities')
        ET.SubElement(self.root, 'Credentials')
        ET.SubElement(self.root, 'Recommendations')
    
    def add_host(self, host_data: Dict):
        """Add host to report."""
        hosts = self.root.find('Hosts')
        
        host = ET.SubElement(hosts, 'Host')
        host.set('ip', host_data.get('ip', ''))
        
        ET.SubElement(host, 'Hostname').text = host_data.get('hostname', '')
        ET.SubElement(host, 'OS').text = host_data.get('os', '')
        ET.SubElement(host, 'Status').text = host_data.get('status', 'up')
        
        # Ports
        ports_elem = ET.SubElement(host, 'Ports')
        for port_data in host_data.get('ports', []):
            port = ET.SubElement(ports_elem, 'Port')
            port.set('number', str(port_data.get('port', '')))
            port.set('protocol', port_data.get('protocol', 'tcp'))
            port.set('service', port_data.get('service', ''))
            port.set('version', port_data.get('version', ''))
    
    def add_vulnerability(self, vuln_data: Dict):
        """Add vulnerability to report."""
        vulns = self.root.find('Vulnerabilities')
        
        vuln = ET.SubElement(vulns, 'Vulnerability')
        vuln.set('id', vuln_data.get('id', f"VULN-{len(vulns):04d}"))
        vuln.set('severity', vuln_data.get('severity', 'medium'))
        
        ET.SubElement(vuln, 'Title').text = vuln_data.get('title', '')
        ET.SubElement(vuln, 'Description').text = vuln_data.get('description', '')
        ET.SubElement(vuln, 'CVSS').text = str(vuln_data.get('cvss', 0.0))
        
        # CVEs
        cves = ET.SubElement(vuln, 'CVEs')
        for cve in vuln_data.get('cve', []):
            ET.SubElement(cves, 'CVE').text = cve
        
        # Affected hosts
        affected = ET.SubElement(vuln, 'AffectedHosts')
        for host in vuln_data.get('affected_hosts', []):
            ET.SubElement(affected, 'Host').text = host
        
        ET.SubElement(vuln, 'Evidence').text = vuln_data.get('evidence', '')
        ET.SubElement(vuln, 'Remediation').text = vuln_data.get('remediation', '')
        
        # References
        refs = ET.SubElement(vuln, 'References')
        for ref in vuln_data.get('references', []):
            ET.SubElement(refs, 'Reference').text = ref
    
    def add_credential(self, cred_data: Dict):
        """Add credential to report."""
        creds = self.root.find('Credentials')
        
        cred = ET.SubElement(creds, 'Credential')
        cred.set('type', cred_data.get('type', 'password'))
        
        ET.SubElement(cred, 'Username').text = cred_data.get('username', '')
        ET.SubElement(cred, 'Password').text = cred_data.get('password', '')
        ET.SubElement(cred, 'Hash').text = cred_data.get('hash', '')
        ET.SubElement(cred, 'Domain').text = cred_data.get('domain', '')
        ET.SubElement(cred, 'Host').text = cred_data.get('host', '')
        ET.SubElement(cred, 'Source').text = cred_data.get('source', '')
    
    def add_recommendation(self, rec_data: Dict):
        """Add recommendation."""
        recs = self.root.find('Recommendations')
        
        rec = ET.SubElement(recs, 'Recommendation')
        rec.set('priority', rec_data.get('priority', 'medium'))
        
        ET.SubElement(rec, 'Title').text = rec_data.get('title', '')
        ET.SubElement(rec, 'Description').text = rec_data.get('description', '')
        ET.SubElement(rec, 'Effort').text = rec_data.get('effort', 'medium')
    
    def update_summary(self):
        """Update executive summary."""
        vulns = self.root.find('Vulnerabilities')
        summary = self.root.find('ExecutiveSummary')
        
        # Clear existing
        summary.clear()
        
        vuln_list = list(vulns)
        
        ET.SubElement(summary, 'TotalHosts').text = str(len(list(self.root.find('Hosts'))))
        ET.SubElement(summary, 'TotalVulnerabilities').text = str(len(vuln_list))
        
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for v in vuln_list:
            sev = v.get('severity', 'medium').lower()
            if sev in counts:
                counts[sev] += 1
        
        ET.SubElement(summary, 'Critical').text = str(counts['critical'])
        ET.SubElement(summary, 'High').text = str(counts['high'])
        ET.SubElement(summary, 'Medium').text = str(counts['medium'])
        ET.SubElement(summary, 'Low').text = str(counts['low'])
        ET.SubElement(summary, 'Informational').text = str(counts['info'])
    
    def generate(self, output_path: str = None, pretty: bool = True) -> str:
        """Generate XML report."""
        output_path = output_path or self.output_path
        
        console.print(f"\n[cyan]📄 Generating XML report...[/cyan]")
        
        self.update_summary()
        
        if pretty:
            xml_str = minidom.parseString(ET.tostring(self.root)).toprettyxml(indent="  ")
            with open(output_path, 'w') as f:
                f.write(xml_str)
        else:
            tree = ET.ElementTree(self.root)
            tree.write(output_path, encoding='unicode', xml_declaration=True)
        
        console.print(f"[green]✓ Report saved to {output_path}[/green]")
        return output_path


class NessusXMLGenerator:
    """
    Generate Nessus-compatible XML format.
    """
    
    def __init__(self, output_path: str = '/tmp/nexuspen_nessus.nessus'):
        self.output_path = output_path
        self.root = None
    
    def initialize(self):
        """Initialize Nessus format."""
        self.root = ET.Element('NessusClientData_v2')
        
        policy = ET.SubElement(self.root, 'Policy')
        policy_name = ET.SubElement(policy, 'policyName')
        policy_name.text = 'NexusPen Scan Policy'
        
        self.report = ET.SubElement(self.root, 'Report')
        self.report.set('name', 'NexusPen Scan Results')
    
    def add_host(self, ip: str, hostname: str = '', os: str = ''):
        """Add host to report."""
        host = ET.SubElement(self.report, 'ReportHost')
        host.set('name', ip)
        
        # Host properties
        props = ET.SubElement(host, 'HostProperties')
        
        if hostname:
            tag = ET.SubElement(props, 'tag')
            tag.set('name', 'hostname')
            tag.text = hostname
        
        if os:
            tag = ET.SubElement(props, 'tag')
            tag.set('name', 'operating-system')
            tag.text = os
        
        tag = ET.SubElement(props, 'tag')
        tag.set('name', 'host-ip')
        tag.text = ip
        
        return host
    
    def add_finding(self, host_elem: ET.Element, finding: Dict):
        """Add finding to host."""
        item = ET.SubElement(host_elem, 'ReportItem')
        item.set('port', str(finding.get('port', 0)))
        item.set('svc_name', finding.get('service', 'general'))
        item.set('protocol', finding.get('protocol', 'tcp'))
        item.set('severity', str(self._severity_to_number(finding.get('severity', 'medium'))))
        item.set('pluginID', finding.get('plugin_id', '0'))
        item.set('pluginName', finding.get('title', ''))
        item.set('pluginFamily', finding.get('family', 'General'))
        
        ET.SubElement(item, 'description').text = finding.get('description', '')
        ET.SubElement(item, 'solution').text = finding.get('remediation', '')
        ET.SubElement(item, 'synopsis').text = finding.get('synopsis', finding.get('title', ''))
        
        if finding.get('cvss'):
            ET.SubElement(item, 'cvss_base_score').text = str(finding['cvss'])
        
        for cve in finding.get('cve', []):
            ET.SubElement(item, 'cve').text = cve
    
    def _severity_to_number(self, severity: str) -> int:
        """Convert severity to Nessus number."""
        mapping = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
        return mapping.get(severity.lower(), 2)
    
    def generate(self, output_path: str = None) -> str:
        """Generate Nessus XML report."""
        output_path = output_path or self.output_path
        
        xml_str = minidom.parseString(ET.tostring(self.root)).toprettyxml(indent="  ")
        with open(output_path, 'w') as f:
            f.write(xml_str)
        
        console.print(f"[green]✓ Nessus report saved to {output_path}[/green]")
        return output_path


class OpenVASXMLGenerator:
    """
    Generate OpenVAS-compatible XML format.
    """
    
    def __init__(self, output_path: str = '/tmp/nexuspen_openvas.xml'):
        self.output_path = output_path
        self.root = None
    
    def initialize(self):
        """Initialize OpenVAS format."""
        self.root = ET.Element('report')
        self.root.set('id', f'nexuspen-{datetime.now().strftime("%Y%m%d%H%M%S")}')
        self.root.set('format_id', 'a994b278-1f62-11e1-96ac-406186ea4fc5')
        
        ET.SubElement(self.root, 'name').text = 'NexusPen Scan Report'
        ET.SubElement(self.root, 'creation_time').text = datetime.now().isoformat()
        
        self.results = ET.SubElement(self.root, 'results')
    
    def add_result(self, result_data: Dict):
        """Add result to report."""
        result = ET.SubElement(self.results, 'result')
        result.set('id', result_data.get('id', ''))
        
        ET.SubElement(result, 'name').text = result_data.get('title', '')
        ET.SubElement(result, 'host').text = result_data.get('host', '')
        ET.SubElement(result, 'port').text = str(result_data.get('port', ''))
        
        threat = ET.SubElement(result, 'threat')
        threat.text = self._severity_to_threat(result_data.get('severity', 'medium'))
        
        nvt = ET.SubElement(result, 'nvt')
        nvt.set('oid', result_data.get('oid', ''))
        ET.SubElement(nvt, 'name').text = result_data.get('title', '')
        ET.SubElement(nvt, 'family').text = result_data.get('family', 'General')
        ET.SubElement(nvt, 'cvss_base').text = str(result_data.get('cvss', 0.0))
        
        for cve in result_data.get('cve', []):
            refs = ET.SubElement(nvt, 'refs')
            ref = ET.SubElement(refs, 'ref')
            ref.set('type', 'cve')
            ref.set('id', cve)
        
        ET.SubElement(result, 'description').text = result_data.get('description', '')
    
    def _severity_to_threat(self, severity: str) -> str:
        """Convert severity to OpenVAS threat level."""
        mapping = {'critical': 'High', 'high': 'High', 'medium': 'Medium', 'low': 'Low', 'info': 'Log'}
        return mapping.get(severity.lower(), 'Medium')
    
    def generate(self, output_path: str = None) -> str:
        """Generate OpenVAS report."""
        output_path = output_path or self.output_path
        
        xml_str = minidom.parseString(ET.tostring(self.root)).toprettyxml(indent="  ")
        with open(output_path, 'w') as f:
            f.write(xml_str)
        
        console.print(f"[green]✓ OpenVAS report saved to {output_path}[/green]")
        return output_path


class JUnitXMLGenerator:
    """
    Generate JUnit XML format for CI/CD integration.
    """
    
    def __init__(self, output_path: str = '/tmp/nexuspen_junit.xml'):
        self.output_path = output_path
        self.root = None
        self.testsuite = None
    
    def initialize(self, name: str = 'NexusPen Security Tests'):
        """Initialize JUnit format."""
        self.root = ET.Element('testsuites')
        self.testsuite = ET.SubElement(self.root, 'testsuite')
        self.testsuite.set('name', name)
        self.testsuite.set('timestamp', datetime.now().isoformat())
    
    def add_test_case(self, test_data: Dict):
        """Add test case."""
        testcase = ET.SubElement(self.testsuite, 'testcase')
        testcase.set('name', test_data.get('name', ''))
        testcase.set('classname', test_data.get('classname', 'security.scan'))
        testcase.set('time', str(test_data.get('time', 0)))
        
        status = test_data.get('status', 'pass')
        
        if status == 'fail':
            failure = ET.SubElement(testcase, 'failure')
            failure.set('type', test_data.get('severity', 'assertion'))
            failure.set('message', test_data.get('message', ''))
            failure.text = test_data.get('details', '')
        elif status == 'error':
            error = ET.SubElement(testcase, 'error')
            error.set('type', 'error')
            error.set('message', test_data.get('message', ''))
        elif status == 'skip':
            ET.SubElement(testcase, 'skipped')
    
    def add_vulnerability_as_test(self, vuln: Dict):
        """Add vulnerability as failed test."""
        self.add_test_case({
            'name': f"[{vuln.get('severity', 'medium').upper()}] {vuln.get('title', '')}",
            'classname': f"security.{vuln.get('severity', 'medium')}",
            'status': 'fail',
            'severity': vuln.get('severity', 'medium'),
            'message': vuln.get('title', ''),
            'details': vuln.get('description', ''),
        })
    
    def update_counts(self):
        """Update test counts."""
        testcases = list(self.testsuite)
        
        tests = len(testcases)
        failures = sum(1 for tc in testcases if tc.find('failure') is not None)
        errors = sum(1 for tc in testcases if tc.find('error') is not None)
        skipped = sum(1 for tc in testcases if tc.find('skipped') is not None)
        
        self.testsuite.set('tests', str(tests))
        self.testsuite.set('failures', str(failures))
        self.testsuite.set('errors', str(errors))
        self.testsuite.set('skipped', str(skipped))
    
    def generate(self, output_path: str = None) -> str:
        """Generate JUnit XML report."""
        output_path = output_path or self.output_path
        
        self.update_counts()
        
        xml_str = minidom.parseString(ET.tostring(self.root)).toprettyxml(indent="  ")
        with open(output_path, 'w') as f:
            f.write(xml_str)
        
        console.print(f"[green]✓ JUnit report saved to {output_path}[/green]")
        return output_path
