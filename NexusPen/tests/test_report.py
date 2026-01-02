#!/usr/bin/env python3
"""
NexusPen - Report Module Tests
===============================
Unit tests for report generation modules.
"""

import pytest
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestReportImports:
    """Test report module imports."""
    
    def test_import_report_module(self):
        """Test importing report package."""
        from modules import report
        assert report is not None
    
    def test_import_html_report(self):
        """Test importing HTML report generator."""
        from modules.report.html_report import HTMLReportGenerator
        assert HTMLReportGenerator is not None
    
    def test_import_json_report(self):
        """Test importing JSON report generator."""
        from modules.report.json_report import JSONReportGenerator
        assert JSONReportGenerator is not None
    
    def test_import_markdown_report(self):
        """Test importing Markdown report generator."""
        from modules.report.markdown_report import MarkdownReportGenerator
        assert MarkdownReportGenerator is not None
    
    def test_import_report_manager(self):
        """Test importing report manager."""
        from modules.report import ReportManager
        assert ReportManager is not None


class TestJSONReport:
    """Test JSON report generation."""
    
    def test_json_report_creation(self, temp_output_dir):
        """Test JSON report creation."""
        from modules.report.json_report import JSONReportGenerator, JSONReportConfig
        
        config = JSONReportConfig(
            output_path=str(temp_output_dir / "test_report.json")
        )
        generator = JSONReportGenerator(config)
        
        assert generator is not None
    
    def test_json_report_add_vulnerability(self, temp_output_dir):
        """Test adding vulnerability to JSON report."""
        from modules.report.json_report import JSONReportGenerator, JSONReportConfig
        
        config = JSONReportConfig(
            output_path=str(temp_output_dir / "test_vuln_report.json")
        )
        generator = JSONReportGenerator(config)
        generator.initialize_report({'target': 'example.com'})
        
        vuln = {
            'name': 'SQL Injection',
            'severity': 'high',
            'description': 'Test vulnerability',
            'remediation': 'Use parameterized queries'
        }
        generator.add_vulnerability(vuln)
        
        output_path = generator.generate()
        
        assert os.path.exists(output_path)
        
        with open(output_path, 'r') as f:
            data = json.load(f)
            assert 'vulnerabilities' in data
            assert len(data['vulnerabilities']) > 0


class TestMarkdownReport:
    """Test Markdown report generation."""
    
    def test_markdown_report_creation(self, temp_output_dir):
        """Test Markdown report creation."""
        from modules.report.markdown_report import MarkdownReportGenerator
        
        output_path = str(temp_output_dir / "test_report.md")
        generator = MarkdownReportGenerator(output_path)
        
        assert generator is not None
    
    def test_markdown_table_generation(self, temp_output_dir):
        """Test Markdown table generation."""
        from modules.report.markdown_report import MarkdownReportGenerator
        
        output_path = str(temp_output_dir / "test_table.md")
        generator = MarkdownReportGenerator(output_path)
        
        headers = ['Name', 'Severity', 'Status']
        rows = [
            ['SQL Injection', 'High', 'Open'],
            ['XSS', 'Medium', 'Fixed'],
        ]
        
        table = generator.create_table(headers, rows)
        
        assert '|' in table
        assert 'SQL Injection' in table
        assert 'High' in table


class TestHTMLReport:
    """Test HTML report generation."""
    
    def test_html_report_creation(self, temp_output_dir):
        """Test HTML report creation."""
        from modules.report.html_report import HTMLReportGenerator
        
        generator = HTMLReportGenerator()
        assert generator is not None
    
    def test_html_report_generation(self, temp_output_dir):
        """Test HTML report file generation."""
        from modules.report.html_report import HTMLReportGenerator
        
        output_path = str(temp_output_dir / "test_report.html")
        generator = HTMLReportGenerator()
        
        # Add some findings
        generator.set_findings([
            {
                'name': 'Test Vulnerability',
                'severity': 'high',
                'description': 'Test description',
            }
        ])
        
        generator.generate(output_path)
        
        assert os.path.exists(output_path)
        
        with open(output_path, 'r', encoding='utf-8') as f:
            content = f.read()
            assert '<html' in content.lower()
            assert 'Test Vulnerability' in content


class TestReportManager:
    """Test report manager functionality."""
    
    def test_manager_creation(self, temp_output_dir):
        """Test report manager creation."""
        from modules.report import ReportManager
        
        manager = ReportManager(str(temp_output_dir))
        assert manager is not None
    
    def test_manager_add_data(self, temp_output_dir):
        """Test adding data to report manager."""
        from modules.report import ReportManager
        
        manager = ReportManager(str(temp_output_dir))
        
        manager.set_target('example.com')
        manager.add_vulnerability({
            'name': 'Test',
            'severity': 'low',
        })
        
        assert 'example.com' in str(manager.report_data.get('target', ''))
