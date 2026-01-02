#!/usr/bin/env python3
"""
NexusPen - Web Module Tests
============================
Unit tests for web security modules.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestWebImports:
    """Test web module imports."""
    
    def test_import_web_module(self):
        """Test importing web package."""
        from modules import web
        assert web is not None
    
    def test_import_sqli_scanner(self):
        """Test importing SQLi scanner."""
        from modules.web.sqli import SQLiScanner
        assert SQLiScanner is not None
    
    def test_import_xss_scanner(self):
        """Test importing XSS scanner."""
        from modules.web.xss import XSSScanner
        assert XSSScanner is not None
    
    def test_import_ssrf_scanner(self):
        """Test importing SSRF scanner."""
        from modules.web.ssrf import SSRFScanner
        assert SSRFScanner is not None
    
    def test_import_jwt_analyzer(self):
        """Test importing JWT analyzer."""
        from modules.web.jwt_session import JWTAnalyzer
        assert JWTAnalyzer is not None


class TestJWTAnalyzer:
    """Test JWT analysis functionality."""
    
    def test_decode_jwt(self, sample_jwt):
        """Test JWT decoding."""
        from modules.web.jwt_session import JWTAnalyzer
        
        analyzer = JWTAnalyzer(sample_jwt)
        header, payload = analyzer.decode()
        
        assert header is not None
        assert payload is not None
        assert header.get('alg') == 'HS256'
        assert payload.get('sub') == '1234567890'
    
    def test_detect_none_algorithm(self):
        """Test detection of none algorithm vulnerability."""
        from modules.web.jwt_session import JWTAnalyzer
        
        # JWT with none algorithm
        none_jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0."
        
        analyzer = JWTAnalyzer(none_jwt)
        vulns = analyzer.analyze_vulnerabilities()
        
        # Should detect none algorithm vulnerability
        assert any('none' in str(v).lower() for v in vulns)


class TestSQLiPayloads:
    """Test SQL injection payloads."""
    
    def test_sqli_scanner_creation(self, sample_url):
        """Test SQLi scanner creation."""
        from modules.web.sqli import SQLiScanner
        
        scanner = SQLiScanner(sample_url + "?id=1")
        assert scanner is not None
        assert scanner.url == sample_url + "?id=1"
    
    def test_sqli_payloads_exist(self):
        """Test that SQLi payloads are defined."""
        from modules.web.sqli import SQLiScanner
        
        scanner = SQLiScanner("http://test.com?id=1")
        # Scanner should have payloads
        assert hasattr(scanner, 'ERROR_PAYLOADS') or hasattr(scanner, 'payloads')


class TestXSSPayloads:
    """Test XSS payloads."""
    
    def test_xss_scanner_creation(self, sample_url):
        """Test XSS scanner creation."""
        from modules.web.xss import XSSScanner
        
        scanner = XSSScanner(sample_url + "?search=test")
        assert scanner is not None
    
    def test_xss_payloads_exist(self):
        """Test that XSS payloads are defined."""
        from modules.web.xss import XSSScanner
        
        scanner = XSSScanner("http://test.com?q=test")
        # Scanner should have payloads
        assert hasattr(scanner, 'PAYLOADS') or hasattr(scanner, 'payloads')


class TestVulnScanner:
    """Test general vulnerability scanner."""
    
    def test_import_vuln_scanner(self):
        """Test importing vulnerability scanner."""
        from modules.web.vuln_scanner import WebVulnScanner
        assert WebVulnScanner is not None
    
    def test_vuln_scanner_creation(self, sample_url):
        """Test vulnerability scanner creation."""
        from modules.web.vuln_scanner import WebVulnScanner
        
        scanner = WebVulnScanner(sample_url)
        assert scanner is not None
        assert scanner.target == sample_url


class TestAPIScanner:
    """Test API security scanner."""
    
    def test_import_api_scanner(self):
        """Test importing API scanner."""
        from modules.web.api_scanner import RESTAPIScanner, GraphQLScanner
        assert RESTAPIScanner is not None
        assert GraphQLScanner is not None
    
    def test_rest_scanner_creation(self, sample_url):
        """Test REST API scanner creation."""
        from modules.web.api_scanner import RESTAPIScanner
        
        scanner = RESTAPIScanner(sample_url + "api/v1")
        assert scanner is not None
