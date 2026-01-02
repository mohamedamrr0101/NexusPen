#!/usr/bin/env python3
"""
NexusPen - Test Configuration
==============================
Pytest configuration and fixtures.
"""

import pytest
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def sample_url():
    """Sample URL for testing."""
    return "http://testphp.vulnweb.com/"


@pytest.fixture
def sample_target():
    """Sample target IP for testing."""
    return "127.0.0.1"


@pytest.fixture
def sample_domain():
    """Sample domain for testing."""
    return "example.com"


@pytest.fixture
def sample_credentials():
    """Sample credentials for testing."""
    return {
        'username': 'admin',
        'password': 'password123',
        'domain': 'WORKGROUP',
    }


@pytest.fixture
def sample_jwt():
    """Sample JWT token for testing."""
    return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"


@pytest.fixture
def sample_hash():
    """Sample password hashes for testing."""
    return {
        'md5': '5f4dcc3b5aa765d61d8327deb882cf99',  # password
        'sha1': '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8',  # password
        'ntlm': 'a4f49c406510bdcab6824ee7c30fd852',  # password
    }


@pytest.fixture
def temp_output_dir(tmp_path):
    """Temporary output directory for tests."""
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    return output_dir


# ============================================================================
# Mock Fixtures
# ============================================================================

@pytest.fixture
def mock_response():
    """Mock HTTP response."""
    class MockResponse:
        def __init__(self, text="", status_code=200, headers=None):
            self.text = text
            self.content = text.encode()
            self.status_code = status_code
            self.headers = headers or {}
            self.url = "http://example.com"
            
        def json(self):
            import json
            return json.loads(self.text)
    
    return MockResponse


@pytest.fixture
def mock_nmap_result():
    """Mock Nmap scan result."""
    return {
        'scan': {
            '127.0.0.1': {
                'hostnames': [{'name': 'localhost'}],
                'status': {'state': 'up'},
                'tcp': {
                    22: {'state': 'open', 'name': 'ssh', 'product': 'OpenSSH'},
                    80: {'state': 'open', 'name': 'http', 'product': 'nginx'},
                    443: {'state': 'open', 'name': 'https', 'product': 'nginx'},
                }
            }
        }
    }


# ============================================================================
# Pytest Configuration
# ============================================================================

def pytest_configure(config):
    """Configure pytest."""
    # Add custom markers
    config.addinivalue_line("markers", "slow: marks tests as slow")
    config.addinivalue_line("markers", "integration: marks tests as integration tests")
    config.addinivalue_line("markers", "network: marks tests that require network access")
    config.addinivalue_line("markers", "requires_root: marks tests that require root privileges")


def pytest_collection_modifyitems(config, items):
    """Modify test collection."""
    # Skip network tests if --no-network flag is set
    if config.getoption("--no-network", default=False):
        skip_network = pytest.mark.skip(reason="Skipping network tests")
        for item in items:
            if "network" in item.keywords:
                item.add_marker(skip_network)


def pytest_addoption(parser):
    """Add custom command line options."""
    parser.addoption(
        "--no-network",
        action="store_true",
        default=False,
        help="Skip tests that require network access"
    )
    parser.addoption(
        "--integration",
        action="store_true",
        default=False,
        help="Run integration tests"
    )
