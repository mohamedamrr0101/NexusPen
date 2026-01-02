#!/usr/bin/env python3
"""
NexusPen - Core Module Tests
=============================
Unit tests for core functionality.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestCoreImports:
    """Test core module imports."""
    
    def test_import_core(self):
        """Test importing core package."""
        from core import engine, database, logger, utils
        assert engine is not None
        assert database is not None
        assert logger is not None
        assert utils is not None
    
    def test_import_engine(self):
        """Test importing engine module."""
        from core.engine import ScanEngine
        assert ScanEngine is not None
    
    def test_import_database(self):
        """Test importing database module."""
        from core.database import Database
        assert Database is not None
    
    def test_import_logger(self):
        """Test importing logger module."""
        from core.logger import NexusPenLogger
        assert NexusPenLogger is not None


class TestCoreUtils:
    """Test core utility functions."""
    
    def test_utils_import(self):
        """Test utils module import."""
        from core import utils
        assert utils is not None
    
    def test_is_valid_ip(self):
        """Test IP validation."""
        from core.utils import is_valid_ip
        
        assert is_valid_ip("192.168.1.1") == True
        assert is_valid_ip("10.0.0.1") == True
        assert is_valid_ip("256.1.1.1") == False
        assert is_valid_ip("invalid") == False
    
    def test_is_valid_domain(self):
        """Test domain validation."""
        from core.utils import is_valid_domain
        
        assert is_valid_domain("example.com") == True
        assert is_valid_domain("sub.example.com") == True
        assert is_valid_domain("invalid..com") == False


class TestLogger:
    """Test logging functionality."""
    
    def test_logger_creation(self):
        """Test logger creation."""
        from core.logger import NexusPenLogger
        
        logger = NexusPenLogger("test")
        assert logger is not None
    
    def test_logger_levels(self):
        """Test logger log levels."""
        from core.logger import NexusPenLogger
        
        logger = NexusPenLogger("test")
        # Should not raise
        logger.info("Test info message")
        logger.debug("Test debug message")
        logger.warning("Test warning message")


class TestDatabase:
    """Test database functionality."""
    
    def test_database_creation(self, temp_output_dir):
        """Test database creation."""
        from core.database import Database
        
        db_path = str(temp_output_dir / "test.db")
        db = Database(db_path)
        assert db is not None
    
    def test_database_init(self, temp_output_dir):
        """Test database initialization."""
        from core.database import Database
        
        db_path = str(temp_output_dir / "test_init.db")
        db = Database(db_path)
        db.initialize()
        
        assert os.path.exists(db_path)
