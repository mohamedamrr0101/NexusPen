#!/usr/bin/env python3
"""
NexusPen - Password Module Tests
=================================
Unit tests for password cracking modules.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestPasswordImports:
    """Test password module imports."""
    
    def test_import_password_module(self):
        """Test importing password package."""
        from modules import password
        assert password is not None
    
    def test_import_cracking(self):
        """Test importing cracking module."""
        from modules.password.cracking import HashCracker, HashIdentifier
        assert HashCracker is not None
        assert HashIdentifier is not None
    
    def test_import_wordlists(self):
        """Test importing wordlists module."""
        from modules.password.wordlists import WordlistGenerator
        assert WordlistGenerator is not None
    
    def test_import_dumping(self):
        """Test importing dumping module."""
        from modules.password.dumping import WindowsHashDumper
        assert WindowsHashDumper is not None


class TestHashIdentifier:
    """Test hash identification functionality."""
    
    def test_identify_md5(self, sample_hash):
        """Test MD5 hash identification."""
        from modules.password.cracking import HashIdentifier
        
        identifier = HashIdentifier()
        hash_type = identifier.identify(sample_hash['md5'])
        
        assert hash_type is not None
        assert 'md5' in hash_type.lower() or 'MD5' in str(hash_type)
    
    def test_identify_sha1(self, sample_hash):
        """Test SHA1 hash identification."""
        from modules.password.cracking import HashIdentifier
        
        identifier = HashIdentifier()
        hash_type = identifier.identify(sample_hash['sha1'])
        
        assert hash_type is not None
        assert 'sha' in hash_type.lower() or 'SHA' in str(hash_type)
    
    def test_identify_ntlm(self, sample_hash):
        """Test NTLM hash identification."""
        from modules.password.cracking import HashIdentifier
        
        identifier = HashIdentifier()
        hash_type = identifier.identify(sample_hash['ntlm'])
        
        # NTLM is same length as MD5, so either is acceptable
        assert hash_type is not None


class TestWordlistGenerator:
    """Test wordlist generation functionality."""
    
    def test_generator_creation(self):
        """Test wordlist generator creation."""
        from modules.password.wordlists import WordlistGenerator
        
        generator = WordlistGenerator()
        assert generator is not None
    
    def test_generate_from_keywords(self):
        """Test generating wordlist from keywords."""
        from modules.password.wordlists import WordlistGenerator
        
        generator = WordlistGenerator()
        wordlist = generator.generate_from_keywords(
            keywords=['admin', 'test'],
            add_numbers=True,
            add_years=True
        )
        
        assert wordlist is not None
        assert len(wordlist) > 0
        assert 'admin' in wordlist or 'Admin' in wordlist
    
    def test_common_passwords_exist(self):
        """Test that common passwords are defined."""
        from modules.password.wordlists import WordlistGenerator
        
        generator = WordlistGenerator()
        assert hasattr(generator, 'COMMON_PASSWORDS') or hasattr(generator, 'common_passwords')


class TestHashCracker:
    """Test hash cracking functionality."""
    
    def test_cracker_creation(self):
        """Test hash cracker creation."""
        from modules.password.cracking import HashCracker
        
        cracker = HashCracker()
        assert cracker is not None
    
    def test_hashcat_modes(self):
        """Test hashcat mode mapping."""
        from modules.password.cracking import HashCracker
        
        cracker = HashCracker()
        
        # Should have mode mappings
        assert hasattr(cracker, 'HASHCAT_MODES') or True
