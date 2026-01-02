#!/usr/bin/env python3
"""
NexusPen - Encoding Utilities Module
=====================================
Encoding, decoding, and obfuscation utilities.
"""

import base64
import hashlib
import binascii
import urllib.parse
import html
import codecs
from typing import Optional

from rich.console import Console

console = Console()


class Encoder:
    """
    Multi-format encoder/decoder.
    """
    
    @staticmethod
    def base64_encode(data: str) -> str:
        """Base64 encode."""
        return base64.b64encode(data.encode()).decode()
    
    @staticmethod
    def base64_decode(data: str) -> str:
        """Base64 decode."""
        return base64.b64decode(data).decode()
    
    @staticmethod
    def base32_encode(data: str) -> str:
        """Base32 encode."""
        return base64.b32encode(data.encode()).decode()
    
    @staticmethod
    def base32_decode(data: str) -> str:
        """Base32 decode."""
        return base64.b32decode(data).decode()
    
    @staticmethod
    def hex_encode(data: str) -> str:
        """Hex encode."""
        return binascii.hexlify(data.encode()).decode()
    
    @staticmethod
    def hex_decode(data: str) -> str:
        """Hex decode."""
        return binascii.unhexlify(data).decode()
    
    @staticmethod
    def url_encode(data: str) -> str:
        """URL encode."""
        return urllib.parse.quote(data)
    
    @staticmethod
    def url_encode_all(data: str) -> str:
        """URL encode all characters."""
        return ''.join(f'%{ord(c):02x}' for c in data)
    
    @staticmethod
    def url_decode(data: str) -> str:
        """URL decode."""
        return urllib.parse.unquote(data)
    
    @staticmethod
    def double_url_encode(data: str) -> str:
        """Double URL encode."""
        return urllib.parse.quote(urllib.parse.quote(data))
    
    @staticmethod
    def html_encode(data: str) -> str:
        """HTML entity encode."""
        return html.escape(data)
    
    @staticmethod
    def html_decode(data: str) -> str:
        """HTML entity decode."""
        return html.unescape(data)
    
    @staticmethod
    def html_numeric_encode(data: str) -> str:
        """HTML numeric entity encode."""
        return ''.join(f'&#{ord(c)};' for c in data)
    
    @staticmethod
    def html_hex_encode(data: str) -> str:
        """HTML hex entity encode."""
        return ''.join(f'&#x{ord(c):x};' for c in data)
    
    @staticmethod
    def unicode_encode(data: str) -> str:
        """Unicode escape encode."""
        return data.encode('unicode_escape').decode()
    
    @staticmethod
    def rot13(data: str) -> str:
        """ROT13 encode/decode."""
        return codecs.encode(data, 'rot_13')
    
    @staticmethod
    def reverse(data: str) -> str:
        """Reverse string."""
        return data[::-1]
    
    @staticmethod
    def binary_encode(data: str) -> str:
        """Convert to binary."""
        return ' '.join(format(ord(c), '08b') for c in data)
    
    @staticmethod
    def binary_decode(data: str) -> str:
        """Convert from binary."""
        binary = data.replace(' ', '')
        return ''.join(chr(int(binary[i:i+8], 2)) for i in range(0, len(binary), 8))


class Hasher:
    """
    Hash generation and identification.
    """
    
    @staticmethod
    def md5(data: str) -> str:
        """Generate MD5 hash."""
        return hashlib.md5(data.encode()).hexdigest()
    
    @staticmethod
    def sha1(data: str) -> str:
        """Generate SHA1 hash."""
        return hashlib.sha1(data.encode()).hexdigest()
    
    @staticmethod
    def sha256(data: str) -> str:
        """Generate SHA256 hash."""
        return hashlib.sha256(data.encode()).hexdigest()
    
    @staticmethod
    def sha512(data: str) -> str:
        """Generate SHA512 hash."""
        return hashlib.sha512(data.encode()).hexdigest()
    
    @staticmethod
    def ntlm(password: str) -> str:
        """Generate NTLM hash."""
        return hashlib.new('md4', password.encode('utf-16le')).hexdigest()
    
    @staticmethod
    def lm(password: str) -> str:
        """Generate LM hash (deprecated, weak)."""
        import binascii
        from Crypto.Cipher import DES
        
        password = password.upper()[:14].ljust(14, '\x00')
        
        key1 = password[:7]
        key2 = password[7:14]
        
        def str_to_key(s):
            key = []
            for i in range(7):
                key.append(ord(s[i]) >> i)
                key.append((ord(s[i]) << (7-i)) | (ord(s[i+1]) >> (i+1)) if i < 6 else ord(s[i]) << (7-i))
            return bytes(k & 0xfe for k in key[:8])
        
        try:
            magic = b"KGS!@#$%"
            des1 = DES.new(str_to_key(key1), DES.MODE_ECB)
            des2 = DES.new(str_to_key(key2), DES.MODE_ECB)
            return (des1.encrypt(magic) + des2.encrypt(magic)).hex()
        except:
            return "LM hash generation requires pycryptodome"
    
    @staticmethod
    def identify_hash(hash_value: str) -> list:
        """Identify hash type based on characteristics."""
        hash_len = len(hash_value)
        possible = []
        
        # Check if hex
        try:
            int(hash_value, 16)
            is_hex = True
        except ValueError:
            is_hex = False
        
        if not is_hex:
            if '$' in hash_value:
                if hash_value.startswith('$1$'):
                    possible.append('MD5crypt')
                elif hash_value.startswith('$2'):
                    possible.append('bcrypt')
                elif hash_value.startswith('$5$'):
                    possible.append('SHA256crypt')
                elif hash_value.startswith('$6$'):
                    possible.append('SHA512crypt')
                elif hash_value.startswith('$apr1$'):
                    possible.append('Apache MD5')
            return possible
        
        if hash_len == 32:
            possible.extend(['MD5', 'NTLM', 'MD4'])
        elif hash_len == 40:
            possible.append('SHA1')
        elif hash_len == 64:
            possible.append('SHA256')
        elif hash_len == 128:
            possible.append('SHA512')
        elif hash_len == 56:
            possible.append('SHA224')
        elif hash_len == 96:
            possible.append('SHA384')
        
        return possible


class SQLiPayloadEncoder:
    """
    Encode payloads for SQL injection bypass.
    """
    
    @staticmethod
    def hex_encode_string(sql: str) -> str:
        """Hex encode string for MySQL."""
        return '0x' + binascii.hexlify(sql.encode()).decode()
    
    @staticmethod
    def char_encode(sql: str) -> str:
        """CHAR() encode for MySQL."""
        return 'CHAR(' + ','.join(str(ord(c)) for c in sql) + ')'
    
    @staticmethod
    def concat_encode(sql: str) -> str:
        """CONCAT() encode."""
        return 'CONCAT(' + ','.join(f"CHAR({ord(c)})" for c in sql) + ')'
    
    @staticmethod
    def case_swap(sql: str) -> str:
        """Swap case for WAF bypass."""
        result = ''
        for i, c in enumerate(sql):
            if c.isalpha():
                result += c.upper() if i % 2 == 0 else c.lower()
            else:
                result += c
        return result
    
    @staticmethod
    def comment_injection(sql: str) -> str:
        """Add inline comments for bypass."""
        keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR']
        for kw in keywords:
            sql = sql.replace(kw, f'/**/{kw}/**/')
            sql = sql.replace(kw.lower(), f'/**/{kw.lower()}/**/')
        return sql
    
    @staticmethod
    def space_bypass(sql: str) -> str:
        """Replace spaces with alternatives."""
        return sql.replace(' ', '/**/').replace('  ', '/**/')
    
    @staticmethod
    def unicode_bypass(sql: str) -> str:
        """Unicode normalization bypass."""
        mapping = {
            "'": "＇",  # Fullwidth apostrophe
            '"': "＂",  # Fullwidth quotation
            '<': "＜",
            '>': "＞",
        }
        for orig, repl in mapping.items():
            sql = sql.replace(orig, repl)
        return sql


class XSSPayloadEncoder:
    """
    Encode payloads for XSS bypass.
    """
    
    @staticmethod
    def html_entities(payload: str) -> str:
        """HTML entity encode."""
        return ''.join(f'&#{ord(c)};' for c in payload)
    
    @staticmethod
    def javascript_escape(payload: str) -> str:
        """JavaScript escape."""
        return ''.join(f'\\x{ord(c):02x}' for c in payload)
    
    @staticmethod
    def unicode_escape(payload: str) -> str:
        """JavaScript Unicode escape."""
        return ''.join(f'\\u{ord(c):04x}' for c in payload)
    
    @staticmethod
    def base64_script(payload: str) -> str:
        """Base64 encoded script."""
        encoded = base64.b64encode(payload.encode()).decode()
        return f'<script>eval(atob("{encoded}"))</script>'
    
    @staticmethod
    def fromcharcode(text: str) -> str:
        """String.fromCharCode() encoding."""
        codes = ','.join(str(ord(c)) for c in text)
        return f'String.fromCharCode({codes})'
    
    @staticmethod
    def svg_xss(payload: str) -> str:
        """SVG-based XSS."""
        return f'<svg onload="{payload}">'
    
    @staticmethod
    def img_xss(payload: str) -> str:
        """Image-based XSS."""
        return f'<img src=x onerror="{payload}">'


# Utility functions
def encode_payload(payload: str, method: str) -> str:
    """Encode payload using specified method."""
    encoder = Encoder()
    
    methods = {
        'base64': encoder.base64_encode,
        'hex': encoder.hex_encode,
        'url': encoder.url_encode,
        'url_all': encoder.url_encode_all,
        'double_url': encoder.double_url_encode,
        'html': encoder.html_encode,
        'html_numeric': encoder.html_numeric_encode,
        'unicode': encoder.unicode_encode,
        'rot13': encoder.rot13,
        'binary': encoder.binary_encode,
    }
    
    if method in methods:
        return methods[method](payload)
    return payload


def hash_string(data: str, algorithm: str = 'md5') -> str:
    """Hash string using specified algorithm."""
    hasher = Hasher()
    
    algorithms = {
        'md5': hasher.md5,
        'sha1': hasher.sha1,
        'sha256': hasher.sha256,
        'sha512': hasher.sha512,
        'ntlm': hasher.ntlm,
    }
    
    if algorithm in algorithms:
        return algorithms[algorithm](data)
    return ""
