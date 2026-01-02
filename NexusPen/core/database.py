#!/usr/bin/env python3
"""
NexusPen - Database Module
==========================
SQLite database for storing scan results and sessions.
"""

import sqlite3
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any
from contextlib import contextmanager


class Database:
    """SQLite database handler for NexusPen."""
    
    def __init__(self, db_path: str = "nexuspen.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
    
    @contextmanager
    def _get_connection(self):
        """Context manager for database connections."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()
    
    def _init_db(self):
        """Initialize database schema."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Sessions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    profile TEXT,
                    phases_completed TEXT,
                    total_findings INTEGER DEFAULT 0,
                    critical_findings INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'in_progress',
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Results table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    module TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    status TEXT NOT NULL,
                    findings TEXT,
                    duration REAL,
                    raw_output TEXT,
                    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
                )
            ''')
            
            # Findings table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    result_id INTEGER,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    evidence TEXT,
                    remediation TEXT,
                    cvss_score REAL,
                    cve_id TEXT,
                    port INTEGER,
                    service TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (session_id) REFERENCES sessions(session_id),
                    FOREIGN KEY (result_id) REFERENCES results(id)
                )
            ''')
            
            # Hosts table (for network scans)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS hosts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    hostname TEXT,
                    os TEXT,
                    status TEXT,
                    open_ports TEXT,
                    services TEXT,
                    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
                )
            ''')
            
            # Credentials table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    host TEXT,
                    service TEXT,
                    port INTEGER,
                    username TEXT,
                    password TEXT,
                    hash TEXT,
                    source TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
                )
            ''')
    
    def save_session(self, session_data: Dict):
        """Save or update a session."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO sessions 
                (session_id, target, start_time, end_time, profile, 
                 phases_completed, total_findings, critical_findings, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                session_data.get('session_id'),
                session_data.get('target'),
                session_data.get('start_time'),
                session_data.get('end_time'),
                json.dumps(session_data.get('profile', {})),
                json.dumps(session_data.get('phases_completed', [])),
                session_data.get('total_findings', 0),
                session_data.get('critical_findings', 0),
                session_data.get('status', 'in_progress')
            ))
    
    def get_session(self, session_id: str) -> Optional[Dict]:
        """Get a session by ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM sessions WHERE session_id = ?', (session_id,))
            row = cursor.fetchone()
            
            if row:
                return {
                    'session_id': row['session_id'],
                    'target': row['target'],
                    'start_time': row['start_time'],
                    'end_time': row['end_time'],
                    'profile': json.loads(row['profile']) if row['profile'] else None,
                    'phases_completed': json.loads(row['phases_completed']) if row['phases_completed'] else [],
                    'total_findings': row['total_findings'],
                    'critical_findings': row['critical_findings'],
                    'status': row['status']
                }
            
            return None
    
    def list_sessions(self, limit: int = 20) -> List[Dict]:
        """List recent sessions."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT session_id, target, start_time, status, total_findings
                FROM sessions
                ORDER BY created_at DESC
                LIMIT ?
            ''', (limit,))
            
            return [dict(row) for row in cursor.fetchall()]
    
    def save_result(self, session_id: str, result: Dict) -> int:
        """Save a scan result."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO results 
                (session_id, module, phase, timestamp, status, findings, duration, raw_output)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                session_id,
                result.get('module'),
                result.get('phase'),
                result.get('timestamp', datetime.now().isoformat()),
                result.get('status'),
                json.dumps(result.get('findings', [])),
                result.get('duration'),
                result.get('raw_output')
            ))
            
            return cursor.lastrowid
    
    def get_results(self, session_id: str, phase: str = None) -> List[Dict]:
        """Get results for a session, optionally filtered by phase."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            if phase:
                cursor.execute('''
                    SELECT * FROM results 
                    WHERE session_id = ? AND phase = ?
                    ORDER BY timestamp
                ''', (session_id, phase))
            else:
                cursor.execute('''
                    SELECT * FROM results 
                    WHERE session_id = ?
                    ORDER BY timestamp
                ''', (session_id,))
            
            results = []
            for row in cursor.fetchall():
                results.append({
                    'id': row['id'],
                    'module': row['module'],
                    'phase': row['phase'],
                    'timestamp': row['timestamp'],
                    'status': row['status'],
                    'findings': json.loads(row['findings']) if row['findings'] else [],
                    'duration': row['duration'],
                    'raw_output': row['raw_output']
                })
            
            return results
    
    def save_finding(self, session_id: str, finding: Dict, result_id: int = None):
        """Save a security finding."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO findings 
                (session_id, result_id, severity, title, description, 
                 evidence, remediation, cvss_score, cve_id, port, service)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                session_id,
                result_id,
                finding.get('severity', 'info'),
                finding.get('title'),
                finding.get('description'),
                finding.get('evidence'),
                finding.get('remediation'),
                finding.get('cvss_score'),
                finding.get('cve_id'),
                finding.get('port'),
                finding.get('service')
            ))
            
            # Update findings count in session
            cursor.execute('''
                UPDATE sessions 
                SET total_findings = total_findings + 1
                WHERE session_id = ?
            ''', (session_id,))
            
            if finding.get('severity') in ['critical', 'high']:
                cursor.execute('''
                    UPDATE sessions 
                    SET critical_findings = critical_findings + 1
                    WHERE session_id = ?
                ''', (session_id,))
    
    def get_findings(self, session_id: str, severity: str = None) -> List[Dict]:
        """Get findings for a session."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            if severity:
                cursor.execute('''
                    SELECT * FROM findings 
                    WHERE session_id = ? AND severity = ?
                    ORDER BY cvss_score DESC
                ''', (session_id, severity))
            else:
                cursor.execute('''
                    SELECT * FROM findings 
                    WHERE session_id = ?
                    ORDER BY 
                        CASE severity 
                            WHEN 'critical' THEN 1 
                            WHEN 'high' THEN 2 
                            WHEN 'medium' THEN 3 
                            WHEN 'low' THEN 4 
                            ELSE 5 
                        END
                ''', (session_id,))
            
            return [dict(row) for row in cursor.fetchall()]
    
    def save_host(self, session_id: str, host: Dict):
        """Save a discovered host."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO hosts 
                (session_id, ip, hostname, os, status, open_ports, services)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                session_id,
                host.get('ip'),
                host.get('hostname'),
                host.get('os'),
                host.get('status'),
                json.dumps(host.get('open_ports', [])),
                json.dumps(host.get('services', {}))
            ))
    
    def get_hosts(self, session_id: str) -> List[Dict]:
        """Get discovered hosts for a session."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM hosts WHERE session_id = ?', (session_id,))
            
            hosts = []
            for row in cursor.fetchall():
                hosts.append({
                    'ip': row['ip'],
                    'hostname': row['hostname'],
                    'os': row['os'],
                    'status': row['status'],
                    'open_ports': json.loads(row['open_ports']) if row['open_ports'] else [],
                    'services': json.loads(row['services']) if row['services'] else {}
                })
            
            return hosts
    
    def save_credential(self, session_id: str, credential: Dict):
        """Save a discovered credential."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO credentials 
                (session_id, host, service, port, username, password, hash, source)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                session_id,
                credential.get('host'),
                credential.get('service'),
                credential.get('port'),
                credential.get('username'),
                credential.get('password'),
                credential.get('hash'),
                credential.get('source')
            ))
    
    def get_credentials(self, session_id: str) -> List[Dict]:
        """Get discovered credentials for a session."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM credentials WHERE session_id = ?', (session_id,))
            
            return [dict(row) for row in cursor.fetchall()]


def list_sessions():
    """CLI function to list sessions."""
    from rich.console import Console
    from rich.table import Table
    
    console = Console()
    db = Database()
    
    sessions = db.list_sessions()
    
    if not sessions:
        console.print("[yellow]No sessions found.[/yellow]")
        return
    
    table = Table(title="Saved Sessions", show_header=True, header_style="bold magenta")
    table.add_column("Session ID", style="cyan")
    table.add_column("Target", style="white")
    table.add_column("Start Time", style="green")
    table.add_column("Status", style="yellow")
    table.add_column("Findings", style="red")
    
    for session in sessions:
        table.add_row(
            session['session_id'],
            session['target'],
            session['start_time'],
            session['status'],
            str(session['total_findings'])
        )
    
    console.print(table)
