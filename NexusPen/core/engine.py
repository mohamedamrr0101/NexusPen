#!/usr/bin/env python3
"""
NexusPen - Core Engine
======================
Main orchestration engine that coordinates all testing phases.
"""

import os
import time
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table
from rich.live import Live

from .detector import TargetDetector, TargetProfile, TargetType
from .database import Database
from .logger import get_logger

console = Console()
logger = get_logger(__name__)


@dataclass
class ScanResult:
    """Represents a single scan result."""
    module: str
    phase: str
    timestamp: str
    status: str  # success, failed, skipped
    findings: List[Dict]
    duration: float
    raw_output: Optional[str] = None


@dataclass
class SessionData:
    """Represents a complete testing session."""
    session_id: str
    target: str
    start_time: str
    end_time: Optional[str] = None
    profile: Optional[Dict] = None
    phases_completed: List[str] = None
    total_findings: int = 0
    critical_findings: int = 0
    results: List[Dict] = None
    status: str = "in_progress"
    
    def __post_init__(self):
        if self.phases_completed is None:
            self.phases_completed = []
        if self.results is None:
            self.results = []


class NexusPenEngine:
    """
    Main orchestration engine for NexusPen.
    
    Coordinates all testing phases:
    1. Reconnaissance
    2. Enumeration  
    3. Vulnerability Assessment
    4. Exploitation
    5. Post-Exploitation
    6. Reporting
    """
    
    PHASES = ['recon', 'enum', 'vuln', 'exploit', 'post', 'report']
    
    def __init__(
        self,
        target: str = None,
        target_list: str = None,
        exclude: str = None,
        mode: str = "full",
        intensity: str = "normal",
        threads: int = 10,
        timeout: int = 30,
        output_dir: str = None,
        report_format: str = "html",
        config_path: str = None,
        safe_mode: bool = False,
        no_exploit: bool = False,
        dry_run: bool = False,
        verbosity: int = 0,
        session_id: str = None
    ):
        self.target = target
        self.target_list = target_list
        self.exclude = exclude
        self.mode = mode
        self.intensity = intensity
        self.threads = threads
        self.timeout = timeout
        self.report_format = report_format
        self.safe_mode = safe_mode
        self.no_exploit = no_exploit
        self.dry_run = dry_run
        self.verbosity = verbosity
        
        # Set up directories
        self.base_dir = Path(__file__).parent.parent
        self.output_dir = Path(output_dir) if output_dir else self.base_dir / "reports"
        self.data_dir = self.base_dir / "data"
        self.logs_dir = self.base_dir / "logs"
        
        # Create directories
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize components
        self.detector = TargetDetector()
        self.db = Database(self.data_dir / "nexuspen.db")
        
        # Load or create session
        if session_id:
            self.session = self._load_session(session_id)
        else:
            self.session = self._create_session()
        
        # Target profile (populated after detection)
        self.profile: Optional[TargetProfile] = None
        
        # Results storage
        self.results: List[ScanResult] = []
        
        # Load configuration
        self.config = self._load_config(config_path)
        
        logger.info(f"NexusPen Engine initialized for target: {target}")
    
    def _load_config(self, config_path: str = None) -> Dict:
        """Load configuration from YAML file."""
        import yaml
        
        if config_path:
            config_file = Path(config_path)
        else:
            config_file = self.base_dir / "config" / "config.yaml"
        
        if config_file.exists():
            with open(config_file, 'r') as f:
                return yaml.safe_load(f)
        
        return {}
    
    def _create_session(self) -> SessionData:
        """Create a new testing session."""
        session_id = f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        session = SessionData(
            session_id=session_id,
            target=self.target,
            start_time=datetime.now().isoformat()
        )
        
        # Save to database
        self.db.save_session(asdict(session))
        
        console.print(f"\n[bold green]📁 Session created: {session_id}[/bold green]")
        
        return session
    
    def _load_session(self, session_id: str) -> SessionData:
        """Load an existing session."""
        session_data = self.db.get_session(session_id)
        
        if session_data:
            return SessionData(**session_data)
        else:
            console.print(f"[red]Session {session_id} not found. Creating new session.[/red]")
            return self._create_session()
    
    def _save_session(self):
        """Save current session state."""
        self.db.save_session(asdict(self.session))
    
    def run_full_assessment(self):
        """Run complete penetration test."""
        console.print(Panel(
            "[bold cyan]Starting Full Penetration Test[/bold cyan]\n"
            f"Target: {self.target}\n"
            f"Mode: {self.mode} | Intensity: {self.intensity}",
            title="🚀 NexusPen",
            border_style="cyan"
        ))
        
        try:
            # Phase 1: Target Detection & Reconnaissance
            self._run_phase_recon()
            
            # Phase 2: Enumeration
            self._run_phase_enum()
            
            # Phase 3: Vulnerability Assessment
            self._run_phase_vuln()
            
            # Phase 4: Exploitation (if not disabled)
            if not self.no_exploit and not self.safe_mode:
                self._run_phase_exploit()
            else:
                console.print("[yellow]⚠️  Exploitation phase skipped (safe mode)[/yellow]")
            
            # Phase 5: Post-Exploitation
            if not self.safe_mode:
                self._run_phase_post()
            
            # Mark session as completed
            self.session.status = "completed"
            self.session.end_time = datetime.now().isoformat()
            self._save_session()
            
        except KeyboardInterrupt:
            console.print("\n[yellow]⚠️  Assessment interrupted. Progress saved.[/yellow]")
            self.session.status = "interrupted"
            self._save_session()
            raise
        except Exception as e:
            console.print(f"\n[red]❌ Error during assessment: {e}[/red]")
            self.session.status = "error"
            self._save_session()
            raise
    
    def run_phase(self, phase: str):
        """Run a specific phase."""
        phase = phase.lower()
        
        phase_methods = {
            'recon': self._run_phase_recon,
            'enum': self._run_phase_enum,
            'vuln': self._run_phase_vuln,
            'exploit': self._run_phase_exploit,
            'post': self._run_phase_post,
            'report': self.generate_report
        }
        
        if phase in phase_methods:
            phase_methods[phase]()
        else:
            console.print(f"[red]Unknown phase: {phase}[/red]")
            console.print(f"Available phases: {', '.join(self.PHASES)}")
    
    def _run_phase_recon(self):
        """Phase 1: Reconnaissance."""
        console.print("\n[bold magenta]═══════════════════════════════════════════════════════════════[/bold magenta]")
        console.print("[bold white]                    PHASE 1: RECONNAISSANCE[/bold white]")
        console.print("[bold magenta]═══════════════════════════════════════════════════════════════[/bold magenta]\n")
        
        start_time = time.time()
        
        # Smart target detection
        console.print("[cyan]🔍 Running smart target detection...[/cyan]")
        self.profile = self.detector.detect(self.target, quick=(self.intensity != 'aggressive'))
        
        # Store profile in session
        self.session.profile = asdict(self.profile)
        self.session.profile['target_type'] = self.profile.target_type.value
        
        # Run appropriate recon modules based on target type
        if self.profile.target_type == TargetType.WINDOWS:
            self._run_windows_recon()
        elif self.profile.target_type == TargetType.LINUX:
            self._run_linux_recon()
        elif self.profile.target_type == TargetType.ACTIVE_DIRECTORY:
            self._run_ad_recon()
        
        # Web recon if web server detected
        if self.profile.is_web_server:
            self._run_web_recon()
        
        # Record phase completion
        duration = time.time() - start_time
        self.session.phases_completed.append('recon')
        self._save_session()
        
        console.print(f"\n[green]✅ Reconnaissance completed in {duration:.2f}s[/green]")
    
    def _run_phase_enum(self):
        """Phase 2: Enumeration."""
        console.print("\n[bold magenta]═══════════════════════════════════════════════════════════════[/bold magenta]")
        console.print("[bold white]                    PHASE 2: ENUMERATION[/bold white]")
        console.print("[bold magenta]═══════════════════════════════════════════════════════════════[/bold magenta]\n")
        
        start_time = time.time()
        
        if not self.profile:
            console.print("[yellow]⚠️  No profile found. Running detection first.[/yellow]")
            self._run_phase_recon()
        
        # Run enumeration based on target type
        if self.profile.target_type == TargetType.WINDOWS:
            self._run_windows_enum()
        elif self.profile.target_type == TargetType.LINUX:
            self._run_linux_enum()
        elif self.profile.target_type == TargetType.ACTIVE_DIRECTORY:
            self._run_ad_enum()
        
        # Web enumeration
        if self.profile.is_web_server:
            self._run_web_enum()
        
        duration = time.time() - start_time
        self.session.phases_completed.append('enum')
        self._save_session()
        
        console.print(f"\n[green]✅ Enumeration completed in {duration:.2f}s[/green]")
    
    def _run_phase_vuln(self):
        """Phase 3: Vulnerability Assessment."""
        console.print("\n[bold magenta]═══════════════════════════════════════════════════════════════[/bold magenta]")
        console.print("[bold white]                    PHASE 3: VULNERABILITY ASSESSMENT[/bold white]")
        console.print("[bold magenta]═══════════════════════════════════════════════════════════════[/bold magenta]\n")
        
        start_time = time.time()
        
        # Run vulnerability scanners
        self._run_vuln_scan()
        
        # Platform-specific vuln checks
        if self.profile.target_type == TargetType.WINDOWS:
            self._run_windows_vuln()
        elif self.profile.target_type == TargetType.LINUX:
            self._run_linux_vuln()
        elif self.profile.target_type == TargetType.ACTIVE_DIRECTORY:
            self._run_ad_vuln()
        
        # Web vulnerability scanning
        if self.profile.is_web_server:
            self._run_web_vuln()
        
        duration = time.time() - start_time
        self.session.phases_completed.append('vuln')
        self._save_session()
        
        console.print(f"\n[green]✅ Vulnerability Assessment completed in {duration:.2f}s[/green]")
    
    def _run_phase_exploit(self):
        """Phase 4: Exploitation."""
        console.print("\n[bold magenta]═══════════════════════════════════════════════════════════════[/bold magenta]")
        console.print("[bold white]                    PHASE 4: EXPLOITATION[/bold white]")
        console.print("[bold magenta]═══════════════════════════════════════════════════════════════[/bold magenta]\n")
        
        if self.dry_run:
            console.print("[yellow]⚠️  Dry run mode - skipping exploitation[/yellow]")
            return
        
        start_time = time.time()
        
        # Run exploitation based on findings
        # This would integrate with Metasploit and other exploit tools
        console.print("[cyan]🎯 Analyzing vulnerabilities for exploitation...[/cyan]")
        
        duration = time.time() - start_time
        self.session.phases_completed.append('exploit')
        self._save_session()
        
        console.print(f"\n[green]✅ Exploitation phase completed in {duration:.2f}s[/green]")
    
    def _run_phase_post(self):
        """Phase 5: Post-Exploitation."""
        console.print("\n[bold magenta]═══════════════════════════════════════════════════════════════[/bold magenta]")
        console.print("[bold white]                    PHASE 5: POST-EXPLOITATION[/bold white]")
        console.print("[bold magenta]═══════════════════════════════════════════════════════════════[/bold magenta]\n")
        
        if self.dry_run:
            console.print("[yellow]⚠️  Dry run mode - skipping post-exploitation[/yellow]")
            return
        
        start_time = time.time()
        
        # Run post-exploitation modules
        console.print("[cyan]🔓 Running post-exploitation modules...[/cyan]")
        
        duration = time.time() - start_time
        self.session.phases_completed.append('post')
        self._save_session()
        
        console.print(f"\n[green]✅ Post-Exploitation phase completed in {duration:.2f}s[/green]")
    
    # Platform-specific methods
    def _run_windows_recon(self):
        """Windows-specific reconnaissance."""
        console.print("\n[yellow]🪟 Running Windows Reconnaissance[/yellow]")
        from modules.windows import recon as win_recon
        win_recon.run(self.target, self.profile, self.results)
    
    def _run_linux_recon(self):
        """Linux-specific reconnaissance."""
        console.print("\n[yellow]🐧 Running Linux Reconnaissance[/yellow]")
        from modules.linux import recon as linux_recon
        linux_recon.run(self.target, self.profile, self.results)
    
    def _run_ad_recon(self):
        """Active Directory reconnaissance."""
        console.print("\n[yellow]🏢 Running Active Directory Reconnaissance[/yellow]")
        from modules.ad import recon as ad_recon
        ad_recon.run(self.target, self.profile, self.results)
    
    def _run_web_recon(self):
        """Web application reconnaissance."""
        console.print("\n[yellow]🌐 Running Web Reconnaissance[/yellow]")
        from modules.web import recon as web_recon
        web_recon.run(self.target, self.profile, self.results)
    
    def _run_windows_enum(self):
        """Windows enumeration."""
        console.print("\n[yellow]🪟 Running Windows Enumeration[/yellow]")
        # Import and run Windows enum modules
    
    def _run_linux_enum(self):
        """Linux enumeration."""
        console.print("\n[yellow]🐧 Running Linux Enumeration[/yellow]")
        # Import and run Linux enum modules
    
    def _run_ad_enum(self):
        """Active Directory enumeration."""
        console.print("\n[yellow]🏢 Running AD Enumeration[/yellow]")
        # Import and run AD enum modules
    
    def _run_web_enum(self):
        """Web enumeration."""
        console.print("\n[yellow]🌐 Running Web Enumeration[/yellow]")
        # Import and run web enum modules
    
    def _run_vuln_scan(self):
        """General vulnerability scanning."""
        console.print("\n[yellow]🔍 Running Vulnerability Scanners[/yellow]")
        # Nuclei, Nmap NSE scripts, etc.
    
    def _run_windows_vuln(self):
        """Windows vulnerability checks."""
        console.print("\n[yellow]🪟 Running Windows Vulnerability Checks[/yellow]")
    
    def _run_linux_vuln(self):
        """Linux vulnerability checks."""
        console.print("\n[yellow]🐧 Running Linux Vulnerability Checks[/yellow]")
    
    def _run_ad_vuln(self):
        """AD vulnerability checks."""
        console.print("\n[yellow]🏢 Running AD Vulnerability Checks[/yellow]")
    
    def _run_web_vuln(self):
        """Web vulnerability scanning."""
        console.print("\n[yellow]🌐 Running Web Vulnerability Scanning[/yellow]")
        # SQLMap, XSS, LFI/RFI, etc.
    
    def generate_report(self):
        """Generate final report."""
        console.print("\n[bold magenta]═══════════════════════════════════════════════════════════════[/bold magenta]")
        console.print("[bold white]                    GENERATING REPORT[/bold white]")
        console.print("[bold magenta]═══════════════════════════════════════════════════════════════[/bold magenta]\n")
        
        from modules.report import html_report
        
        report_path = html_report.generate(
            session=self.session,
            profile=self.profile,
            results=self.results,
            output_dir=self.output_dir
        )
        
        console.print(f"\n[green]📄 Report generated: {report_path}[/green]")
        
        self.session.phases_completed.append('report')
        self._save_session()
