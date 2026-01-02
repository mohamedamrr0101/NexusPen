#!/usr/bin/env python3
"""
NexusPen - Professional Penetration Testing Framework
=====================================================
A comprehensive, automated penetration testing framework for Kali Linux.
Simulates the methodology of an expert penetration tester.

Author: Security Professional
Version: 1.0.0
License: For authorized security testing only
"""

import argparse
import sys
import os
from pathlib import Path

# Add the project root to Python path
sys.path.insert(0, str(Path(__file__).parent))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import print as rprint

from core.engine import NexusPenEngine
from core.logger import setup_logger
from core.utils import print_banner, validate_target, check_root
from core.ai_analyzer import AIAnalyzer

console = Console()

VERSION = "1.0.0"
AUTHOR = "NexusPen Team"


def print_banner_art():
    """Display the NexusPen banner."""
    banner = """
    ███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗██████╗ ███████╗███╗   ██╗
    ████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝██╔══██╗██╔════╝████╗  ██║
    ██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗██████╔╝█████╗  ██╔██╗ ██║
    ██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║██╔═══╝ ██╔══╝  ██║╚██╗██║
    ██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║██║     ███████╗██║ ╚████║
    ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝     ╚══════╝╚═╝  ╚═══╝
                Professional Penetration Testing Framework
                         Version: {version}
    """.format(version=VERSION)
    
    console.print(Panel(banner, style="bold red", border_style="red"))


def create_parser():
    """Create and return the argument parser."""
    parser = argparse.ArgumentParser(
        prog="nexuspen",
        description="NexusPen - Professional Penetration Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full penetration test
  sudo python3 nexuspen.py -t 192.168.1.0/24 --mode full

  # Reconnaissance only
  sudo python3 nexuspen.py -t example.com --phase recon

  # Web application testing
  sudo python3 nexuspen.py -t https://target.com --mode web

  # Interactive mode
  sudo python3 nexuspen.py --interactive

  # Generate report only
  sudo python3 nexuspen.py --report-only --session <session_id>
        """
    )
    
    # Target options
    target_group = parser.add_argument_group("Target Options")
    target_group.add_argument(
        "-t", "--target",
        help="Target IP, hostname, URL, or CIDR range"
    )
    target_group.add_argument(
        "-tL", "--target-list",
        help="File containing list of targets (one per line)"
    )
    target_group.add_argument(
        "-x", "--exclude",
        help="Hosts to exclude from scanning"
    )
    
    # Scan mode options
    mode_group = parser.add_argument_group("Scan Mode")
    mode_group.add_argument(
        "-m", "--mode",
        choices=["full", "web", "network", "quick", "stealth"],
        default="full",
        help="Scan mode (default: full)"
    )
    mode_group.add_argument(
        "-p", "--phase",
        help="Specific phases to run (comma-separated: recon,enum,vuln,exploit,post)"
    )
    mode_group.add_argument(
        "-i", "--intensity",
        choices=["stealth", "normal", "aggressive", "insane"],
        default="normal",
        help="Scan intensity (default: normal)"
    )
    
    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument(
        "-o", "--output",
        help="Output directory for results"
    )
    output_group.add_argument(
        "-r", "--report",
        choices=["html", "pdf", "json", "xml", "all"],
        default="html",
        help="Report format (default: html)"
    )
    output_group.add_argument(
        "-v", "--verbose",
        action="count",
        default=0,
        help="Increase verbosity level (-v, -vv, -vvv)"
    )
    output_group.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Quiet mode, minimal output"
    )
    
    # Port options
    port_group = parser.add_argument_group("Port Options")
    port_group.add_argument(
        "--ports",
        help="Specific ports to scan (e.g., 22,80,443 or 1-1000)"
    )
    port_group.add_argument(
        "--top-ports",
        type=int,
        help="Scan top N most common ports"
    )
    port_group.add_argument(
        "--all-ports",
        action="store_true",
        help="Scan all 65535 ports"
    )
    
    # Advanced options
    advanced_group = parser.add_argument_group("Advanced Options")
    advanced_group.add_argument(
        "--threads",
        type=int,
        default=10,
        help="Number of concurrent threads (default: 10)"
    )
    advanced_group.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Timeout in seconds for network operations (default: 30)"
    )
    advanced_group.add_argument(
        "--no-exploit",
        action="store_true",
        help="Disable automatic exploitation"
    )
    advanced_group.add_argument(
        "--safe-mode",
        action="store_true",
        help="Only run safe, non-destructive tests"
    )
    advanced_group.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without actually running scans"
    )
    
    # Interactive mode
    interactive_group = parser.add_argument_group("Interactive Mode")
    interactive_group.add_argument(
        "--interactive",
        action="store_true",
        help="Launch interactive mode"
    )
    
    # Session management
    session_group = parser.add_argument_group("Session Management")
    session_group.add_argument(
        "--session",
        help="Resume a previous session by ID"
    )
    session_group.add_argument(
        "--list-sessions",
        action="store_true",
        help="List all saved sessions"
    )
    session_group.add_argument(
        "--report-only",
        action="store_true",
        help="Generate report from existing session"
    )
    
    # Configuration
    config_group = parser.add_argument_group("Configuration")
    config_group.add_argument(
        "-c", "--config",
        help="Path to custom configuration file"
    )
    config_group.add_argument(
        "--check-tools",
        action="store_true",
        help="Check if required tools are installed"
    )
    
    # Version
    parser.add_argument(
        "--version",
        action="version",
        version=f"NexusPen {VERSION}"
    )
    
    return parser


def check_required_tools():
    """Check if required tools are installed."""
    tools = [
        ("nmap", "Network scanner"),
        ("masscan", "Fast port scanner"),
        ("nikto", "Web vulnerability scanner"),
        ("nuclei", "Template-based scanner"),
        ("gobuster", "Directory bruteforcer"),
        ("sqlmap", "SQL injection tool"),
        ("hydra", "Password cracker"),
        ("msfconsole", "Metasploit Framework"),
        ("searchsploit", "Exploit database search"),
        ("enum4linux", "SMB enumeration"),
    ]
    
    table = Table(title="Tool Availability Check", show_header=True, header_style="bold magenta")
    table.add_column("Tool", style="cyan")
    table.add_column("Description", style="white")
    table.add_column("Status", style="green")
    
    all_available = True
    for tool, desc in tools:
        status = "✅ Available" if os.system(f"which {tool} > /dev/null 2>&1") == 0 else "❌ Missing"
        if "Missing" in status:
            all_available = False
            table.add_row(tool, desc, "[red]❌ Missing[/red]")
        else:
            table.add_row(tool, desc, "[green]✅ Available[/green]")
    
    console.print(table)
    
    if not all_available:
        console.print("\n[yellow]⚠️  Some tools are missing. Install them using:[/yellow]")
        console.print("   [cyan]sudo apt update && sudo apt install -y nmap masscan nikto nuclei gobuster sqlmap hydra metasploit-framework exploitdb enum4linux[/cyan]")
    
    return all_available


def interactive_mode():
    """Launch interactive mode."""
    console.print("\n[bold cyan]═══════════════════════════════════════════════════════════════[/bold cyan]")
    console.print("[bold white]                  NexusPen Interactive Mode[/bold white]")
    console.print("[bold cyan]═══════════════════════════════════════════════════════════════[/bold cyan]\n")
    
    # Phase selection menu
    phases = {
        "1": ("Reconnaissance", "recon"),
        "2": ("Enumeration", "enum"),
        "3": ("Vulnerability Assessment", "vuln"),
        "4": ("Exploitation", "exploit"),
        "5": ("Post-Exploitation", "post"),
        "6": ("Full Assessment", "full"),
        "7": ("Generate Report", "report"),
        "8": ("Check Tools", "check"),
        "9": ("Exit", "exit")
    }
    
    # Initialize AI Analyzer
    ai_analyzer = AIAnalyzer()
    
    # Prompt for API key if not set but user wants AI
    if not ai_analyzer.enabled:
        console.print("\n[bold yellow]🤖 Enable DeepSeek AI Analysis?[/bold yellow]")
        if input("[?] (y/n): ").lower().startswith('y'):
            api_key = input("[?] Enter DeepSeek API Key: ").strip()
            if api_key:
                ai_analyzer = AIAnalyzer(api_key=api_key)

    while True:
        console.print("\n[bold yellow]Select Phase:[/bold yellow]")
        for key, (name, _) in phases.items():
            console.print(f"  [{key}] {name}")
        
        choice = input("\n[?] Enter choice: ").strip()
        
        if choice not in phases:
            console.print("[red]Invalid choice. Please try again.[/red]")
            continue
        
        phase_name, phase_id = phases[choice]
        
        if phase_id == "exit":
            console.print("[green]Goodbye![/green]")
            sys.exit(0)
        
        if phase_id == "check":
            check_required_tools()
            continue
        
        target = input("[?] Enter target (IP/domain/URL): ").strip()
        if not target:
            console.print("[red]Target is required.[/red]")
            continue

        # Verbosity selection
        console.print("\n[bold yellow]Select Verbosity Level:[/bold yellow]")
        console.print("  [1] Standard (Status updates only)")
        console.print("  [2] Verbose (Show executed commands)")
        console.print("  [3] Debug (Show full output and specialized debug info)")
        
        v_choice = input("\n[?] Enter verbosity [default: 2]: ").strip()
        verbosity = 2  # Default to verbose as requested by user ("show me the work")
        
        if v_choice == "1":
            verbosity = 0
        elif v_choice == "3":
            verbosity = 2
        elif v_choice == "2":
            verbosity = 1
            
        # Initialize engine and run selected phase
        engine = NexusPenEngine(target=target, verbosity=verbosity)
        
        # Track command history start for this phase
        history_start_idx = len(engine.command_runner.history) if engine.command_runner else 0
        
        if phase_id == "full":
            engine.run_full_assessment()
        elif phase_id == "report":
            engine.generate_report()
        else:
            engine.run_phase(phase_id)
            
        # AI Analysis
        if ai_analyzer.enabled and engine.command_runner:
            # Get only new commands from this phase
            new_commands = engine.command_runner.history[history_start_idx:]
            
            # Get findings
            findings = engine.db.get_findings(engine.session.session_id)
            
            if new_commands:
                ai_analyzer.summarize_phase(phase_name, new_commands, findings)
            else:
                if verbosity > 0:
                    console.print("[dim]No commands executed to analyze.[/dim]")


def main():
    """Main entry point."""
    print_banner_art()
    
    # Check if running as root
    if os.geteuid() != 0:
        console.print("[yellow]⚠️  Warning: Some features require root privileges.[/yellow]")
        console.print("[yellow]   Consider running with: sudo python3 nexuspen.py[/yellow]\n")
    
    parser = create_parser()
    args = parser.parse_args()
    
    # Setup logging
    log_level = "DEBUG" if args.verbose >= 2 else "INFO" if args.verbose == 1 else "WARNING" if args.quiet else "INFO"
    logger = setup_logger(log_level)
    
    # Check tools if requested
    if args.check_tools:
        check_required_tools()
        sys.exit(0)
    
    # List sessions if requested
    if args.list_sessions:
        from core.database import list_sessions
        list_sessions()
        sys.exit(0)
    
    # Interactive mode
    if args.interactive:
        interactive_mode()
        sys.exit(0)
    
    # Validate target
    if not args.target and not args.target_list and not args.report_only:
        parser.print_help()
        console.print("\n[red]Error: Target (-t) or target list (-tL) is required.[/red]")
        sys.exit(1)
    
    # Initialize engine
    try:
        engine = NexusPenEngine(
            target=args.target,
            target_list=args.target_list,
            exclude=args.exclude,
            mode=args.mode,
            intensity=args.intensity,
            threads=args.threads,
            timeout=args.timeout,
            output_dir=args.output,
            report_format=args.report,
            config_path=args.config,
            safe_mode=args.safe_mode,
            no_exploit=args.no_exploit,
            dry_run=args.dry_run,
            verbosity=args.verbose,
            session_id=args.session
        )
        
        # Determine which phases to run
        if args.phase:
            phases = [p.strip() for p in args.phase.split(",")]
            for phase in phases:
                engine.run_phase(phase)
        elif args.report_only:
            engine.generate_report()
        else:
            engine.run_full_assessment()
        
        # Generate report
        if not args.report_only:
            engine.generate_report()
        
        console.print("\n[bold green]✅ Assessment completed successfully![/bold green]")
        
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Interrupted by user. Saving progress...[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red]❌ Error: {str(e)}[/red]")
        if args.verbose >= 2:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
