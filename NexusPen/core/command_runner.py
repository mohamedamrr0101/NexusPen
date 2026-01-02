#!/usr/bin/env python3
"""
NexusPen - Command Runner
=========================
Smart command execution with live output streaming.
"""

import subprocess
import threading
import time
import queue
from typing import Dict, List, Optional, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


class CommandStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    TOOL_NOT_FOUND = "tool_not_found"
    SKIPPED = "skipped"


@dataclass
class CommandResult:
    """Result of a command execution."""
    command: List[str]
    status: CommandStatus
    stdout: str = ""
    stderr: str = ""
    return_code: Optional[int] = None
    duration: float = 0.0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None


@dataclass
class CommandEntry:
    """Entry in the live command panel."""
    command: str
    status: CommandStatus = CommandStatus.PENDING
    output_lines: List[str] = field(default_factory=list)
    duration: float = 0.0
    
    def get_status_icon(self) -> str:
        icons = {
            CommandStatus.PENDING: "⏸️",
            CommandStatus.RUNNING: "⏳",
            CommandStatus.SUCCESS: "✅",
            CommandStatus.FAILED: "❌",
            CommandStatus.TIMEOUT: "⏰",
            CommandStatus.TOOL_NOT_FOUND: "⚠️",
            CommandStatus.SKIPPED: "⏭️",
        }
        return icons.get(self.status, "❓")
    
    def get_status_color(self) -> str:
        colors = {
            CommandStatus.PENDING: "dim",
            CommandStatus.RUNNING: "cyan",
            CommandStatus.SUCCESS: "green",
            CommandStatus.FAILED: "red",
            CommandStatus.TIMEOUT: "yellow",
            CommandStatus.TOOL_NOT_FOUND: "yellow",
            CommandStatus.SKIPPED: "dim",
        }
        return colors.get(self.status, "white")


class LiveCommandPanel:
    """Live updating panel showing command execution."""
    
    def __init__(self, max_entries: int = 10, max_output_lines: int = 5):
        self.max_entries = max_entries
        self.max_output_lines = max_output_lines
        self.entries: List[CommandEntry] = []
        self.live: Optional[Live] = None
        self._lock = threading.Lock()
    
    def start(self):
        """Start the live display."""
        self.live = Live(
            self._render(),
            console=console,
            refresh_per_second=4,
            transient=False
        )
        self.live.start()
    
    def stop(self):
        """Stop the live display."""
        if self.live:
            self.live.stop()
            self.live = None
    
    def add_command(self, command: str) -> int:
        """Add a new command entry and return its index."""
        with self._lock:
            entry = CommandEntry(command=command, status=CommandStatus.RUNNING)
            self.entries.append(entry)
            
            # Trim old entries
            if len(self.entries) > self.max_entries:
                self.entries = self.entries[-self.max_entries:]
            
            self._refresh()
            return len(self.entries) - 1
    
    def update_status(self, index: int, status: CommandStatus, duration: float = 0.0):
        """Update the status of a command."""
        with self._lock:
            if 0 <= index < len(self.entries):
                self.entries[index].status = status
                self.entries[index].duration = duration
                self._refresh()
    
    def add_output(self, index: int, line: str):
        """Add output line to a command."""
        with self._lock:
            if 0 <= index < len(self.entries):
                self.entries[index].output_lines.append(line)
                # Trim old output
                if len(self.entries[index].output_lines) > self.max_output_lines:
                    self.entries[index].output_lines = self.entries[index].output_lines[-self.max_output_lines:]
                self._refresh()
    
    def _refresh(self):
        """Refresh the live display."""
        if self.live:
            self.live.update(self._render())
    
    def _render(self) -> Panel:
        """Render the command panel."""
        content = Text()
        
        for entry in self.entries:
            # Command line with status icon
            status_icon = entry.get_status_icon()
            status_color = entry.get_status_color()
            
            content.append(f"{status_icon} ", style=status_color)
            content.append(f"$ {entry.command}\n", style="bold grey70")
            
            # Output lines
            for line in entry.output_lines:
                content.append(f"   {line}\n", style="dim")
            
            # Duration for completed commands
            if entry.status in [CommandStatus.SUCCESS, CommandStatus.FAILED, CommandStatus.TIMEOUT]:
                content.append(f"   [{status_color}]Completed in {entry.duration:.1f}s[/{status_color}]\n")
            elif entry.status == CommandStatus.TOOL_NOT_FOUND:
                content.append(f"   [yellow]Tool not installed[/yellow]\n")
            
            content.append("─" * 60 + "\n", style="dim")
        
        if not self.entries:
            content.append("[dim]Waiting for commands...[/dim]")
        
        return Panel(
            content,
            title="[bold cyan]🖥️ LIVE COMMAND EXECUTION[/bold cyan]",
            border_style="cyan",
            expand=True
        )


class CommandRunner:
    """
    Smart command runner with live output and tool management integration.
    """
    
    def __init__(self, verbosity: int = 0, tool_manager=None, live_panel: bool = True):
        self.verbosity = verbosity
        self.tool_manager = tool_manager
        self.use_live_panel = live_panel and verbosity > 0
        self.panel: Optional[LiveCommandPanel] = None
        self._panel_started = False
    
    def start_panel(self):
        """Start the live panel if enabled."""
        if self.use_live_panel and not self._panel_started:
            self.panel = LiveCommandPanel()
            self.panel.start()
            self._panel_started = True
    
    def stop_panel(self):
        """Stop the live panel."""
        if self.panel:
            self.panel.stop()
            self.panel = None
            self._panel_started = False
    
    def execute(
        self,
        cmd: List[str],
        timeout: int = 60,
        check_tool: bool = True,
        capture_output: bool = True,
        stream_output: bool = False
    ) -> CommandResult:
        """
        Execute a command with smart handling.
        
        Args:
            cmd: Command and arguments as a list
            timeout: Timeout in seconds
            check_tool: Whether to check if the tool exists first
            capture_output: Whether to capture stdout/stderr
            stream_output: Whether to stream output to the live panel
        
        Returns:
            CommandResult with execution details
        """
        cmd_str = ' '.join(cmd)
        tool_name = cmd[0]
        
        result = CommandResult(
            command=cmd,
            status=CommandStatus.PENDING,
            start_time=datetime.now()
        )
        
        # Add to live panel
        panel_index = -1
        if self.panel:
            panel_index = self.panel.add_command(cmd_str)
        elif self.verbosity > 0:
            console.print(f"[grey50]$ {cmd_str}[/grey50]")
        
        # Check if tool exists
        if check_tool and self.tool_manager:
            tool_path = self.tool_manager.check_tool(tool_name)
            if not tool_path:
                # Tool not found
                result.status = CommandStatus.TOOL_NOT_FOUND
                result.end_time = datetime.now()
                
                if self.panel:
                    self.panel.update_status(panel_index, CommandStatus.TOOL_NOT_FOUND)
                
                # Try to get install command
                install_cmd = self.tool_manager.get_install_command(tool_name)
                if install_cmd and self.verbosity > 0:
                    if self.panel:
                        self.panel.add_output(panel_index, f"Install: {install_cmd}")
                    else:
                        console.print(f"[yellow]⚠ {tool_name} not found. Install: {install_cmd}[/yellow]")
                
                return result
        
        # Execute the command
        try:
            start_time = time.time()
            
            if stream_output and self.panel:
                # Stream output in real-time
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1
                )
                
                stdout_lines = []
                for line in iter(process.stdout.readline, ''):
                    line = line.rstrip()
                    if line:
                        stdout_lines.append(line)
                        self.panel.add_output(panel_index, line)
                
                process.wait(timeout=timeout)
                result.stdout = '\n'.join(stdout_lines)
                result.return_code = process.returncode
            else:
                # Standard execution
                proc_result = subprocess.run(
                    cmd,
                    capture_output=capture_output,
                    text=True,
                    timeout=timeout
                )
                
                result.stdout = proc_result.stdout if capture_output else ""
                result.stderr = proc_result.stderr if capture_output else ""
                result.return_code = proc_result.returncode
                
                # Add first few lines to panel
                if self.panel and result.stdout:
                    for line in result.stdout.split('\n')[:3]:
                        if line.strip():
                            self.panel.add_output(panel_index, line.strip()[:80])
            
            duration = time.time() - start_time
            result.duration = duration
            result.end_time = datetime.now()
            
            if result.return_code == 0:
                result.status = CommandStatus.SUCCESS
            else:
                result.status = CommandStatus.FAILED
            
            if self.panel:
                self.panel.update_status(panel_index, result.status, duration)
            elif self.verbosity > 1 and result.status == CommandStatus.FAILED:
                console.print(f"[red]Command failed with code {result.return_code}[/red]")
                
        except subprocess.TimeoutExpired:
            result.status = CommandStatus.TIMEOUT
            result.end_time = datetime.now()
            result.duration = timeout
            
            if self.panel:
                self.panel.update_status(panel_index, CommandStatus.TIMEOUT, timeout)
            elif self.verbosity > 0:
                console.print(f"[yellow]⚠ Command timed out after {timeout}s[/yellow]")
                
        except FileNotFoundError:
            result.status = CommandStatus.TOOL_NOT_FOUND
            result.end_time = datetime.now()
            
            if self.panel:
                self.panel.update_status(panel_index, CommandStatus.TOOL_NOT_FOUND)
            elif self.verbosity > 0:
                console.print(f"[yellow]⚠ {tool_name} not found[/yellow]")
                
        except Exception as e:
            result.status = CommandStatus.FAILED
            result.stderr = str(e)
            result.end_time = datetime.now()
            
            if self.panel:
                self.panel.update_status(panel_index, CommandStatus.FAILED)
            elif self.verbosity > 0:
                console.print(f"[red]Error: {e}[/red]")
        
        return result
    
    def execute_simple(self, cmd: List[str], timeout: int = 60) -> Tuple[bool, str]:
        """
        Simple execution returning (success, output).
        For backward compatibility.
        """
        result = self.execute(cmd, timeout=timeout)
        return result.status == CommandStatus.SUCCESS, result.stdout
    
    def execute_streaming(self, cmd: List[str], check_tool: bool = True) -> CommandResult:
        """
        Execute command with live streaming output and NO timeout.
        User can press Ctrl+C to skip to the next command.
        
        Args:
            cmd: Command and arguments as a list
            check_tool: Whether to check if the tool exists first
        
        Returns:
            CommandResult with execution details
        """
        cmd_str = ' '.join(cmd)
        tool_name = cmd[0]
        
        result = CommandResult(
            command=cmd,
            status=CommandStatus.PENDING,
            start_time=datetime.now()
        )
        
        # Print command header
        console.print()
        console.print("╔" + "═" * 68 + "╗")
        console.print(f"║  [bold cyan]🖥️ LIVE TERMINAL[/bold cyan] - [dim]Press Ctrl+C to skip command[/dim]" + " " * 14 + "║")
        console.print("╠" + "═" * 68 + "╣")
        console.print(f"│ [bold yellow]$ {cmd_str[:64]}[/bold yellow]" + " " * max(0, 66 - len(cmd_str)) + "│")
        console.print("╠" + "─" * 68 + "╣")
        
        # Check if tool exists
        if check_tool and self.tool_manager:
            tool_path = self.tool_manager.check_tool(tool_name)
            if not tool_path:
                result.status = CommandStatus.TOOL_NOT_FOUND
                result.end_time = datetime.now()
                install_cmd = self.tool_manager.get_install_command(tool_name)
                console.print(f"│ [yellow]⚠️ Tool not found: {tool_name}[/yellow]" + " " * 30 + "│")
                if install_cmd:
                    console.print(f"│ [dim]Install: {install_cmd[:56]}[/dim]" + " " * max(0, 57 - len(install_cmd)) + "│")
                console.print("╚" + "═" * 68 + "╝")
                return result
        
        # Execute with streaming
        try:
            start_time = time.time()
            stdout_lines = []
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1  # Line buffered
            )
            
            # Stream output line by line - NO TIMEOUT
            try:
                for line in iter(process.stdout.readline, ''):
                    line = line.rstrip()
                    if line:
                        stdout_lines.append(line)
                        # Truncate long lines for display
                        display_line = line[:66] if len(line) > 66 else line
                        console.print(f"│ [dim]{display_line}[/dim]" + " " * max(0, 67 - len(display_line)) + "│")
                
                process.wait()  # Wait for completion - NO TIMEOUT
                
            except KeyboardInterrupt:
                # User pressed Ctrl+C - skip this command
                process.terminate()
                try:
                    process.wait(timeout=2)
                except:
                    process.kill()
                
                result.status = CommandStatus.SKIPPED
                result.end_time = datetime.now()
                result.duration = time.time() - start_time
                result.stdout = '\n'.join(stdout_lines)
                
                console.print("├" + "─" * 68 + "┤")
                console.print(f"│ [yellow]⏭️  Skipped (Ctrl+C)[/yellow]" + " " * 44 + "│")
                console.print("╚" + "═" * 68 + "╝")
                console.print()
                return result
            
            # Command completed normally
            duration = time.time() - start_time
            result.duration = duration
            result.end_time = datetime.now()
            result.stdout = '\n'.join(stdout_lines)
            result.return_code = process.returncode
            
            if process.returncode == 0:
                result.status = CommandStatus.SUCCESS
                console.print("├" + "─" * 68 + "┤")
                console.print(f"│ [green]✅ Completed in {duration:.1f}s[/green]" + " " * (49 - len(f"{duration:.1f}")) + "│")
            else:
                result.status = CommandStatus.FAILED
                console.print("├" + "─" * 68 + "┤")
                console.print(f"│ [red]❌ Failed (exit code: {process.returncode})[/red]" + " " * 35 + "│")
            
            console.print("╚" + "═" * 68 + "╝")
            console.print()
            
        except FileNotFoundError:
            result.status = CommandStatus.TOOL_NOT_FOUND
            result.end_time = datetime.now()
            console.print(f"│ [yellow]⚠️ Command not found: {tool_name}[/yellow]" + " " * 30 + "│")
            console.print("╚" + "═" * 68 + "╝")
            
        except Exception as e:
            result.status = CommandStatus.FAILED
            result.stderr = str(e)
            result.end_time = datetime.now()
            console.print(f"│ [red]❌ Error: {str(e)[:55]}[/red]" + " " * max(0, 56 - len(str(e))) + "│")
            console.print("╚" + "═" * 68 + "╝")
        
        return result


# Global instance
_command_runner: Optional[CommandRunner] = None


def get_command_runner(verbosity: int = 0, tool_manager=None) -> CommandRunner:
    """Get or create the global CommandRunner instance."""
    global _command_runner
    if _command_runner is None:
        _command_runner = CommandRunner(verbosity=verbosity, tool_manager=tool_manager)
    return _command_runner
