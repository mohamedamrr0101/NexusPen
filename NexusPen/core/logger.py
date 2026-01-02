#!/usr/bin/env python3
"""
NexusPen - Logger Module
========================
Centralized logging for the framework.
"""

import logging
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional
from rich.logging import RichHandler
from rich.console import Console


# Global logger cache
_loggers = {}


def setup_logger(
    level: str = "INFO",
    log_file: Optional[str] = None,
    name: str = "nexuspen"
) -> logging.Logger:
    """
    Setup and configure the NexusPen logger.
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional path to log file
        name: Logger name
        
    Returns:
        Configured logger instance
    """
    # Convert string level to logging constant
    log_level = getattr(logging, level.upper(), logging.INFO)
    
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(log_level)
    
    # Clear existing handlers
    logger.handlers = []
    
    # Console handler with Rich
    console_handler = RichHandler(
        console=Console(stderr=True),
        show_time=True,
        show_path=False,
        markup=True,
        rich_tracebacks=True
    )
    console_handler.setLevel(log_level)
    console_format = logging.Formatter("%(message)s")
    console_handler.setFormatter(console_format)
    logger.addHandler(console_handler)
    
    # File handler (if specified)
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_path)
        file_handler.setLevel(log_level)
        file_format = logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        file_handler.setFormatter(file_format)
        logger.addHandler(file_handler)
    
    # Cache logger
    _loggers[name] = logger
    
    return logger


def get_logger(name: str = "nexuspen") -> logging.Logger:
    """
    Get or create a logger.
    
    Args:
        name: Logger name
        
    Returns:
        Logger instance
    """
    if name in _loggers:
        return _loggers[name]
    
    return setup_logger(name=name)


class ScanLogger:
    """
    Specialized logger for scan operations.
    Provides structured logging for scan results.
    """
    
    def __init__(self, session_id: str, module: str):
        self.session_id = session_id
        self.module = module
        self.logger = get_logger(f"nexuspen.{module}")
        self.start_time = None
    
    def start_scan(self, target: str):
        """Log scan start."""
        self.start_time = datetime.now()
        self.logger.info(f"[{self.module}] Starting scan on {target}")
    
    def end_scan(self, findings_count: int = 0):
        """Log scan end with duration."""
        if self.start_time:
            duration = (datetime.now() - self.start_time).total_seconds()
            self.logger.info(
                f"[{self.module}] Scan completed in {duration:.2f}s - "
                f"{findings_count} findings"
            )
    
    def finding(self, severity: str, title: str, details: str = None):
        """Log a finding."""
        severity_colors = {
            'critical': 'red',
            'high': 'orange',
            'medium': 'yellow',
            'low': 'blue',
            'info': 'green'
        }
        color = severity_colors.get(severity.lower(), 'white')
        
        self.logger.warning(f"[{severity.upper()}] {title}")
        if details:
            self.logger.debug(f"  Details: {details}")
    
    def progress(self, message: str):
        """Log progress update."""
        self.logger.info(f"[{self.module}] {message}")
    
    def error(self, message: str, exc_info: bool = False):
        """Log error."""
        self.logger.error(f"[{self.module}] {message}", exc_info=exc_info)
    
    def debug(self, message: str):
        """Log debug message."""
        self.logger.debug(f"[{self.module}] {message}")
