#!/usr/bin/env python3
"""
NexusPen - Linux Enumeration Module
====================================
Comprehensive Linux system enumeration.
"""

import subprocess
import os
from typing import Dict, List, Optional
from dataclasses import dataclass

from rich.console import Console
from rich.table import Table

console = Console()


@dataclass
class LinuxSystemInfo:
    """Linux system information."""
    hostname: str
    kernel: str
    distro: str
    architecture: str
    users: List[str]
    groups: List[str]
    network_interfaces: List[Dict]
    listening_ports: List[Dict]
    running_processes: List[Dict]
    installed_packages: List[str]
    cron_jobs: List[str]
    environment_vars: Dict[str, str]


class LinuxEnumerator:
    """
    Comprehensive Linux system enumeration.
    For authorized access scenarios (post-exploitation).
    """
    
    def __init__(self, target: str = None, ssh_creds: Dict = None):
        """
        Initialize Linux enumerator.
        
        Args:
            target: Target IP (for remote enumeration)
            ssh_creds: SSH credentials {'username': '', 'password'/'key': ''}
        """
        self.target = target
        self.ssh_creds = ssh_creds
        self.is_remote = target is not None
    
    def _run_command(self, cmd: str, timeout: int = 30) -> str:
        """Run command locally or remotely via SSH."""
        if self.is_remote and self.ssh_creds:
            # Build SSH command
            user = self.ssh_creds.get('username', 'root')
            if 'key' in self.ssh_creds:
                ssh_cmd = f"ssh -i {self.ssh_creds['key']} -o StrictHostKeyChecking=no {user}@{self.target} '{cmd}'"
            else:
                # Use sshpass for password auth
                password = self.ssh_creds.get('password', '')
                ssh_cmd = f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no {user}@{self.target} '{cmd}'"
            cmd = ssh_cmd
        
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=timeout
            )
            return result.stdout.strip()
        except:
            return ""
    
    def get_system_info(self) -> Dict:
        """Get basic system information."""
        console.print("\n[cyan]📋 Gathering system information...[/cyan]")
        
        info = {
            'hostname': self._run_command('hostname'),
            'kernel': self._run_command('uname -a'),
            'distro': self._run_command('cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2'),
            'architecture': self._run_command('uname -m'),
            'uptime': self._run_command('uptime'),
            'date': self._run_command('date'),
        }
        
        return info
    
    def get_users(self) -> List[Dict]:
        """Enumerate all users."""
        console.print("\n[cyan]👤 Enumerating users...[/cyan]")
        
        users = []
        
        # Parse /etc/passwd
        passwd = self._run_command('cat /etc/passwd')
        for line in passwd.split('\n'):
            if line:
                parts = line.split(':')
                if len(parts) >= 7:
                    users.append({
                        'username': parts[0],
                        'uid': parts[2],
                        'gid': parts[3],
                        'home': parts[5],
                        'shell': parts[6],
                        'login_capable': parts[6] not in ['/sbin/nologin', '/usr/sbin/nologin', '/bin/false']
                    })
        
        console.print(f"[green]✓ Found {len(users)} users[/green]")
        return users
    
    def get_groups(self) -> List[Dict]:
        """Enumerate all groups."""
        console.print("\n[cyan]👥 Enumerating groups...[/cyan]")
        
        groups = []
        
        group_file = self._run_command('cat /etc/group')
        for line in group_file.split('\n'):
            if line:
                parts = line.split(':')
                if len(parts) >= 4:
                    groups.append({
                        'name': parts[0],
                        'gid': parts[2],
                        'members': parts[3].split(',') if parts[3] else []
                    })
        
        # Highlight interesting groups
        interesting = ['sudo', 'admin', 'wheel', 'docker', 'lxd', 'root', 'shadow']
        for g in groups:
            if g['name'] in interesting and g['members']:
                console.print(f"[yellow]  ⚠️ {g['name']}: {', '.join(g['members'])}[/yellow]")
        
        return groups
    
    def get_network_info(self) -> Dict:
        """Get network configuration."""
        console.print("\n[cyan]🌐 Gathering network information...[/cyan]")
        
        info = {
            'interfaces': self._run_command('ip addr 2>/dev/null || ifconfig'),
            'routes': self._run_command('ip route 2>/dev/null || route -n'),
            'arp_cache': self._run_command('arp -a 2>/dev/null || ip neigh'),
            'dns': self._run_command('cat /etc/resolv.conf'),
            'hosts': self._run_command('cat /etc/hosts'),
            'listening_tcp': self._run_command('ss -tlnp 2>/dev/null || netstat -tlnp'),
            'listening_udp': self._run_command('ss -ulnp 2>/dev/null || netstat -ulnp'),
            'established': self._run_command('ss -tnp 2>/dev/null || netstat -tnp'),
        }
        
        return info
    
    def get_running_processes(self) -> List[Dict]:
        """Get running processes."""
        console.print("\n[cyan]⚙️ Enumerating running processes...[/cyan]")
        
        processes = []
        
        ps_output = self._run_command('ps auxww')
        lines = ps_output.split('\n')[1:]  # Skip header
        
        for line in lines:
            parts = line.split(None, 10)
            if len(parts) >= 11:
                processes.append({
                    'user': parts[0],
                    'pid': parts[1],
                    'cpu': parts[2],
                    'mem': parts[3],
                    'command': parts[10]
                })
        
        # Highlight root processes
        root_procs = [p for p in processes if p['user'] == 'root']
        console.print(f"[green]✓ Found {len(processes)} processes ({len(root_procs)} as root)[/green]")
        
        return processes
    
    def get_installed_packages(self) -> List[str]:
        """Get installed packages."""
        console.print("\n[cyan]📦 Enumerating installed packages...[/cyan]")
        
        # Try different package managers
        packages = []
        
        # Debian/Ubuntu
        dpkg = self._run_command('dpkg -l 2>/dev/null | tail -n +6 | awk \'{print $2 " " $3}\'')
        if dpkg:
            packages = dpkg.split('\n')
        
        # Red Hat/CentOS
        if not packages:
            rpm = self._run_command('rpm -qa 2>/dev/null')
            if rpm:
                packages = rpm.split('\n')
        
        # Arch
        if not packages:
            pacman = self._run_command('pacman -Q 2>/dev/null')
            if pacman:
                packages = pacman.split('\n')
        
        console.print(f"[green]✓ Found {len(packages)} packages[/green]")
        return packages
    
    def get_cron_jobs(self) -> Dict:
        """Enumerate cron jobs."""
        console.print("\n[cyan]⏰ Enumerating cron jobs...[/cyan]")
        
        cron = {
            'crontab': self._run_command('cat /etc/crontab 2>/dev/null'),
            'cron_d': self._run_command('ls -la /etc/cron.d/ 2>/dev/null'),
            'cron_daily': self._run_command('ls -la /etc/cron.daily/ 2>/dev/null'),
            'cron_hourly': self._run_command('ls -la /etc/cron.hourly/ 2>/dev/null'),
            'cron_weekly': self._run_command('ls -la /etc/cron.weekly/ 2>/dev/null'),
            'cron_monthly': self._run_command('ls -la /etc/cron.monthly/ 2>/dev/null'),
            'user_crontabs': self._run_command('cat /var/spool/cron/crontabs/* 2>/dev/null'),
            'systemd_timers': self._run_command('systemctl list-timers --all 2>/dev/null'),
        }
        
        return cron
    
    def get_services(self) -> Dict:
        """Enumerate running services."""
        console.print("\n[cyan]🔧 Enumerating services...[/cyan]")
        
        services = {
            'systemd': self._run_command('systemctl list-units --type=service --state=running 2>/dev/null'),
            'init_d': self._run_command('ls -la /etc/init.d/ 2>/dev/null'),
            'rc_local': self._run_command('cat /etc/rc.local 2>/dev/null'),
        }
        
        return services
    
    def find_suid_binaries(self) -> List[str]:
        """Find SUID binaries."""
        console.print("\n[cyan]🔴 Finding SUID binaries...[/cyan]")
        
        suid = self._run_command('find / -perm -4000 -type f 2>/dev/null')
        binaries = [b for b in suid.split('\n') if b]
        
        # Known exploitable SUID binaries
        exploitable = [
            'bash', 'sh', 'python', 'python3', 'perl', 'ruby', 'php',
            'vim', 'vi', 'nano', 'less', 'more', 'find', 'nmap', 'awk',
            'env', 'cp', 'mv', 'dd', 'tar', 'zip', 'gzip', 'docker',
            'systemctl', 'service', 'mount', 'pkexec', 'sudo'
        ]
        
        for binary in binaries:
            name = os.path.basename(binary)
            if name in exploitable:
                console.print(f"[red]  ⚠️ EXPLOITABLE: {binary}[/red]")
        
        console.print(f"[green]✓ Found {len(binaries)} SUID binaries[/green]")
        return binaries
    
    def find_sgid_binaries(self) -> List[str]:
        """Find SGID binaries."""
        console.print("\n[cyan]🟡 Finding SGID binaries...[/cyan]")
        
        sgid = self._run_command('find / -perm -2000 -type f 2>/dev/null')
        binaries = [b for b in sgid.split('\n') if b]
        
        console.print(f"[green]✓ Found {len(binaries)} SGID binaries[/green]")
        return binaries
    
    def find_capabilities(self) -> List[Dict]:
        """Find files with capabilities."""
        console.print("\n[cyan]🟣 Finding capabilities...[/cyan]")
        
        caps = self._run_command('getcap -r / 2>/dev/null')
        capabilities = []
        
        for line in caps.split('\n'):
            if line and '=' in line:
                parts = line.rsplit(' ', 1)
                if len(parts) == 2:
                    capabilities.append({
                        'file': parts[0].strip(),
                        'caps': parts[1].strip()
                    })
                    
                    # Highlight dangerous capabilities
                    if any(c in parts[1] for c in ['cap_setuid', 'cap_setgid', 'cap_dac_override', 'cap_sys_admin']):
                        console.print(f"[red]  ⚠️ {line}[/red]")
        
        return capabilities
    
    def find_writable_files(self) -> Dict:
        """Find world-writable files and directories."""
        console.print("\n[cyan]📝 Finding writable locations...[/cyan]")
        
        writable = {
            'files': self._run_command('find / -writable -type f 2>/dev/null | head -100'),
            'directories': self._run_command('find / -writable -type d 2>/dev/null | head -100'),
            'etc_writable': self._run_command('find /etc -writable -type f 2>/dev/null'),
        }
        
        return writable
    
    def get_sensitive_files(self) -> Dict:
        """Check for readable sensitive files."""
        console.print("\n[cyan]🔐 Checking sensitive files...[/cyan]")
        
        files = {}
        sensitive_paths = [
            '/etc/passwd', '/etc/shadow', '/etc/sudoers',
            '/root/.ssh/id_rsa', '/root/.ssh/authorized_keys',
            '/root/.bash_history', '/root/.profile',
            '/etc/mysql/my.cnf', '/etc/mysql/debian.cnf',
            '/var/lib/mysql/mysql.user', '/etc/postgresql/*/pg_hba.conf',
            '/var/www/html/wp-config.php', '/var/www/html/.env',
            '/home/*/.ssh/id_rsa', '/home/*/.bash_history',
            '/home/*/.aws/credentials', '/home/*/.gnupg/*',
        ]
        
        for path in sensitive_paths:
            content = self._run_command(f'cat {path} 2>/dev/null | head -50')
            if content:
                files[path] = 'READABLE'
                console.print(f"[yellow]  📄 {path} - readable[/yellow]")
        
        return files
    
    def check_sudo_permissions(self) -> str:
        """Check sudo permissions for current user."""
        console.print("\n[cyan]🔑 Checking sudo permissions...[/cyan]")
        
        sudo_l = self._run_command('sudo -l 2>/dev/null')
        
        if 'NOPASSWD' in sudo_l:
            console.print("[red]  ⚠️ NOPASSWD entries found![/red]")
        
        return sudo_l
    
    def check_docker(self) -> Dict:
        """Check Docker configuration."""
        console.print("\n[cyan]🐳 Checking Docker...[/cyan]")
        
        docker = {
            'installed': bool(self._run_command('which docker 2>/dev/null')),
            'running': bool(self._run_command('docker ps 2>/dev/null')),
            'images': self._run_command('docker images 2>/dev/null'),
            'containers': self._run_command('docker ps -a 2>/dev/null'),
            'socket_writable': bool(self._run_command('ls -la /var/run/docker.sock 2>/dev/null | grep -E "^srw"')),
            'user_in_group': bool(self._run_command('id | grep docker')),
        }
        
        if docker['user_in_group']:
            console.print("[red]  ⚠️ User is in docker group - potential privesc![/red]")
        
        if docker['socket_writable']:
            console.print("[red]  ⚠️ Docker socket is writable![/red]")
        
        return docker
    
    def check_lxc_lxd(self) -> Dict:
        """Check LXC/LXD configuration."""
        console.print("\n[cyan]📦 Checking LXC/LXD...[/cyan]")
        
        lxd = {
            'installed': bool(self._run_command('which lxc 2>/dev/null')),
            'user_in_group': bool(self._run_command('id | grep lxd')),
            'containers': self._run_command('lxc list 2>/dev/null'),
        }
        
        if lxd['user_in_group']:
            console.print("[red]  ⚠️ User is in lxd group - potential privesc![/red]")
        
        return lxd
    
    def run_full_enumeration(self) -> Dict:
        """Run complete enumeration."""
        console.print("\n[bold cyan]═══════════════════════════════════════════════════════════[/bold cyan]")
        console.print("[bold cyan]              LINUX SYSTEM ENUMERATION                       [/bold cyan]")
        console.print("[bold cyan]═══════════════════════════════════════════════════════════[/bold cyan]")
        
        results = {
            'system': self.get_system_info(),
            'users': self.get_users(),
            'groups': self.get_groups(),
            'network': self.get_network_info(),
            'processes': self.get_running_processes(),
            'packages': self.get_installed_packages(),
            'cron': self.get_cron_jobs(),
            'services': self.get_services(),
            'suid': self.find_suid_binaries(),
            'sgid': self.find_sgid_binaries(),
            'capabilities': self.find_capabilities(),
            'writable': self.find_writable_files(),
            'sensitive': self.get_sensitive_files(),
            'sudo': self.check_sudo_permissions(),
            'docker': self.check_docker(),
            'lxd': self.check_lxc_lxd(),
        }
        
        return results


class SSHEnumerator:
    """SSH-specific enumeration."""
    
    def __init__(self, target: str, port: int = 22):
        self.target = target
        self.port = port
    
    def get_banner(self) -> str:
        """Get SSH banner."""
        import socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target, self.port))
            banner = sock.recv(1024).decode().strip()
            sock.close()
            return banner
        except:
            return ""
    
    def check_auth_methods(self) -> List[str]:
        """Check available authentication methods."""
        result = subprocess.run(
            ['ssh', '-v', '-o', 'PreferredAuthentications=none', 
             '-o', 'StrictHostKeyChecking=no',
             f'test@{self.target}', '-p', str(self.port)],
            capture_output=True, text=True, timeout=10
        )
        
        methods = []
        if 'publickey' in result.stderr:
            methods.append('publickey')
        if 'password' in result.stderr:
            methods.append('password')
        if 'keyboard-interactive' in result.stderr:
            methods.append('keyboard-interactive')
        
        return methods
    
    def enumerate_users(self, userlist: List[str]) -> List[str]:
        """
        Enumerate valid users (CVE-2018-15473 - OpenSSH <7.7).
        Note: This only works on old vulnerable versions.
        """
        console.print(f"\n[cyan]🔍 Attempting user enumeration on {self.target}...[/cyan]")
        
        # Check if vulnerable version
        banner = self.get_banner()
        console.print(f"[dim]SSH Banner: {banner}[/dim]")
        
        # Use external tool if available
        valid_users = []
        
        # Manual approach using timing (less reliable)
        for user in userlist[:50]:  # Limit to prevent detection
            try:
                result = subprocess.run(
                    ['ssh', '-o', 'BatchMode=yes',
                     '-o', 'StrictHostKeyChecking=no',
                     '-o', 'ConnectTimeout=3',
                     f'{user}@{self.target}'],
                    capture_output=True, timeout=5
                )
                # Valid users often have different error messages
                if 'Permission denied' in result.stderr.decode():
                    valid_users.append(user)
            except:
                pass
        
        return valid_users


class NFSEnumerator:
    """NFS enumeration."""
    
    def __init__(self, target: str):
        self.target = target
    
    def list_exports(self) -> List[str]:
        """List NFS exports."""
        console.print(f"\n[cyan]📂 Enumerating NFS exports on {self.target}...[/cyan]")
        
        result = subprocess.run(
            ['showmount', '-e', self.target],
            capture_output=True, text=True, timeout=30
        )
        
        exports = []
        for line in result.stdout.split('\n')[1:]:  # Skip header
            if line:
                exports.append(line)
                console.print(f"[green]  📁 {line}[/green]")
        
        return exports
    
    def check_no_root_squash(self, export: str) -> bool:
        """Check if export has no_root_squash."""
        # Would need to mount and check
        # This is a simplified check
        return 'no_root_squash' in export.lower()
    
    def generate_mount_commands(self, exports: List[str]) -> List[str]:
        """Generate mount commands for discovered exports."""
        commands = []
        for export in exports:
            path = export.split()[0] if export else ''
            if path:
                commands.append(f"mkdir -p /mnt/nfs && mount -t nfs {self.target}:{path} /mnt/nfs")
        return commands
