# OSCP Enumeration Master Guide

## Table of Contents
- [Initial Network Discovery](#initial-network-discovery)
- [Port Scanning Strategies](#port-scanning-strategies)
- [Service Enumeration](#service-enumeration)
- [Web Application Enumeration](#web-application-enumeration)
- [SMB Enumeration](#smb-enumeration)
- [Common Mistakes to Avoid](#common-mistakes-to-avoid)

## Initial Network Discovery

### Quick Network Scan (Copy-Paste Ready)
```bash
# Initial ping sweep (if needed)
nmap -sn 10.11.1.0/24

# Fast TCP port scan
nmap -Pn -T4 --top-ports 1000 <target>

# Full TCP port scan (run in background)
nmap -Pn -T4 -p- <target> -oN fullscan.txt &

# Quick UDP scan (top 20 ports)
sudo nmap -sU --top-ports 20 <target>
```

### Comprehensive Nmap Scanning
```bash
# Initial scan
nmap -Pn -sC -sV -T4 <target> -oN initial.txt

# All ports TCP scan
nmap -Pn -p- -T4 <target> -oN allports.txt

# Service enumeration on discovered ports
nmap -Pn -sC -sV -p <ports> <target> -oN services.txt

# UDP scan for SNMP, DNS, DHCP
sudo nmap -sU -p 53,67,68,123,135,137,138,139,161,162,445,500,514,631,1434,1900 <target>
```

## Port Scanning Strategies

### Time Management Strategy
- **First 15 minutes**: Quick scan to identify open ports
- **Background scans**: Full TCP and UDP scans running while you work
- **Parallel approach**: Start with obvious services while comprehensive scans run

### Rustscan (Faster Alternative)
```bash
# Install and use rustscan
rustscan -a <target> -p 1-65535 -- -sC -sV
```

## Service Enumeration

### Port 21 - FTP
```bash
# Anonymous login test
ftp <target>
# Try: anonymous / anonymous or ftp / ftp

# Banner grab and test commands
nc -nv <target> 21
nmap --script ftp-* <target> -p 21

# File transfer commands (if you have access)
binary
passive
get <filename>
put <filename>
```

### Port 22 - SSH  
```bash
# Banner grab
nc -nv <target> 22

# SSH enumeration
ssh-audit <target>
nmap --script ssh2-enum-algos <target> -p 22
nmap --script ssh-hostkey <target> -p 22

# User enumeration (be careful with noise)
python ssh-username-enum.py <target> <userlist>
```

### Port 25 - SMTP
```bash
# Connect and enumerate
nc -nv <target> 25

# User enumeration commands
VRFY <username>
EXPN <username>  
RCPT TO: <username>

# Nmap scripts
nmap --script smtp-enum-users <target> -p 25
nmap --script smtp-commands <target> -p 25
```

### Port 53 - DNS
```bash
# Zone transfer attempt
dig axfr <domain> @<target>

# DNS enumeration
dnsrecon -d <domain> -t axfr
dnsrecon -d <domain> -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t brt

# PTR records
dig -x <target>
```

### Port 80/443/8080/8000 - HTTP/HTTPS
```bash
# Quick checks
curl -I http://<target>
curl -k -I https://<target>

# Certificate information (HTTPS)
openssl s_client -connect <target>:443

# Technology identification
whatweb <target>
```

### Port 88 - Kerberos (AD Environment)
```bash
# Check if Kerberos is running
nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='<domain>' <target>
```

### Port 110/995 - POP3/POP3S
```bash
# Connect and test
nc -nv <target> 110
telnet <target> 110

# Commands to try
USER <username>
PASS <password>
LIST
RETR <message_number>
```

### Port 111 - RPC
```bash
# RPC enumeration
rpcinfo -p <target>
showmount -e <target>

# Nmap scripts
nmap --script rpc-grind <target> -p 111
```

### Port 135 - Microsoft RPC
```bash
# RPC enumeration
rpcdump.py <target>
rpcmap.py <target>
```

### Port 139/445 - SMB
```bash
# SMB version detection
smbclient -L //<target>
smbclient -L //<target> -N

# Share enumeration
smbmap -H <target>
smbmap -H <target> -u null -p null
smbmap -H <target> -u guest -p ""

# Connect to shares
smbclient //<target>/<share>
smbclient //<target>/<share> -N

# Enumerate users and shares
enum4linux -a <target>
```

### Port 143/993 - IMAP/IMAPS  
```bash
# Connect to IMAP
nc -nv <target> 143

# Commands
A01 LOGIN <username> <password>
A02 LIST "" "*"
A03 SELECT INBOX
A04 FETCH 1 BODY.PEEK[]
```

### Port 161 - SNMP
```bash
# SNMP enumeration
snmpwalk -c public -v1 <target>
snmpwalk -c private -v1 <target> 
snmpwalk -c public -v2c <target>

# Common OIDs
snmpwalk -c public -v1 <target> 1.3.6.1.2.1.1.5.0  # Hostname
snmpwalk -c public -v1 <target> 1.3.6.1.4.1.77.1.2.25  # Users
snmpwalk -c public -v1 <target> 1.3.6.1.2.1.6.13.1.3  # TCP ports

# Community string bruteforcing
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt <target>
```

### Port 389/636 - LDAP/LDAPS
```bash
# Anonymous bind test
ldapsearch -h <target> -x -b "DC=domain,DC=com"

# Enumerate naming contexts
ldapsearch -h <target> -x -s base namingcontexts

# User enumeration
ldapsearch -h <target> -x -b "DC=domain,DC=com" "(objectclass=person)"
```

### Port 1433 - MSSQL
```bash
# Connect with impacket
impacket-mssqlclient <username>:<password>@<target> -windows-auth

# Nmap enumeration
nmap --script ms-sql-info <target> -p 1433
nmap --script ms-sql-empty-password <target> -p 1433
nmap --script ms-sql-brute <target> -p 1433
```

### Port 2049 - NFS
```bash
# Show exports
showmount -e <target>

# Mount NFS share
mkdir /tmp/mount
sudo mount -t nfs <target>:/<path> /tmp/mount -nolock
```

### Port 3306 - MySQL  
```bash
# Connect
mysql -h <target> -u <username> -p<password>

# Remote connection test
mysql -h <target> -u root
mysql -h <target> -u root -p

# Nmap enumeration  
nmap --script mysql-info <target> -p 3306
nmap --script mysql-empty-password <target> -p 3306
```

### Port 3389 - RDP
```bash
# RDP connection test
rdesktop <target>
xfreerdp /v:<target> /u:<username> /p:<password>

# Certificate information
nmap --script rdp-enum-encryption <target> -p 3389
```

### Port 5432 - PostgreSQL
```bash
# Connect
psql -h <target> -U <username> -d <database>

# Nmap enumeration
nmap --script pgsql-brute <target> -p 5432
```

### Port 5985/5986 - WinRM
```bash
# Test connection
evil-winrm -i <target> -u <username> -p <password>

# Nmap enumeration
nmap --script winrm-brute <target> -p 5985
```

## Web Application Enumeration

### Initial Web Reconnaissance
```bash
# Technology fingerprinting
whatweb <target>
wafw00f <target>

# Certificate analysis (HTTPS)
sslscan <target>
sslyze --regular <target>
```

### Directory and File Discovery

#### Gobuster (Recommended)
```bash
# Basic directory scan
gobuster dir -u http://<target> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 20

# With extensions
gobuster dir -u http://<target> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt,js -t 20

# Specific directory
gobuster dir -u http://<target>/admin -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 20

# DNS subdomain enumeration
gobuster dns -d <target> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

#### Dirsearch
```bash
# Basic scan
dirsearch -u http://<target> -t 50

# Specific extensions
dirsearch -u http://<target> -e php,html,js,txt -t 50

# Recursive scan
dirsearch -u http://<target> -r -t 50
```

#### Ffuf (Fast)
```bash
# Directory fuzzing
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://<target>/FUZZ -t 50

# File extension fuzzing  
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://<target>/FUZZ -e .php,.html,.txt,.js -t 50

# Parameter fuzzing
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u http://<target>/admin.php?FUZZ=test
```

### Nikto Scanning
```bash
# Basic scan
nikto -h http://<target>

# Specific port
nikto -h http://<target> -p 8080

# Save results
nikto -h http://<target> -o nikto.txt
```

### Manual Testing Checklist

#### Always Check These Files/Directories:
- `/robots.txt`
- `/sitemap.xml` 
- `/.htaccess`
- `/backup/`
- `/admin/`
- `/administrator/`
- `/wp-admin/` (WordPress)
- `/phpmyadmin/`
- `/test/`
- `/dev/`

#### Quick Manual Tests:
```bash
# Check robots.txt
curl http://<target>/robots.txt

# View source for comments/hidden elements
curl http://<target> | grep -i "comment\|password\|user\|admin\|key"

# Check for backup files
for ext in .bak .backup .old .orig .save; do
    curl -I http://<target>/index.php$ext
done
```

### Web Application Vulnerability Testing

#### SQL Injection Testing
```bash
# Basic tests (URL parameter)
http://<target>/page.php?id=1'
http://<target>/page.php?id=1"
http://<target>/page.php?id=1 OR 1=1--
http://<target>/page.php?id=1 UNION SELECT 1,2,3--

# SQLMap (use sparingly in exam)
sqlmap -u "http://<target>/page.php?id=1" --batch --dump
```

#### Local File Inclusion (LFI) Testing
```bash
# Basic LFI tests
http://<target>/page.php?file=../../../etc/passwd
http://<target>/page.php?file=....//....//....//etc/passwd
http://<target>/page.php?file=/etc/passwd%00

# Windows LFI
http://<target>/page.php?file=../../../windows/system32/drivers/etc/hosts
http://<target>/page.php?file=C:\windows\system32\drivers\etc\hosts
```

#### Command Injection Testing  
```bash
# Basic tests
http://<target>/ping.php?ip=127.0.0.1;id
http://<target>/ping.php?ip=127.0.0.1|id  
http://<target>/ping.php?ip=127.0.0.1&&id
http://<target>/ping.php?ip=127.0.0.1`id`
```

## SMB Enumeration

### Anonymous Access Testing
```bash
# Test null session
smbclient -L //<target>
smbclient -L //<target> -N
smbmap -H <target>
smbmap -H <target> -u null -p null
```

### Share Enumeration
```bash
# List shares
smbclient -L //<target> -U ""
smbmap -H <target>
smbmap -H <target> -u guest

# Connect to share
smbclient //<target>/<share>
smbclient //<target>/<share> -N

# Recursive listing
smbmap -H <target> -R
```

### User Enumeration  
```bash
# Enumerate users
enum4linux -U <target>
rpcclient -U "" -N <target>
> enumdomusers
> enumdomgroups
> queryuser <RID>
```

### CrackMapExec Usage
```bash
# SMB enumeration
crackmapexec smb <target>
crackmapexec smb <target> -u '' -p '' --shares
crackmapexec smb <target> -u guest -p '' --shares
crackmapexec smb <target> --users
```

## Common Mistakes to Avoid

### 1. Insufficient Enumeration
❌ **Wrong**: Running one basic nmap scan and moving on
✅ **Correct**: Running comprehensive scans while investigating initial findings

### 2. Not Checking Default Credentials
Always try these combinations:
- admin:admin, admin:password, admin:123456
- root:root, root:toor, root:password  
- service-specific defaults (e.g., tomcat:tomcat for Tomcat)

### 3. Forgetting About UDP Services
```bash
# Always scan important UDP ports
sudo nmap -sU --top-ports 100 <target>
# Focus on: 53(DNS), 69(TFTP), 123(NTP), 161(SNMP), 500(IPSec)
```

### 4. Not Testing All Discovered Credentials
- Test credentials against ALL services (SSH, SMB, FTP, HTTP, etc.)
- Use crackmapexec for credential spraying across multiple hosts

### 5. Missing Obvious Enumeration
```bash
# Always check these basics
id                    # Current user privileges  
hostname              # System hostname
uname -a              # System information
cat /etc/passwd       # All users (Linux)
net user              # All users (Windows)
ps aux                # Running processes
netstat -tulpn        # Network connections
```

## Time Management Tips

### Phase 1: Quick Discovery (30 minutes)
1. Initial nmap scan with top 1000 ports
2. Start full port scan in background
3. Immediate investigation of obvious services

### Phase 2: Deep Enumeration (1-2 hours)  
1. Service-specific enumeration
2. Web application testing
3. Share and user enumeration

### Phase 3: Exploitation Attempts
- Focus on high-confidence vulnerabilities first
- Document all findings for potential lateral movement

## Final Checklist

Before moving to exploitation, ensure you have:
- [ ] Complete port scan results
- [ ] Service banner information  
- [ ] Web directories/files discovered
- [ ] All shares enumerated
- [ ] User lists gathered
- [ ] Potential credentials identified
- [ ] Configuration files reviewed
- [ ] Technology stack identified

Remember: "Enumerate harder, not faster" - The exam rewards thorough enumeration over speed.