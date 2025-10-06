# OSCP Enhanced Enumeration Master Guide

## Table of Contents
- [Initial Network Discovery](#initial-network-discovery)
- [Port Scanning Strategies](#port-scanning-strategies)
- [Service Enumeration](#service-enumeration)
- [Advanced Web Application Enumeration](#advanced-web-application-enumeration)
- [SMB Deep Enumeration](#smb-deep-enumeration)
- [API Testing and Discovery](#api-testing-and-discovery)
- [Common Enumeration Pitfalls](#common-enumeration-pitfalls)

## Initial Network Discovery

### Quick Network Scan (Copy-Paste Ready)
```bash
# Initial ping sweep (if needed)
nmap -sn 10.11.1.0/24

# Fast TCP port scan with top ports
nmap -Pn -T4 --top-ports 1000 <target>

# Full TCP port scan (run in background)
nmap -Pn -T4 -p- <target> -oN fullscan.txt &

# Quick UDP scan (top 20 ports)
sudo nmap -sU --top-ports 20 <target>

# Aggressive scan for immediate info
nmap -Pn -T4 -A <target> -oN aggressive.txt
```

### Advanced Port Discovery
```bash
# All ports TCP (includes non-standard)
nmap -Pn -p1-65535 -T4 <target>

# Specific ranges for common non-standard ports
nmap -Pn -p 8000-8999,9000-9999,10000-10999 <target>

# SYN scan with version detection on all ports
nmap -Pn -sS -sV -p- <target> -T4

# Check for services on non-standard ports
nmap -Pn -sV -p 8080,8443,9443,10443,8888,9999 <target>
```

### Comprehensive Nmap Scanning
```bash
# Initial scan with scripts
nmap -Pn -sC -sV -T4 <target> -oN initial.txt

# All ports TCP scan with timing optimization  
nmap -Pn -p- -T4 <target> -oN allports.txt --min-rate=1000

# Service enumeration on discovered ports
nmap -Pn -sC -sV -p <ports> <target> -oN services.txt

# UDP scan for critical services
sudo nmap -sU -p 53,67,68,123,135,137,138,139,161,162,445,500,514,631,1434,1900 <target>

# Script scan for vulnerabilities
nmap -Pn --script vuln <target> -p <open-ports>
```

## Port Scanning Strategies

### Time Management Strategy
- **First 5 minutes**: Quick scan to identify obvious services
- **Background scans**: Full TCP and UDP scans running continuously
- **Parallel approach**: Start service enumeration while comprehensive scans run
- **Documentation**: Note everything immediately, don't wait

### Rustscan Integration
```bash
# Super fast port discovery
rustscan -a <target> -p 1-65535 -- -sC -sV -oN rustscan.txt

# Rustscan with custom threads
rustscan -a <target> -t 2000 -p 1-65535 -- -A
```

## Service Enumeration

### Port 21 - FTP Advanced
```bash
# Anonymous login test
ftp <target>
# Try combinations: anonymous/anonymous, ftp/ftp, user/user

# Banner grab and enumerate capabilities
nc -nv <target> 21
# After connection, try:
# HELP
# FEAT  
# STAT

# Nmap enumeration with all FTP scripts
nmap --script "ftp-* and not ftp-brute" <target> -p 21

# Check for bounce attacks (rare but possible)
nmap --script ftp-bounce <target> -p 21

# File transfer testing (if access granted)
binary
passive  
ls -la
get filename
put testfile.txt

# Check writable directories
ftp> cd upload
ftp> put test.txt
```

### Port 22 - SSH Advanced  
```bash
# Banner grab for version info
nc -nv <target> 22

# SSH audit for security issues
ssh-audit <target>

# Check for user enumeration vulnerability
python3 /usr/share/seclists/Usernames/Names/names.txt -t <target>

# Algorithm enumeration
nmap --script ssh2-enum-algos <target> -p 22

# Check for specific vulnerabilities
nmap --script ssh-hostkey <target> -p 22
nmap --script ssh-auth-methods <target> -p 22

# Test weak ciphers
ssh -c aes128-cbc <target>
```

### Port 25 - SMTP Advanced
```bash
# Connect and enumerate
nc -nv <target> 25

# Extended commands enumeration
EHLO test.com
HELP
EXPN root
VRFY root
RCPT TO: root

# User enumeration with wordlists
for user in $(cat /usr/share/seclists/Usernames/top-usernames-shortlist.txt); do echo "VRFY $user" | nc -nv <target> 25; done

# Nmap scripts for SMTP
nmap --script smtp-* <target> -p 25

# Test for relaying
telnet <target> 25
HELO test.com
MAIL FROM: test@test.com  
RCPT TO: external@external.com
```

### Port 53 - DNS Deep Dive
```bash
# Zone transfer attempts
dig axfr <domain> @<target>
dnsrecon -d <domain> -t axfr

# Comprehensive DNS enumeration
dnsrecon -d <domain> -t std
dnsrecon -d <domain> -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t brt

# Check for DNS cache snooping
nmap --script dns-cache-snoop <target>

# Reverse DNS lookups
dig -x <target>
dnsrecon -r <target-range>

# Test for DNS amplification
dig @<target> . NS +short
```

### Port 80/443/8080/8000 - HTTP/HTTPS Advanced
```bash
# Technology fingerprinting (multiple methods)
whatweb <target>
curl -I http://<target>
curl -k -I https://<target>

# Check HTTP methods
curl -X OPTIONS http://<target> -v
nmap --script http-methods <target> -p 80

# Headers analysis  
curl -s -D- http://<target> -o /dev/null
nmap --script http-headers <target>

# SSL/TLS analysis (HTTPS)
sslscan <target>
sslyze --regular <target>
nmap --script ssl-* <target> -p 443

# Certificate analysis
openssl s_client -connect <target>:443 -servername <target>

# WAF detection
wafw00f http://<target>
```

### Port 111 - RPC Advanced
```bash
# RPC enumeration comprehensive
rpcinfo -p <target>
showmount -e <target>

# Nmap RPC scripts
nmap --script rpc-* <target> -p 111

# Check for specific RPC services
rpcinfo -T tcp <target> 100003  # NFS
rpcinfo -T tcp <target> 100005  # mountd
```

### Port 135 - Microsoft RPC
```bash
# Impacket RPC tools
rpcdump.py <target>
rpcmap.py <target>

# Nmap enumeration
nmap --script ms-sql-info <target> -p 135
```

### Port 139/445 - SMB Deep Enumeration

#### Anonymous/Null Session Testing
```bash
# Multiple null session attempts
smbclient -L //<target>
smbclient -L //<target> -N
smbclient -L //<target> -U ""
smbclient -L //<target> -U ""%""

# Share enumeration
smbmap -H <target>
smbmap -H <target> -u null -p null
smbmap -H <target> -u guest -p ""
smbmap -H <target> -u anonymous -p anonymous

# Connect to specific shares
smbclient //<target>/<share>
smbclient //<target>/<share> -N
smbclient //<target>/<share> -U guest

# Comprehensive enumeration
enum4linux -a <target>
enum4linux -u administrator -p password <target>
```

#### Advanced SMB Techniques
```bash
# RPC enumeration
rpcclient -U "" -N <target>
# Once connected:
srvinfo
enumdomusers
enumdomgroups
enumprivs
queryuser <RID>
querygroupmem <group-RID>

# CrackMapExec enumeration
crackmapexec smb <target>
crackmapexec smb <target> --users
crackmapexec smb <target> --groups
crackmapexec smb <target> --shares
crackmapexec smb <target> --sessions

# SMB vulnerability scanning
nmap --script smb-vuln* <target> -p 139,445
nmap --script smb-os-discovery <target>
```

### Port 161 - SNMP Advanced
```bash
# Community string enumeration
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt <target>

# SNMP walking with different versions
snmpwalk -c public -v1 <target>
snmpwalk -c private -v1 <target>
snmpwalk -c public -v2c <target>

# Specific OID enumeration
snmpwalk -c public -v1 <target> 1.3.6.1.2.1.1.5.0    # Hostname
snmpwalk -c public -v1 <target> 1.3.6.1.4.1.77.1.2.25 # Users
snmpwalk -c public -v1 <target> 1.3.6.1.2.1.6.13.1.3  # TCP ports
snmpwalk -c public -v1 <target> 1.3.6.1.2.1.25.4.2.1.2 # Processes

# Full system enumeration via SNMP
snmpenum <target> public windows.txt
```

### Port 389/636 - LDAP/LDAPS Advanced
```bash
# Anonymous bind testing
ldapsearch -h <target> -x -b ""
ldapsearch -h <target> -x -s base namingcontexts

# Domain enumeration
ldapsearch -h <target> -x -b "DC=domain,DC=com"
ldapsearch -h <target> -x -b "DC=domain,DC=com" "(objectclass=person)"
ldapsearch -h <target> -x -b "DC=domain,DC=com" "(objectclass=computer)"

# User enumeration with different filters
ldapsearch -h <target> -x -b "DC=domain,DC=com" "(objectclass=user)"
ldapsearch -h <target> -x -b "DC=domain,DC=com" "(&(objectclass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
```

## Advanced Web Application Enumeration

### Initial Web Reconnaissance Enhanced
```bash
# Multiple technology fingerprinting
whatweb <target>
wafw00f <target>
curl -s http://<target> | grep -i "generator\|powered\|built\|version"

# Header analysis
curl -I http://<target>
curl -I http://<target> -H "User-Agent: Mozilla/5.0"

# Check for different responses with various user agents
curl -H "User-Agent: Googlebot" http://<target>
curl -H "User-Agent: curl/7.68.0" http://<target>
```

### Directory and File Discovery Advanced

#### Gobuster Enhanced Techniques
```bash
# Basic directory scan with status codes
gobuster dir -u http://<target> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -x php,html,txt,js,xml,json,bak -s 200,301,302,403

# Multiple wordlist approach
gobuster dir -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 50
gobuster dir -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/big.txt -t 50

# Specific file extensions based on technology
# PHP applications
gobuster dir -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/PHP.fuzz.txt -x php,phtml,php3,php5

# ASP.NET applications
gobuster dir -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/IIS.fuzz.txt -x asp,aspx,ashx,asmx

# Backup and old files
gobuster dir -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/common.txt -x bak,backup,old,orig,save,tmp,~,swp

# Admin panel discovery
gobuster dir -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/CMS/wp-admin.fuzz.txt
```

#### Dirsearch Advanced Usage
```bash
# Recursive with depth limit
dirsearch -u http://<target> -r -R 3 -t 50

# Specific extensions with exclusions
dirsearch -u http://<target> -e php,html,js,txt -x 404,403 -t 50

# Force extensions and common files
dirsearch -u http://<target> -f -e php -w /usr/share/seclists/Discovery/Web-Content/PHP.fuzz.txt
```

#### Ffuf Advanced Fuzzing
```bash
# Directory fuzzing with filters
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://<target>/FUZZ -t 100 -fs 0,1234 -fc 404

# Parameter fuzzing (GET)
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u "http://<target>/page.php?FUZZ=test" -t 50

# POST parameter fuzzing
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u http://<target>/login.php -X POST -d "FUZZ=test" -H "Content-Type: application/x-www-form-urlencoded" -t 50

# Header fuzzing
ffuf -w /usr/share/seclists/Discovery/Web-Content/BurpSuite-ParamNames.txt -u http://<target> -H "FUZZ: test" -t 50

# Virtual host discovery
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://<target> -H "Host: FUZZ.<domain>" -fs 1234
```

### Manual Enumeration Checklist

#### Always Check These Files (Copy-Paste List)
```bash
# Essential files every time
curl -s http://<target>/robots.txt
curl -s http://<target>/sitemap.xml
curl -s http://<target>/.htaccess
curl -s http://<target>/web.config
curl -s http://<target>/crossdomain.xml
curl -s http://<target>/clientaccesspolicy.xml

# Common sensitive files
curl -s http://<target>/.git/config
curl -s http://<target>/.svn/entries
curl -s http://<target>/.env
curl -s http://<target>/config.php
curl -s http://<target>/configuration.php
curl -s http://<target>/wp-config.php
curl -s http://<target>/settings.py

# Backup and development files
for file in index.php login.php admin.php config.php; do
  for ext in .bak .backup .old .orig .save .tmp .swp ~; do
    curl -s -o /dev/null -w "%{http_code} - $file$ext\n" http://<target>/$file$ext
  done
done

# Common directories check
for dir in admin administrator wp-admin phpmyadmin manager-gui manager manager/html admin-panel cpanel; do
  echo "Testing /$dir: $(curl -s -o /dev/null -w "%{http_code}" http://<target>/$dir/)"
done
```

#### Advanced Manual Testing
```bash
# Source code analysis patterns
curl -s http://<target> | grep -E "(password|admin|config|key|secret|token)" -i
curl -s http://<target> | grep -E "<!--.*-->" 

# JavaScript file analysis
curl -s http://<target> | grep -oP 'src="\K[^"]*\.js' | while read jsfile; do
  echo "Analyzing: $jsfile"
  curl -s http://<target>/$jsfile | grep -E "(password|admin|api|key|token|endpoint)" -i
done

# Check for exposed version control
curl -s http://<target>/.git/HEAD
curl -s http://<target>/.svn/wc.db
```

## API Testing and Discovery

### API Endpoint Discovery
```bash
# Common API paths
gobuster dir -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt

# API versioning
for version in v1 v2 v3 api/v1 api/v2; do
  curl -s http://<target>/$version/ | head -5
done

# GraphQL discovery
curl -s http://<target>/graphql -d '{"query":"{__schema{types{name}}}"}' -H "Content-Type: application/json"
curl -s http://<target>/v1/graphql -d '{"query":"{__schema{types{name}}}"}' -H "Content-Type: application/json"

# API documentation paths
for path in api-docs swagger.json openapi.json docs api/docs; do
  curl -s http://<target>/$path | head -5
done
```

### API Testing Techniques
```bash
# REST API enumeration
for method in GET POST PUT DELETE PATCH OPTIONS; do
  curl -X $method http://<target>/api/users -v
done

# Parameter pollution testing
curl "http://<target>/api/users?id=1&id=2" -v

# JSON parameter testing
curl -X POST http://<target>/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"password"}'

# XML parameter testing  
curl -X POST http://<target>/api/login \
  -H "Content-Type: application/xml" \
  -d '<login><username>admin</username><password>password</password></login>'
```

## SMB Deep Enumeration

### Comprehensive SMB Testing
```bash
# Multi-tool approach
smbclient -L //<target>
smbclient -L //<target> -N
smbmap -H <target>
enum4linux -a <target>

# Share-specific enumeration
smbclient //<target>/<share> -N
# Once connected:
ls
cd ..
ls
get interesting_file.txt
```

### RPC Deep Dive
```bash
# RPC client comprehensive enumeration
rpcclient -U "" -N <target>
# Commands inside rpcclient:
srvinfo
enumdomusers
enumdomgroups
enumprivs
queryuser 500
queryuser 501
querygroupmem 512
querygroupmem 513
```

## Common Enumeration Pitfalls

### Mistake 1: Insufficient Port Coverage
❌ **Wrong**: Only scanning top 1000 ports
✅ **Correct**: Always run full port scan in background

```bash
# Wrong approach
nmap -T4 <target>

# Correct approach  
nmap -T4 --top-ports 1000 <target> &  # Quick results
nmap -p- -T4 <target> -oN fullscan.txt &  # Complete scan
```

### Mistake 2: Missing HTTP Methods
❌ **Wrong**: Only testing GET requests
✅ **Correct**: Test all HTTP methods

```bash
# Test all methods
for method in GET POST PUT DELETE PATCH OPTIONS HEAD; do
  curl -X $method http://<target>/admin -v
done
```

### Mistake 3: Not Checking Non-Standard Directories
❌ **Wrong**: Using only common wordlists
✅ **Correct**: Technology-specific enumeration

```bash
# PHP-specific
gobuster dir -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/PHP.fuzz.txt

# WordPress-specific
wpscan --url http://<target> --enumerate ap,at,tt,cb,dbe
```

### Mistake 4: Ignoring Error Pages
❌ **Wrong**: Dismissing 403/404 responses
✅ **Correct**: Analyze error pages for information disclosure

```bash
# Check different status codes
curl -s http://<target>/nonexistent | grep -i "version\|server\|apache\|nginx"
```

### Mistake 5: Not Following Redirects
❌ **Wrong**: Ignoring 301/302 redirects
✅ **Correct**: Follow redirects and analyze chains

```bash
# Follow redirects
curl -L http://<target>/admin
curl -v http://<target>/login 2>&1 | grep -i location
```

## Time-Saving One-Liners

### Quick Service Check
```bash
# Check if service responds
nc -zv <target> 22 80 443 && echo "Core services up"
```

### Quick Web Discovery
```bash
# Rapid web enumeration
gobuster dir -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt -t 50 -q --no-error
```

### Quick SMB Check
```bash
# Rapid SMB enumeration
smbclient -L //<target> -N 2>/dev/null | grep -v "^$\|Connection\|session"
```

### Parameter Fuzzing One-Liner
```bash
# Quick parameter discovery
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u "http://<target>/page.php?FUZZ=test" -fs 1234 -s
```

## Final Enumeration Checklist

Before moving to exploitation, ensure you have:
- [ ] Complete port scan results (including UDP)
- [ ] Service version information for all open ports
- [ ] Web directories and files enumerated with multiple tools
- [ ] All HTTP methods tested on discovered endpoints
- [ ] SMB shares and permissions mapped
- [ ] User lists gathered from multiple sources
- [ ] Technology stack identified (web server, framework, CMS)
- [ ] Potential credentials found (default, in files, etc.)
- [ ] API endpoints discovered and documented
- [ ] All backup/temp files checked
- [ ] robots.txt, sitemap.xml analyzed
- [ ] Error pages analyzed for information disclosure

Remember: "Enumerate like your certification depends on it" - because it does! The OSCP exam rewards methodical, thorough enumeration more than flashy exploits.