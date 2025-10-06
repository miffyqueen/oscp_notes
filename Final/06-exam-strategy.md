# OSCP Exam Strategy & Methodology Guide

## Table of Contents
- [Exam Overview](#exam-overview)
- [Pre-Exam Preparation](#pre-exam-preparation)
- [Exam Day Strategy](#exam-day-strategy)
- [Machine Approach Methodology](#machine-approach-methodology)
- [Time Management](#time-management)
- [Common Scenarios and Solutions](#common-scenarios-and-solutions)
- [Report Writing](#report-writing)
- [Mental Preparation](#mental-preparation)

## Exam Overview

### Current OSCP Exam Format (2024-2025)
```
Total Points Required: 70/100
Exam Duration: 23 hours 45 minutes
Report Duration: 24 hours

Point Distribution:
- Active Directory Set: 40 points (3 machines)
- Standalone Machine 1: 20 points (10 local + 10 root)
- Standalone Machine 2: 20 points (10 local + 10 root) 
- Standalone Machine 3: 20 points (10 local + 10 root)

Note: Metasploit usage is restricted - can only be used on ONE standalone machine
```

### Passing Scenarios
```
Scenario 1: AD Set + 1 Standalone = 60 points (Need bonus points)
Scenario 2: AD Set + 2 Standalones = 80 points (Pass)
Scenario 3: 3 Standalones + some AD = 60-80 points (Depends on execution)
Scenario 4: All machines = 100 points (Perfect score)
```

## Pre-Exam Preparation

### Essential Tools Checklist
```bash
# Network Enumeration
nmap
masscan
rustscan
autorecon

# Web Enumeration  
gobuster
dirsearch
ffuf
nikto
burp suite

# Windows Tools
winPEAS.exe
PowerUp.ps1
Seatbelt.exe
JuicyPotato.exe
PrintSpoofer.exe
SharpHound.exe

# Linux Tools
linpeas.sh
LinEnum.sh
pspy64
linux-smart-enumeration

# Active Directory
impacket suite
crackmapexec
bloodhound-python
responder
```

### Kali Setup Checklist
```bash
# Update system
sudo apt update && sudo apt upgrade

# Install additional tools
sudo apt install seclists curl dnsrecon enum4linux feroxbuster impacket-scripts onesixtyone redis-tools smbclient smbmap snmp sslscan sipvicious tnscmd10g whatweb wkhtmltopdf

# Web server setup
sudo systemctl enable apache2
sudo systemctl start apache2

# Set up file serving
mkdir -p /var/www/html/tools
# Copy all tools to /var/www/html/tools/

# Test connectivity
python3 -m http.server 8000
```

### Note-Taking Template Setup
```markdown
# Machine Name: [IP]

## Enumeration
### Nmap Results
[Paste nmap output]

### Web Enumeration  
[Directory/file discoveries]

### Service Enumeration
[Detailed service information]

## Exploitation
### Initial Access
[How you got initial shell]

### Screenshots
[Path to screenshots]

### Privilege Escalation
[Steps taken to get root/system]

## Credentials Found
[All credentials discovered]

## Lessons Learned
[What worked, what didn't]
```

## Exam Day Strategy

### Hour-by-Hour Plan
```
Hours 0-2: Environment Setup & Initial Scans
- Set up VPN connection
- Start comprehensive scans on all targets
- Begin with AD set enumeration
- Start working on easiest standalone

Hours 2-8: Active Directory Focus
- Deep AD enumeration
- Authentication attacks
- Lateral movement
- Aim for domain controller compromise

Hours 8-14: Standalone Machines
- Focus on machines showing most promise
- Use Metasploit on hardest machine (if needed)
- Document everything thoroughly

Hours 14-20: Final Push
- Complete any partially compromised machines
- Double-check all flags and screenshots
- Verify you have enough points

Hours 20-24: Buffer & Documentation
- Final attempts on remaining machines
- Organize all evidence
- Prepare report materials
```

### Starting Sequence (First 30 Minutes)
```bash
# 1. Connect to VPN and verify connectivity
sudo openvpn exam.ovpn

# 2. Add targets to /etc/hosts
echo "192.168.x.y dc01.exam.local" >> /etc/hosts
echo "192.168.x.z ws01.exam.local" >> /etc/hosts

# 3. Start comprehensive scans on all targets
nmap -Pn -T4 --top-ports 1000 192.168.x.0/24 -oN quick_scan.txt
for ip in 192.168.x.y 192.168.x.z; do
    nmap -Pn -T4 -p- $ip -oN ${ip}_full.txt &
done

# 4. Begin AD enumeration while scans run
```

## Machine Approach Methodology

### Universal Machine Methodology
```
1. Port Scan (15 minutes)
   - Quick scan: nmap -Pn -T4 --top-ports 1000
   - Full scan: nmap -Pn -p- (background)
   - Service scan: nmap -Pn -sC -sV -p <discovered ports>

2. Service Enumeration (30-60 minutes)
   - Web apps: gobuster/dirsearch
   - SMB: smbmap/smbclient/enum4linux
   - Other services: version-specific enumeration

3. Initial Access Attempts (1-2 hours)
   - Web vulnerabilities (LFI, RFI, SQLi, etc.)
   - Service exploits
   - Default credentials
   - Brute force (last resort)

4. Post-Exploitation Enumeration (30 minutes)
   - System information gathering
   - User enumeration
   - Network discovery
   - Credential hunting

5. Privilege Escalation (1-3 hours)
   - Automated tools (WinPEAS/LinPEAS)
   - Manual techniques
   - Kernel exploits (last resort)

6. Documentation (Throughout)
   - Screenshot every step
   - Document all commands
   - Save all outputs
```

### Active Directory Specific Methodology
```
1. Domain Discovery (30 minutes)
   - Identify domain controllers
   - Enumerate domain name
   - Check for anonymous access

2. User Enumeration (45 minutes)
   - Null sessions (RPC, LDAP, SMB)
   - Guest access attempts
   - Username generation/discovery

3. Authentication Attacks (2-3 hours)
   - Password spraying
   - ASREPRoast
   - Kerberoasting
   - Credential stuffing

4. Post-Authentication (2-4 hours)
   - BloodHound collection
   - Lateral movement
   - Privilege escalation paths
   - Domain controller compromise

5. Persistence (30 minutes)
   - Golden/Silver tickets
   - Additional user accounts
   - Credential extraction
```

## Time Management

### The 4-Hour Rule
- **Never spend more than 4 hours on a single machine**  
- Set timers for each machine
- Move on if you're not making progress
- Return later with fresh perspective

### Point Prioritization Strategy
```
Priority 1: AD Set (40 points)
- Highest value
- Often requires all 3 machines for full points
- Focus 8-10 hours here

Priority 2: Easiest Standalone (20 points)  
- Quick wins
- Build confidence
- Usually 2-4 hours

Priority 3: Remaining Standalones
- Fill remaining time
- Use Metasploit if needed
- 2-4 hours each maximum
```

### Signs to Move On
- Same exploit attempted 3+ times without success
- No new enumeration findings for 1+ hour
- Spent maximum time allocation on machine
- Frustration/fatigue setting in

## Common Scenarios and Solutions

### Scenario 1: AD Set Not Cooperating
```
Problem: Can't get initial foothold in AD
Solutions:
1. Focus on standalone machines first
2. Build up to 60 points from standalones
3. Return to AD with fresh perspective
4. Look for simpler attack vectors (default creds, simple web vulns)
```

### Scenario 2: Stuck at Local User
```
Problem: Have shell but can't escalate privileges
Solutions:
1. Run automated tools (WinPEAS/LinPEAS)
2. Check for stored credentials
3. Enumerate all services and processes
4. Look for scheduled tasks/cron jobs
5. Check file permissions and SUID binaries
```

### Scenario 3: Rabbit Holes
```
Problem: Spending too much time on false leads
Prevention:
1. Set time limits for each approach
2. Document what doesn't work
3. Ask yourself: "Am I making progress?"
4. Take breaks to reassess
```

### Scenario 4: Technical Issues
```
Problem: VPN disconnections, tool failures
Solutions:
1. Always check connectivity first
2. Have backup tools ready
3. Keep reconnection commands handy
4. Test tools before exam day
```

## Report Writing

### Report Structure
```
1. Executive Summary
2. High-Level Summary
3. Attack Narrative
4. Technical Details per Machine
5. Additional Information
6. Remediation Recommendations
```

### Essential Report Elements
- **Screenshots of flags**: Exact commands showing flag contents
- **Proof screenshots**: Demonstrating successful compromise  
- **Step-by-step reproduction**: Every command used
- **Code snippets**: Any custom scripts or modifications
- **Network diagrams**: For AD environments

### Screenshot Requirements
```bash
# Linux root proof
whoami && hostname && cat /root/proof.txt

# Linux local proof
whoami && hostname && cat /home/user/local.txt

# Windows SYSTEM proof  
whoami && hostname && type C:\proof.txt

# Windows user proof
whoami && hostname && type C:\Users\user\local.txt

# AD proof (on domain controller)
whoami && hostname && type C:\proof.txt
```

### Report Writing Tips
- Write as you go, don't wait until the end
- Use consistent formatting and structure
- Include enough detail for reproduction
- Proofread for technical accuracy
- Submit early - don't use all 24 hours

## Mental Preparation

### Mindset for Success
1. **Stay Calm**: Exam stress is normal, take breaks
2. **Be Methodical**: Follow your methodology consistently  
3. **Document Everything**: You'll thank yourself later
4. **Accept Failure**: Not every technique will work
5. **Think Simple**: Often the solution is easier than expected

### Dealing with Frustration
- Take 15-minute breaks every 2 hours
- Walk away from stuck machines
- Remember it's a test of persistence, not just knowledge
- Talk through problems out loud (to yourself)
- Review your notes from practice

### Energy Management
- Eat regular meals during the exam
- Stay hydrated
- Get some sleep (4-6 hours recommended)
- Avoid excessive caffeine
- Do light stretching/exercise

## Emergency Procedures

### If You're Failing at Hour 16
```
1. Stop and assess current points
2. Identify quickest path to 70 points
3. Focus only on achievable goals
4. Use Metasploit if not already used
5. Consider partial credit scenarios
6. Don't give up - many pass in final hours
```

### Technical Emergency Contacts
- VPN issues: Reset connection, try different servers
- Proctoring issues: Contact support immediately  
- Machine issues: Document and contact support
- Tool failures: Have backups ready

### Last-Ditch Techniques
- Try default credentials on everything
- Focus on web applications (often have obvious vulns)
- Check for misconfigurations in services
- Look for easy privilege escalation (sudo -l)
- Use searchsploit extensively

## Final Exam Day Checklist

### Day Before
- [ ] Get good sleep (8+ hours)
- [ ] Prepare workspace and tools
- [ ] Review methodologies
- [ ] Test VPN connection
- [ ] Prepare food and drinks

### Morning Of
- [ ] Light breakfast
- [ ] Connect to VPN 30 minutes early
- [ ] Test proctoring software
- [ ] Organize note-taking
- [ ] Set timers and reminders

### During Exam
- [ ] Follow methodology strictly
- [ ] Take screenshots of everything
- [ ] Document all commands
- [ ] Stay hydrated and fed
- [ ] Take breaks regularly

### After Initial 24 Hours
- [ ] Organize all evidence
- [ ] Begin report writing immediately
- [ ] Include all required elements
- [ ] Proofread thoroughly
- [ ] Submit early (don't wait until deadline)

## Success Mantras

Remember these throughout the exam:

1. **"Try Harder"** - The OSCP motto exists for a reason
2. **"Enumerate Harder"** - Most solutions are found in enumeration  
3. **"Simple Over Complex"** - Don't overthink solutions
4. **"Document Everything"** - Your report depends on good notes
5. **"Progress Over Perfection"** - Partial points count

## Final Words

The OSCP exam tests not just your technical knowledge, but your methodology, persistence, and ability to work under pressure. Trust in your preparation, follow your methodology, and remember that many successful candidates needed multiple attempts. Each attempt is a learning experience that brings you closer to success.

**You've got this! Stay calm, stay methodical, and Try Harder!**