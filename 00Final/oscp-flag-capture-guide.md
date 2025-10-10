# OSCP Flag Capture & Hunting Command Reference Guide

## Overview
This guide consolidates all essential commands and procedures for capturing and hunting flags in the OSCP exam, including Windows `dir` demonstrations and Linux equivalents. It addresses common candidate difficulties gathered from Reddit, CSDN, GitHub, and other sources.

## Critical Exam Requirements

### Mandatory Screenshot Elements
- **Contents of the flag file** (local.txt or proof.txt)
- **IP address of the target** using `ipconfig`, `ifconfig`, or `ip addr`
- **Interactive shell session** (NOT web shell)
- **Full path to the flag file** (absolute path required)
- **Username/privileges** displayed with `whoami`

⚠️ **Missing any of these will yield zero points**

## Flag Locations

### Windows Systems
- **proof.txt**: `C:\Users\Administrator\Desktop\proof.txt`
- **local.txt**: `C:\Users\[username]\Desktop\local.txt`

### Linux Systems
- **proof.txt**: `/root/proof.txt`
- **local.txt**: `/home/[username]/local.txt`

## Directory Listing Commands (Windows `dir` vs Linux `ls`)

### Common Candidate Issues
- Forgetting hidden/system files (flags sometimes hidden)
- Not using absolute paths
- Ignoring recursive search

### Windows `dir` Examples

#### 1. Basic Listing
```cmd
C:\> dir
 Volume in drive C has no label.
 Directory of C:\

10/10/2025 10:15 AM <DIR> Program Files
10/10/2025 10:15 AM <DIR> Users
10/10/2025 10:15 AM <DIR> Windows
               0 File(s) 0 bytes
               3 Dir(s) 120,000,000,000 bytes free
```

#### 2. Bare Format (Names Only)
```cmd
C:\> dir /b
Program Files
Users
Windows
```

#### 3. Including Hidden & System Files
```cmd
C:\> dir /a
.
.. 
$Recycle.Bin <DIR>
Program Files
Users
Windows
```

#### 4. Recursive Search for Flag Files
```cmd
C:\> dir /s /b *.txt
C:\Users\Tester\Desktop\proof.txt
C:\Users\Tester\Documents\notes.txt
```

#### 5. Tree View
```cmd
C:\> tree /f
Folder PATH listing for volume OS
C:\
+---Program Files
+---Users
|   \---Tester
|       +---Desktop
|       |       proof.txt
|       \---Documents
|               notes.txt
\---Windows
```

### Linux `ls` & Search Equivalents

```bash
# Basic listing
ls -la

# Names only
ls

# Recursive search for all .txt files
find / -type f -name "*.txt" 2>/dev/null

# Locate proof.txt or local.txt
find / -name proof.txt 2>/dev/null
find / -name local.txt 2>/dev/null
```

## Complete Flag Capture Commands

### Windows Flag Capture
```cmd
# Administrator proof.txt
dhostname && whoami && type "C:\Users\Administrator\Desktop\proof.txt" && ipconfig

# Local user local.txt
dhostname && whoami && type "C:\Users\%USERNAME%\Desktop\local.txt" && ipconfig
```

### Linux Flag Capture
```bash
# Root proof.txt
hostname && whoami && cat /root/proof.txt && ifconfig

# Local user local.txt
hostname && whoami && cat /home/$USER/local.txt && ip addr
```

## Flag Discovery Commands

### Windows Search
```cmd
# Find flag files across system
dir C:\ /s /b | findstr /i proof.txt
forfiles /s /m *.txt /c "cmd /c echo @path" | findstr /i "proof\|local"
```

### Linux Search
```bash
# Find all flag or proof files
find / -type f \( -iname "proof.txt" -o -iname "local.txt" \) 2>/dev/null
grep -r "OS{" / 2>/dev/null
```

## Troubleshooting & Best Practices

- Always use **absolute paths** (e.g., `C:\Users\...`) to avoid missing flags.
- Include **hidden** files with `/a` on Windows or `-a` on Linux.
- Combine **search** before capture: use `dir /s` or `find` to locate files first.
- Show **IP address**, **hostname**, and **whoami** in the same screenshot.
- Avoid web shells; ensure a **fully interactive** session.

## One-Liner Copy/Paste Commands

**Windows Administrator Proof**:
```cmd
hostname && whoami && type "C:\Users\Administrator\Desktop\proof.txt" && ipconfig
```

**Linux Root Proof**:
```bash
hostname && whoami && cat /root/proof.txt && ifconfig
```

---
*Compiled and refined based on real OSCP candidate experiences and common pitfalls from Reddit r/oscp, CSDN tutorials, GitHub repos, and OffSec documentation.*