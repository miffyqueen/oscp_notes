# OSCP All-in-One Host Discovery & Port Scanning Commands

## 🎯 Quick Setup - Just Change the Target!

```bash
# SET YOUR TARGET HERE - Just change this line!
target=192.168.1.100

# For network ranges, use this instead:
# target=192.168.1.0/24
```

## 🚀 Copy-Paste Ready Commands

### Step 1: Quick Host Discovery
```bash
# Basic ping sweep for network ranges
nmap -sn $target --open -v | tee host_discovery.txt

# Extract live hosts (for network ranges)
grep "Nmap scan report for" host_discovery.txt | awk '{print $5}' > live_hosts.txt

# Advanced host discovery with multiple techniques
nmap -sn -PE -PP -PS21,22,23,25,53,80,139,443,445,993,995 -PA80,443 -PU53,161,500 $target -oN discovery_detailed.txt --open -v
```

### Step 2: Fast Port Discovery (Choose One)

#### Option A: RustScan (Fastest - if available)
```bash
# RustScan with nmap integration
rustscan -a $target --ulimit 5000 -b 4500 --timeout 1500 --range 1-65535 -- -sV -sC -A -oN rustscan_$target.txt

# RustScan basic (if above fails)  
rustscan -a $target -p 1-65535 -- -Pn -oN rustscan_basic_$target.txt
```

#### Option B: Masscan (Ultra-fast alternative)
```bash
# Masscan all ports
sudo masscan -p1-65535 $target --rate=1000 -oG masscan_$target.txt

# Extract ports from masscan for nmap
ports=$(grep "open" masscan_$target.txt | awk '{print $4}' | cut -d'/' -f1 | sort -u | tr '\n' ',' | sed 's/,$//') && echo "Found ports: $ports"
```

#### Option C: Nmap Fast Scan (Most reliable)
```bash
# Fast all-ports TCP scan
sudo nmap -sS -T4 --min-rate 1000 --max-retries 1 -p- $target -oN fast_tcp_$target.txt --open -v

# Extract open ports
ports=$(grep -E "^[0-9]+/tcp.*open" fast_tcp_$target.txt | cut -d'/' -f1 | sort -u | tr '\n' ',' | sed 's/,$//') && echo "Open ports: $ports"
```

### Step 3: Detailed Service Enumeration

#### If you have ports from previous steps:
```bash
# Detailed scan on discovered ports (replace $ports with actual ports or use variable)
nmap -sC -sV -A -T4 -p $ports $target -oN detailed_$target.txt --script="default,vuln" -v

# If no ports variable, scan common ports:
nmap -sC -sV -A -T4 -p 21,22,23,25,53,80,110,135,139,143,443,445,993,995,3389,5985,5986 $target -oN detailed_common_$target.txt --script="default,vuln" -v
```

#### Full comprehensive scan (slower but thorough):
```bash
# All-in-one detailed scan
nmap -Pn -sC -sV -A -T4 -p- --open --reason --script="default,vuln" $target -oA comprehensive_$target -v
```

### Step 4: UDP Scanning
```bash
# Top 100 UDP ports
sudo nmap -sU --top-ports 100 -T4 $target -oN udp_top100_$target.txt --open -v

# Common UDP services
sudo nmap -sU -sV -p 53,67,68,69,123,135,137,138,139,161,162,445,500,514,520,631,1434,1900,4500,49152 $target -oN udp_common_$target.txt --open -v
```

### Step 5: Vulnerability Scanning
```bash
# NSE vulnerability scripts on discovered ports
nmap --script vuln -sV -p $ports $target -oN vuln_$target.txt -v

# If no ports variable, scan common vulnerable services:
nmap --script vuln -sV -p 21,22,23,25,53,80,110,135,139,143,443,445,993,995,3389,5985 $target -oN vuln_common_$target.txt -v

# SMB-specific vulnerability scan
nmap --script "smb-vuln-*" -p139,445 $target -oN smb_vuln_$target.txt -v

# Web vulnerability scan
nmap --script "http-vuln-*" -p80,443,8080,8443 $target -oN web_vuln_$target.txt -v
```

## 🔥 Ultimate One-Liners

### Single Target - Complete Scan
```bash
# Set target and run everything
target=192.168.1.100 && echo "Scanning $target..." && rustscan -a $target --ulimit 5000 -- -sV -sC -A --script="default,vuln" -oN ultimate_$target.txt || nmap -Pn -sC -sV -A -T4 -p- --open --script="default,vuln" $target -oA fallback_$target -v
```

### Network Range - Complete Enumeration
```bash
# Network discovery and enumeration
target=192.168.1.0/24 && nmap -sn $target --open | grep "Nmap scan report" | awk '{print $5}' > live_hosts.txt && while read host; do echo "Scanning $host..."; nmap -sC -sV -T4 --top-ports 1000 "$host" -oN "scan_$host.txt" --open -v; done < live_hosts.txt
```

### Masscan + Nmap Combo
```bash
# Ultra-fast discovery then detailed enumeration
target=192.168.1.100 && sudo masscan -p1-65535 $target --rate=1000 | grep "open" | awk '{print $4}' | cut -d'/' -f1 | sort -u | tr '\n' ',' | sed 's/,$//' > ports_$target.txt && ports=$(cat ports_$target.txt) && nmap -sC -sV -A -p $ports $target -oN masscan_nmap_$target.txt --script="default,vuln" -v
```

## 📊 Results Analysis

### Extract Key Information
```bash
# Show all open ports from scans
grep -E "^[0-9]+/(tcp|udp).*open" *$target*.txt | sort -u

# Find potential vulnerabilities
grep -i "vulnerable\|vuln" *$target*.txt

# Extract service versions
grep -E "^[0-9]+/(tcp|udp).*open.*" *$target*.txt | grep -v "filtered"

# Show SMB information
grep -i "smb\|netbios\|microsoft-ds" *$target*.txt
```

## ⚠️ Important Notes

1. **Always replace** `target=192.168.1.100` with your actual target
2. **For network ranges** use format like `192.168.1.0/24`
3. **Run with sudo** for masscan and some nmap options
4. **Check RustScan installation** with `rustscan --version`
5. **Verify output files** are created successfully
6. **Use absolute paths** if running from different directories

## 🛠️ Troubleshooting

### If RustScan fails:
```bash
# Install RustScan
cargo install rustscan

# Alternative installation
wget https://github.com/RustScan/RustScan/releases/download/2.0.1/rustscan_2.0.1_amd64.deb
sudo dpkg -i rustscan_2.0.1_amd64.deb
```

### If Masscan requires privileges:
```bash
# Run with sudo
sudo masscan --help

# Or adjust ulimits
ulimit -n 65535
```

### Test connectivity:
```bash
# Basic connectivity test
ping -c 3 $target

# TCP connectivity test
nc -nv $target 80
```

## 🎯 OSCP Exam Ready Template

```bash
#!/bin/bash

# OSCP Exam Scan Template
# Usage: ./scan.sh <target_ip>

if [ $# -eq 0 ]; then
    echo "Usage: $0 <target_ip>"
    echo "Example: $0 192.168.1.100"
    exit 1
fi

target=$1
echo "Starting comprehensive scan of $target"

# Create results directory
mkdir -p "results_$target"
cd "results_$target"

# Step 1: Fast port discovery
echo "[+] Fast port discovery..."
rustscan -a $target --ulimit 5000 -- -sV -sC -oN rustscan.txt || nmap -sS -T4 --min-rate 1000 -p- $target -oN fast_scan.txt --open -v

# Step 2: Detailed enumeration
echo "[+] Detailed enumeration..."
nmap -sC -sV -A -T4 --top-ports 1000 $target -oN detailed.txt --script="default,vuln" -v

# Step 3: UDP scan
echo "[+] UDP scanning..."
sudo nmap -sU --top-ports 100 $target -oN udp.txt --open -v

# Step 4: Generate summary
echo "[+] Generating summary..."
echo "=== SCAN RESULTS FOR $target ===" > summary.txt
echo "Date: $(date)" >> summary.txt
echo "" >> summary.txt
echo "=== OPEN PORTS ===" >> summary.txt
grep -E "^[0-9]+/(tcp|udp).*open" *.txt >> summary.txt

echo "Scan complete! Check results_$target/ directory"
```

## 📚 Reference Commands Used in Research

Based on community recommendations from Reddit, GitHub, and CSDN:

- **RustScan**: Fastest scanner for initial discovery
- **Masscan**: Best for large network ranges  
- **Nmap**: Most reliable for detailed enumeration
- **Combined approach**: Speed + accuracy
- **Always include UDP**: Often overlooked but important
- **Script scanning**: Use `--script=vuln` for vulnerabilities
- **Proper output**: Always save results with `-oN` or `-oA`

---
*Commands tested and verified for OSCP exam compatibility*
