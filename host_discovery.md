# Phase 1 — **Host Discovery & Information Gathering (OSCP Exam Gamebook)**

*Beginner-friendly, step-by-step, copy/paste ready. All commands are independent and create their own folders. Built for Kali, HTB/OffSec VPNs, and PEN-200 methodology with the common candidate mistakes explicitly addressed throughout.*

---

## 0) Exam warm-up (once) — logging, structure, and sudo cache

> Why: Clean evidence, repeatability, and no “sudo password” pauses later. Skipping this is a top source of chaos later.

```bash
# 0.1 Create a tidy workspace and start a full command log
mkdir -p ~/oscp-exam/{scans,notes,loot,screens,tmp} && script -af ~/oscp-exam/command_history.log

# 0.2 Cache sudo so future commands don’t stall asking for a password
sudo -v

# 0.3 Verify VPN interface + reach a known address (HTB/OffSec labs often use tun0)
ip a | grep -E "tun0|tap0" || echo "[!] No tun interface detected"
```

**Common mistakes this prevents (and how):** scattered notes, missing logs/screenshots, “sudo prompt ate my reverse shell,” and “where did I save that scan?”—all of which burn time later.

---

## 1) Scoping & sanity (target(s) vs subnet)

Decide if you’re working a **single host** (e.g., `10.10.10.56`) or a **whole subnet** (e.g., `10.10.10.0/24`). Use **both** ICMP **and** TCP/UDP pings; many exam networks block ICMP.

> **Do not** stop after a single discovery method—candidates miss hosts by relying on one probe type.

### 1.1 Whole subnet discovery (pick all three; they’re fast)

```bash
# Subnet folder
sudo mkdir -p scans/10.10.10.0_24/hostdisco

# ICMP ping sweep
sudo nmap -vv -n -sn 10.10.10.0/24 -oA scans/10.10.10.0_24/hostdisco/icmp_ping

# TCP SYN ping to common ports (finds “ICMP-silent” hosts)
sudo nmap -vv -n -sn -PS21,22,80,135,139,445,3389 10.10.10.0/24 -oA scans/10.10.10.0_24/hostdisco/tcp_syn_ping

# UDP ping to common infra ports (DNS/DHCP/NTP/NetBIOS/SNMP)
sudo nmap -vv -n -sn -PU53,67,68,123,137,161 10.10.10.0/24 -oA scans/10.10.10.0_24/hostdisco/udp_ping
```

### 1.2 Single host “is it up?” (only if you already know the IP)

```bash
# ICMP + TCP SYN + UDP discovery to a single IP
sudo mkdir -p scans/10.10.10.56/hostdisco
sudo nmap -vv -n -sn 10.10.10.56 -oA scans/10.10.10.56/hostdisco/icmp_ping
sudo nmap -vv -n -sn -PS21,22,80,135,139,445,3389 10.10.10.56 -oA scans/10.10.10.56/hostdisco/tcp_syn_ping
sudo nmap -vv -n -sn -PU53,67,68,123,137,161 10.10.10.56 -oA scans/10.10.10.56/hostdisco/udp_ping
```

**Mistake callouts:**

* *Only ICMP sweep*: you’ll miss hosts with ICMP blocked.
* *No `-oA` output*: you can’t quickly grep/parse later.

---

## 2) TCP/UDP port discovery (don’t skip UDP)

> **Why:** Skipping UDP is one of the most expensive exam mistakes—SNMP/DNS/NetBIOS often give creds or maps.
> **Root helps:** Use `sudo` for raw SYN/UDP; non-root falls back to slower/less reliable modes.

### 2.1 Full TCP sweep (SYN) — **Stable profile** (recommended)

```bash
sudo mkdir -p scans/10.10.10.56/nmap
sudo nmap -vv -n -Pn -sS -p- --max-retries 3 --host-timeout 5m 10.10.10.56 \
  -oA scans/10.10.10.56/nmap/tcp_allports_syn
```

> If VPN is very healthy and you want speed, add `--min-rate 1000`. If you saw “retransmission cap hit” earlier, keep `--max-retries 3` and avoid pushing the rate.

### 2.2 Top UDP (fast signal first)

```bash
sudo nmap -vv -n -sU --top-ports 50 --max-retries 3 10.10.10.56 \
  -oA scans/10.10.10.56/nmap/udp_top50
```

> You can later escalate to `-sU -p <interesting ports>` if SNMP/DNS pop up.

### 2.3 Quick CSV views for triage (no external deps)

```bash
# TCP open ports (CSV)
grep "/open/tcp" scans/10.10.10.56/nmap/tcp_allports_syn.gnmap \
| awk -F'Ports: ' '{print $2}' | tr ',' '\n' | awk -F'/' '{print $1","$3}' \
| sed 's/ //g' > scans/10.10.10.56/nmap/tcp_open.csv && column -s, -t scans/10.10.10.56/nmap/tcp_open.csv

# UDP open ports (CSV)
grep "/open/udp" scans/10.10.10.56/nmap/udp_top50.gnmap \
| awk -F'Ports: ' '{print $2}' | tr ',' '\n' | awk -F'/' '{print $1","$3}' \
| sed 's/ //g' > scans/10.10.10.56/nmap/udp_open.csv && column -s, -t scans/10.10.10.56/nmap/udp_open.csv
```

**Mistake callouts:**

* *Scanning only defaults*: we always use `-p-` for TCP.
* *Tunnel vision*: Don’t spend 30 minutes reading raw scans—CSV + service playbooks next.

---

## 3) Scripted service/versions (auto-context without the noise)

> Purpose: Discover service names/versions safely, and let NSE sniff obvious leaks.

```bash
sudo nmap -vv -n -sC -sV -p- --max-retries 3 10.10.10.56 \
  -oA scans/10.10.10.56/nmap/tcp_scripts_versions
```

**Tip:** Re-run this targeted later (e.g., `-p 22,80,445,3389`) if you refine the port list.

---

## 4) Mini-playbooks by service (run **only** what applies)

> **Rule:** As soon as you get a credential/config/file path/hostname, **loot and branch** (don’t “finish the list” first). This maximizes points and avoids rabbit holes.

### 4.1 DNS / NS (the **infra** bridge into web/AD)

* **When:** UDP/53 or TCP/53, or you see a domain on banners/SMB/LDAP.

```bash
# Create space
mkdir -p scans/10.10.10.56/dns

# 4.1.1 Identify nameservers for a discovered domain (replace example.htb)
dig NS example.htb +noall +answer | tee scans/10.10.10.56/dns/ns.txt

# 4.1.2 Attempt zone transfer (AXFR) against each NS
for s in $(awk '{print $5}' scans/10.10.10.56/dns/ns.txt); do dig AXFR example.htb @$s | tee -a scans/10.10.10.56/dns/axfr_$s.txt; done

# 4.1.3 Subdomain brute (Kali-native)
dnsrecon -d example.htb -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t brt -n 1.1.1.1 -o scans/10.10.10.56/dns/dnsrecon_brt.xml

# 4.1.4 Reverse PTR sweep (if you guessed/know the /24)
for i in $(seq 1 254); do host 10.10.10.$i | grep -i "pointer" | tee -a scans/10.10.10.56/dns/ptr_sweep.txt; done
```

> **Don’t forget:** Add new hostnames to `/etc/hosts` and re-enum HTTP later. Many exam takers miss vhosts → miss the foothold.

---

### 4.2 SMB / Windows RPC (139/445/135)

```bash
mkdir -p scans/10.10.10.56/smb

# Null session share list
smbclient -L //10.10.10.56 -N | tee scans/10.10.10.56/smb/shares.txt

# Broad enum
enum4linux -a 10.10.10.56 | tee scans/10.10.10.56/smb/enum4linux_a.txt

# Share permissions map (guest/null)
smbmap -H 10.10.10.56 -u "" -p "" | tee scans/10.10.10.56/smb/smbmap_guest.txt

# RPC checks
rpcclient -U "" -N 10.10.10.56 -c "enumdomusers; enumdomgroups; querydominfo" | tee scans/10.10.10.56/smb/rpcclient.txt
```

> **Stop if:** You see readable shares or config files → **loot** immediately.
> **Caution:** Don’t start brute-forcing yet; lockouts end runs.

---

### 4.3 SNMP (UDP/161) — “public/private” wins

```bash
mkdir -p scans/10.10.10.56/snmp

# Default communities check (small, fast list)
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-default-community-strings.txt 10.10.10.56 \
  | tee scans/10.10.10.56/snmp/onesixtyone.txt

# Full walk if valid
snmpwalk -v2c -c public 10.10.10.56 1.3.6.1.2.1 | tee scans/10.10.10.56/snmp/walk_public.txt
```

> **Hunt:** Usernames, routes, processes, software versions; often enough to pivot or craft vulns.

---

### 4.4 SMTP (25) — user discovery & relay tests (safe)

```bash
mkdir -p scans/10.10.10.56/smtp
nmap -n -p25 --script smtp-enum-users 10.10.10.56 -oA scans/10.10.10.56/smtp/nse_enum
smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/top-usernames-shortlist.txt -t 10.10.10.56 \
  | tee scans/10.10.10.56/smtp/vrfy.txt
```

> **Use later:** Harvested users → **targeted** password tests (not now).

---

### 4.5 LDAP / AD tells (389/636)

```bash
mkdir -p scans/10.10.10.56/ldap
ldapsearch -x -H ldap://10.10.10.56 -b "DC=example,DC=htb" > scans/10.10.10.56/ldap/anonymous.txt
nmap -n -p389 --script ldap-search 10.10.10.56 -oA scans/10.10.10.56/ldap/nse
```

> **Note:** Domain/forest levels, DC names, SPNs. If AD is in play, plan an AD-intro enum next (outside Phase-1’s scope) and **pivot back**.

---

### 4.6 SSH (22)

```bash
mkdir -p scans/10.10.10.56/ssh
nmap -n -sV -p22 --script ssh2-enum-algos,ssh-hostkey 10.10.10.56 -oA scans/10.10.10.56/ssh/nse
ssh -o PreferredAuthentications=none -o PubkeyAuthentication=no 10.10.10.56
```

> **Check:** Weak algorithms, root login, banner versions (for version-specific CVEs).

---

### 4.7 FTP (21)

```bash
mkdir -p scans/10.10.10.56/ftp
nmap -n -sV -p21 --script ftp-anon,ftp-syst,ftp-bounce 10.10.10.56 -oA scans/10.10.10.56/ftp/nse
ftp -inv 10.10.10.56 <<EOF
user anonymous anonymous
ls -la
bye
EOF
```

> **If writable & webroot-backed:** stage a webshell in **Phase 2 (Web)**.

---

### 4.8 RDP / WinRM (3389 / 5985/5986)

```bash
mkdir -p scans/10.10.10.56/rdp_winrm
nmap -n -p3389 --script rdp-enum-encryption 10.10.10.56 -oA scans/10.10.10.56/rdp_winrm/rdp
nmap -n -sV -p5985,5986 --script ssl-enum-ciphers 10.10.10.56 -oA scans/10.10.10.56/rdp_winrm/winrm
```

> **Look:** NLA disabled, weak TLS. With creds later → `evil-winrm`.

---

### 4.9 HTTP/HTTPS (80/443/8080/…) — the **bridge** to Phase 2 (Web)

```bash
mkdir -p scans/10.10.10.56/http

# Fingerprint + light tech stack
whatweb -a 3 http://10.10.10.56 | tee scans/10.10.10.56/http/whatweb.txt

# Headers (HTTP/HTTPS)
curl -sI http://10.10.10.56 | tee scans/10.10.10.56/http/headers_http.txt
curl -skI https://10.10.10.56 | tee scans/10.10.10.56/http/headers_https.txt

# Nikto quick safety check
nikto -h http://10.10.10.56 -o scans/10.10.10.56/http/nikto_http.txt

# TLS ciphers/key info (if 443)
sslscan --no-failed 10.10.10.56:443 | tee scans/10.10.10.56/http/sslscan.txt
```

**Always check these relative paths immediately (low-hanging fruit):**
`/robots.txt`, `/sitemap.xml`, `/backup`, `/backups`, `/old`, `/dev`, `/test`, `/tmp`, `/upload`, `/uploads`, `/files`, `/private`, `/config`, `/phpinfo.php`, `/admin`, `/adminer.php`, `/login`, `/console`, `/server-status`

> **Vhosts note:** If DNS found `admin.example.htb`, add to `/etc/hosts` and rerun the above **per vhost** before dirbusting. Missing vhosts = missing footholds.

---

## 5) When to pivot (time management)

* **20–30 minutes without new facts?** Pivot target or service.
* Found **AD indicators?** Park web and do an AD intro enum next (users/SPNs/safe reads), then come back.
* Found **HTTP foothold?** Jump to your **Phase 2 (Web)** playbook immediately.

> **Why:** Tunnel vision is a documented fail pattern; points come from breadth plus decisive chaining, not from finishing a checklist in order.

---

## 6) Evidence discipline (screens & notes)

* Screenshot proof for: service banners, directory indexes, config leaks, creds, sensitive files, and later user.txt/proof.txt.
* Keep **loot** (configs, creds, tickets, dumps) in `~/oscp-exam/loot` with per-host subfolders.
* Log **failures/rabbit holes** too, so you don’t repeat them under pressure.

---

## 7) “Do-nots” & built-in safeguards (common mistakes addressed)

* **Do not skip UDP.** We included UDP sweep + SNMP/DNS playbooks by default.
* **Do not brute-force early.** We harvest users safely first; spraying waits until you have high-signal targets (and you understand lockout policy).
* **Do not rely on one tool.** DNS uses `dig` + `dnsrecon` + `host`; SMB uses `smbclient` + `enum4linux` + `smbmap` + `rpcclient`.
* **Do not scan only default ports.** All TCP scans are `-p-`.
* **Do not ignore vhosts.** DNS results → `/etc/hosts` → re-enum HTTP per host.
* **Do not kill stability with timings.** We use `--max-retries 3` and a stable profile to avoid “retransmission cap hit.”
* **Do not scatter notes.** We use a single `~/oscp-exam` tree and `script -af` logging.
* **Do not proceed without saving output.** Every scan uses `-oA`.

---

## 8) Quick checklists

**Host Discovery (subnet):** ICMP sweep → TCP SYN ping → UDP ping → triage gnmap.
**Single Host TCP/UDP:** `-sS -p-` (stable) → `-sU --top-ports 50` → `-sC -sV`.
**Service branch (based on ports):**

* 53 → DNS mini-playbook (AXFR/brute/PTR) & vhosts.
* 139/445/135 → SMB/RPC enum, loot shares.
* 161/udp → SNMP walk for creds/routes/processes.
* 25 → SMTP user enum (later spraying).
* 389 → LDAP safe reads (note DC/forest/SPNs).
* 22/21 → SSH/FTP banners, anon access, weak algos.
* 3389/5985 → RDP/WinRM capabilities.
* 80/443 → WhatWeb/headers/Nikto/SSL → handoff to Web (Phase 2).

---

### Why this mirrors PEN-200 & fixes real exam pain points

* It follows **Active Information Gathering** → **service-specific enumeration** as taught in PEN-200, with explicit coverage for DNS/SMB/SMTP/SNMP/LDAP/HTTP(S).
* It bakes in candidate pitfalls: skipping UDP, scanning only defaults, single-tool reliance, scattered notes, poor timing profiles, early brute-forcing, forgetting vhosts, and lack of a written methodology.

---

**Next:** If HTTP\[S] or vhosts are present, open your **Phase 2 (Web Application)** notes and proceed with directory/file discovery, parameter testing, upload/LFI/SQLi, etc. If AD is visible, launch your **AD intro** enum (safe, read-only) before deeper attacks.
