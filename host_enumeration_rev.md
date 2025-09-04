# OSCP Host Discovery & Port Scanning — Exam-Safe Gamebook (GitHub MD)

**Beginner-friendly • calm under pressure • copy-paste ready • real IP examples (e.g., `10.10.10.15`)**
Organized so the **first command you run is literally first**. Every block is self-contained.

---

## 0) START HERE — Paste This First (once per session)

```bash
# Safe workspace + tools + VPN sanity
OUTDIR="${OUTDIR:-OSCP-10.10.10.0-24/scans}"   # change the /24 if your scope differs
mkdir -p "$OUTDIR"
command -v nmap >/dev/null 2>&1 || { sudo apt update && sudo apt install -y nmap; }
ip -4 addr show tun0 >/dev/null 2>&1 || echo "[!] No tun0 interface — connect your VPN."
echo "[i] Outputs -> $OUTDIR"
```

Why: creates a predictable output path, ensures Nmap exists, and warns if VPN isn’t up.

---

## 1) Discovery — Find Live Hosts (choose ONE path)

### A) Single host (example `10.10.10.15`)

```bash
TARGET="10.10.10.15"
sudo nmap -sn -n -T4 \
  -PE -PP \
  -PS22,80,139,443,445,3389 \
  -PA80,443 \
  -PU53 \
  -oA "$OUTDIR/01-discover-$TARGET" "$TARGET"
```

You want to see: `Host is up (… latency)` — mixed ICMP/TCP/UDP probes catch Windows hosts that drop plain ping.

### B) Whole /24 (example `10.10.10.0/24`)

```bash
SUBNET="10.10.10.0/24"
sudo nmap -sn -n -T4 -PE -PP -PS22,80,139,443,445,3389 -PA80,443 -PU53 \
  -oA "$OUTDIR/01-discover-$(echo "$SUBNET" | tr '/' '-')" "$SUBNET"
```

### C) Custom list (safer than typing)

```bash
cat > "$OUTDIR/targets.txt" << 'EOF'
10.10.10.15
10.10.10.20
10.10.10.25
EOF
sudo nmap -sn -n -T4 -PE -PP -PS22,80,139,443,445,3389 -PA80,443 -PU53 \
  -iL "$OUTDIR/targets.txt" -oA "$OUTDIR/01-discover-list"
```

---

## 2) Build `hosts_up.txt` (your canonical live-host list)

```bash
# Auto-pick the most recent discovery .gnmap produced by step 1
DISC_GNMAP=$(ls -t "$OUTDIR"/01-discover*.gnmap 2>/dev/null | head -1)
if [ -z "${DISC_GNMAP:-}" ]; then
  echo "[!] No discovery results found in $OUTDIR"; echo "    Run step 1 first."; 
else
  awk '/Status: Up/{print $2}' "$DISC_GNMAP" | sort -V > "$OUTDIR/hosts_up.txt"
  echo "[i] Live hosts:"; cat "$OUTDIR/hosts_up.txt"
fi
```

---

## 3) If “0 hosts up” — Panic-Proof Ladder (run in this order)

```bash
# 3.1 ARP scan (only if same L2 segment)
SUBNET="${SUBNET:-10.10.10.0/24}"
sudo nmap -sn -n -PR -oA "$OUTDIR/01b-arp-$(echo "$SUBNET" | tr '/' '-')" "$SUBNET"
awk '/Status: Up/{print $2}' "$OUTDIR/01b-arp-$(echo "$SUBNET" | tr '/' '-').gnmap" | sort -V > "$OUTDIR/hosts_up.txt" || true
cat "$OUTDIR/hosts_up.txt" 2>/dev/null

# 3.2 Treat as up (-Pn) and probe a few ports for proof-of-life
TARGET="${TARGET:-10.10.10.15}"
sudo nmap -Pn -n -T3 -p22,80,443,445,3389 --reason -oA "$OUTDIR/02-pn-probe-$TARGET" "$TARGET"

# 3.3 UDP ping fallback (DNS/SNMP)
sudo nmap -sn -n -PU53,161 -oA "$OUTDIR/01c-udp-ping-$(echo "$SUBNET" | tr '/' '-')" "$SUBNET"
awk '/Status: Up/{print $2}' "$OUTDIR/01c-udp-ping-$(echo "$SUBNET" | tr '/' '-').gnmap" | sort -V > "$OUTDIR/hosts_up.txt" || true

# 3.4 Plumbing checks (routing/VPN)
ip -4 addr show tun0 | awk '/inet /{print "[i] tun0:",$2}' || echo "[!] No tun0 IPv4?"
ip route | grep "^10\.10\.10\." >/dev/null || echo "[!] No route to 10.10.10.0/24"
```

---

## 4) Full TCP Scan — **ALL ports 1–65535** (the “don’t miss 6xxxx” step)

```bash
# Scans every host in hosts_up.txt; caps parallelism at 3 to be VPN-friendly
JOBS=0; MAXJ=3
while read -r H; do
  [ -z "$H" ] && continue
  echo "[*] Full TCP sweep -> $H"
  sudo nmap -Pn -n -T3 -p- --min-rate 1000 --max-retries 2 --host-timeout 30m \
    -oA "$OUTDIR/10-fulltcp-$H" "$H" &
  JOBS=$((JOBS+1)); [ "$JOBS" -ge "$MAXJ" ] && { wait; JOBS=0; }
done < "$OUTDIR/hosts_up.txt"
wait
```

Why: `-p-` guarantees **1–65535**; `T3` + retry/timeouts behave better over VPN.

---

## 5) Focused Service Detection — only on discovered open ports

```bash
# Per host: parse open TCP, then run sV + default scripts
while read -r H; do
  [ -f "$OUTDIR/10-fulltcp-$H.nmap" ] || { echo "[!] No full scan for $H"; continue; }
  OPEN=$(awk -F/ '/^[0-9]+\/tcp/ && /open/ {print $1}' "$OUTDIR/10-fulltcp-$H.nmap" | paste -sd, -)
  if [ -n "$OPEN" ]; then
    echo "[*] Service detection -> $H : $OPEN"
    sudo nmap -Pn -n -T3 -sV -sC -p"$OPEN" -oA "$OUTDIR/20-svcs-$H" "$H"
  else
    echo "[i] No open TCP ports parsed for $H"
  fi
done < "$OUTDIR/hosts_up.txt"
```

Tip: Only escalate to `-A` if you still need OS/traceroute detail.

---

## 6) Targeted UDP (when services feel “missing”)

```bash
# Quick UDP triage (top ports) + version probes
TARGET="${TARGET:-10.10.10.15}"
sudo nmap -Pn -n -sU --top-ports 25 -sV --defeat-icmp-ratelimit \
  -oA "$OUTDIR/21-udp-$TARGET" "$TARGET"

# SNMP-focused check (very common in labs)
sudo nmap -Pn -n -sU -p161 --script snmp-info,snmp-interfaces \
  -oA "$OUTDIR/22-snmp-$TARGET" "$TARGET"
```

Reading UDP: look for `open|filtered` — often worth manual follow-ups (e.g., `snmpwalk` if 161 looks alive).

---

## 7) All-in-One Runners (standalone, pick the one you need)

### 7.1 Single target (`10.10.10.15`)

```bash
TARGET="10.10.10.15"
OUTDIR="OSCP-$(echo "$TARGET" | tr '.' '-')/scans"; mkdir -p "$OUTDIR"

# Discovery
sudo nmap -sn -n -T4 -PE -PP -PS22,80,139,443,445,3389 -PA80,443 -PU53 \
  -oA "$OUTDIR/00-discovery-$TARGET" "$TARGET" || true

# Fast triage (top 1000) — parallel with full
sudo nmap -Pn -n -T4 --top-ports 1000 -sV --version-intensity 0 \
  -oA "$OUTDIR/01-fast-$TARGET" "$TARGET" &

# Full sweep (all ports) -> then focused sV/sC
sudo nmap -Pn -n -T3 -p- --min-rate 1000 --max-retries 2 --host-timeout 30m \
  -oA "$OUTDIR/02-full-$TARGET" "$TARGET" && \
OPEN=$(awk '/^[0-9]+\/tcp/ && /open/ {gsub(/\/.*/,"",$1); print $1}' "$OUTDIR/02-full-$TARGET.nmap" | paste -sd, -) && \
[ -n "$OPEN" ] && sudo nmap -Pn -n -T3 -sV -sC -p"$OPEN" \
  -oA "$OUTDIR/03-services-$TARGET" "$TARGET" || echo "[i] No open ports on $TARGET"
wait
```

### 7.2 Subnet `/24` (`10.10.10.0/24`)

```bash
SUBNET="10.10.10.0/24"
OUTDIR="OSCP-$(echo "$SUBNET" | tr '/' '-')/scans"; mkdir -p "$OUTDIR"

sudo nmap -sn -n -T4 -PE -PP -PS22,80,139,443,445,3389 -PA80,443 -PU53 \
  -oA "$OUTDIR/00-discovery" "$SUBNET"
awk '/Status: Up/{print $2}' "$OUTDIR/00-discovery.gnmap" | sort -V > "$OUTDIR/hosts_up.txt"

JOBS=0; MAXJ=3
while read -r H; do
  [ -z "$H" ] && continue
  sudo nmap -Pn -n -T4 --top-ports 1000 -sV --version-intensity 0 -oA "$OUTDIR/01-fast-$H" "$H" &
  sudo nmap -Pn -n -T3 -p- --min-rate 800 --max-retries 2 --host-timeout 30m -oA "$OUTDIR/02-full-$H" "$H" &
  JOBS=$((JOBS+1)); [ "$JOBS" -ge "$MAXJ" ] && { wait; JOBS=0; }
done < "$OUTDIR/hosts_up.txt"
wait

while read -r H; do
  OPEN=$(awk '/^[0-9]+\/tcp/ && /open/ {gsub(/\/.*/,"",$1); print $1}' "$OUTDIR/02-full-$H.nmap" | paste -sd, -)
  [ -n "$OPEN" ] && sudo nmap -Pn -n -T3 -sV -sC -p"$OPEN" -oA "$OUTDIR/03-services-$H" "$H" &
done < "$OUTDIR/hosts_up.txt"
wait
```

### 7.3 Custom list (`targets.txt`)

```bash
cat > targets.txt << 'EOF'
10.10.10.15
10.10.10.20
10.10.10.25
EOF
OUTDIR="OSCP-custom/scans"; mkdir -p "$OUTDIR"

while read -r T; do
  [ -z "$T" ] && continue
  sudo nmap -sn -n -T4 -PE -PP -PS22,80,139,443,445,3389 -PA80,443 -PU53 \
    -oA "$OUTDIR/00-discovery-$T" "$T"
  if grep -q "Status: Up" "$OUTDIR/00-discovery-$T.gnmap"; then
    sudo nmap -Pn -n -T4 --top-ports 1000 -sV --version-intensity 0 -oA "$OUTDIR/01-fast-$T" "$T" &
    sudo nmap -Pn -n -T3 -p- --min-rate 1000 --max-retries 2 --host-timeout 30m -oA "$OUTDIR/02-full-$T" "$T" &
  fi
done < targets.txt
wait

while read -r T; do
  [ -f "$OUTDIR/02-full-$T.nmap" ] || continue
  OPEN=$(awk '/^[0-9]+\/tcp/ && /open/ {gsub(/\/.*/,"",$1); print $1}' "$OUTDIR/02-full-$T.nmap" | paste -sd, -)
  [ -n "$OPEN" ] && sudo nmap -Pn -n -T3 -sV -sC -p"$OPEN" -oA "$OUTDIR/03-services-$T" "$T" &
done < targets.txt
wait
```

---

## 8) Quick Monitoring & Roll-ups

```bash
# See running Nmap tasks
ps aux | grep '[n]map'

# Show latest outputs
ls -lt "$OUTDIR" | head

# Roll-up: all open TCP ports found
grep -H "open" "$OUTDIR"/10-fulltcp-*.nmap "$OUTDIR"/02-full-*.nmap 2>/dev/null | tee "$OUTDIR/_open-ports.txt"

# Per-host dashboard (after full scans)
while read -r H; do
  echo "=== $H ==="
  awk '/^[0-9]+\/tcp/ && /open/ {print $1,$3,$4,$5}' "$OUTDIR"/10-fulltcp-"$H".nmap 2>/dev/null || true
done < "$OUTDIR/hosts_up.txt"
```

---

## 9) Tiny Mistake Cards (pin these)

* **Missed high ports:** Top-1000 ≠ all ports → always run `-p-` full sweep per host.
* **ICMP-only discovery:** Windows ≠ chatty → use mixed probes or `-Pn` ladder.
* **Using `T5` over VPN:** Packet loss fakes “filtered” → prefer `T3` (full) / `T4` (discovery).
* **No `sudo`:** Raw probes fail → hosts look “down”.
* **Parsing wrong file:** `.gnmap` for host up, `.nmap` for port lines.
* **Root-owned outputs:** Fix with `sudo chown -R "$USER":"$USER" "$OUTDIR"` before parsing.

---

## 10) FAQ (fast)

**Does discovery include all ports?** No. It only checks if hosts respond. **Full TCP with `-p-`** catches 1–65535 so you don’t miss 6xxxx.
**When use `-A`?** After `-sV -sC` if you still need OS/traceroute. It’s slower and louder.
**Parallelism?** Capped at \~3 hosts in examples to avoid melting the VPN. Raise with care.
**UDP worth it?** Yes when nothing shows on TCP but service clues exist (RDP banners, SNMP, DNS behavior). Use §6.

---

### Final one-liner flow to remember

**Discovery → `hosts_up.txt` → Full `-p-` → Focused `-sV -sC` → (Optional) UDP check.**
Keep `-n`, name outputs, and never trust top-1000 alone.
