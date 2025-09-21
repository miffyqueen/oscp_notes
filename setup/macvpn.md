# OpenVPN Quick Reset Script (macOS, OSCP Exam Ready)

This is a minimal, exam‑day friendly script for macOS to **kill any stale OpenVPN process, relaunch your VPN, and follow the log**. No extra fluff, just reliable workflow.

---

## Script: `vpn.sh`

```bash
#!/usr/bin/env bash
# vpn.sh — Quick OpenVPN reset + launch (macOS)

CONF="$HOME/Downloads/universal.ovpn"   # adjust if your config is elsewhere
LOG="$HOME/offsec-openvpn.log"

echo "[*] Killing any running OpenVPN..."
sudo pkill openvpn 2>/dev/null || true

echo "[*] Starting OpenVPN with config: $CONF"
sudo nohup openvpn --config "$CONF" --verb 3 > "$LOG" 2>&1 &

sleep 2
echo "[*] Tailing log: $LOG (Ctrl-C to stop tail, VPN keeps running)"
sudo tail -f "$LOG"
```

---

## Setup

```bash
mkdir -p ~/bin
nano ~/bin/vpn.sh   # paste the script above
chmod +x ~/bin/vpn.sh
```

Ensure `~/bin` is in your PATH (add this to `~/.zshrc` or `~/.bash_profile` if needed):

```bash
export PATH="$HOME/bin:$PATH"
```

---

## Usage

Run the script:

```bash
vpn.sh
```

This will:
1. Kill any stale `openvpn` process.  
2. Start OpenVPN with your `.ovpn` config.  
3. Log to `~/offsec-openvpn.log`.  
4. Follow the log live so you can debug instantly.  

---

## Optional Alias

For even faster usage, add this to your `~/.zshrc`:

```bash
alias vpnrun="~/bin/vpn.sh"
```

Then you can connect with:

```bash
vpnrun
```

---

## Notes
- Always **start your listener before** firing reverse shells.  
- Keep this script handy — it avoids wasting time on exam day.  
- You can swap out `CONF` if OffSec sends you a different `.ovpn`.  
