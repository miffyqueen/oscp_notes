# Connect to `universal.ovpn` on **Kali Linux** (copy-paste guide)

> You’re on Kali, and your file lives at: **`/home/kali/Downloads/universal.ovpn`** (from your screenshot).
> All commands below are **standalone**: you can run any single block by itself. Replace paths if you moved the file.

---

## 0) Install/verify the OpenVPN client

```bash
sudo apt update && sudo apt install -y openvpn
```

Check version (helpful for debugging):

```bash
openvpn --version
```

---

## 1) Quick connect (foreground — best first test)

```bash
sudo openvpn --config /home/kali/Downloads/universal.ovpn
```

* Shows live logs in the terminal.
* Press `Ctrl+C` to disconnect.

---

## 2) Quick connect (background/daemon)

```bash
sudo openvpn --config /home/kali/Downloads/universal.ovpn --daemon
```

Stop any backgrounded OpenVPN:

```bash
sudo pkill openvpn
```

---

## 3) If your VPN needs username/password (auth file option)

Create a two-line auth file (line 1 = username, line 2 = password).

> ⚠️ Stored in cleartext—remove it after use.

```bash
printf "YOUR_USERNAME\nYOUR_PASSWORD\n" | sudo tee /root/ovpn-auth.txt >/dev/null && sudo chmod 600 /root/ovpn-auth.txt
```

Connect using that auth file:

```bash
sudo openvpn --config /home/kali/Downloads/universal.ovpn --auth-user-pass /root/ovpn-auth.txt
```

Securely remove the auth file when done (optional):

```bash
sudo shred -u /root/ovpn-auth.txt
```

---

## 4) NetworkManager (GUI/CLI) alternative on Kali

Import the profile (creates a reusable connection):

```bash
nmcli connection import type openvpn file /home/kali/Downloads/universal.ovpn
```

List connections (find the exact imported name):

```bash
nmcli -p connection show
```

Bring the VPN up (replace `<Imported-Name>` with the name you saw above):

```bash
nmcli connection up id "<Imported-Name>"
```

Bring it down:

```bash
nmcli connection down id "<Imported-Name>"
```

Show active connections:

```bash
nmcli connection show --active
```

---

## 5) Verify it’s working

See the tunnel interface:

```bash
ip addr show
```

Check routes:

```bash
ip route
```

Check your external IPv4:

```bash
curl -4 ifconfig.me
```

DNS status (Kali/systemd-resolved):

```bash
resolvectl status
```

---

## 6) Common fixes (independent checks)

More verbose logs (run in foreground for clarity):

```bash
sudo openvpn --config /home/kali/Downloads/universal.ovpn --verb 4
```

Ensure TUN device is available:

```bash
sudo modprobe tun
```

Kill any stray OpenVPN processes:

```bash
sudo pkill openvpn
```

Flush DNS cache (NetworkManager/systemd-resolved often handles this automatically, but you can bounce the connection):

```bash
nmcli connection down id "<Imported-Name>" ; nmcli connection up id "<Imported-Name>"
```

---

## 7) Optional: Auto-start at boot with systemd (client mode)

Copy your config into the system location (renamed to `.conf`):

```bash
sudo install -D /home/kali/Downloads/universal.ovpn /etc/openvpn/client/universal.conf
```

Enable and start the client service:

```bash
sudo systemctl enable --now openvpn-client@universal
```

Check status:

```bash
systemctl status openvpn-client@universal
```

Disable/stop:

```bash
sudo systemctl disable --now openvpn-client@universal
```

---

## 8) Quick checklist

* ✅ OpenVPN installed on Kali
* ✅ Connected once **in foreground** (saw logs)
* ✅ Verified interface, routes, external IP, DNS
* ✅ (Optional) Switched to daemon or NetworkManager profile
* ✅ (Optional) Added systemd autostart and confirmed status

If anything still hangs, run the **foreground** command with `--verb 4`, copy the last \~20 log lines, and I’ll help you decode them.
