# OpenVPN Cleanup & Reconnect Script

Sometimes stale routes or leftover `tun` interfaces can break your OffSec VPN session.  
Use this script to kill any running OpenVPN process, clear old interfaces, delete broken routes, and reconnect cleanly.

## Commands

```bash
# Kill any running openvpn
sudo pkill openvpn || true

# Remove tun interfaces (tun0–tun3)
for i in {0..3}; do sudo ip link del tun$i 2>/dev/null || true; done

# Delete the stale lab route if it exists
sudo ip route del 192.168.133.0/24 2>/dev/null || true

# Now reconnect fresh
sudo openvpn --config ~/Downloads/universal.ovpn --verb 3
