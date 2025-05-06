#### [SMBClient] List shares on a machine using NULL session####
`smbclient -L \\IP`
#### [SMBClient] List shares on a machine using a valid username & pass####
`smbclient -L IP -U username%password`
#### [SMBClient] List files on a specific share####
`smbclient //targetIP/share$ -c 'ls' password -U username`
### [SMBClient] Download an specific file from share ###
`smbclient //targetIP/share$ -c 'cd folder;filename password -U username`

### [RPCClient] Anonymous connection###
`rpcclient -U "" -N <ip>`
### [RPCClient] Connection with user ###
	`rpcclient -U "username" <ip>`
### [RPCClient] Get information about objects ###
``` bash
enumdomains
enumdomgroups
enumalgroups builtin

#Domain password policy
getdompwinfo

#Enumerate truste domains
dsr_enumtrustdom

# Get username for a defined user
getusername

# Query user, group etc informations
queryuser RID
querygroupmem519
queryaliasmem builtin 0x220

# Query info policy
lsaquery

# Convert SID to names
lookupsids SID
```

Change user password
```bash
net rpc password adminuser -U helpdesk -S 192.168.80.10
```

Connect with NTLM hash
```bash
sudo proxychains smbclient \\\\172.16.212.11\\C -U medtech.com/wario --pw-nt-hash fdf36048c1cf88f5630381c5e38feb8e
```