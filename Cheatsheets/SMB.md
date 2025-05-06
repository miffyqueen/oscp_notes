When SMB is found conduct the following enumeration steps:

- Enumerate Host
    - `netexec smb [ip]`
- List Shares
    - `netexec smb [host/ip] -u [user] -p [pass] --shares`
    - `netexec smb [host/ip] -u guest -p '' --shares`
    - `smbclient -N -L //[ip]`
- Enumerate Files
    - `smbclient //[ip]/[share] -N`
    - `smbclient //[ip]/[share] -U [username] [password]`
    - `netexec smb -u [user] -p [pass] -M spider_plus`
    - `smbclient.py '[domain]/[user]:[pass]@[ip/host] -k -no-pass` - Kerberos auth
    - `manspider.py --threads 256 [IP/CIDR] -u [username] -p [pass] [options]`
- User enumeration
    - RID Cycling
        - `lookupsid.py guest@[ip] -no-pass`
        - `netexec smb [ip] -u guest -p '' --rid-brute`
    - SAM Remote Protocol - `samrdump.py [domain]/[user]:[pass]@[ip]`
- Check for Vulnerabilities - `nmap --script smb-vuln* -p 139,445 [ip]`
