#smb #bruteforce
Enumerate SMB Information `crackmapexec smb 10.129.204.177`
Enumerate Users `crackmapexec smb 10.129.204.177  -u '' -p '' --users`
Enumerate password policies `crackmapexec smb 10.129.204.177  -u '' -p '' --pass-pol`
Enumerate SMB Shares `crackmapexec smb 10.129.29.43  -u guest -p '' --shares`
Show al folders in the IT share `crackmapexec smb 10.129.203.121 -u guest -p '' --spider IT --regex .`
RID Bruteforce ``crackmapexec smb 10.0.2.8 -u ‘guest’ -p ‘’ — rid-brute``
Password Spraying `crackmapexec smb 192.168.50.75 -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success`
 Check credentials `crackmapexec smb 192.168.156.76 -u pete -p 'Nexus123!' -d corp.com`