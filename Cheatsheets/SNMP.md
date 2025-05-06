https://hacktricks.boitatech.com.br/pentesting/pentesting-snmp
```
apt-get install snmp-mibs-downloader
download-mibs
```

```bash
snmpwalk -v [VERSION_SNMP] -c [COMM_STRING] [DIR_IP] .1 #Enum all
snmpwalk -v X -c public <IP> NET-SNMP-EXTEND-MIB::nsExtendOutputFull
```


Check community name: 
```
..[$] <()> onesixtyone 192.168.220.149 
Scanning 1 hosts, 2 communities
192.168.220.149 [public] Linux oscp 5.9.0-050900-generic #202010112230 SMP Sun Oct 11 22:34:01 UTC 2020 x86_64


```