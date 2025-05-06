`ldapsearch -LLL -x -H ldap://dc01.zeus.corp -D 'DC=zeus,DC=corp' -W -b 'DC=ZEUS,DC=CORP' '*'`

`ldapsearch -LLL -x -H ldap://dc01.secura.yzx -D 'DC=secura,DC=yzx' -W -b 'DC=SECURA,DC=YZX' 'objectClass=*'`

```bash
ldapsearch -LLL -x -H ldap://pdc01.lab.ropnop.com -b ‘’ -s base ‘(objectclass=*)’
```
