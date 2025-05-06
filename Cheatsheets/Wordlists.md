### CEWL
```
cewl https://www.geeksforgeeks.org/ -w wordlists.txt
cewl -w <file> <url>
# To spider a site and follow links to other sites
cewl -o <url>

# To spider a site using a given user-agent 
cewl -u <user-agent> <url>

# To spider a site for a given depth and minimum word length
cewl -d <depth> -m <min word length> <url>

# To spider a site and include a count for each word
cewl -c <url>

# To spider a site inluding meta data and separate the meta_data words
cewl -a -meta_file <file> <url>

# To spider a site and store email adresses in a separate file
cewl -e -email_file <file> <url>
```

## Custom wordlists
#### Hashcat rule wordlist
Grab head of rockyou: `head /usr/share/wordlists/rockyou.txt > demo.txt` -> 
Add "1" to end off wordlist: `echo \$1 > demo.rule`
Now use as custom rule `hashcat -r demo.rule --stdout demo.txt`


