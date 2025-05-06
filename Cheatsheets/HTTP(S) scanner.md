## Gobuser
#### DIR Mode
Default DIR scanning
`gobuster dir -u https://example.com -w ~/wordlists/shortlist.txt`

With Content-Length
`gobuster dir -u https://example.com -w ~/wordlists/shortlist.txt -l`
#### DNS Mode
`gobuster dns -d example.com -t 50 -w common-names.txt`
`gobuster dns -d example.com-w ~/wordlists/subdomains.txt`

With Show IP `gobuster dns -d example.com -w ~/wordlists/subdomains.txt -i`

### VHost Mode
gobuster vhost -u https://example.com -w common-vhosts.txt

#### Different modes

| Switch | Description                                                          |
| ------ | -------------------------------------------------------------------- |
| dir    | the classic directory brute-forcing mode                             |
| dns    | DNS subdomain brute-forcing mode                                     |
| s3     | Enumerate open S3 buckets and look for existence and bucket listings |
| vhost  | irtual host brute-forcing mode (not the same as DNS!)                |
#### Global flags
|Short Switch|Long Switch|Description|
|---|---|---|
|-z|--no-progress|Don't display progress|
|-o|--output string|Output file to write results to (defaults to stdout)|
|-q|--quiet|Don't print the banner and other noise|
|-t|--threads int|Number of concurrent threads (default 10)|
|-i|--show-ips|Show IP addresses|
||--delay duration|DNS resolver timeout (default 1s)|
|-v,|--verbose|Verbose output (errors)|
|-w|--wordlist string||
#### DNS Mode Options
| Short Switch | Long Switch        | Description                                                  |
| ------------ | ------------------ | ------------------------------------------------------------ |
| -h,          | --help             | help for dns                                                 |
| -d,          | --domain string    | The target domain                                            |
| -r,          | --resolver string  | Use custom DNS server (format server.com or server.com:port) |
| -c,          | --show-cname       | Show CNAME records (cannot be used with '-i' option)         |
| -i,          | --show-ips         | Show IP addresses                                            |
|              | --timeout duration | DNS resolver timeout (default 1s)                            |
### DIR Mode options
|Short Switch|Long Switch|Description|
|---|---|---|
|-h,|--help|help for dir|
|-f,|--add-slash|Append / to each request|
|-c,|--cookies string|Cookies to use for the requests|
|-e,|--expanded|Expanded mode, print full URLs|
|-x,|--extensions string|File extension(s) to search for|
|-r,|--follow-redirect|Follow redirects|
|-H,|--headers stringArray|Specify HTTP headers, -H 'Header1: val1' -H 'Header2: val2'|
|-l,|--include-length|Include the length of the body in the output|
|-k,|--no-tls-validation|Skip TLS certificate verification|
|-n,|--no-status|Don't print status codes|
|-P,|--password string|Password for Basic Auth|
|-p,|--proxy string|Proxy to use for requests [http(s)://host:port]|
|-s,|--status-codes string|Positive status codes (will be overwritten with status-codes-blacklist if set) (default "200,204,301,302,307,401,403")|
|-b,|--status-codes-blacklist|string Negative status codes (will override status-codes if set)|
||--timeout duration|HTTP Timeout (default 10s)|
|-u,|--url string|The target URL|
|-a,|--useragent string|Set the User-Agent string (default "gobuster/3.1.0")|
|-U,|--username string|Username for Basic Auth|
|-d,|--discover-backup|Upon finding a file search for backup files|
||--wildcard|Force continued operation when wildcard found|
#### vHost Options
| Short Switch | Long Switch           | Description                                                 |
| ------------ | --------------------- | ----------------------------------------------------------- |
| -h           | --help                | help for vhost                                              |
| -c           | --cookies string      | Cookies to use for the requests                             |
| -r           | --follow-redirect     | Follow redirects                                            |
| -H           | --headers stringArray | Specify HTTP headers, -H 'Header1: val1' -H 'Header2: val2' |
| -k           | --no-tls-validation   | Skip TLS certificate verification                           |
| -P           | --password string     | Password for Basic Auth                                     |
| -p           | --proxy string        | Proxy to use for requests [http(s)://host:port]             |
|              | --timeout duration    | HTTP Timeout (default 10s)                                  |
| -u           | --url string          | The target URL                                              |
| -a           | --useragent string    | Set the User-Agent string (default "gobuster/3.1.0")        |
| -U           | --username string     | Username for Basic Auth                                     |

## FFUF 
#### Directory discovery
ffuf -w /path/to/wordlist -u https://target/FUZZ
#### Adding classical header (some WAF bypass)
ffuf -c -w "/opt/host/main.txt:FILE" -H "X-Originating-IP: 127.0.0.1, X-Forwarded-For: 127.0.0.1, X-Remote-IP: 127.0.0.1, X-Remote-Addr: 127.0.0.1, X-Client-IP: 127.0.0.1" -fs 5682,0 -u https://target/FUZZ
#### match all responses but filter out those with content-size 42
ffuf -w wordlist.txt -u https://example.org/FUZZ -mc all -fs 42 -c -v
#### Fuzz Host-header, match HTTP 200 responses.
ffuf -w hosts.txt -u https://example.org/ -H "Host: FUZZ" -mc 200
#### Virtual host discovery (without DNS records)
ffuf -w /path/to/vhost/wordlist -u https://target -H "Host: FUZZ" -fs 4242
#### Playing with threads and wait
./ffuf -u https://target/FUZZ -w /home/mdayber/Documents/Tools/Wordlists/WebContent_Discovery/content_discovery_4500.txt -c -p 0.1 -t 10
#### GET param fuzzing, filtering for invalid response size (or whatever)
ffuf -w /path/to/paramnames.txt -u https://target/script.php?FUZZ=test_value -fs 4242
#### GET parameter fuzzing if the param is known (fuzzing values) and filtering 401
ffuf -w /path/to/values.txt -u https://target/script.php?valid_name=FUZZ -fc 401
#### POST parameter fuzzing
ffuf -w /path/to/postdata.txt -X POST -d "username=admin\&password=FUZZ" -u https://target/login.php -fc 401
#### Fuzz POST JSON data. Match all responses not containing text "error".
ffuf -w entries.txt -u https://example.org/ -X POST -H "Content-Type: application/json" \
      -d '{"name": "FUZZ", "anotherkey": "anothervalue"}' -fr "error"

|   |   |
|---|---|
|`ffuf -h`|ffuf help|
|`ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ`|Directory Fuzzing|
|`ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/indexFUZZ`|Extension Fuzzing|
|`ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/blog/FUZZ.php`|Page Fuzzing|
|`ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v`|Recursive Fuzzing|
|`ffuf -w wordlist.txt:FUZZ -u https://FUZZ.hackthebox.eu/`|Sub-domain Fuzzing|
|`ffuf -w wordlist.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb' -fs xxx`|VHost Fuzzing|
|`ffuf -w wordlist.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key -fs xxx`|Parameter Fuzzing - GET|
|`ffuf -w wordlist.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx`|Parameter Fuzzing - POST|
|`ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx`|Value Fuzzing|