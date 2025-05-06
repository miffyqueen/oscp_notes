
## Sub directory busters ##
##### Katana -> https://github.com/projectdiscovery/katana
`katana -u https://tesla.com`
##### Dirb 
`dirb /usr/share/wordlist/dirb/common.txt http://main.htb`
##### ffuf 
`./ffuf -w /usr/share/SecLists/Discovery/Web-Content/common.txt -u http://10.10.10.93/FUZZ`
## Sub Domain Fuzzing ##
### WFUZZ ####
Sub domain fuzzing with wfuzz:
`wfuzz -H "Host: FUZZ.shibboleth.htb" -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt --hh 290 --hc 302 http://shibboleth.htb/`

```
--hs/ss "regex" #Hide/Show #Simple example, match a string: "Invalid username" 
--hc/sc CODE #Hide/Show by code in response 
--hl/sl NUM #Hide/Show by number of lines in response 
--hw/sw NUM #Hide/Show by number of words in response 
--hh/sh NUM #Hide/Show by number of chars in response 
--hc/sc NUM #Hide/Show by response code
```

### FFUF ###
`./ffuf -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u http://sea.htb -H "Host: FUZZ.sea.htb" -fl 87`

```
 _**fw**_ : to filter by the amount of words
 _**fl**_ : to filter by the number of lines
 _**fs**_ : to filter by the size of the response
 _**fc**_ : to filter by the status code
 _**fr**_ : to filter by the regex pattern
```

[https://book.hacktricks.xyz/pentesting-web/web-tool-wfuzz](https://book.hacktricks.xyz/pentesting-web/web-tool-wfuzz)


```
0000000000000000000000000000000000000000 0cbc7831c1104f1fb0948ba46f75f1666e18e64c adam <adam@trickster.htb> 1716538399 -0400	commit (initial): update admin pannel




```

### Gobuster
### Examples

[](https://github.com/OJ/gobuster#examples)

```
gobuster dns -d mysite.com -t 50 -w common-names.txt
```

Normal sample run goes like this:

```
gobuster dns -d google.com -w ~/wordlists/subdomains.txt

===============================================================
Gobuster v3.2.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Mode         : dns
[+] Url/Domain   : google.com
[+] Threads      : 10
[+] Wordlist     : /home/oj/wordlists/subdomains.txt
===============================================================
2019/06/21 11:54:20 Starting gobuster
===============================================================
Found: chrome.google.com
Found: ns1.google.com
Found: admin.google.com
Found: www.google.com
Found: m.google.com
Found: support.google.com
Found: translate.google.com
Found: cse.google.com
Found: news.google.com
Found: music.google.com
Found: mail.google.com
Found: store.google.com
Found: mobile.google.com
Found: search.google.com
Found: wap.google.com
Found: directory.google.com
Found: local.google.com
Found: blog.google.com
===============================================================
2019/06/21 11:54:20 Finished
===============================================================
```

Show IP sample run goes like this:

```
gobuster dns -d google.com -w ~/wordlists/subdomains.txt -i

===============================================================
Gobuster v3.2.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Mode         : dns
[+] Url/Domain   : google.com
[+] Threads      : 10
[+] Wordlist     : /home/oj/wordlists/subdomains.txt
===============================================================
2019/06/21 11:54:54 Starting gobuster
===============================================================
Found: www.google.com [172.217.25.36, 2404:6800:4006:802::2004]
Found: admin.google.com [172.217.25.46, 2404:6800:4006:806::200e]
Found: store.google.com [172.217.167.78, 2404:6800:4006:802::200e]
Found: mobile.google.com [172.217.25.43, 2404:6800:4006:802::200b]
Found: ns1.google.com [216.239.32.10, 2001:4860:4802:32::a]
Found: m.google.com [172.217.25.43, 2404:6800:4006:802::200b]
Found: cse.google.com [172.217.25.46, 2404:6800:4006:80a::200e]
Found: chrome.google.com [172.217.25.46, 2404:6800:4006:802::200e]
Found: search.google.com [172.217.25.46, 2404:6800:4006:802::200e]
Found: local.google.com [172.217.25.46, 2404:6800:4006:80a::200e]
Found: news.google.com [172.217.25.46, 2404:6800:4006:802::200e]
Found: blog.google.com [216.58.199.73, 2404:6800:4006:806::2009]
Found: support.google.com [172.217.25.46, 2404:6800:4006:802::200e]
Found: wap.google.com [172.217.25.46, 2404:6800:4006:802::200e]
Found: directory.google.com [172.217.25.46, 2404:6800:4006:802::200e]
Found: translate.google.com [172.217.25.46, 2404:6800:4006:802::200e]
Found: music.google.com [172.217.25.46, 2404:6800:4006:802::200e]
Found: mail.google.com [172.217.25.37, 2404:6800:4006:802::2005]
===============================================================
2019/06/21 11:54:55 Finished
===============================================================
```

Base domain validation warning when the base domain fails to resolve. This is a warning rather than a failure in case the user fat-fingers while typing the domain.

```
gobuster dns -d yp.to -w ~/wordlists/subdomains.txt -i

===============================================================
Gobuster v3.2.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Mode         : dns
[+] Url/Domain   : yp.to
[+] Threads      : 10
[+] Wordlist     : /home/oj/wordlists/subdomains.txt
===============================================================
2019/06/21 11:56:43 Starting gobuster
===============================================================
2019/06/21 11:56:53 [-] Unable to validate base domain: yp.to
Found: cr.yp.to [131.193.32.108, 131.193.32.109]
===============================================================
2019/06/21 11:56:53 Finished
===============================================================
```

Wildcard DNS is also detected properly:

```
gobuster dns -d 0.0.1.xip.io -w ~/wordlists/subdomains.txt

===============================================================
Gobuster v3.2.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Mode         : dns
[+] Url/Domain   : 0.0.1.xip.io
[+] Threads      : 10
[+] Wordlist     : /home/oj/wordlists/subdomains.txt
===============================================================
2019/06/21 12:13:48 Starting gobuster
===============================================================
2019/06/21 12:13:48 [-] Wildcard DNS found. IP address(es): 1.0.0.0
2019/06/21 12:13:48 [!] To force processing of Wildcard DNS, specify the '--wildcard' switch.
===============================================================
2019/06/21 12:13:48 Finished
===============================================================
```

If the user wants to force processing of a domain that has wildcard entries, use `--wildcard`:

```
gobuster dns -d 0.0.1.xip.io -w ~/wordlists/subdomains.txt --wildcard

===============================================================
Gobuster v3.2.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Mode         : dns
[+] Url/Domain   : 0.0.1.xip.io
[+] Threads      : 10
[+] Wordlist     : /home/oj/wordlists/subdomains.txt
===============================================================
2019/06/21 12:13:51 Starting gobuster
===============================================================
2019/06/21 12:13:51 [-] Wildcard DNS found. IP address(es): 1.0.0.0
Found: 127.0.0.1.xip.io
Found: test.127.0.0.1.xip.io
===============================================================
2019/06/21 12:13:53 Finished
===============================================================
```

## `dir` Mode

[](https://github.com/OJ/gobuster#dir-mode)

### Options

[](https://github.com/OJ/gobuster#options-1)

```
Uses directory/file enumeration mode

Usage:
  gobuster dir [flags]

Flags:
  -f, --add-slash                       Append / to each request
  -c, --cookies string                  Cookies to use for the requests
  -d, --discover-backup                 Also search for backup files by appending multiple backup extensions
      --exclude-length ints             exclude the following content length (completely ignores the status). Supply multiple times to exclude multiple sizes.
  -e, --expanded                        Expanded mode, print full URLs
  -x, --extensions string               File extension(s) to search for
  -r, --follow-redirect                 Follow redirects
  -H, --headers stringArray             Specify HTTP headers, -H 'Header1: val1' -H 'Header2: val2'
  -h, --help                            help for dir
      --hide-length                     Hide the length of the body in the output
  -m, --method string                   Use the following HTTP method (default "GET")
  -n, --no-status                       Don't print status codes
  -k, --no-tls-validation               Skip TLS certificate verification
  -P, --password string                 Password for Basic Auth
      --proxy string                    Proxy to use for requests [http(s)://host:port]
      --random-agent                    Use a random User-Agent string
      --retry                           Should retry on request timeout
      --retry-attempts int              Times to retry on request timeout (default 3)
  -s, --status-codes string             Positive status codes (will be overwritten with status-codes-blacklist if set)
  -b, --status-codes-blacklist string   Negative status codes (will override status-codes if set) (default "404")
      --timeout duration                HTTP Timeout (default 10s)
  -u, --url string                      The target URL
  -a, --useragent string                Set the User-Agent string (default "gobuster/3.2.0")
  -U, --username string                 Username for Basic Auth

Global Flags:
      --delay duration    Time each thread waits between requests (e.g. 1500ms)
      --no-color          Disable color output
      --no-error          Don't display errors
  -z, --no-progress       Don't display progress
  -o, --output string     Output file to write results to (defaults to stdout)
  -p, --pattern string    File containing replacement patterns
  -q, --quiet             Don't print the banner and other noise
  -t, --threads int       Number of concurrent threads (default 10)
  -v, --verbose           Verbose output (errors)
  -w, --wordlist string   Path to the wordlist
```

### Examples

[](https://github.com/OJ/gobuster#examples-1)

```
gobuster dir -u https://mysite.com/path/to/folder -c 'session=123456' -t 50 -w common-files.txt -x .php,.html
```

Default options looks like this:

```
gobuster dir -u https://buffered.io -w ~/wordlists/shortlist.txt

===============================================================
Gobuster v3.2.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Mode         : dir
[+] Url/Domain   : https://buffered.io/
[+] Threads      : 10
[+] Wordlist     : /home/oj/wordlists/shortlist.txt
[+] Status codes : 200,204,301,302,307,401,403
[+] User Agent   : gobuster/3.2.0
[+] Timeout      : 10s
===============================================================
2019/06/21 11:49:43 Starting gobuster
===============================================================
/categories (Status: 301)
/contact (Status: 301)
/posts (Status: 301)
/index (Status: 200)
===============================================================
2019/06/21 11:49:44 Finished
===============================================================
```

Default options with status codes disabled looks like this:

```
gobuster dir -u https://buffered.io -w ~/wordlists/shortlist.txt -n

===============================================================
Gobuster v3.2.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Mode         : dir
[+] Url/Domain   : https://buffered.io/
[+] Threads      : 10
[+] Wordlist     : /home/oj/wordlists/shortlist.txt
[+] Status codes : 200,204,301,302,307,401,403
[+] User Agent   : gobuster/3.2.0
[+] No status    : true
[+] Timeout      : 10s
===============================================================
2019/06/21 11:50:18 Starting gobuster
===============================================================
/categories
/contact
/index
/posts
===============================================================
2019/06/21 11:50:18 Finished
===============================================================
```

Verbose output looks like this:

```
gobuster dir -u https://buffered.io -w ~/wordlists/shortlist.txt -v

===============================================================
Gobuster v3.2.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Mode         : dir
[+] Url/Domain   : https://buffered.io/
[+] Threads      : 10
[+] Wordlist     : /home/oj/wordlists/shortlist.txt
[+] Status codes : 200,204,301,302,307,401,403
[+] User Agent   : gobuster/3.2.0
[+] Verbose      : true
[+] Timeout      : 10s
===============================================================
2019/06/21 11:50:51 Starting gobuster
===============================================================
Missed: /alsodoesnotexist (Status: 404)
Found: /index (Status: 200)
Missed: /doesnotexist (Status: 404)
Found: /categories (Status: 301)
Found: /posts (Status: 301)
Found: /contact (Status: 301)
===============================================================
2019/06/21 11:50:51 Finished
===============================================================
```

Example showing content length:

```
gobuster dir -u https://buffered.io -w ~/wordlists/shortlist.txt -l

===============================================================
Gobuster v3.2.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Mode         : dir
[+] Url/Domain   : https://buffered.io/
[+] Threads      : 10
[+] Wordlist     : /home/oj/wordlists/shortlist.txt
[+] Status codes : 200,204,301,302,307,401,403
[+] User Agent   : gobuster/3.2.0
[+] Show length  : true
[+] Timeout      : 10s
===============================================================
2019/06/21 11:51:16 Starting gobuster
===============================================================
/categories (Status: 301) [Size: 178]
/posts (Status: 301) [Size: 178]
/contact (Status: 301) [Size: 178]
/index (Status: 200) [Size: 51759]
===============================================================
2019/06/21 11:51:17 Finished
===============================================================
```

Quiet output, with status disabled and expanded mode looks like this ("grep mode"):

```
gobuster dir -u https://buffered.io -w ~/wordlists/shortlist.txt -q -n -e
https://buffered.io/index
https://buffered.io/contact
https://buffered.io/posts
https://buffered.io/categories
```

## `vhost` Mode

[](https://github.com/OJ/gobuster#vhost-mode)

### Options

[](https://github.com/OJ/gobuster#options-2)

```
Uses VHOST enumeration mode (you most probably want to use the IP address as the URL parameter)

Usage:
  gobuster vhost [flags]

Flags:
      --append-domain         Append main domain from URL to words from wordlist. Otherwise the fully qualified domains need to be specified in the wordlist.
  -c, --cookies string        Cookies to use for the requests
      --domain string         the domain to append when using an IP address as URL. If left empty and you specify a domain based URL the hostname from the URL is extracted
      --exclude-length ints   exclude the following content length (completely ignores the status). Supply multiple times to exclude multiple sizes.
  -r, --follow-redirect       Follow redirects
  -H, --headers stringArray   Specify HTTP headers, -H 'Header1: val1' -H 'Header2: val2'
  -h, --help                  help for vhost
  -m, --method string         Use the following HTTP method (default "GET")
  -k, --no-tls-validation     Skip TLS certificate verification
  -P, --password string       Password for Basic Auth
      --proxy string          Proxy to use for requests [http(s)://host:port]
      --random-agent          Use a random User-Agent string
      --retry                 Should retry on request timeout
      --retry-attempts int    Times to retry on request timeout (default 3)
      --timeout duration      HTTP Timeout (default 10s)
  -u, --url string            The target URL
  -a, --useragent string      Set the User-Agent string (default "gobuster/3.2.0")
  -U, --username string       Username for Basic Auth

Global Flags:
      --delay duration    Time each thread waits between requests (e.g. 1500ms)
      --no-color          Disable color output
      --no-error          Don't display errors
  -z, --no-progress       Don't display progress
  -o, --output string     Output file to write results to (defaults to stdout)
  -p, --pattern string    File containing replacement patterns
  -q, --quiet             Don't print the banner and other noise
  -t, --threads int       Number of concurrent threads (default 10)
  -v, --verbose           Verbose output (errors)
  -w, --wordlist string   Path to the wordlist
```

### Examples

[](https://github.com/OJ/gobuster#examples-2)

```
gobuster vhost -u https://mysite.com -w common-vhosts.txt
```

Normal sample run goes like this:

```
gobuster vhost -u https://mysite.com -w common-vhosts.txt

===============================================================
Gobuster v3.2.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          https://mysite.com
[+] Threads:      10
[+] Wordlist:     common-vhosts.txt
[+] User Agent:   gobuster/3.2.0
[+] Timeout:      10s
===============================================================
2019/06/21 08:36:00 Starting gobuster
===============================================================
Found: www.mysite.com
Found: piwik.mysite.com
Found: mail.mysite.com
===============================================================
2019/06/21 08:36:05 Finished
===============================================================
```

## `fuzz` Mode

[](https://github.com/OJ/gobuster#fuzz-mode)

### Options

[](https://github.com/OJ/gobuster#options-3)

```
Uses fuzzing mode

Usage:
  gobuster fuzz [flags]

Flags:
  -c, --cookies string              Cookies to use for the requests
      --exclude-length ints         exclude the following content length (completely ignores the status). Supply multiple times to exclude multiple sizes.
  -b, --excludestatuscodes string   Negative status codes (will override statuscodes if set)
  -r, --follow-redirect             Follow redirects
  -H, --headers stringArray         Specify HTTP headers, -H 'Header1: val1' -H 'Header2: val2'
  -h, --help                        help for fuzz
  -m, --method string               Use the following HTTP method (default "GET")
  -k, --no-tls-validation           Skip TLS certificate verification
  -P, --password string             Password for Basic Auth
      --proxy string                Proxy to use for requests [http(s)://host:port]
      --random-agent                Use a random User-Agent string
      --retry                       Should retry on request timeout
      --retry-attempts int          Times to retry on request timeout (default 3)
      --timeout duration            HTTP Timeout (default 10s)
  -u, --url string                  The target URL
  -a, --useragent string            Set the User-Agent string (default "gobuster/3.2.0")
  -U, --username string             Username for Basic Auth

Global Flags:
      --delay duration    Time each thread waits between requests (e.g. 1500ms)
      --no-color          Disable color output
      --no-error          Don't display errors
  -z, --no-progress       Don't display progress
  -o, --output string     Output file to write results to (defaults to stdout)
  -p, --pattern string    File containing replacement patterns
  -q, --quiet             Don't print the banner and other noise
  -t, --threads int       Number of concurrent threads (default 10)
  -v, --verbose           Verbose output (errors)
  -w, --wordlist string   Path to the wordlist
```

### Examples

[](https://github.com/OJ/gobuster#examples-3)

```
gobuster fuzz -u https://example.com?FUZZ=test -w parameter-names.txt
```

## `s3` Mode

[](https://github.com/OJ/gobuster#s3-mode)

### Options

[](https://github.com/OJ/gobuster#options-4)

```
Uses aws bucket enumeration mode

Usage:
  gobuster s3 [flags]

Flags:
  -h, --help                 help for s3
  -m, --maxfiles int         max files to list when listing buckets (only shown in verbose mode) (default 5)
  -k, --no-tls-validation    Skip TLS certificate verification
      --proxy string         Proxy to use for requests [http(s)://host:port]
      --random-agent         Use a random User-Agent string
      --retry                Should retry on request timeout
      --retry-attempts int   Times to retry on request timeout (default 3)
      --timeout duration     HTTP Timeout (default 10s)
  -a, --useragent string     Set the User-Agent string (default "gobuster/3.2.0")

Global Flags:
      --delay duration    Time each thread waits between requests (e.g. 1500ms)
      --no-color          Disable color output
      --no-error          Don't display errors
  -z, --no-progress       Don't display progress
  -o, --output string     Output file to write results to (defaults to stdout)
  -p, --pattern string    File containing replacement patterns
  -q, --quiet             Don't print the banner and other noise
  -t, --threads int       Number of concurrent threads (default 10)
  -v, --verbose           Verbose output (errors)
  -w, --wordlist string   Path to the wordlist
```

### Examples

[](https://github.com/OJ/gobuster#examples-4)

```
gobuster s3 -w bucket-names.txt
```

## `gcs` Mode

[](https://github.com/OJ/gobuster#gcs-mode)

### Options

[](https://github.com/OJ/gobuster#options-5)

```
Uses gcs bucket enumeration mode

Usage:
  gobuster gcs [flags]

Flags:
  -h, --help                 help for gcs
  -m, --maxfiles int         max files to list when listing buckets (only shown in verbose mode) (default 5)
  -k, --no-tls-validation    Skip TLS certificate verification
      --proxy string         Proxy to use for requests [http(s)://host:port]
      --random-agent         Use a random User-Agent string
      --retry                Should retry on request timeout
      --retry-attempts int   Times to retry on request timeout (default 3)
      --timeout duration     HTTP Timeout (default 10s)
  -a, --useragent string     Set the User-Agent string (default "gobuster/3.2.0")

Global Flags:
      --delay duration    Time each thread waits between requests (e.g. 1500ms)
      --no-color          Disable color output
      --no-error          Don't display errors
  -z, --no-progress       Don't display progress
  -o, --output string     Output file to write results to (defaults to stdout)
  -p, --pattern string    File containing replacement patterns
  -q, --quiet             Don't print the banner and other noise
  -t, --threads int       Number of concurrent threads (default 10)
  -v, --verbose           Verbose output (errors)
  -w, --wordlist string   Path to the wordlist
```

### Examples

[](https://github.com/OJ/gobuster#examples-5)

```
gobuster gcs -w bucket-names.txt
```

## `tftp` Mode

[](https://github.com/OJ/gobuster#tftp-mode)

### Options

[](https://github.com/OJ/gobuster#options-6)

```
Uses TFTP enumeration mode

Usage:
  gobuster tftp [flags]

Flags:
  -h, --help               help for tftp
  -s, --server string      The target TFTP server
      --timeout duration   TFTP timeout (default 1s)

Global Flags:
      --delay duration    Time each thread waits between requests (e.g. 1500ms)
      --no-color          Disable color output
      --no-error          Don't display errors
  -z, --no-progress       Don't display progress
  -o, --output string     Output file to write results to (defaults to stdout)
  -p, --pattern string    File containing replacement patterns
  -q, --quiet             Don't print the banner and other noise
  -t, --threads int       Number of concurrent threads (default 10)
  -v, --verbose           Verbose output (errors)
  -w, --wordlist string   Path to the wordlist
```

### Examples

[](https://github.com/OJ/gobuster#examples-6)

```
gobuster tftp -s tftp.example.com -w common-filenames.txt
```

## Wordlists via STDIN

[](https://github.com/OJ/gobuster#wordlists-via-stdin)

Wordlists can be piped into `gobuster` via stdin by providing a `-` to the `-w` option:

```shell
hashcat -a 3 --stdout ?l | gobuster dir -u https://mysite.com -w -
```

Note: If the `-w` option is specified at the same time as piping from STDIN, an error will be shown and the program will terminate.

## Patterns

[](https://github.com/OJ/gobuster#patterns)

You can supply pattern files that will be applied to every word from the wordlist. Just place the string `{GOBUSTER}` in it and this will be replaced with the word. This feature is also handy in s3 mode to pre- or postfix certain patterns.

**Caution:** Using a big pattern file can cause a lot of request as every pattern is applied to every word in the wordlist.

### Example file

[](https://github.com/OJ/gobuster#example-file)

```
{GOBUSTER}Partial
{GOBUSTER}Service
PRE{GOBUSTER}POST
{GOBUSTER}-prod
{GOBUSTER}-dev
```

#### Use case in combination with patterns

[](https://github.com/OJ/gobuster#use-case-in-combination-with-patterns)

- Create a custom wordlist for the target containing company names and so on
- Create a pattern file to use for common bucket names.

```shell
curl -s --output - https://raw.githubusercontent.com/eth0izzle/bucket-stream/master/permutations/extended.txt | sed -s 's/%s/{GOBUSTER}/' > patterns.txt
```

- Run gobuster with the custom input. Be sure to turn verbose mode on to see the bucket details

```
gobuster s3 --wordlist my.custom.wordlist -p patterns.txt -v
```

Normal sample run goes like this:

```
PS C:\Users\firefart\Documents\code\gobuster> .\gobuster.exe s3 --wordlist .\wordlist.txt
===============================================================
Gobuster v3.2.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Threads:                 10
[+] Wordlist:                .\wordlist.txt
[+] User Agent:              gobuster/3.2.0
[+] Timeout:                 10s
[+] Maximum files to list:   5
===============================================================
2019/08/12 21:48:16 Starting gobuster in S3 bucket enumeration mode
===============================================================
webmail
hacking
css
img
www
dav
web
localhost
===============================================================
2019/08/12 21:48:17 Finished
===============================================================
```

Verbose and sample run

```
PS C:\Users\firefart\Documents\code\gobuster> .\gobuster.exe s3 --wordlist .\wordlist.txt -v
===============================================================
Gobuster v3.2.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Threads:                 10
[+] Wordlist:                .\wordlist.txt
[+] User Agent:              gobuster/3.2.0
[+] Verbose:                 true
[+] Timeout:                 10s
[+] Maximum files to list:   5
===============================================================
2019/08/12 21:49:00 Starting gobuster in S3 bucket enumeration mode
===============================================================
www [Error: All access to this object has been disabled (AllAccessDisabled)]
hacking [Error: Access Denied (AccessDenied)]
css [Error: All access to this object has been disabled (AllAccessDisabled)]
webmail [Error: All access to this object has been disabled (AllAccessDisabled)]
img [Bucket Listing enabled: GodBlessPotomac1.jpg (1236807b), HOMEWORKOUTAUDIO.zip (203908818b), ProductionInfo.xml (11946b), Start of Perpetual Motion Logo-1.mp3 (621821b), addressbook.gif (3115b)]
web [Error: Access Denied (AccessDenied)]
dav [Error: All access to this object has been disabled (AllAccessDisabled)]
localhost [Error: Access Denied (AccessDenied)]
===============================================================
2019/08/12 21:49:01 Finished
===============================================================
```

Extended sample run

```
PS C:\Users\firefart\Documents\code\gobuster> .\gobuster.exe s3 --wordlist .\wordlist.txt -e
===============================================================
Gobuster v3.2.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Threads:                 10
[+] Wordlist:                .\wordlist.txt
[+] User Agent:              gobuster/3.2.0
[+] Timeout:                 10s
[+] Expanded:                true
[+] Maximum files to list:   5
===============================================================
2019/08/12 21:48:38 Starting gobuster in S3 bucket enumeration mode
===============================================================
http://css.s3.amazonaws.com/
http://www.s3.amazonaws.com/
http://webmail.s3.amazonaws.com/
http://hacking.s3.amazonaws.com/
http://img.s3.amazonaws.com/
http://web.s3.amazonaws.com/
http://dav.s3.amazonaws.com/
http://localhost.s3.amazonaws.com/
===============================================================
2019/08/12 21:48:38 Finished
===============================================================
```