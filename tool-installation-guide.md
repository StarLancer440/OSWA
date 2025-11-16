# Complete Tool Installation Guide - OSWA

## Table of Contents
1. [Environment Setup](#environment-setup)
2. [XSS Tools](#xss-tools)
3. [SQL Injection Tools](#sql-injection-tools)
4. [Directory Traversal Tools](#directory-traversal-tools)
5. [XXE Tools](#xxe-tools)
6. [SSTI Tools](#ssti-tools)
7. [Command Injection Tools](#command-injection-tools)
8. [SSRF Tools](#ssrf-tools)
9. [General Purpose Tools](#general-purpose-tools)
10. [Browser Extensions](#browser-extensions)
11. [Troubleshooting](#troubleshooting)

---

## Environment Setup

### Kali Linux (Recommended)
Most tools pre-installed. Update first:
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install git python3 python3-pip ruby golang -y
```

### Ubuntu/Debian
```bash
sudo apt update
sudo apt install git python3 python3-pip ruby-full golang build-essential -y
```

### Windows (WSL2 Required)
```powershell
# Install WSL2 first
wsl --install -d Ubuntu-22.04

# Then follow Ubuntu instructions inside WSL
```

---

## XSS Tools

### XSStrike
```bash
cd ~/tools
git clone https://github.com/s0md3v/XSStrike
cd XSStrike
pip3 install -r requirements.txt

# Test installation
python3 xsstrike.py -h
```

**Troubleshooting**:
```bash
# If colorama error
pip3 install --upgrade colorama

# If fuzzywuzzy error
pip3 install python-Levenshtein fuzzywuzzy
```

### Dalfox
```bash
# Go installation required
go install github.com/hahwul/dalfox/v2@latest

# Add to PATH
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
source ~/.bashrc

# Test
dalfox version
```

**Alternative (Pre-compiled)**:
```bash
wget https://github.com/hahwul/dalfox/releases/download/v2.9.2/dalfox_2.9.2_linux_amd64.tar.gz
tar -xvf dalfox_2.9.2_linux_amd64.tar.gz
sudo mv dalfox /usr/local/bin/
```

### XSS Hunter
```bash
# Self-hosted option
git clone https://github.com/mandatoryprogrammer/xsshunter-express
cd xsshunter-express
npm install
# Configure config.yaml
npm start
```

**Or use hosted**: https://xsshunter.com (register for free)

---

## SQL Injection Tools

### SQLMap
```bash
# Usually pre-installed on Kali
sqlmap --version

# If not installed
sudo apt install sqlmap

# Or from source
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev
cd sqlmap-dev
python3 sqlmap.py --version
```

### Ghauri
```bash
pip3 install ghauri

# Or from source
git clone https://github.com/r0oth3x49/ghauri.git
cd ghauri
python3 -m pip install --upgrade -r requirements.txt
python3 setup.py install

# Test
ghauri --version
```

### jSQL Injection (GUI Tool)
```bash
# Download latest release
wget https://github.com/ron190/jsql-injection/releases/download/v0.85/jsql-injection-v0.85.jar

# Run (requires Java)
java -jar jsql-injection-v0.85.jar
```

### NoSQLMap
```bash
git clone https://github.com/codingo/NoSQLMap
cd NoSQLMap
python3 -m pip install -r requirements.txt

# Test
python3 nosqlmap.py -h
```

---

## Directory Traversal Tools

### DotDotPwn
```bash
git clone https://github.com/wireghoul/dotdotpwn
cd dotdotpwn
chmod +x dotdotpwn.pl

# Install dependencies
sudo apt install libsocket-perl libnetaddr-ip-perl

# Test
./dotdotpwn.pl -h
```

### LFISuite
```bash
git clone https://github.com/D35m0nd142/LFISuite
cd LFISuite
pip3 install -r requirements.txt

# Test
python3 lfisuite.py -h
```

### Kadimus
```bash
git clone https://github.com/P0cL4bs/Kadimus
cd Kadimus
make

# Install to system
sudo make install

# Test
kadimus -h
```

---

## XXE Tools

### XXEinjector
```bash
git clone https://github.com/enjoiz/XXEinjector
cd XXEinjector

# No dependencies needed for basic use
# Test
ruby XXEinjector.rb -h
```

### oxml_xxe (Office Documents)
```bash
git clone https://github.com/BuffaloWill/oxml_xxe
cd oxml_xxe

# Install dependencies
gem install rubyzip
gem install nokogiri

# Test
ruby oxml_xxe.rb -h
```

---

## SSTI Tools

### tplmap
```bash
git clone https://github.com/epinna/tplmap
cd tplmap
pip3 install -r requirements.txt

# Test
python3 tplmap.py -h
```

### SSTImap
```bash
git clone https://github.com/vladko312/SSTImap
cd SSTImap
pip3 install -r requirements.txt

# Test
python3 sstimap.py -h
```

---

## Command Injection Tools

### commix
```bash
# Clone repository
git clone https://github.com/commixproject/commix
cd commix
python3 commix.py --install

# Or use pip
pip3 install commix

# Test
python3 commix.py --version
```

---

## SSRF Tools

### SSRFmap
```bash
git clone https://github.com/swisskyrepo/SSRFmap
cd SSRFmap
pip3 install -r requirements.txt

# Test
python3 ssrfmap.py -h
```

### Gopherus
```bash
git clone https://github.com/tarunkant/Gopherus
cd Gopherus
chmod +x install.sh
./install.sh

# Test
gopherus -h
```

### Interactsh (Collaborator Alternative)
```bash
# Download binary
wget https://github.com/projectdiscovery/interactsh/releases/download/v1.1.8/interactsh_1.1.8_linux_amd64.zip
unzip interactsh_1.1.8_linux_amd64.zip
sudo mv interactsh-client /usr/local/bin/

# Or install with Go
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# Test
interactsh-client -h
```

---

## General Purpose Tools

### Burp Suite Community Edition
```bash
# Download from PortSwigger
wget "https://portswigger.net/burp/releases/download?product=community&version=2023.10.3.7&type=Linux"

# Make executable
chmod +x burpsuite_community_linux_*.sh

# Install
./burpsuite_community_linux_*.sh
```

**Useful Extensions**:
- Autorize (IDOR testing)
- AuthMatrix (Access control testing)
- Param Miner (Hidden parameter discovery)
- Collaborator Everywhere (SSRF/XXE detection)
- Turbo Intruder (Fast fuzzing)

### OWASP ZAP
```bash
# Install via package manager
sudo snap install zaproxy --classic

# Or download from website
wget https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2.14.0_Linux.tar.gz
tar -xvf ZAP_2.14.0_Linux.tar.gz
cd ZAP_2.14.0
./zap.sh

# For headless/command-line
sudo apt install zaproxy
```

### ffuf (Fast Fuzzer)
```bash
# Install with Go
go install github.com/ffuf/ffuf/v2@latest

# Or download binary
wget https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz
tar -xvf ffuf_2.1.0_linux_amd64.tar.gz
sudo mv ffuf /usr/local/bin/

# Test
ffuf -h
```

### wfuzz
```bash
# Install via pip
pip3 install wfuzz

# Or from repo
git clone https://github.com/xmendez/wfuzz
cd wfuzz
python3 setup.py install

# Test
wfuzz -h
```

### Nuclei (Template-based Scanner)
```bash
# Install
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Update templates
nuclei -update-templates

# Test
nuclei -version
```

### httpx (HTTP Toolkit)
```bash
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Test
httpx -version
```

### Arjun (Parameter Discovery)
```bash
git clone https://github.com/s0md3v/Arjun
cd Arjun
pip3 install -r requirements.txt

# Test
python3 arjun.py -h
```

---

## Browser Extensions

### Firefox Extensions
```
1. Open Firefox
2. Go to Add-ons (Ctrl+Shift+A)
3. Search and install:
   - FoxyProxy (Proxy management)
   - Wappalyzer (Technology detection)
   - Cookie-Editor (Cookie manipulation)
   - HackTools (Pentesting toolkit)
```

### Chrome Extensions
```
1. Open Chrome Web Store
2. Search and install:
   - FoxyProxy
   - Wappalyzer
   - EditThisCookie
   - HackBar (if available)
```

### Burp Suite Browser Extension
```bash
# Built-in Chromium browser
# Launch from: Proxy → Intercept → Open Browser
# Automatically configured to work with Burp
```

---

## Wordlists

### SecLists (Essential)
```bash
cd /usr/share/wordlists
sudo git clone https://github.com/danielmiessler/SecLists.git

# Or specific location
cd ~/tools
git clone https://github.com/danielmiessler/SecLists.git
```

**Key wordlists for OSWA**:
```
SecLists/Fuzzing/LFI/
SecLists/Fuzzing/XSS/
SecLists/Fuzzing/SQLi/
SecLists/Discovery/Web-Content/
SecLists/Passwords/
```

### Custom Wordlist Locations
```bash
# Create symlinks for easy access
sudo ln -s ~/tools/SecLists /usr/share/seclists

# Or add to environment
echo 'export WORDLISTS=/usr/share/wordlists/SecLists' >> ~/.bashrc
source ~/.bashrc
```

---

## Python Environment Setup

### Virtual Environment (Recommended)
```bash
# Create dedicated environment
python3 -m venv ~/oswa-env

# Activate
source ~/oswa-env/bin/activate

# Install common libraries
pip install requests beautifulsoup4 urllib3 pwntools

# Deactivate when done
deactivate
```

### Common Python Libraries
```bash
pip3 install requests        # HTTP requests
pip3 install beautifulsoup4  # HTML parsing
pip3 install lxml            # XML parsing
pip3 install pwntools        # Exploitation library
pip3 install colorama        # Colored output
pip3 install urllib3         # URL handling
```

---

## Troubleshooting

### Common Issues

#### 1. Permission Denied
```bash
# Make script executable
chmod +x script.py

# Run with python explicitly
python3 script.py
```

#### 2. Module Not Found
```bash
# Install missing module
pip3 install module_name

# Check Python path
python3 -c "import sys; print(sys.path)"

# Install in user directory
pip3 install --user module_name
```

#### 3. Tool Not Found in PATH
```bash
# Find tool location
which tool_name

# Add to PATH temporarily
export PATH=$PATH:/path/to/tool

# Add to PATH permanently
echo 'export PATH=$PATH:/path/to/tool' >> ~/.bashrc
source ~/.bashrc
```

#### 4. Port Already in Use
```bash
# Find process using port
sudo lsof -i :8080

# Kill process
sudo kill -9 PID

# Or use different port
tool --port 8081
```

#### 5. SSL Certificate Errors
```bash
# Ignore SSL warnings (testing only!)
curl -k https://target.com
python3 tool.py --insecure

# Update CA certificates
sudo update-ca-certificates
```

#### 6. Burp Suite Won't Start
```bash
# Check Java version
java -version

# Install/update Java
sudo apt install openjdk-17-jdk

# Increase memory
java -jar -Xmx4g burpsuite.jar
```

---

## Verification Script

Save this script to verify your installation:

```bash
#!/bin/bash
# tool-check.sh - Verify OSWA tool installation

echo "=== OSWA Tool Installation Verification ==="
echo ""

check_tool() {
    if command -v $1 &> /dev/null; then
        echo "[✓] $1 installed"
    else
        echo "[✗] $1 NOT FOUND"
    fi
}

check_python_module() {
    python3 -c "import $1" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "[✓] Python module: $1"
    else
        echo "[✗] Python module: $1 NOT FOUND"
    fi
}

echo "Core Tools:"
check_tool python3
check_tool pip3
check_tool ruby
check_tool go
check_tool git
check_tool curl

echo ""
echo "XSS Tools:"
check_tool dalfox
[ -f ~/tools/XSStrike/xsstrike.py ] && echo "[✓] XSStrike" || echo "[✗] XSStrike"

echo ""
echo "SQL Injection:"
check_tool sqlmap
check_tool ghauri

echo ""
echo "Directory Traversal:"
[ -f ~/tools/dotdotpwn/dotdotpwn.pl ] && echo "[✓] DotDotPwn" || echo "[✗] DotDotPwn"
check_tool kadimus

echo ""
echo "XXE:"
[ -f ~/tools/XXEinjector/XXEinjector.rb ] && echo "[✓] XXEinjector" || echo "[✗] XXEinjector"

echo ""
echo "SSTI:"
[ -f ~/tools/tplmap/tplmap.py ] && echo "[✓] tplmap" || echo "[✗] tplmap"

echo ""
echo "Command Injection:"
check_tool commix

echo ""
echo "SSRF:"
[ -f ~/tools/SSRFmap/ssrfmap.py ] && echo "[✓] SSRFmap" || echo "[✗] SSRFmap"
check_tool gopherus

echo ""
echo "General Tools:"
check_tool ffuf
check_tool wfuzz
check_tool nuclei
check_tool httpx

echo ""
echo "Python Modules:"
check_python_module requests
check_python_module bs4
check_python_module urllib3

echo ""
echo "Wordlists:"
[ -d /usr/share/wordlists/SecLists ] && echo "[✓] SecLists" || echo "[✗] SecLists"

echo ""
echo "=== Verification Complete ==="
```

**Usage**:
```bash
chmod +x tool-check.sh
./tool-check.sh
```

---

## Quick Installation Script

**One-liner to install most tools**:

```bash
#!/bin/bash
# quick-install.sh - Install all OSWA tools

set -e

echo "[*] Creating tools directory..."
mkdir -p ~/tools
cd ~/tools

echo "[*] Installing XSS tools..."
git clone https://github.com/s0md3v/XSStrike
git clone https://github.com/hahwul/dalfox

echo "[*] Installing SQL injection tools..."
sudo apt install sqlmap -y
pip3 install ghauri

echo "[*] Installing directory traversal tools..."
git clone https://github.com/wireghoul/dotdotpwn
git clone https://github.com/D35m0nd142/LFISuite
git clone https://github.com/P0cL4bs/Kadimus

echo "[*] Installing XXE tools..."
git clone https://github.com/enjoiz/XXEinjector

echo "[*] Installing SSTI tools..."
git clone https://github.com/epinna/tplmap
git clone https://github.com/vladko312/SSTImap

echo "[*] Installing command injection tools..."
pip3 install commix

echo "[*] Installing SSRF tools..."
git clone https://github.com/swisskyrepo/SSRFmap
git clone https://github.com/tarunkant/Gopherus

echo "[*] Installing general tools..."
go install github.com/ffuf/ffuf/v2@latest
pip3 install wfuzz
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

echo "[*] Installing SecLists..."
cd /usr/share/wordlists
sudo git clone https://github.com/danielmiessler/SecLists.git

echo "[*] Installing Python requirements..."
pip3 install -r ~/tools/XSStrike/requirements.txt
pip3 install -r ~/tools/LFISuite/requirements.txt
pip3 install -r ~/tools/tplmap/requirements.txt
pip3 install -r ~/tools/SSRFmap/requirements.txt
pip3 install requests beautifulsoup4 urllib3

echo "[+] Installation complete!"
echo "[+] Run ~/tools/tool-check.sh to verify"
```

**Usage**:
```bash
chmod +x quick-install.sh
./quick-install.sh
```

---

## Post-Installation

### Update Tools Regularly
```bash
# Create update script
cat > ~/update-tools.sh << 'EOF'
#!/bin/bash
cd ~/tools
for dir in */; do
    echo "Updating $dir"
    cd "$dir"
    git pull 2>/dev/null || echo "Not a git repo"
    cd ..
done
nuclei -update-templates
EOF

chmod +x ~/update-tools.sh
./update-tools.sh
```

### Aliases for Quick Access
Add to `~/.bashrc`:
```bash
alias xss='cd ~/tools/XSStrike && python3 xsstrike.py'
alias sqli='sqlmap'
alias lfi='cd ~/tools/LFISuite && python3 lfisuite.py'
alias xxe='cd ~/tools/XXEinjector && ruby XXEinjector.rb'
alias ssti='cd ~/tools/tplmap && python3 tplmap.py'
alias cmdi='commix'
alias ssrf='cd ~/tools/SSRFmap && python3 ssrfmap.py'
```

Then run: `source ~/.bashrc`

---

**Installation complete! You're ready for OSWA!**
