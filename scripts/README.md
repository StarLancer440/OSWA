# OSWA Helper Scripts

Collection of Python scripts for quick vulnerability testing during the OSWA exam.

## Scripts Overview

### 1. idor_tester.py
Tests for Insecure Direct Object Reference (IDOR) vulnerabilities by enumerating IDs.

**Usage**:
```bash
# Basic usage
python3 idor_tester.py -u "https://example.com/api/users?id=1" -p id -s 1 -e 100

# With authentication
python3 idor_tester.py -u "https://example.com/api/documents?doc_id=1" -p doc_id -s 1 -e 500 -t YOUR_TOKEN

# With custom headers
python3 idor_tester.py -u "https://example.com/api/orders?order_id=1" -p order_id -s 1000 -e 2000 -H "Authorization: Bearer TOKEN"
```

**Features**:
- Automatic ID enumeration
- Response size analysis
- HTTP status code tracking
- Custom header support
- Bearer token authentication

---

### 2. sqli_tester.py
Quick SQL injection vulnerability tester supporting error-based, boolean-based, and time-based detection.

**Usage**:
```bash
# Full scan (all techniques)
python3 sqli_tester.py -u https://example.com/page -p id

# Error-based only (faster)
python3 sqli_tester.py -u https://example.com/page -p id --error-only

# Boolean-based only
python3 sqli_tester.py -u https://example.com/page -p id --boolean-only

# Time-based only (slowest but catches blind SQLi)
python3 sqli_tester.py -u https://example.com/page -p id --time-only

# With custom headers
python3 sqli_tester.py -u https://example.com/page -p id -H "Cookie: session=abc123"
```

**Features**:
- Error-based SQL injection detection
- Boolean-based blind SQL injection
- Time-based blind SQL injection
- Support for MySQL, PostgreSQL, MSSQL
- Automatic detection of SQL errors
- SQLMap command suggestions

---

### 3. xss_tester.py
Cross-Site Scripting (XSS) vulnerability tester for reflected, DOM-based, and stored XSS.

**Usage**:
```bash
# Test reflected XSS (GET)
python3 xss_tester.py -u https://example.com/search -p q

# Test reflected XSS (POST)
python3 xss_tester.py -u https://example.com/search -p query -m POST

# Test DOM XSS only
python3 xss_tester.py -u https://example.com/page --dom-only

# Test stored XSS (requires manual verification)
python3 xss_tester.py -u https://example.com/comments -p comment --stored-only

# With authentication
python3 xss_tester.py -u https://example.com/profile -p bio -H "Cookie: session=xyz789"
```

**Features**:
- Multiple XSS payload types
- Encoded payload testing
- Filter bypass techniques
- DOM XSS detection patterns
- Stored XSS payload submission
- Context-aware detection

---

## Installation

### Requirements
```bash
pip3 install requests argparse
```

Or install all dependencies:
```bash
pip3 install -r requirements.txt
```

### Make Scripts Executable
```bash
chmod +x idor_tester.py sqli_tester.py xss_tester.py
```

---

## General Usage Tips

### 1. Always Test Responsibly
- Only test on authorized systems
- Follow scope guidelines
- Document all findings

### 2. Combine with Manual Testing
- These scripts are for quick detection
- Manual verification is always required
- Use professional tools (Burp Suite, SQLMap) for exploitation

### 3. Customize as Needed
- Scripts are designed to be modified
- Add your own payloads
- Adjust detection logic

### 4. Output Management
```bash
# Save output to file
python3 idor_tester.py -u URL -p param -s 1 -e 100 | tee idor_results.txt

# Suppress colors for cleaner logs
python3 sqli_tester.py -u URL -p param 2>&1 | sed 's/\x1b\[[0-9;]*m//g' > sqli_results.txt
```

---

## Advanced Examples

### Chaining Scripts in Exam Scenarios

**Scenario 1: Quick API Testing**
```bash
# 1. Test for IDOR
python3 idor_tester.py -u "https://api.target.com/users?id=1" -p id -s 1 -e 1000 -t TOKEN

# 2. Test for SQL injection on discovered endpoints
python3 sqli_tester.py -u "https://api.target.com/search" -p query

# 3. Test for XSS in search
python3 xss_tester.py -u "https://target.com/search" -p q
```

**Scenario 2: Authenticated Testing**
```bash
# Export token
export TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Test all endpoints with authentication
python3 idor_tester.py -u "https://app.com/api/docs?id=1" -p id -s 1 -e 500 -t $TOKEN
python3 sqli_tester.py -u "https://app.com/api/search" -p q -H "Authorization: Bearer $TOKEN"
python3 xss_tester.py -u "https://app.com/profile" -p bio -H "Authorization: Bearer $TOKEN"
```

---

## Troubleshooting

### Script Doesn't Execute
```bash
# Ensure Python 3 is being used
python3 --version

# Check script permissions
chmod +x script_name.py

# Run explicitly with Python 3
python3 script_name.py --help
```

### Connection Errors
```bash
# Check target is accessible
curl -I https://target.com

# Verify proxy settings if needed
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
```

### Import Errors
```bash
# Install missing modules
pip3 install requests

# Or install all at once
pip3 install requests argparse urllib3
```

---

## Extending the Scripts

### Adding Custom Payloads

**For IDOR**:
Edit `idor_tester.py` and modify the enumeration logic.

**For SQLi**:
Add to `SQLI_PAYLOADS` list in `sqli_tester.py`:
```python
SQLI_PAYLOADS = [
    # ... existing payloads ...
    "your_custom_payload",
]
```

**For XSS**:
Add to `XSS_PAYLOADS` list in `xss_tester.py`:
```python
XSS_PAYLOADS = [
    # ... existing payloads ...
    "<your custom XSS payload>",
]
```

### Adding New Detection Methods

Example: Add header-based SQLi detection
```python
def test_header_sqli(url, headers=None):
    """Test for SQL injection in headers"""
    test_headers = headers.copy() if headers else {}
    test_headers['User-Agent'] = "' OR '1'='1"

    response = requests.get(url, headers=test_headers)
    # ... detection logic ...
```

---

## Integration with Burp Suite

### Route Traffic Through Burp
```bash
# Set proxy environment variables
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080

# Run script (will go through Burp)
python3 idor_tester.py -u "https://target.com/api?id=1" -p id -s 1 -e 100

# Disable SSL verification if needed (add to script)
# requests.get(url, verify=False)
```

---

## Performance Optimization

### For Large ID Ranges
```bash
# Use threading (requires script modification)
# Or test in batches
python3 idor_tester.py -u URL -p id -s 1 -e 1000
python3 idor_tester.py -u URL -p id -s 1001 -e 2000
```

### For Faster SQLi Detection
```bash
# Start with error-based (fastest)
python3 sqli_tester.py -u URL -p param --error-only

# Only if error-based fails, try boolean
python3 sqli_tester.py -u URL -p param --boolean-only

# Last resort: time-based (slowest)
python3 sqli_tester.py -u URL -p param --time-only
```

---

## Contributing

Feel free to modify these scripts for your specific needs. They are designed to be simple and educational.

---

## Disclaimer

These scripts are for authorized security testing only. Misuse of these tools against systems you don't have permission to test is illegal. Always:
- Get written authorization
- Follow the rules of engagement
- Document your testing
- Report findings responsibly

---

**Good luck with your OSWA exam!**
