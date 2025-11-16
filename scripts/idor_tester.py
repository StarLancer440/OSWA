#!/usr/bin/env python3
"""
IDOR (Insecure Direct Object Reference) Tester
Tests for IDOR vulnerabilities by attempting to access other users' resources
"""

import requests
import argparse
import sys
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'

def print_banner():
    banner = """
╔═══════════════════════════════════════╗
║     IDOR Vulnerability Tester         ║
║           OSWA Edition                ║
╚═══════════════════════════════════════╝
    """
    print(Colors.BLUE + banner + Colors.END)

def test_idor(url, param_name, start_id, end_id, headers=None):
    """
    Test for IDOR vulnerability by enumerating IDs
    """
    if headers is None:
        headers = {}

    print(f"\n[*] Testing IDOR on: {url}")
    print(f"[*] Parameter: {param_name}")
    print(f"[*] Range: {start_id} - {end_id}\n")

    vulnerable_ids = []
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)

    for current_id in range(start_id, end_id + 1):
        # Update parameter
        query_params[param_name] = [str(current_id)]
        new_query = urlencode(query_params, doseq=True)
        new_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))

        try:
            response = requests.get(new_url, headers=headers, timeout=10)

            # Check for successful access
            if response.status_code == 200:
                # Simple heuristic: different content = different resource
                if len(response.text) > 100:  # Avoid empty responses
                    print(f"{Colors.GREEN}[+]{Colors.END} ID {current_id}: {response.status_code} - Accessible ({len(response.text)} bytes)")
                    vulnerable_ids.append(current_id)
            elif response.status_code == 403:
                print(f"{Colors.YELLOW}[-]{Colors.END} ID {current_id}: {response.status_code} - Forbidden")
            elif response.status_code == 404:
                print(f"{Colors.RED}[-]{Colors.END} ID {current_id}: {response.status_code} - Not Found")
            else:
                print(f"[*] ID {current_id}: {response.status_code}")

        except requests.exceptions.RequestException as e:
            print(f"{Colors.RED}[!]{Colors.END} Error testing ID {current_id}: {e}")

    return vulnerable_ids

def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description='Test for IDOR vulnerabilities',
        epilog='Example: python3 idor_tester.py -u "https://example.com/api/users?id=1" -p id -s 1 -e 100'
    )
    parser.add_argument('-u', '--url', required=True, help='Target URL with parameter')
    parser.add_argument('-p', '--param', required=True, help='Parameter name to test (e.g., id, user_id)')
    parser.add_argument('-s', '--start', type=int, required=True, help='Start ID')
    parser.add_argument('-e', '--end', type=int, required=True, help='End ID')
    parser.add_argument('-H', '--header', action='append', help='Custom headers (format: "Name: Value")')
    parser.add_argument('-t', '--token', help='Authorization token (Bearer token)')

    args = parser.parse_args()

    # Build headers
    headers = {}
    if args.header:
        for header in args.header:
            if ':' in header:
                name, value = header.split(':', 1)
                headers[name.strip()] = value.strip()

    if args.token:
        headers['Authorization'] = f'Bearer {args.token}'

    # Run test
    vulnerable = test_idor(args.url, args.param, args.start, args.end, headers)

    # Summary
    print(f"\n{Colors.BLUE}{'='*50}{Colors.END}")
    print(f"{Colors.BLUE}Summary:{Colors.END}")
    print(f"Total IDs tested: {args.end - args.start + 1}")
    print(f"Accessible IDs: {len(vulnerable)}")

    if vulnerable:
        print(f"\n{Colors.GREEN}[+] Potentially vulnerable IDs:{Colors.END}")
        for vid in vulnerable:
            print(f"    - {vid}")
        print(f"\n{Colors.YELLOW}[!] IDOR vulnerability likely present!{Colors.END}")
    else:
        print(f"\n{Colors.GREEN}[+] No IDOR vulnerability detected{Colors.END}")

    print(f"{Colors.BLUE}{'='*50}{Colors.END}\n")

if __name__ == '__main__':
    main()
