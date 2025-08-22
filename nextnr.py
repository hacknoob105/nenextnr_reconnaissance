#!/usr/bin/env python3
"""
nextnr_advanced_v3.py
Upgraded Advanced Next/React/Node Recon
Usage:
    python3 nextnr_advanced_v3.py https://target.example --maps --fuzz --graphql --js-secrets --dom-xss

Dependencies:
    pip3 install requests beautifulsoup4 tqdm

IMPORTANT:
 - Run only with explicit written permission.
 - Tool does NOT include exploits — it's reconnaissance & surface discovery only.
"""

import argparse, json, re, sys, os, time
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from bs4 import BeautifulSoup
from datetime import datetime, timezone
from tqdm import tqdm
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---- Config ----
HEADERS = {"User-Agent": "Mozilla/5.0 (Kali nextnr_v3/1.0)"}
DEFAULT_TIMEOUT = 10
THREADS = 16
SAFE_FUZZ_PAYLOADS = ["nrtest", "test123", "1"]
COMMON_PATHS = [
    "/package.json","/.env","/.env.local","/.env.production","/next.config.js","/server.js",
    "/config.js","/config.json","/.git/config","/.git/HEAD","/robots.txt","/sitemap.xml",
    "/backup.zip","/backup.tar.gz","/.htpasswd","/admin/","/admin.php","/wp-admin/",
    "/.ssh/",".DS_Store","/composer.json","/composer.lock"
]
SMALL_WORDLIST = [
    "admin","old","backup","test","dev","staging","api","config",".env","package.json",
    "server.js","next.config.js",".git","robots.txt","sitemap.xml","uploads","files",".well-known"
]
NEXT_PREFIXES = ["/_next/","/next/","/_next/static/","/_next/data/"]
SOURCE_MAP_EXT = [".map"]
SECURITY_HEADERS = [
    "content-security-policy","strict-transport-security","x-frame-options",
    "x-content-type-options","referrer-policy","permissions-policy","x-xss-protection"
]

# ---- Helpers ----
def fetch(url, method="GET", payload=None):
    try:
        if method == "GET":
            r = requests.get(url, headers=HEADERS, timeout=DEFAULT_TIMEOUT, verify=False)
        else:
            r = requests.post(url, data=payload, headers=HEADERS, timeout=DEFAULT_TIMEOUT, verify=False)
        return r
    except Exception:
        return None

def check_path(base, path):
    full = urljoin(base, path)
    r = fetch(full)
    if r and r.status_code < 500:
        return (full, r.status_code, len(r.text))
    return None

def extract_js_endpoints(js_text):
    endpoints = set()
    regex = re.findall(r'["\'](\/[A-Za-z0-9_\-\/\.\?\=\&]+)["\']', js_text)
    for e in regex:
        if not e.startswith("//") and len(e) > 1:
            endpoints.add(e)
    return endpoints

def analyze_headers(r):
    found, missing = {}, []
    for h in SECURITY_HEADERS:
        if h in r.headers:
            found[h] = r.headers[h]
        else:
            missing.append(h)
    return found, missing

def scan_js_secrets(js_text):
    secrets = []
    patterns = [
        r"AIza[0-9A-Za-z\\-_]{35}",             # Google API key
        r"sk_live_[0-9a-zA-Z]{24}",             # Stripe live key
        r"AKIA[0-9A-Z]{16}",                    # AWS Access Key
        r"(?i)api[_-]?key['\\\"]?\\s*[:=]\\s*['\\\"][0-9a-zA-Z\\-_]+['\\\"]",
        r"(?i)token['\\\"]?\\s*[:=]\\s*['\\\"][0-9a-zA-Z\\-_]+['\\\"]"
    ]
    for pat in patterns:
        found = re.findall(pat, js_text)
        if found:
            secrets.extend(found)
    return secrets

def scan_dom_xss(js_text):
    sinks = []
    patterns = [
        r"document\\.write",
        r"innerHTML",
        r"outerHTML",
        r"eval\\(",
        r"setTimeout\\(",
        r"setInterval\\(",
    ]
    for pat in patterns:
        if re.search(pat, js_text, re.IGNORECASE):
            sinks.append(pat)
    return sinks

def scan_graphql_queries(js_text):
    queries = []
    regex = re.findall(r"(query|mutation)\\s+\\w+\\s*\\{", js_text)
    if regex:
        queries.extend(regex)
    return queries

# ---- Main ----
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="Target URL, e.g. https://site.com")
    parser.add_argument("--maps", action="store_true", help="Check for sourcemaps")
    parser.add_argument("--fuzz", action="store_true", help="Parameter fuzzing")
    parser.add_argument("--graphql", action="store_true", help="GraphQL introspection + source scan")
    parser.add_argument("--js-secrets", action="store_true", help="Scan JavaScript files for secrets")
    parser.add_argument("--dom-xss", action="store_true", help="Scan JavaScript for DOM XSS sinks")
    args = parser.parse_args()

    base = args.target.rstrip("/")
    print(f"[*] Starting nextnr_advanced_v3 on {base}\\n")

    # Common paths
    print("[+] Checking common paths...")
    with ThreadPoolExecutor(max_workers=THREADS) as exe:
        futures = [exe.submit(check_path, base, p) for p in COMMON_PATHS]
        for f in tqdm(as_completed(futures), total=len(COMMON_PATHS)):
            res = f.result()
            if res:
                print(f"    {res[0]}  [{res[1]}]  len={res[2]}")

    # Homepage fetch
    r = fetch(base)
    if not r:
        print("[-] Could not fetch homepage")
        return

    # Security headers
    print("\\n[+] Security headers:")
    found, missing = analyze_headers(r)
    for h, v in found.items():
        print(f"    {h}: {v}")
    if missing:
        print("    Missing:", ", ".join(missing))

    # Extract JS files
    print("\\n[+] Extracting JavaScript files...")
    soup = BeautifulSoup(r.text, "html.parser")
    scripts = [urljoin(base, s['src']) for s in soup.find_all("script", src=True)]
    for js in scripts:
        print(f"    {js}")
        rjs = fetch(js)
        if rjs and rjs.status_code == 200:
            eps = extract_js_endpoints(rjs.text)
            for e in eps:
                print(f"       -> {e}")

            # JS Secrets Scan
            if args.js_secrets:
                secrets = scan_js_secrets(rjs.text)
                if secrets:
                    print("       [!] Found potential secrets:")
                    for s in secrets:
                        print(f"          {s}")

            # DOM XSS Scan
            if args.dom_xss:
                sinks = scan_dom_xss(rjs.text)
                if sinks:
                    print("       [!] Found potential DOM XSS sinks:")
                    for sink in sinks:
                        print(f"          {sink}")

            # GraphQL Query Scan
            if args.graphql:
                queries = scan_graphql_queries(rjs.text)
                if queries:
                    print("       [!] Found GraphQL queries/mutations:")
                    for q in queries:
                        print(f"          {q}")

    # Sourcemaps
    if args.maps:
        print("\\n[+] Checking for source maps...")
        for js in scripts:
            for ext in SOURCE_MAP_EXT:
                sm_url = js + ext
                rsm = fetch(sm_url)
                if rsm and rsm.status_code == 200:
                    print(f"    Found source map: {sm_url} (len {len(rsm.text)})")

    # GraphQL endpoint check
    if args.graphql:
        print("\\n[+] Checking GraphQL endpoint...")
        gql_paths = ["/graphql", "/api/graphql"]
        for gp in gql_paths:
            gurl = urljoin(base, gp)
            rql = fetch(gurl)
            if rql and rql.status_code in [200, 400]:
                print(f"    Potential GraphQL endpoint: {gurl}")

    print("\\n[*] Recon complete.")

if __name__ == "__main__":
    main()
