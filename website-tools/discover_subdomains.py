#!/usr/bin/env python3
"""
discover_subdomains.py  -  Subdomain discovery tool
===================================================

WHAT IT DOES
------------
Given a domain (e.g. example.com) and a wordlist of common subdomain names
(www, mail, dev, staging, admin, ...), it checks which subdomains actually
respond. This mirrors tools like `sublist3r` and `knockpy`, using the simplest
possible technique: guess-and-check.

WHY THIS WORKS (the concept)
----------------------------
Organisations host many services under one domain: www.example.com,
mail.example.com, vpn.example.com, dev.example.com. Each is a separate
"subdomain" and often a separate server/app. Developers frequently expose
*staging* or *dev* subdomains that are less hardened than production but reach
the same databases - a classic foothold. Enumerating subdomains expands the
"attack surface" a defender must worry about.

Two ways to test whether a subdomain exists:
  1. DNS resolution - does the name resolve to an IP at all?
  2. HTTP request    - does a web server answer on it?
This tool does an HTTP request, which also tells you *something is listening*,
not just that a DNS record exists.

PYTHON CONCEPTS TAUGHT
----------------------
- `requests` for HTTP, and how a failed connection raises an exception.
- Building strings (subdomain + "." + domain).
- `threading` / `concurrent.futures` to run many checks in parallel - network
  I/O spends most of its time *waiting*, so threads give a big speedup.
- Thread-safe printing with a `Lock`.
- Functions, loops, exceptions.

DEFENSIVE TAKEAWAY
------------------
Keep an inventory of every subdomain you publish. Retire DNS records that point
at decommissioned services (dangling records enable "subdomain takeover").
Don't leave dev/staging environments internet-facing without auth. Monitor
certificate-transparency logs - every TLS cert you issue publicly reveals the
subdomain name anyway.

AUTHORIZATION
-------------
Enumerating subdomains of a domain you don't control is reconnaissance against
someone else's infrastructure. Only target domains you own or are authorized to
assess. See README.md.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

import requests

# One lock shared by all threads so their print() calls don't interleave into
# garbled output. Only one thread holds it at a time.
print_lock = Lock()


def check_subdomain(subdomain, domain, timeout):
    """Return the full hostname if a web server answers there, else None.

    We try https first, then http, because many hosts only serve one.
    """
    host = f"{subdomain}.{domain}"
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            requests.get(url, timeout=timeout)
            return host  # got any HTTP response -> it exists
        except requests.RequestException:
            continue      # try the other scheme / give up
    return None


def discover(domain, wordlist, threads=20, timeout=4):
    """Fan the wordlist out across a thread pool and collect live subdomains."""
    found = []
    # ThreadPoolExecutor manages a pool of worker threads for us. We submit one
    # job per candidate subdomain; the pool runs up to `threads` at once.
    with ThreadPoolExecutor(max_workers=threads) as pool:
        future_to_word = {
            pool.submit(check_subdomain, word, domain, timeout): word
            for word in wordlist
        }
        for future in as_completed(future_to_word):
            host = future.result()
            if host:
                found.append(host)
                with print_lock:
                    print(f"[+] {host}")
    return found


def load_wordlist(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]


def main():
    parser = argparse.ArgumentParser(
        description="Discover live subdomains of an AUTHORIZED domain."
    )
    parser.add_argument("domain", help="Target domain, e.g. example.com")
    parser.add_argument("wordlist", help="Path to a subdomain wordlist")
    parser.add_argument("-T", "--threads", type=int, default=20,
                        help="Concurrent workers (default: 20)")
    parser.add_argument("-t", "--timeout", type=float, default=4.0,
                        help="Per-request timeout seconds (default: 4)")
    args = parser.parse_args()

    print("[*] Reminder: only enumerate domains you own or are authorized to test.")
    words = load_wordlist(args.wordlist)
    print(f"[*] Trying {len(words)} candidate subdomains of {args.domain} ...\n")

    hits = discover(args.domain, words, threads=args.threads, timeout=args.timeout)

    print(f"\n[*] Done. {len(hits)} live subdomain(s) found.")


if __name__ == "__main__":
    main()
