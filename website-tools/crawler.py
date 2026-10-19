#!/usr/bin/env python3
"""
crawler.py  -  Hidden file & directory discovery tool
=====================================================

WHAT IT DOES
------------
Given a target base URL and a wordlist, it asks the web server whether each
candidate path (e.g. /admin, /config.php, /backup.zip) exists, and reports the
ones that return a "real" response. This is the same idea behind well-known
tools like `dirb`, `gobuster` and `dirbuster`.

WHY THIS WORKS (the web concept)
--------------------------------
A web server maps URL paths to files/handlers. When your browser asks for
`GET /admin`, the server replies with an HTTP *status code*:
    200 OK            -> the resource exists and was returned
    301/302 Found     -> it exists but redirects somewhere (often /admin -> /admin/)
    401/403            -> it exists but you are not allowed (still useful intel!)
    404 Not Found      -> no such resource
Sites often leave sensitive paths unlinked from any page ("security by
obscurity"): old backups, admin panels, .git folders, config files. Because
they are never linked, a normal crawler that only follows links will miss them.
A *content discovery* crawler instead guesses common names from a wordlist and
checks the status code. Anything that is not a 404 is worth a human's attention.

PYTHON CONCEPTS TAUGHT
----------------------
- The `requests` library: sending HTTP GET requests, reading `.status_code`.
- String formatting / building URLs safely.
- Reading a file line by line (the wordlist).
- Loops, `if` decision-making, and functions.
- Exception handling for network errors (`try`/`except`).
- `argparse` for a real command-line interface.

DEFENSIVE TAKEAWAY
------------------
Don't rely on obscurity. Remove old backups and `.git`/`.env` files from web
roots, return a consistent 404 for things that don't exist, rate-limit
requests, and watch your access logs for bursts of 404s hitting common
wordlist names - that burst is exactly what this tool produces.

AUTHORIZATION
-------------
Only run this against sites you own or have *written* permission to test
(your own lab, DVWA, bWAPP, a CTF target). Scanning random websites can be
illegal and will light up intrusion-detection systems. See README.md.
"""

import argparse
import sys

import requests


def load_wordlist(path):
    """Read a wordlist file and return a list of candidate paths.

    We strip whitespace/newlines and skip blank lines and comment lines
    (lines starting with '#'). Teaching point: files are iterable line by
    line, and `with` makes sure the file is closed even if an error happens.
    """
    words = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            word = line.strip()
            if word and not word.startswith("#"):
                words.append(word)
    return words


def check_path(session, base_url, path, timeout):
    """Request one candidate path and return (url, status_code) if it looks
    like it exists, otherwise return None.

    We use a persistent `requests.Session` so the TCP connection is reused
    across many requests - much faster than a fresh connection each time.
    """
    # Build the full URL. rstrip/lstrip avoids accidental double slashes.
    url = base_url.rstrip("/") + "/" + path.lstrip("/")
    try:
        # allow_redirects=False so a 301/302 is reported as-is instead of being
        # silently followed - the redirect itself is a useful signal.
        resp = session.get(url, timeout=timeout, allow_redirects=False)
    except requests.RequestException:
        # Network error, DNS failure, timeout, connection reset, etc.
        # We swallow it so one bad path doesn't stop the whole scan.
        return None

    # 404 means "not here". Everything else is at least worth a look.
    if resp.status_code != 404:
        return (url, resp.status_code)
    return None


def crawl(base_url, wordlist, timeout=5, verbose=False):
    """Loop over every word in the wordlist and collect the hits."""
    session = requests.Session()
    # A browser-like User-Agent is more representative of normal traffic.
    session.headers.update({"User-Agent": "Mozilla/5.0 (edu-crawler)"})

    found = []
    total = len(wordlist)
    for i, word in enumerate(wordlist, start=1):
        if verbose:
            # \r returns the cursor to the start of the line so we overwrite
            # the progress counter in place instead of spamming the screen.
            sys.stdout.write(f"\r[{i}/{total}] testing {word[:40]:<40}")
            sys.stdout.flush()

        result = check_path(session, base_url, word, timeout)
        if result:
            url, status = result
            found.append(result)
            # \033[K clears the leftover progress text on this line.
            print(f"\r\033[K[+] {status}  {url}")

    if verbose:
        sys.stdout.write("\r\033[K")  # clear the progress line at the end
    return found


def main():
    parser = argparse.ArgumentParser(
        description="Discover hidden files/directories on an AUTHORIZED target."
    )
    parser.add_argument("url", help="Base URL, e.g. http://127.0.0.1/dvwa")
    parser.add_argument("wordlist", help="Path to a wordlist file")
    parser.add_argument(
        "-t", "--timeout", type=float, default=5.0,
        help="Per-request timeout in seconds (default: 5)",
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true",
        help="Hide the live progress counter",
    )
    args = parser.parse_args()

    print("[*] Reminder: only scan targets you own or are authorized to test.")
    words = load_wordlist(args.wordlist)
    print(f"[*] Loaded {len(words)} words. Scanning {args.url} ...\n")

    hits = crawl(args.url, words, timeout=args.timeout, verbose=not args.quiet)

    print(f"\n[*] Done. {len(hits)} interesting path(s) found.")


if __name__ == "__main__":
    main()
