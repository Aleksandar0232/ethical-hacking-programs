#!/usr/bin/env python3
"""
spider.py  -  Website mapper / link crawler
============================================

WHAT IT DOES
------------
Starting from one page, it downloads the HTML, extracts every link (<a href>)
and form (<form action>) that points back into the same site, then repeats the
process on each newly discovered page until the whole site has been mapped.
The result is a list of every reachable URL and every form, which is the
foundation other tools (like the vulnerability scanner) build on.

This differs from crawler.py: the crawler *guesses* hidden paths from a
wordlist; the spider *follows the links that actually exist*. Real recon uses
both - the spider finds the linked surface, the crawler finds the unlinked one.

WHY THIS WORKS (the concept)
----------------------------
A web page is HTML text. Links are <a href="..."> elements; forms are
<form action="..." method="..."> containing <input> fields. By parsing the HTML
we can see exactly where a page can take a user and what data each form expects.
Collecting every form's fields is the first step to testing those inputs for
vulnerabilities later (that's what a scanner does). We keep a "visited" set so
we never fetch the same page twice and never wander off onto other domains.

PYTHON CONCEPTS TAUGHT
----------------------
- `requests` to fetch pages.
- `BeautifulSoup` (bs4) to parse HTML and query elements - far more robust than
  regex for real-world HTML.
- `urllib.parse.urljoin` / `urlparse` to turn relative links ("about.html")
  into absolute URLs and to keep the crawl on one host.
- Data structures: a `set` for O(1) "have I seen this?" checks, a list as a
  work queue (breadth-first search).
- Recursion vs. iteration: we use an explicit queue (iterative BFS) to avoid
  hitting Python's recursion limit on large sites.

DEFENSIVE TAKEAWAY
------------------
Everything a spider can reach, an attacker can reach. Don't put secrets in
linked pages or hidden form fields. Respect/robots are advisory only - never
rely on robots.txt to "hide" something. Watch for a single client fetching your
whole site quickly; legitimate users don't do that.

AUTHORIZATION
-------------
Mapping a site generates many requests. Only spider sites you own or are
authorized to test, and keep the --delay sane so you don't stress the server.
See README.md.
"""

import argparse
import time
from collections import deque
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


def same_host(url, root_netloc):
    """True if `url` is on the same host as the site we started on.

    urlparse(url).netloc is the "host:port" part. Staying on one host keeps us
    from crawling the entire internet by accident.
    """
    return urlparse(url).netloc == root_netloc


def extract_links_and_forms(html, current_url):
    """Parse one page's HTML and return (set_of_links, list_of_forms).

    Each form is a dict describing its action URL, method, and input fields -
    exactly the shape the vulnerability scanner will want to consume.
    """
    soup = BeautifulSoup(html, "html.parser")

    links = set()
    for a in soup.find_all("a", href=True):
        # urljoin turns "page2.html" or "/dir/x" into a full absolute URL
        # relative to the page we are currently on.
        links.add(urljoin(current_url, a["href"]))

    forms = []
    for form in soup.find_all("form"):
        action = urljoin(current_url, form.get("action") or current_url)
        method = (form.get("method") or "get").lower()
        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            inputs.append({
                "name": inp.get("name"),
                "type": inp.get("type", "text"),
                "value": inp.get("value", ""),
            })
        forms.append({"action": action, "method": method, "inputs": inputs})

    return links, forms


def spider(start_url, max_pages=200, delay=0.0, timeout=5):
    """Breadth-first crawl of one site, bounded by `max_pages`."""
    root_netloc = urlparse(start_url).netloc
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (edu-spider)"})

    visited = set()               # pages we've already fetched
    queue = deque([start_url])    # pages waiting to be fetched (FIFO -> BFS)
    all_forms = []

    while queue and len(visited) < max_pages:
        url = queue.popleft()
        if url in visited:
            continue
        visited.add(url)

        try:
            resp = session.get(url, timeout=timeout)
        except requests.RequestException:
            continue

        # Only parse things that are actually HTML (skip images, PDFs, etc.)
        content_type = resp.headers.get("Content-Type", "")
        if "text/html" not in content_type:
            continue

        print(f"[>] {url}")
        links, forms = extract_links_and_forms(resp.text, url)

        for form in forms:
            all_forms.append(form)
            print(f"    [form] {form['method'].upper()} {form['action']} "
                  f"({len(form['inputs'])} field(s))")

        # Queue up newly discovered, same-host links we haven't seen.
        for link in links:
            # Drop the #fragment so /x and /x#top aren't treated as two pages.
            link = link.split("#")[0]
            if link and same_host(link, root_netloc) and link not in visited:
                queue.append(link)

        if delay:
            time.sleep(delay)  # be polite to the server

    return visited, all_forms


def main():
    parser = argparse.ArgumentParser(
        description="Map an AUTHORIZED website's pages and forms."
    )
    parser.add_argument("url", help="Start URL, e.g. http://127.0.0.1/dvwa/")
    parser.add_argument("-m", "--max-pages", type=int, default=200,
                        help="Stop after this many pages (default: 200)")
    parser.add_argument("-d", "--delay", type=float, default=0.0,
                        help="Seconds to wait between requests (default: 0)")
    args = parser.parse_args()

    print("[*] Reminder: only spider sites you own or are authorized to test.\n")
    pages, forms = spider(args.url, max_pages=args.max_pages, delay=args.delay)

    print(f"\n[*] Done. Mapped {len(pages)} page(s), found {len(forms)} form(s).")


if __name__ == "__main__":
    main()
