# Website Hacking Tools (Python) — Study Edition

Educational implementations of the **website / web-application** programs from
Zaid Sabih's *Learn Python & Ethical Hacking From Scratch*. Each file is a
self-contained, heavily-commented Python 3 script that teaches **one web
security concept and the Python that implements it** at the same time.

## ⚠️ Authorization — read this first

These tools send requests to web servers. Several of them (`guess_login`,
`vulnerability_scanner`) send **active, crafted inputs**. Using them against a
system you do not own or do not have **written permission** to test is almost
certainly illegal (e.g. the US CFAA, the UK Computer Misuse Act, and equivalents
elsewhere) and will trip intrusion-detection systems.

**Only run these against targets you control or are explicitly authorized to
assess**, such as:

- A local **DVWA** (Damn Vulnerable Web Application)
- **bWAPP**, **OWASP Juice Shop**, **WebGoat**
- A deliberately vulnerable VM (e.g. Metasploitable) on an **isolated** network
- A CTF target, or a web app you built yourself
- A site with a signed penetration-test authorization / an in-scope bug-bounty

`guess_login` and `vulnerability_scanner` are marked **LAB USE ONLY** at the top
of the file. Keep it that way.

## The tools

| Script | What it does | Key Python lessons |
|---|---|---|
| `crawler.py` | Finds **unlinked** files/dirs by guessing paths from a wordlist (like `dirb`/`gobuster`) | `requests`, HTTP status codes, file I/O, loops, exceptions, `argparse` |
| `discover_subdomains.py` | Finds live **subdomains** from a wordlist (like `sublist3r`) | threading with `concurrent.futures`, `Lock`, string building |
| `spider.py` | **Follows links** to map every page + form on a site | `BeautifulSoup` HTML parsing, `urljoin`/`urlparse`, BFS with a `set`+`deque` |
| `guess_login.py` | Dictionary **attack on a login form** (like `hydra`) — LAB ONLY | HTTP POST, sessions/cookies, `itertools.product`, response analysis |
| `vulnerability_scanner.py` | Spiders a site then tests forms/params for **reflected XSS**, **SQLi signals**, and **missing security headers**; writes a report — LAB ONLY | module reuse (imports `spider`), `json`, URL tampering, building a pipeline |

## Suggested learning order

1. **`crawler.py`** — simplest: one request, one status check, in a loop.
2. **`discover_subdomains.py`** — same idea + your first taste of threading.
3. **`spider.py`** — parse real HTML and model links/forms as data.
4. **`guess_login.py`** — POST requests, sessions, and detecting success.
5. **`vulnerability_scanner.py`** — ties it all together into a mini-scanner.

Each script's docstring has four sections worth reading before the code:
*what it does*, *why it works* (the web concept), *Python concepts taught*, and
the *defensive takeaway* — because understanding the attack is how you learn to
defend against it.

## Setup

```bash
python3 -m pip install requests beautifulsoup4
```

(Standard library handles the rest: `argparse`, `json`, `threading`,
`itertools`, `urllib.parse`.)

## Setting up a safe practice lab (recommended)

The easiest fully-contained target is **DVWA** via Docker:

```bash
docker run --rm -it -p 127.0.0.1:8080:80 vulnerables/web-dvwa
# then browse http://127.0.0.1:8080  (login admin / password, click "Create/Reset Database")
```

Binding to `127.0.0.1` keeps it on your own machine only. Now every example
below is legal, local, and safe.

## Usage examples (against your local lab)

```bash
# 1. Discover hidden paths
python3 crawler.py http://127.0.0.1:8080 wordlists/dirs.txt

# 2. Discover subdomains (needs a domain + DNS; mostly for real labs)
python3 discover_subdomains.py example.lab wordlists/subdomains.txt

# 3. Map the site and list its forms
python3 spider.py http://127.0.0.1:8080/ --delay 0.1

# 4. Dictionary-attack a login form (LAB ONLY)
#    --failure-text is a string that appears ONLY on a failed login.
python3 guess_login.py http://127.0.0.1:8080/login.php \
    wordlists/users.txt wordlists/passwords.txt \
    --user-field username --pass-field password \
    --failure-text "Login failed" --extra Login=Login

# 5. Scan the app for basic weaknesses and write a report (LAB ONLY)
python3 vulnerability_scanner.py http://127.0.0.1:8080/ -o my_scan
#    -> writes my_scan.txt (readable) and my_scan.json (machine-readable)
```

The `wordlists/` folder ships with tiny starter lists so the tools run out of
the box. For real practice, swap in the big lists from
[SecLists](https://github.com/danielmiessler/SecLists).

## Defensive summary (the point of all this)

| Attack the tool models | How to defend |
|---|---|
| Content discovery (crawler) | Remove backups/`.git`/`.env` from web roots; consistent 404s; log & alert on 404 bursts |
| Subdomain enumeration | Inventory all subdomains; kill dangling DNS; don't expose dev/staging |
| Site mapping (spider) | No secrets in linked pages or hidden fields; don't trust robots.txt to hide |
| Login brute-force | Rate-limit, lockouts, MFA, CAPTCHA, slow salted hashes (argon2/bcrypt) |
| XSS | Context-aware output encoding, CSP, auto-escaping frameworks |
| SQL injection | Parameterised queries / prepared statements; hide DB errors |
| Missing headers | Set CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |

Run the scanner against **your own** apps in CI to catch these before they ship.
