# Ethical Hacking Programs — Study Set

A collection of small, heavily-commented **Python 3** programs built while
working through Zaid Sabih's *Learn Python & Ethical Hacking From Scratch*.
Each program is meant to be **read and studied**, not just run: it pairs a
security concept (how something works, where it's weak) with the Python
language features used to build it, and ends with a **defensive takeaway**.

The repo is organised into the course's three sections, each with its own
detailed README:

| Section | What's inside | Details |
|---|---|---|
| [`network-tools/`](network-tools/) | 8 programs: MAC changer, network scanner, ARP spoofer + detector, packet sniffer, DNS spoofer, file interceptor, code injector | [README](network-tools/README.md) |
| [`website-tools/`](website-tools/) | 5 programs: directory/file crawler, subdomain discovery, site spider, login brute-forcer, basic vulnerability scanner | [README](website-tools/README.md) |
| [`payloads-backdoor/`](payloads-backdoor/) | Remote-command execution payloads (more of this section is intentionally omitted — see its README) | [README](payloads-backdoor/README.md) |

Each section teaches two things at once:

1. **A security concept** — how a protocol or web technology works, where it's
   weak, and why.
2. **A Python concept** — `subprocess`, regex, loops, OOP, threading, sockets,
   `scapy`, `requests`, `BeautifulSoup`, HTTP, and more.

---

## ⚠️ Ethics & authorization — read this first

These programs manipulate network traffic, probe web applications, and
demonstrate remote-command execution. In most of the world, running them
against systems you do not own or have **explicit written permission** to test
is illegal (e.g. the US Computer Fraud and Abuse Act, the UK Computer Misuse
Act, and equivalents elsewhere) — regardless of intent.

**Only ever use these on:**

- A lab you built yourself (each section's README explains how to set one up), or
- Networks, sites, and devices that you own, or
- Systems you have **explicit, documented authorization** to test.

The point of this set is to *understand* attacks so you can *defend* against
them. If you are ever unsure whether a target is in scope: it isn't.

---

## Requirements

- Python 3
- Some programs need extra libraries (e.g. `scapy`, `requests`,
  `beautifulsoup4`, `netfilterqueue`). Each section's README lists what to
  install for that section.

Study each program's docstring first — it explains what the program does, why
the technique works, which Python concepts it teaches, and how a defender
detects or prevents it.
