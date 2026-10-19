# Payloads & Backdoor — Python 3 (educational, lab-only)

This folder follows the *Payloads & Backdoor* section of Zaid Sabih's
"Learn Python & Ethical Hacking From Scratch". Every program here is a
**teaching exercise**: each one pairs a small hacking concept with the
Python language features used to build it, and each ends with a
**defensive takeaway** explaining how a defender would detect the
behaviour.

---

## ⚠️ Ethics & authorization — read this first

These programs demonstrate how remote-command execution, data
exfiltration, reverse shells and keyloggers work. That knowledge is
used by both attackers and defenders. Use it only where you are
explicitly allowed to:

- **Run against your own machines and your own lab VMs only** —
  `localhost`, or a target VM *you own* on an isolated host-only network.
- **Never** run any of this against a computer, network, account or
  person you do not own or do not have **written permission** to test.
- Unauthorized access, interception, or keystroke logging is a crime in
  most jurisdictions (e.g. the US Computer Fraud and Abuse Act, the UK
  Computer Misuse Act, and equivalents elsewhere) — regardless of intent.
- This code is deliberately **plain and non-stealthy**. There is no
  anti-virus evasion, no persistence, and no disguise/trojan code here
  (see `NOTES_antivirus_and_trojans.md` for why those are out of scope
  and how defenders handle them). The point is to *understand* the
  mechanics, not to build something you could misuse.

If you are ever unsure whether a target is in scope: it isn't.

---

## Lab setup (safe practice environment)

1. **Two VMs on a host-only / internal network** (VirtualBox or VMware):
   - *Attacker*: Kali Linux (or any Linux/macOS with Python 3).
   - *Target*: a throwaway VM you own (Windows or Linux). Take a snapshot
     first so you can roll back.
2. Give them static IPs on an isolated network with **no route to the
   internet or your real LAN**. For the download payloads, host the test
   file on the attacker VM (e.g. `python3 -m http.server`).
3. For quick experiments you don't even need two VMs — most of these run
   fine with the "attacker" and "target" both on `localhost` in two
   terminals.

Python 3 only. A couple of programs use third-party libraries
(`requests`, `pynput`); install notes are inside each file.

---

## Index

| # | File | Concept | Key Python topics |
|---|------|---------|-------------------|
| 1 | `01_execute_command.py` | Run a local system command | `subprocess`, exceptions, function design |
| 2 | `02_execute_and_report.py` | Run a command, email the result | `subprocess`, `smtplib`, `email`, serialization of output |
| 3 | `03_download_and_execute.py` | Download a file and run it | `requests`/`urllib`, temp files, `subprocess` |
| 4 | `04_download_execute_and_report.py` | Combine download + report | module reuse, composing functions |
| 5 | `05_reverse_backdoor_server.py` + `05_reverse_backdoor_client.py` | Reverse shell with file access | sockets, TCP, threading-free loop, JSON serialization, OOP, base64 file transfer |
| 6 | `06_keylogger.py` | Record keystrokes, report by email | `pynput`, threading (`Timer`), global state, buffering |
| 7 | `07_packaging_notes.md` | Convert a .py into an executable | `pyinstaller`, cross-platform binaries |
| — | `NOTES_antivirus_and_trojans.md` | How AV & trojans work (defensive write-up, **no code**) | detection concepts |

Read them in order — later programs reuse ideas from earlier ones.

---

## A note on how these connect to real defense

Each file's "Defensive takeaway" is the most important part for anyone
doing blue-team / detection work. Patterns you'll see recur:

- A normal user process spawning `cmd.exe` / `/bin/sh` is a classic
  detection signal (EDR watches process-parent trees).
- Long-lived outbound TCP connections to an unusual host/port, especially
  from a non-browser process, are what reverse shells look like on the wire.
- Programs that read raw keyboard input, or that batch-and-email data on a
  timer, are what host-based monitoring and DLP tools flag.

Understanding the offensive mechanic is what lets you write the detection
for it.
