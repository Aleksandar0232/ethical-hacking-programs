# Network Security Tools — Study Set

A set of small, heavily-commented Python 3 programs that accompany the network
section of Zaid Sabih's *Learn Python & Ethical Hacking From Scratch*. Each file
is meant to be **read and studied**, not just run: the goal is to understand the
protocol, see its weakness, see how a program takes advantage of that weakness,
and — just as important — learn how to **detect and defend** against it.

Every program teaches two things at once:

1. **A security concept** — how a protocol works, where it's weak, and why.
2. **A Python concept** — `subprocess`, regex, loops, OOP, threading, `scapy`,
   `netfilterqueue`, sockets, string manipulation, and so on.

---

## ⚠️ Ethics & authorization — read this first

These programs manipulate network traffic. In most of the world, running them
against networks or devices you do not own or have **explicit written permission**
to test is illegal (in the US, e.g., the Computer Fraud and Abuse Act; elsewhere,
equivalent computer-misuse laws).

**Only ever use these on:**

- A lab you built yourself (see "Lab setup" below), or
- Networks and devices that you own, or
- Systems you have **explicit, documented authorization** to test.

The point of this set is to *understand* attacks so you can *defend* against them.
Each file ends with a **Defensive takeaway** section for exactly that reason.
None of these scripts run anything against a real network on your behalf — they
are code to study and to run inside your own isolated lab.

---

## Lab setup (safe practice environment)

Practice entirely inside virtual machines on an isolated virtual network so no
real traffic and no real people are ever involved.

1. **Install a hypervisor**: VirtualBox (free) or VMware.
2. **Attacker VM**: Kali Linux (ships with Python, scapy, and the networking
   tools these scripts assume). Download the prebuilt VirtualBox image from
   kali.org.
3. **Target VM(s)**: a second Linux VM, a Windows evaluation VM, or
   [Metasploitable]. These are your "victims" — machines you own.
4. **Network mode**: put every VM on a **Host-Only** or **Internal Network**
   adapter. This keeps all traffic inside the virtual lab and off your real LAN
   and the internet. Do *not* use Bridged mode for attack practice.
5. Take a **snapshot** of each VM once it's set up so you can roll back after
   experiments.

Verify the VMs can see each other (`ping`) before trying anything else.

---

## Requirements

- **Python 3.8+**
- **Linux** (Kali recommended). Several tools rely on Linux-only facilities
  (raw sockets via scapy, `iptables`/`NFQUEUE`, `ifconfig`/`ip`).
- Python packages:

  ```bash
  sudo apt update
  sudo apt install python3-pip
  pip3 install scapy
  # For dns_spoofer / file_interceptor / code_injector (packet rewriting):
  sudo apt install build-essential python3-dev libnetfilter-queue-dev
  pip3 install netfilterqueue
  ```

- Most scripts need **root** (raw sockets, iptables), so run them with `sudo`.

---

## The programs (suggested study order)

| # | File | Concept | Python focus |
|---|------|---------|--------------|
| 1 | `mac_changer.py` | MAC addresses & filtering | `subprocess`, regex, `argparse` |
| 2 | `network_scanner.py` | ARP, host discovery | scapy, lists of dicts |
| 3 | `arp_spoofer.py` | ARP cache poisoning / MITM | scapy, loops, OOP, signals |
| 4 | `packet_sniffer.py` | Reading traffic off the wire | scapy layers, string parsing |
| 5 | `dns_spoofer.py` | DNS & response forgery | netfilterqueue + scapy |
| 6 | `file_interceptor.py` | HTTP downloads, redirects | netfilterqueue, HTTP headers |
| 7 | `code_injector.py` | Injecting into HTML responses | regex, Content-Length math |
| 8 | `arpspoof_detector.py` | **Defense**: spotting the attack | scapy sniffing, state tracking |

Read each file top to bottom. The long comment block at the top of every file is
the lesson; the code below it is the worked example.

---

## How attacks 5–7 fit together (the MITM chain)

Tools 5, 6, and 7 only make sense *after* you are the "man in the middle". The
chain is:

1. `arp_spoofer.py` puts your machine between the target and the router, so their
   traffic flows through you.
2. You enable IP forwarding so traffic still reaches its destination (the target
   notices nothing).
3. `dns_spoofer` / `file_interceptor` / `code_injector` then read and rewrite
   that forwarded traffic with `NFQUEUE`.

Each file's notes point back to this chain so you always know where it sits.

---

*Built for self-study in an isolated lab. Understand the attack, then go read the
"Defensive takeaway" and learn to stop it.*
