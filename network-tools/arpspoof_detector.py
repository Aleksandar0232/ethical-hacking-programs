#!/usr/bin/env python3
"""
arpspoof_detector.py — the DEFENSE: spot an ARP spoofing attack in progress.

================================ THE LESSON ================================

WHY THIS FILE EXISTS
    Tools #3-7 showed the attack. This one closes the loop by DEFENDING against
    it. Every attack in this set should leave you able to answer "how would I
    catch this?" — here is the worked answer for ARP spoofing. If you only build
    one of these tools to keep, build this one.

HOW THE ATTACK LOOKS ON THE WIRE
    Recall arp_spoofer.py poisons the target by sending ARP replies that claim
    "the gateway is at MY MAC". The giveaway is a MISMATCH:
        - The attacker's reply says gateway_ip -> attacker_mac.
        - But the REAL gateway, when asked honestly, answers gateway_ip ->
          real_mac.
    So an IP that suddenly resolves to a different MAC than it "really" has is
    the fingerprint of the attack. (Equivalently: two different IPs mapping to
    the same MAC.)

HOW THIS PROGRAM DETECTS IT
    For every ARP *reply* we sniff, we do an independent, trustworthy lookup of
    the real MAC for that IP (a normal ARP request — the real owner answers),
    and compare:
        response_mac = what this reply CLAIMS
        real_mac     = what an honest request RETURNS
    If they differ, someone is lying about that IP — i.e. an ARP spoofing
    attack is underway. We alert and name the suspicious MAC.

    (A lightweight alternative, noted below, is to just keep a table of
    IP -> MAC and alert whenever a known IP's MAC changes. The active-probe
    version here is more immediate and is what the course teaches.)

=============================== THE PYTHON ================================
    * scapy sniff() with a filter — only wake us for ARP traffic ("arp").
    * reusing a helper (get_real_mac) — same honest-request technique as the
      scanner/spoofer, now used for GOOD.
    * comparison / branching — the detection is literally one `!=`.
    * exception-safe callbacks — one weird packet shouldn't crash the monitor.

=========================== DEFENSIVE TAKEAWAY ===========================
    Detection is the start; prevention is better:
        - Managed switch: enable Dynamic ARP Inspection (DAI) + DHCP snooping so
          forged replies are dropped before any host sees them.
        - Static ARP entries for critical hosts (your gateway) can't be
          overwritten by a reply.
        - 802.1X / NAC controls who gets onto the segment at all.
        - End-to-end encryption (HTTPS, VPN) makes a successful MITM worthless.
    Run this detector on a host to get an early warning even when you don't
    control the switch — e.g. on a laptop on an untrusted network.

USAGE (inside your lab, as root). Start it, then run arp_spoofer.py from
another VM and watch it fire:
    sudo python3 arpspoof_detector.py -i eth0
===========================================================================
"""

import argparse

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import Ether, ARP, srp, sniff


def get_arguments():
    parser = argparse.ArgumentParser(description="Detect ARP spoofing on an interface.")
    parser.add_argument("-i", "--interface", dest="interface", required=True,
                        help="Interface to monitor, e.g. eth0")
    return parser.parse_args()


def get_real_mac(ip):
    """Ask the network honestly 'who has <ip>?' and return the MAC that answers.

    The REAL owner of the IP responds to a normal broadcast request. An attacker
    forging gratuitous replies doesn't suppress the genuine owner, so this gives
    us ground truth to compare the sniffed reply against.
    """
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    answered, _ = srp(request, timeout=2, verbose=False, retry=1)
    return answered[0][1].hwsrc if answered else None


def process_packet(packet):
    """Callback for each sniffed ARP packet; alert on a claim/truth mismatch."""
    # op == 2 is an ARP reply ("is-at") — the only kind that can poison a cache.
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        try:
            claimed_ip = packet[ARP].psrc
            response_mac = packet[ARP].hwsrc        # what this reply CLAIMS
            real_mac = get_real_mac(claimed_ip)     # what's actually true

            if real_mac is None:
                return  # couldn't verify (host quiet); don't cry wolf

            if real_mac != response_mac:
                print("\n" + "!" * 60)
                print(f"[ALERT] Possible ARP spoofing for {claimed_ip}")
                print(f"        reply claims : {response_mac}")
                print(f"        real MAC is  : {real_mac}")
                print("        -> someone is impersonating this IP.")
                print("!" * 60 + "\n")
        except (IndexError, AttributeError):
            # A malformed packet shouldn't take the whole monitor down.
            return


def main():
    args = get_arguments()
    print(f"[i] Monitoring {args.interface} for ARP spoofing. Ctrl+C to stop.\n")
    # filter="arp": let the kernel hand us only ARP frames — far cheaper than
    # inspecting every packet in Python.
    sniff(iface=args.interface, store=False, filter="arp", prn=process_packet)


if __name__ == "__main__":
    main()
