#!/usr/bin/env python3
"""
network_scanner.py — discover live hosts on your local network via ARP.

================================ THE LESSON ================================

WHAT IS ARP?
    IP is a Layer-3 (logical) address; MAC is a Layer-2 (hardware) address.
    To actually deliver a packet to 192.168.1.5 on the local wire, a machine
    must know that IP's MAC address. The Address Resolution Protocol answers
    exactly that question:
        - BROADCAST: "Who has 192.168.1.5? Tell 192.168.1.10"   (ARP request)
        - UNICAST reply: "192.168.1.5 is at aa:bb:cc:dd:ee:ff"  (ARP reply)
    Every host on the segment hears the broadcast; the one that owns that IP
    answers.

THE WEAKNESS / PROPERTY WE USE
    ARP has no authentication (remember that — it's the root of the ARP
    spoofing attack in tool #3). For scanning, we use a simpler fact: if we
    broadcast an ARP request for every IP in a range, *every live host* is
    obligated to answer. Silence means "no host there." That gives us a fast,
    reliable map of who is on the network — IP + MAC for each device.

HOW THIS PROGRAM WORKS
    scapy lets us hand-craft the two stacked layers of one frame:
        Ether(dst="ff:ff:ff:ff:ff:ff")   <- Layer 2: broadcast to everyone
        / ARP(pdst="192.168.1.0/24")     <- Layer 3: "who has these IPs?"
    We send it with srp() ("send/receive at layer 2") and read back the
    replies. Each reply's source IP and source MAC is one live host.

=============================== THE PYTHON ================================
    * scapy        — build/send/receive packets as Python objects. The "/"
                     operator stacks layers; indexing (pkt[ARP]) reads a layer.
    * list of dict — a clean, extensible way to hold structured results.
    * list comprehension-friendly loops over the answered packets.
    * string formatting — a tidy aligned table with f-strings.

=========================== DEFENSIVE TAKEAWAY ===========================
    Scanning itself is just asking questions every host is designed to answer,
    so you can't "block ARP replies" without breaking the network. Instead:
        - On managed switches / IDS, a host suddenly ARPing the ENTIRE subnet
          is a classic recon signature — alert on it.
        - Network Access Control (NAC) and 802.1X decide *who is allowed on*
          the segment in the first place, which is the real control.
        - Segment sensitive devices into their own VLANs so a scan from a
          guest network can't even see them.

USAGE (inside your lab, as root):
    sudo python3 network_scanner.py -t 192.168.1.0/24
===========================================================================
"""

import argparse

# scapy prints a noisy IPv6 warning on import; silence it for clean output.
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import Ether, ARP, srp


def get_arguments():
    parser = argparse.ArgumentParser(description="ARP-scan a subnet for live hosts.")
    parser.add_argument("-t", "--target", dest="target", required=True,
                        help="Target IP or CIDR range, e.g. 192.168.1.0/24")
    return parser.parse_args()


def scan(target):
    """Broadcast an ARP request for `target` and return the hosts that reply.

    Build one frame by stacking two layers with the `/` operator:
        Ether(dst=broadcast)  — deliver this frame to EVERY device on the wire
        ARP(pdst=target)      — the question: "who owns these IP(s)?"

    srp() sends at Layer 2 and waits for replies. It returns a pair
    (answered, unanswered); we only care about `answered`, which is a list of
    (sent_packet, received_packet) tuples. Each received packet's .psrc / .hwsrc
    is the responding host's IP / MAC.
    """
    broadcast = "ff:ff:ff:ff:ff:ff"
    request = Ether(dst=broadcast) / ARP(pdst=target)

    # timeout=2: wait 2s for replies. verbose=False: don't print scapy's own
    # send counter, so our table is the only output.
    answered, _unanswered = srp(request, timeout=2, verbose=False)

    hosts = []
    for _sent, received in answered:
        hosts.append({"ip": received.psrc, "mac": received.hwsrc})
    return hosts


def print_result(hosts):
    """Print the discovered hosts as a simple aligned table."""
    print("\nIP Address".ljust(20) + "MAC Address")
    print("-" * 40)
    for host in hosts:
        print(host["ip"].ljust(20) + host["mac"])
    print(f"\n[+] {len(hosts)} host(s) found.")


def main():
    args = get_arguments()
    print(f"[i] Scanning {args.target} ...")
    hosts = scan(args.target)
    print_result(hosts)


if __name__ == "__main__":
    main()
