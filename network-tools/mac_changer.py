#!/usr/bin/env python3
"""
mac_changer.py — change a network interface's MAC address.

================================ THE LESSON ================================

WHAT IS A MAC ADDRESS?
    Every network interface (your Wi-Fi card, your Ethernet port) has a
    48-bit hardware address called a MAC address, written as six hex pairs:
        00:11:22:33:44:55
    The first three bytes identify the manufacturer (the "OUI"); the last
    three are assigned by that manufacturer. It is used to deliver frames on
    the LOCAL network segment (Layer 2). IP addresses route across networks;
    MAC addresses deliver the final hop within a network.

THE WEAKNESS WE'RE LEARNING ABOUT
    The MAC address is "burned in" to the card, BUT the operating system is
    free to tell the card to present a DIFFERENT address. Nothing forces the
    advertised MAC to match the hardware. This matters because networks often
    use the MAC as if it were a trustworthy identity:
        - MAC filtering / allow-lists ("only these devices may connect")
        - captive portals that track you by MAC
        - time-limited free Wi-Fi that remembers your MAC
    Because the MAC can be freely changed, all of these are weak controls.

HOW THIS PROGRAM "ATTACKS" IT
    We simply ask the OS to bring the interface down, set a new MAC, and bring
    it back up — the same three commands an admin would type by hand:
        ifconfig <iface> down
        ifconfig <iface> hw ether <new_mac>
        ifconfig <iface> up
    The program just wraps those commands and validates input.

=============================== THE PYTHON ================================
    * subprocess  — run external system commands from Python, the safe way
                    (a LIST of arguments, never a shell string).
    * re (regex)  — validate that user input really looks like a MAC, and
                    scrape the current MAC out of command output.
    * argparse    — turn command-line flags (-i / -m) into clean variables.
    * functions   — each step is one small, named, testable function.

=========================== DEFENSIVE TAKEAWAY ===========================
    Because MACs are trivially spoofable (this whole file is ~60 lines of
    logic), do NOT rely on them for security:
        - MAC allow-lists stop casual users, not attackers. Use WPA2/WPA3 with
          a strong passphrase or 802.1X certificate-based auth instead.
        - Don't use MAC as a unique customer identity for billing/quotas.
    To DETECT spoofing on a network you run: watch for the same MAC appearing
    on different switch ports, or a known OUI prefix behaving oddly. Managed
    switches offer "port security" to lock a port to one learned MAC.

USAGE (inside your lab, as root):
    sudo python3 mac_changer.py -i eth0 -m 00:11:22:33:44:55
===========================================================================
"""

import argparse
import re
import subprocess


def get_arguments():
    """Parse -i/--interface and -m/--mac from the command line.

    argparse handles -h/--help, missing-value errors, and type conversion for
    us. `required=True` means the program refuses to run without both flags,
    which is friendlier than crashing halfway through.
    """
    parser = argparse.ArgumentParser(description="Change a network interface's MAC address.")
    parser.add_argument("-i", "--interface", dest="interface", required=True,
                        help="Interface to change, e.g. eth0")
    parser.add_argument("-m", "--mac", dest="new_mac", required=True,
                        help="New MAC address, e.g. 00:11:22:33:44:55")
    return parser.parse_args()


def is_valid_mac(mac):
    """Return True if `mac` looks like six colon-separated hex pairs.

    The regex, piece by piece:
        ^                 start of string
        ([0-9A-Fa-f]{2}:) a hex pair followed by a colon ...
        {5}               ... exactly five times (xx: xx: xx: xx: xx:)
        [0-9A-Fa-f]{2}    one final hex pair with no trailing colon
        $                 end of string
    Validating input BEFORE handing it to a system command is a security habit
    worth building early: it stops typos and stops command injection.
    """
    pattern = r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$"
    return re.match(pattern, mac) is not None


def get_current_mac(interface):
    """Return the interface's current MAC by scraping `ifconfig` output.

    subprocess.check_output runs the command and hands us its stdout as bytes;
    .decode() turns those bytes into a normal string we can search with regex.
    re.search scans anywhere in the text (unlike re.match, which only checks
    the start). If no MAC is found we return None and let the caller decide.
    """
    try:
        output = subprocess.check_output(["ifconfig", interface]).decode()
    except subprocess.CalledProcessError:
        return None
    match = re.search(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", output)
    return match.group(0) if match else None


def change_mac(interface, new_mac):
    """Run the three commands that actually change the MAC.

    Note every command is passed as a LIST of separate arguments. We never
    build a single string and hand it to a shell, so a malicious value like
    "eth0; rm -rf /" cannot break out and run extra commands — the whole thing
    would just be treated as one (invalid) interface name.
    """
    print(f"[+] Changing MAC for {interface} -> {new_mac}")
    subprocess.run(["ifconfig", interface, "down"], check=True)
    subprocess.run(["ifconfig", interface, "hw", "ether", new_mac], check=True)
    subprocess.run(["ifconfig", interface, "up"], check=True)


def main():
    args = get_arguments()

    if not is_valid_mac(args.new_mac):
        print(f"[-] '{args.new_mac}' is not a valid MAC address (want xx:xx:xx:xx:xx:xx).")
        return

    before = get_current_mac(args.interface)
    print(f"[i] Current MAC: {before}")

    change_mac(args.interface, args.new_mac)

    # Verify the change actually took effect instead of assuming it did.
    after = get_current_mac(args.interface)
    if after == args.new_mac:
        print(f"[+] Success. MAC is now {after}")
    else:
        print(f"[-] MAC did not change as expected (now {after}). "
              f"Check the interface name and that you ran as root.")


if __name__ == "__main__":
    main()
