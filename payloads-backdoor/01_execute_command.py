#!/usr/bin/env python3
"""
01 - execute_command payload
============================================================

WHAT IT DOES
    The simplest possible "payload": a program that runs a system
    command on the machine it is executed on and shows the output.
    This is the building block for everything else in this section --
    once you can run a command and capture its result, you can report
    that result, chain it after a download, or drive it remotely over a
    socket (the reverse backdoor).

WHY IT MATTERS (hacking concept)
    A payload is just "the code that runs on the target". A huge share
    of real-world post-exploitation is literally this: run a command,
    read what it prints. `whoami`, `id`, `ipconfig`/`ifconfig`,
    `cat /etc/passwd` -- information gathering is command execution.

PYTHON TOPICS TAUGHT
    - subprocess: the right way to run external programs from Python
    - capturing stdout/stderr and return codes
    - functions with a clear single responsibility
    - exception handling (the command might not exist / might fail)

LAB-ONLY. Run this on your own machine. See README.md.
"""

import subprocess


def execute_command(command):
    """Run `command` and return its combined output as text.

    `command` is a LIST, e.g. ["whoami"] or ["ping", "-c", "4", "10.0.0.1"].
    Passing a list (instead of one big string with shell=True) is the
    safe habit: the OS runs exactly these arguments, so a value that
    contains spaces or shell metacharacters can't accidentally become a
    second command. This matters the moment any part of the command
    comes from somewhere you don't fully control.
    """
    # subprocess.run is the modern, recommended entry point.
    #   capture_output=True  -> collect stdout and stderr instead of
    #                           letting them print straight to the screen
    #   text=True            -> decode bytes to str using the default
    #                           encoding, so we get a normal string back
    result = subprocess.run(command, capture_output=True, text=True)

    # Commands report success/failure with an exit code (0 == success).
    # We return stdout on success, and fall back to stderr otherwise so
    # the caller can see WHY it failed.
    if result.returncode == 0:
        return result.stdout
    return result.stderr or f"(command exited with code {result.returncode})"


def main():
    # In a real payload the command would be hard-coded or received from
    # a controller. Here we just demonstrate a harmless one.
    try:
        output = execute_command(["whoami"])
        print("[+] Output of the command:")
        print(output)
    except FileNotFoundError:
        # Raised when the program in the command list doesn't exist.
        print("[-] That command/program was not found on this system.")
    except Exception as error:
        # Any other failure -- never let a payload crash silently while
        # you're learning; print what went wrong.
        print(f"[-] Unexpected error: {error}")


if __name__ == "__main__":
    main()


# ------------------------------------------------------------------
# DEFENSIVE TAKEAWAY
# ------------------------------------------------------------------
# Command execution is the single most-watched behaviour in endpoint
# security:
#   * EDR/antivirus build a process tree. A document viewer, browser, or
#     random script spawning a shell (cmd.exe, powershell.exe, /bin/sh)
#     or recon tools (whoami, net, systeminfo) is a high-signal alert.
#   * On Linux, auditd / Sysmon-for-Linux and eBPF tools log execve()
#     calls -- every command run is recorded with its parent process.
#   * Defenders baseline "what normally runs here"; unusual child
#     processes stand out even without a signature.
# The lesson: offense is cheap (one subprocess call), but it is noisy.
# Good detection focuses on the PARENT/CHILD relationship, not the
# command string alone.
