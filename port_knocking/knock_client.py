#!/usr/bin/env python3
"""Starter template for the port knocking client.

Expanded with print output and banner grab on --check.
"""

import argparse
import socket
import time

DEFAULT_KNOCK_SEQUENCE = [1234, 5678, 9012]
DEFAULT_PROTECTED_PORT = 2222
DEFAULT_DELAY = 0.3


def send_knock(target, port, delay):
    """Send a single TCP knock to the target port."""
    print(f"  [*] Knocking port {port}")
    try:
        with socket.create_connection((target, port), timeout=1.0):
            pass
    except OSError:
        pass
    time.sleep(delay)


def perform_knock_sequence(target, sequence, delay):
    """Send the full knock sequence."""
    print(f"[*] Sending knock sequence to {target}: {sequence}")
    for port in sequence:
        send_knock(target, port, delay)
    print("[+] Knock sequence sent.")


def check_protected_port(target, protected_port):
    """Try connecting to the protected port after knocking."""
    print(f"[*] Checking port {protected_port}...")
    try:
        sock = socket.create_connection((target, protected_port), timeout=3.0)
        print(f"[+] SUCCESS - port {protected_port} is OPEN")
        try:
            sock.settimeout(2.0)
            banner = sock.recv(1024).decode(errors="replace").strip()
            if banner:
                print(f"[+] Banner: {banner[:200]}")
        except OSError:
            pass
        sock.close()
    except OSError:
        print(f"[-] FAILED - port {protected_port} is still closed")


def parse_args():
    parser = argparse.ArgumentParser(description="Port knocking client")
    parser.add_argument("--target", required=True, help="Target host or IP")
    parser.add_argument(
        "--sequence",
        default=",".join(str(port) for port in DEFAULT_KNOCK_SEQUENCE),
        help="Comma-separated knock ports",
    )
    parser.add_argument(
        "--protected-port",
        type=int,
        default=DEFAULT_PROTECTED_PORT,
        help="Protected service port",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=DEFAULT_DELAY,
        help="Delay between knocks in seconds",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Attempt connection to protected port after knocking",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        sequence = [int(port) for port in args.sequence.split(",")]
    except ValueError:
        raise SystemExit("Invalid sequence. Use comma-separated integers.")

    perform_knock_sequence(args.target, sequence, args.delay)

    if args.check:
        check_protected_port(args.target, args.protected_port)


if __name__ == "__main__":
    main()
