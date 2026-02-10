#!/usr/bin/env python3
"""Starter template for the port knocking server.

Expanded with:
- TCP listeners on each knock port
- Per-IP sequence tracking with timing window
- iptables integration to open/close protected port
- Auto-close after configurable grace period
"""

import argparse
import logging
import socket
import subprocess
import threading
import time

DEFAULT_KNOCK_SEQUENCE = [1234, 5678, 9012]
DEFAULT_PROTECTED_PORT = 2222
DEFAULT_SEQUENCE_WINDOW = 10.0
DEFAULT_OPEN_SECONDS = 30


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler()],
    )


def _iptables(args_list):
    """Run an iptables command, log on failure."""
    try:
        subprocess.run(["iptables"] + args_list, check=True,
                       capture_output=True, timeout=5)
    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        logging.warning("iptables failed: %s", e)


def open_protected_port(client_ip, protected_port):
    """Open the protected port for a specific client IP."""
    _iptables(["-I", "INPUT", "1", "-p", "tcp", "-s", client_ip,
               "--dport", str(protected_port), "-j", "ACCEPT"])
    logging.info("Opened port %s for %s", protected_port, client_ip)


def close_protected_port(client_ip, protected_port):
    """Close the protected port for a specific client IP."""
    _iptables(["-D", "INPUT", "-p", "tcp", "-s", client_ip,
               "--dport", str(protected_port), "-j", "ACCEPT"])
    logging.info("Closed port %s for %s", protected_port, client_ip)


def block_protected_port(protected_port):
    """Block the protected port by default."""
    _iptables(["-A", "INPUT", "-p", "tcp", "--dport",
               str(protected_port), "-j", "DROP"])
    logging.info("Default DROP rule for port %s", protected_port)


# Per-IP knock tracking: {ip: (next_index, first_knock_time)}
_progress = {}
_lock = threading.Lock()


def record_knock(ip, port, sequence, window):
    """Record a knock; return True if the sequence is now complete."""
    with _lock:
        idx, first_time = _progress.get(ip, (0, None))
        expected = sequence[idx]

        if port != expected:
            # Wrong port -- maybe it's the start of a new sequence
            if port == sequence[0]:
                _progress[ip] = (1, time.time())
            else:
                _progress.pop(ip, None)
            return False

        if idx == 0:
            first_time = time.time()

        if time.time() - first_time > window:
            _progress.pop(ip, None)
            return False

        next_idx = idx + 1
        logging.info("KNOCK %s port %s (%d/%d)", ip, port, next_idx, len(sequence))

        if next_idx >= len(sequence):
            _progress.pop(ip, None)
            return True

        _progress[ip] = (next_idx, first_time)
        return False


def listen_on_port(knock_port, sequence, window, protected_port, open_seconds):
    """Listen on a single knock port for TCP connections."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", knock_port))
    srv.listen(5)
    logging.info("Listening on knock port %s", knock_port)

    while True:
        conn, addr = srv.accept()
        conn.close()
        client_ip = addr[0]
        if record_knock(client_ip, knock_port, sequence, window):
            logging.info("SEQUENCE COMPLETE from %s", client_ip)
            open_protected_port(client_ip, protected_port)

            def _close(ip=client_ip):
                time.sleep(open_seconds)
                close_protected_port(ip, protected_port)

            threading.Thread(target=_close, daemon=True).start()


def listen_for_knocks(sequence, window_seconds, protected_port,
                      open_seconds=DEFAULT_OPEN_SECONDS):
    """Start listeners on all knock ports and block forever."""
    logger = logging.getLogger("KnockServer")
    logger.info("Knock sequence : %s", sequence)
    logger.info("Protected port : %s", protected_port)
    logger.info("Window         : %ss", window_seconds)

    block_protected_port(protected_port)

    for port in set(sequence):
        t = threading.Thread(target=listen_on_port,
                             args=(port, sequence, window_seconds,
                                   protected_port, open_seconds),
                             daemon=True)
        t.start()

    while True:
        time.sleep(1)


def parse_args():
    parser = argparse.ArgumentParser(description="Port knocking server")
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
        "--window",
        type=float,
        default=DEFAULT_SEQUENCE_WINDOW,
        help="Seconds allowed to complete the sequence",
    )
    parser.add_argument(
        "--open-seconds",
        type=int,
        default=DEFAULT_OPEN_SECONDS,
        help="Seconds the port stays open (default: 30)",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    setup_logging()

    try:
        sequence = [int(port) for port in args.sequence.split(",")]
    except ValueError:
        raise SystemExit("Invalid sequence. Use comma-separated integers.")

    listen_for_knocks(sequence, args.window, args.protected_port, args.open_seconds)


if __name__ == "__main__":
    main()
