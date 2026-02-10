#!/usr/bin/env python3
"""Starter template for the honeypot assignment.

Expanded with:
- SSH banner simulation (OpenSSH 8.9p1)
- Fake KEXINIT packet to keep clients connected
- Auth attempt capture (username/password extraction)
- JSONL logging via logger.py
- Brute-force alerting
"""

import json
import logging
import os
import socket
import struct
import threading
import time

from logger import HoneypotLogger

LOG_PATH = "/app/logs/honeypot.log"
JSONL_PATH = "/app/logs/connections.jsonl"
BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
MAX_AUTH_ATTEMPTS = 3


def setup_logging():
    os.makedirs("/app/logs", exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.FileHandler(LOG_PATH), logging.StreamHandler()],
    )


def _build_fake_kexinit():
    """Minimal SSH_MSG_KEXINIT so clients stay connected longer."""
    cookie = os.urandom(16)
    payload = bytes([20]) + cookie
    for _ in range(10):
        payload += struct.pack(">I", 0)
    payload += b"\x00" + struct.pack(">I", 0)
    pad_len = 8 - ((len(payload) + 5) % 8)
    if pad_len < 4:
        pad_len += 8
    packet = struct.pack(">IB", len(payload) + pad_len + 1, pad_len)
    packet += payload + os.urandom(pad_len)
    return packet


def _extract_printable(data):
    """Pull printable strings from raw bytes."""
    parts = []
    current = []
    for ch in data.decode(errors="replace"):
        if ch.isprintable() and ch != "\x00":
            current.append(ch)
        else:
            s = "".join(current).strip()
            if len(s) >= 2:
                parts.append(s)
            current = []
    s = "".join(current).strip()
    if len(s) >= 2:
        parts.append(s)
    return parts


def handle_connection(conn, addr, hp_logger):
    """Handle one SSH honeypot connection."""
    client_ip, client_port = addr
    connect_time = time.time()
    logger = logging.getLogger("Honeypot")
    logger.info("Connection from %s:%s", client_ip, client_port)

    session = {
        "event": "connection",
        "src_ip": client_ip,
        "src_port": client_port,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "auth_attempts": [],
    }

    conn.settimeout(30.0)

    # Send SSH banner
    try:
        conn.sendall((BANNER + "\r\n").encode())
    except OSError:
        conn.close()
        return

    # Read client banner
    try:
        client_data = conn.recv(1024)
        if client_data:
            session["client_banner"] = client_data.decode(errors="replace").strip()
    except (socket.timeout, OSError):
        pass

    # Send fake KEXINIT
    try:
        conn.sendall(_build_fake_kexinit())
    except OSError:
        pass

    # Discard client KEXINIT
    try:
        conn.recv(8192)
    except (socket.timeout, OSError):
        pass

    # Auth loop
    attempts = 0
    while attempts < MAX_AUTH_ATTEMPTS:
        try:
            data = conn.recv(4096)
        except (socket.timeout, OSError):
            break
        if not data:
            break

        parts = _extract_printable(data)
        username = parts[0][:64] if len(parts) >= 1 else ""
        password = parts[1][:64] if len(parts) >= 2 else ""

        if username or password:
            attempts += 1
            session["auth_attempts"].append({
                "attempt": attempts,
                "username": username,
                "password": password,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            })
            logger.info("Auth %d from %s: user=%s pass=%s",
                        attempts, client_ip, username, password)

        # Always deny
        try:
            conn.sendall(b"\x00\x00\x00\x0c\x06\x33password\x00")
        except OSError:
            break

    session["duration_seconds"] = round(time.time() - connect_time, 2)
    session["total_auth_attempts"] = len(session["auth_attempts"])

    try:
        conn.close()
    except OSError:
        pass

    logger.info("Disconnected %s:%s (%.1fs, %d attempts)",
                client_ip, client_port,
                session["duration_seconds"],
                session["total_auth_attempts"])

    hp_logger.log_event(session)
    hp_logger.check_brute_force(client_ip, session["total_auth_attempts"])


def run_honeypot():
    logger = logging.getLogger("Honeypot")
    hp_logger = HoneypotLogger(JSONL_PATH)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", 22))
    srv.listen(50)

    logger.info("Honeypot SSH server listening on port 22")
    logger.info("Banner: %s", BANNER)

    try:
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=handle_connection,
                             args=(conn, addr, hp_logger),
                             daemon=True).start()
    except KeyboardInterrupt:
        logger.info("Shutting down")
    finally:
        srv.close()


if __name__ == "__main__":
    setup_logging()
    run_honeypot()
