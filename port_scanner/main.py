#!/usr/bin/env python3
"""
Port Scanner - Starter Template for Students
Assignment 2: Network Security

This is a STARTER TEMPLATE to help you get started.
You should expand and improve upon this basic implementation.

TODO for students:
1. Implement multi-threading for faster scans              [DONE]
2. Add banner grabbing to detect services                  [DONE]
3. Add support for CIDR notation (e.g., 192.168.1.0/24)   [DONE]
4. Add different scan types (SYN scan, UDP scan, etc.)
5. Add output formatting (JSON, CSV, etc.)                 [DONE]
6. Implement timeout and error handling                    [DONE]
7. Add progress indicators                                 [DONE]
8. Add service fingerprinting
"""

import argparse
import ipaddress
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


def scan_port(target, port, timeout=1.0):
    """
    Scan a single port on the target host.

    Returns:
        tuple: (port, is_open, banner)
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        if result == 0:
            banner = grab_banner(sock, timeout)
            sock.close()
            return (port, True, banner)
        sock.close()
        return (port, False, "")
    except (socket.timeout, ConnectionRefusedError, OSError):
        return (port, False, "")


def grab_banner(sock, timeout=1.0):
    """Try to read a banner from an already-connected socket."""
    try:
        sock.settimeout(timeout)
        data = sock.recv(1024)
        if data:
            return data.decode(errors="replace").strip()
    except (socket.timeout, OSError):
        pass
    try:
        sock.sendall(b"GET / HTTP/1.0\r\nHost: target\r\n\r\n")
        sock.settimeout(timeout)
        data = sock.recv(4096)
        if data:
            return data.decode(errors="replace").strip()[:512]
    except (socket.timeout, OSError, BrokenPipeError):
        pass
    return ""


def scan_range(target, start_port, end_port, threads=100, timeout=1.0):
    """
    Scan a range of ports on the target host using threading.

    Returns:
        list: List of dicts with port, state, banner, time_ms
    """
    open_ports = []
    ports = list(range(start_port, end_port + 1))
    total = len(ports)

    print(f"[*] Scanning {target} from port {start_port} to {end_port}")
    print(f"[*] {total} ports | {threads} threads")

    def _scan(p):
        start = time.time()
        port_num, is_open, banner = scan_port(target, p, timeout)
        elapsed = round((time.time() - start) * 1000, 1)
        if is_open:
            return {"port": port_num, "state": "open", "banner": banner, "time_ms": elapsed}
        return None

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(_scan, p): p for p in ports}
        done = 0
        for f in as_completed(futures):
            done += 1
            if done % 500 == 0:
                pct = done * 100 // total
                print(f"    ... {done}/{total} scanned ({pct}%)", file=sys.stderr, flush=True)
            result = f.result()
            if result:
                open_ports.append(result)

    print(f"    ... {total}/{total} scanned (100%)", file=sys.stderr, flush=True)

    open_ports.sort(key=lambda r: r["port"])
    return open_ports


def cidr_to_hosts(cidr_str):
    """Convert CIDR string to list of host IPs, or return as single host."""
    try:
        net = ipaddress.ip_network(cidr_str, strict=False)
        if net.prefixlen == 32:
            return [str(net.network_address)]
        return [str(h) for h in net.hosts()]
    except ValueError:
        return [cidr_str]


def main():
    """Main function with argparse CLI."""
    parser = argparse.ArgumentParser(description="TCP port scanner")
    parser.add_argument("--target", "-t", required=True,
                        help="Target IP, hostname, or CIDR range")
    parser.add_argument("--ports", "-p", default="1-1024",
                        help="Port range (e.g. 1-10000)")
    parser.add_argument("--threads", type=int, default=100,
                        help="Thread count (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="Timeout in seconds (default: 1.0)")
    parser.add_argument("--format", "-f", choices=["text", "json"], default="text",
                        help="Output format")
    args = parser.parse_args()

    hosts = cidr_to_hosts(args.target)

    # Parse port range
    if "-" in args.ports:
        lo, hi = args.ports.split("-", 1)
        start_port, end_port = int(lo), int(hi)
    else:
        start_port = end_port = int(args.ports)

    print(f"[*] Starting port scan")
    print(f"[*] Target(s): {args.target} ({len(hosts)} host(s))")

    all_results = []
    scan_start = time.time()

    for host in hosts:
        results = scan_range(host, start_port, end_port, args.threads, args.timeout)
        all_results.append({"target": host, "results": results})

        if args.format == "text":
            print(f"\n{'='*60}")
            print(f"  Results for {host}")
            print(f"{'='*60}")
            print(f"  {'PORT':<8} {'STATE':<8} {'BANNER'}")
            print(f"  {'-'*6:<8} {'-'*6:<8} {'-'*40}")
            for r in results:
                b = r["banner"][:50].replace("\n", " ") if r["banner"] else ""
                print(f"  {r['port']:<8} {r['state']:<8} {b}")
            print(f"\n  [+] {len(results)} open port(s)")

    elapsed = round(time.time() - scan_start, 2)
    print(f"\n[*] Scan complete in {elapsed}s", file=sys.stderr)

    if args.format == "json":
        print(json.dumps(all_results, indent=2))


if __name__ == "__main__":
    main()
