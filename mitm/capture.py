#!/usr/bin/env python3
"""
MITM Traffic Capture – Assignment 2: Network Security

A raw-socket packet sniffer that captures and analyzes MySQL (port 3306)
traffic between the web application and database containers on the Docker
bridge network.

How it works
------------
1. Opens a raw socket on the Docker bridge interface.
2. Parses Ethernet -> IP -> TCP headers manually (stdlib only).
3. Filters for TCP segments where src or dst port == 3306.
4. Extracts printable ASCII from the TCP payload – MySQL queries and
   result-set data travel in plaintext when SSL is disabled.
5. Writes captured packets to a log file and prints them to stdout.

Usage (run with root/sudo from a host that can see the Docker bridge):
  sudo python3 mitm/capture.py
  sudo python3 mitm/capture.py --interface br-<network_id> --output mitm/capture.log

Alternatively, use tcpdump and then analyze with this script:
  sudo tcpdump -i br-<network_id> -A -s 0 'port 3306' -w mitm/capture.pcap

NOTE: On Linux, raw sockets require CAP_NET_RAW or root privileges.
      On macOS/Windows you may need to use tcpdump/Wireshark instead.

Only standard-library modules are used.
"""

import argparse
import os
import socket
import struct
import sys
import time


# ---------------------------------------------------------------------------
# Packet parsing helpers
# ---------------------------------------------------------------------------

def parse_ip_header(data):
    """Parse an IPv4 header and return (src_ip, dst_ip, protocol, header_len, total_len)."""
    if len(data) < 20:
        return None
    version_ihl = data[0]
    ihl = (version_ihl & 0x0F) * 4
    total_length = struct.unpack("!H", data[2:4])[0]
    protocol = data[9]
    src_ip = socket.inet_ntoa(data[12:16])
    dst_ip = socket.inet_ntoa(data[16:20])
    return src_ip, dst_ip, protocol, ihl, total_length


def parse_tcp_header(data):
    """Parse a TCP header and return (src_port, dst_port, header_len, flags)."""
    if len(data) < 20:
        return None
    src_port, dst_port = struct.unpack("!HH", data[0:4])
    data_offset = (data[12] >> 4) * 4
    flags = data[13]
    return src_port, dst_port, data_offset, flags


def extract_printable(data, min_run=4):
    """Return printable ASCII runs of at least *min_run* characters."""
    runs = []
    current = []
    for byte in data:
        ch = chr(byte) if 32 <= byte < 127 else None
        if ch:
            current.append(ch)
        else:
            if len(current) >= min_run:
                runs.append("".join(current))
            current = []
    if len(current) >= min_run:
        runs.append("".join(current))
    return runs


# ---------------------------------------------------------------------------
# Sniffer
# ---------------------------------------------------------------------------

def sniff_mysql(interface, target_port, output_path, duration):
    """Sniff packets on *interface* and log MySQL-related traffic."""

    print(f"[*] MITM Capture starting", file=sys.stderr)
    print(f"[*] Interface : {interface or 'default'}", file=sys.stderr)
    print(f"[*] Filter    : TCP port {target_port}", file=sys.stderr)
    print(f"[*] Output    : {output_path}", file=sys.stderr)
    print(f"[*] Duration  : {duration}s (0 = unlimited)", file=sys.stderr)
    print(f"[*] Press Ctrl-C to stop\n", file=sys.stderr)

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    # Open raw socket (Linux only – requires root)
    try:
        raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        if interface:
            raw.bind((interface, 0))
    except (AttributeError, OSError) as exc:
        print(f"[!] Cannot open raw socket: {exc}", file=sys.stderr)
        print("[!] This script requires Linux with root privileges.", file=sys.stderr)
        print("[!] Alternative: use tcpdump to capture traffic:", file=sys.stderr)
        print(f"[!]   sudo tcpdump -i <interface> -A -s 0 'port {target_port}' -w mitm/capture.pcap",
              file=sys.stderr)
        sys.exit(1)

    start_time = time.time()
    pkt_count = 0

    with open(output_path, "a") as log:
        try:
            while True:
                if duration and (time.time() - start_time) >= duration:
                    break

                packet, _ = raw.recvfrom(65535)

                # Skip Ethernet header (14 bytes)
                if len(packet) < 14:
                    continue
                eth_proto = struct.unpack("!H", packet[12:14])[0]
                if eth_proto != 0x0800:  # IPv4 only
                    continue

                ip_data = packet[14:]
                ip_parsed = parse_ip_header(ip_data)
                if ip_parsed is None:
                    continue
                src_ip, dst_ip, proto, ip_hlen, ip_total = ip_parsed

                if proto != 6:  # TCP only
                    continue

                tcp_data = ip_data[ip_hlen:]
                tcp_parsed = parse_tcp_header(tcp_data)
                if tcp_parsed is None:
                    continue
                src_port, dst_port, tcp_hlen, flags = tcp_parsed

                # Filter for MySQL traffic
                if src_port != target_port and dst_port != target_port:
                    continue

                payload = tcp_data[tcp_hlen:]
                if not payload:
                    continue

                pkt_count += 1
                ts = time.strftime("%Y-%m-%d %H:%M:%S")
                direction = "REQUEST " if dst_port == target_port else "RESPONSE"

                printable = extract_printable(payload)
                if not printable:
                    continue

                header_line = (f"[{ts}] {direction} {src_ip}:{src_port} -> "
                               f"{dst_ip}:{dst_port} ({len(payload)} bytes)")
                print(header_line)
                log.write(header_line + "\n")

                for run in printable:
                    print(f"    {run}")
                    log.write(f"    {run}\n")

                    # Highlight flags if found
                    if "FLAG{" in run:
                        flag_start = run.index("FLAG{")
                        flag_end = run.index("}", flag_start) + 1
                        flag = run[flag_start:flag_end]
                        alert = f"  >>> CAPTURED FLAG: {flag}"
                        print(alert)
                        log.write(alert + "\n")

                log.write("\n")
                log.flush()

        except KeyboardInterrupt:
            pass

    elapsed = round(time.time() - start_time, 1)
    print(f"\n[*] Capture stopped. {pkt_count} MySQL packets logged in {elapsed}s",
          file=sys.stderr)


# ---------------------------------------------------------------------------
# Offline analysis helper
# ---------------------------------------------------------------------------

def analyze_log(path):
    """Read a capture log file and summarise interesting findings."""
    if not os.path.exists(path):
        print(f"[!] File not found: {path}", file=sys.stderr)
        return

    flags_found = []
    queries = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if "FLAG{" in line:
                start = line.index("FLAG{")
                end = line.index("}", start) + 1
                flags_found.append(line[start:end])
            if "SELECT" in line.upper() or "INSERT" in line.upper():
                queries.append(line)

    print(f"\n{'='*60}")
    print(f"  Analysis of {path}")
    print(f"{'='*60}")
    print(f"  SQL queries observed : {len(queries)}")
    for q in queries[:20]:
        print(f"    {q}")
    print(f"\n  Flags captured       : {len(flags_found)}")
    for f in set(flags_found):
        print(f"    {f}")
    print(f"{'='*60}\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="MITM MySQL traffic capture")
    parser.add_argument("--interface", "-i", default=None,
                        help="Network interface to sniff on (e.g. br-abc123)")
    parser.add_argument("--port", "-p", type=int, default=3306,
                        help="Target port to filter (default: 3306)")
    parser.add_argument("--output", "-o", default="mitm/capture.log",
                        help="Output log file (default: mitm/capture.log)")
    parser.add_argument("--duration", "-d", type=int, default=0,
                        help="Capture duration in seconds (0 = unlimited)")
    parser.add_argument("--analyze", "-a", default=None,
                        help="Analyze an existing capture log instead of sniffing")
    args = parser.parse_args()

    if args.analyze:
        analyze_log(args.analyze)
    else:
        sniff_mysql(args.interface, args.port, args.output, args.duration)


if __name__ == "__main__":
    main()
