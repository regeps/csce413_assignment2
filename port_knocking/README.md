## Port Knocking Starter Template

This directory is a starter template for the port knocking portion of the assignment.

### What you need to implement
- Pick a protected service/port (default is 2222).
- Define a knock sequence (e.g., 1234, 5678, 9012).
- Implement a server that listens for knocks and validates the sequence.
- Open the protected port only after a valid sequence.
- Add timing constraints and reset on incorrect sequences.
- Implement a client to send the knock sequence.

### Getting started
1. Implement your server logic in `knock_server.py`.
2. Implement your client logic in `knock_client.py`.
3. Update `demo.sh` to demonstrate your flow.
4. Run from the repo root with `docker compose up port_knocking`.

### Example usage
```bash
python3 knock_client.py --target 172.20.0.40 --sequence 1234,5678,9012
```

---

### Implementation Notes

**Design:** TCP-based knocks. The server binds a listener on each knock
port and detects connections via `accept()`. Per-IP state tracking with
a 10-second timing window. iptables ACCEPT rules are inserted on valid
sequence and auto-removed after 30 seconds.

**Files:**
| File | Purpose |
|---|---|
| `knock_server.py` | Listens for knocks, manages iptables |
| `knock_client.py` | Sends TCP knock sequence |
| `demo.sh` | End-to-end demo |
| `Dockerfile` | Python 3.11 + iptables |

**Security notes:**
- Brute-forcing a 3-port sequence across 65,535 ports is impractical.
- Limitation: passive network observers can capture the sequence (replay attack).
- Improvement: HOTP-based one-time sequences would prevent replay.
