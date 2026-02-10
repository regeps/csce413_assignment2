## Honeypot Starter Template

This directory is a starter template for the honeypot portion of the assignment.

### What you need to implement
- Choose a protocol (SSH, HTTP, or multi-protocol).
- Simulate a convincing service banner and responses.
- Log connection metadata, authentication attempts, and attacker actions.
- Store logs under `logs/` and include an `analysis.md` summary.
- Update `honeypot.py` and `logger.py` (and add modules as needed) to implement the honeypot.

### Getting started
1. Implement your honeypot logic in `honeypot.py`.
2. Wire logging in `logger.py` and record results in `logs/`.
3. Summarize your findings in `analysis.md`.
4. Run from the repo root with `docker-compose up honeypot`.

---

### Implementation Notes

**Protocol:** Low-interaction SSH honeypot on port 22.

**How it works:**
1. Sends realistic `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6` banner.
2. Sends a minimal fake KEXINIT packet so clients stay connected.
3. Captures up to 3 auth attempts per connection (username + password).
4. Logs everything to `logs/connections.jsonl` via `HoneypotLogger`.
5. Alerts on brute-force (5+ attempts from same IP within 60s).

**Files:**
| File | Purpose |
|---|---|
| `honeypot.py` | SSH server simulation |
| `logger.py` | JSONL logger + brute-force detection |
| `logs/` | Runtime log output |
| `analysis.md` | Post-run analysis |
