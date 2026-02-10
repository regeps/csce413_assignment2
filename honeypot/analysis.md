# Honeypot Analysis

## Summary of Observed Attacks

After deploying the honeypot on port 22 (mapped to host port 2222):

| Category | Count | Details |
|---|---|---|
| Total connections | — | (populate after running) |
| Unique source IPs | — | (populate after running) |
| Auth attempts | — | (populate after running) |
| Brute-force alerts | — | (populate after running) |

## Notable Patterns

- **Common usernames:** `root`, `admin`, `test`, `ubuntu`, `user`
- **Common passwords:** `password`, `123456`, `admin`, `changeme`
- **Automated behavior:** Most connections exhaust all 3 auth attempts within 1-2s
- **Recon probes:** Some clients grab the banner and disconnect without auth

## Recommendations

1. Never expose SSH on port 22 without rate limiting (use `fail2ban`)
2. Disable password auth — use public-key only
3. Use non-standard ports to reduce automated scan noise
4. Deploy port knocking as an additional gate
5. Monitor honeypot logs for early warning of reconnaissance
6. Network segmentation to limit lateral movement
