"""Logging helpers for the honeypot."""

import json
import logging
import os
import threading
import time


class HoneypotLogger:
    """JSONL event logger with brute-force detection."""

    def __init__(self, jsonl_path, brute_threshold=5, brute_window=60):
        self._path = jsonl_path
        self._threshold = brute_threshold
        self._window = brute_window
        self._lock = threading.Lock()
        self._ip_attempts = {}
        os.makedirs(os.path.dirname(jsonl_path), exist_ok=True)

    def log_event(self, event_dict):
        """Append event as a JSON line."""
        line = json.dumps(event_dict, default=str)
        with self._lock:
            with open(self._path, "a") as f:
                f.write(line + "\n")

    def check_brute_force(self, ip, num_attempts):
        """Alert if IP exceeds threshold within window."""
        now = time.time()
        with self._lock:
            self._ip_attempts.setdefault(ip, [])
            self._ip_attempts[ip].extend([now] * num_attempts)
            cutoff = now - self._window
            self._ip_attempts[ip] = [t for t in self._ip_attempts[ip] if t >= cutoff]
            total = len(self._ip_attempts[ip])

        if total >= self._threshold:
            alert = {
                "event": "brute_force_alert",
                "src_ip": ip,
                "attempts_in_window": total,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
            logging.warning("BRUTE-FORCE ALERT: %s (%d attempts)", ip, total)
            self.log_event(alert)


def create_logger(jsonl_path="/app/logs/connections.jsonl"):
    """Factory function matching the original starter signature."""
    return HoneypotLogger(jsonl_path)
