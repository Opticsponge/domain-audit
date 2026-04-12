"""Thread-safe rate limiter for outbound HTTP requests.

Uses a token-bucket algorithm with per-host and global limits to avoid
hammering third-party APIs (crt.sh, ip-api.com, CertSpotter, RDAP servers)
and to be a good citizen when scanning target domains.
"""

from __future__ import annotations

import threading
import time
from urllib.parse import urlparse


class _TokenBucket:
    """Simple token bucket — thread-safe."""

    __slots__ = ("_capacity", "_rate", "_tokens", "_last_refill", "_lock")

    def __init__(self, rate: float, capacity: int):
        self._rate = rate          # tokens per second
        self._capacity = capacity  # max burst
        self._tokens = float(capacity)
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, timeout: float = 30.0) -> bool:
        """Block until a token is available or *timeout* seconds elapse."""
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                self._refill()
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return True
                wait = (1.0 - self._tokens) / self._rate
            # Sleep outside the lock
            if time.monotonic() + wait > deadline:
                return False
            time.sleep(min(wait, 0.5))

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
        self._last_refill = now


class RateLimiter:
    """Per-host + global rate limiter.

    Defaults:
        global_rps=10   — max 10 requests/second across all hosts
        host_rps=2      — max 2 requests/second to any single host
        host_burst=5    — allow short bursts of up to 5 to one host

    These are conservative defaults. ip-api.com allows 45/min (~0.75/s),
    crt.sh is undocumented but slow, and target domains shouldn't be hammered.
    """

    def __init__(
        self,
        global_rps: float = 10.0,
        host_rps: float = 2.0,
        host_burst: int = 5,
    ):
        self._global = _TokenBucket(rate=global_rps, capacity=int(global_rps * 2))
        self._host_rps = host_rps
        self._host_burst = host_burst
        self._hosts: dict[str, _TokenBucket] = {}
        self._lock = threading.Lock()

    def acquire(self, url: str, timeout: float = 30.0) -> bool:
        """Wait for permission to make a request to *url*.

        Returns True if acquired within timeout, False otherwise.
        """
        host = urlparse(url).hostname or url

        with self._lock:
            if host not in self._hosts:
                self._hosts[host] = _TokenBucket(
                    rate=self._host_rps,
                    capacity=self._host_burst,
                )
            host_bucket = self._hosts[host]

        # Acquire both global and per-host tokens
        if not self._global.acquire(timeout):
            return False
        if not host_bucket.acquire(timeout):
            return False
        return True


# Module-level singleton — shared across all scanners in a session.
_limiter = RateLimiter()


def throttle(url: str) -> None:
    """Call before making an HTTP request. Blocks until rate limit allows."""
    _limiter.acquire(url)
