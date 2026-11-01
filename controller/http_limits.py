"""Bounded token buckets keyed by authenticated identity, not proxy headers."""
from collections import OrderedDict
import threading
import time


class RateLimited(Exception):
    pass


class RequestLimits:
    RATES = {"global": (5000, 10000), "agent": (10, 40), "admin": (10, 50), "enrollment": (2, 20), "login": (.1, 10), "anonymous": (5, 40)}

    def __init__(self, *, max_entries=20000, clock=time.monotonic):
        self.clock, self.max_entries = clock, max_entries
        self.lock, self.buckets = threading.Lock(), OrderedDict()

    def check(self, category, identity):
        rate, burst = self.RATES[category]
        current, key = self.clock(), (category, str(identity)[:256])
        with self.lock:
            tokens, previous = self.buckets.pop(key, (float(burst), current))
            tokens = min(float(burst), tokens + max(0, current - previous) * rate)
            accepted = tokens >= 1
            self.buckets[key] = (tokens - 1 if accepted else tokens, current)
            while len(self.buckets) > self.max_entries:
                self.buckets.popitem(last=False)
        if not accepted:
            raise RateLimited("Request limit reached; retry after a short delay")
