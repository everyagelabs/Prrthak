"""Bounded token buckets for authenticated identities and trusted network peers."""
from collections import OrderedDict
import ipaddress
import threading
import time


class RateLimited(Exception):
    pass


def network_peer(identity):
    try:
        address = ipaddress.ip_address(identity)
    except ValueError:
        return "unknown"
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            return str(address.ipv4_mapped)
        return str(ipaddress.IPv6Network((address, 64), strict=False))
    return str(address)


class RequestLimits:
    RATES = {"agent": (10, 40), "admin": (10, 50), "enrollment": (2, 20), "login": (.1, 10), "anonymous": (5, 40)}
    CEILINGS = {"global": (5000, 10000), "login": (4, 60), "enrollment": (20, 200)}

    def __init__(self, *, max_entries=20000, clock=time.monotonic):
        self.clock, self.max_entries = clock, max_entries
        self.lock, self.buckets = threading.Lock(), OrderedDict()
        self.ceilings = {}

    @staticmethod
    def _refill(bucket, current, rate, burst):
        if bucket is None:
            return float(burst), current
        tokens, previous = bucket
        return min(float(burst), tokens + max(0, current - previous) * rate), max(previous, current)

    def _take_ceiling(self, category, current):
        tokens, updated = self._refill(self.ceilings.get(category), current, *self.CEILINGS[category])
        accepted = tokens >= 1
        self.ceilings[category] = (tokens - int(accepted), updated)
        return accepted

    def check(self, category, identity):
        if category in ("login", "enrollment"):
            identity = network_peer(identity)
        with self.lock:
            current = self.clock()
            if category == "global":
                accepted = self._take_ceiling(category, current)
            else:
                key = (category, str(identity)[:256])
                tokens, updated = self._refill(self.buckets.pop(key, None), current, *self.RATES[category])
                accepted = tokens >= 1
                # A peer already over its own limit cannot spend the shared budget.
                if accepted and category in self.CEILINGS:
                    accepted = self._take_ceiling(category, current)
                self.buckets[key] = (tokens - int(accepted), updated)
                while len(self.buckets) > self.max_entries:
                    self.buckets.popitem(last=False)
        if not accepted:
            raise RateLimited("Request limit reached; retry after a short delay")
