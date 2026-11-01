"""Bounded worker-local physical connections; no data or authority caching."""
from contextlib import contextmanager
from dataclasses import dataclass
import os
import threading
import time


class PoolUnavailable(RuntimeError):
    pass


@dataclass
class Entry:
    connection: object
    created_at: float
    settings_fingerprint: str | None = None


class WorkerPool:
    def __init__(self, factory, maximum, wait_seconds, validate):
        self.factory, self.maximum, self.wait_seconds, self.validate = factory, maximum, wait_seconds, validate
        self.pid = os.getpid()
        self.condition = threading.Condition()
        self.idle, self.total, self.closed = [], 0, False

    @staticmethod
    def healthy(connection):
        return not connection.closed and not connection.broken and int(connection.info.transaction_status) == 0

    def discard(self, entry):
        try:
            entry.connection.close()
        finally:
            with self.condition:
                self.total -= 1
                self.condition.notify()

    def take(self, deadline):
        with self.condition:
            while True:
                if self.pid != os.getpid():
                    raise PoolUnavailable("A worker cannot reuse another process's database sockets")
                if self.closed:
                    raise PoolUnavailable("The database worker is stopping")
                if self.idle:
                    return self.idle.pop()
                if self.total < self.maximum:
                    self.total += 1
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise PoolUnavailable("Database connection capacity is busy; retry")
                self.condition.wait(remaining)
        try:
            return Entry(self.factory(), time.monotonic())
        except BaseException:
            with self.condition:
                self.total -= 1
                self.condition.notify()
            raise

    @contextmanager
    def connection(self):
        deadline, entry = time.monotonic() + self.wait_seconds, None
        for attempt in range(2):
            candidate = self.take(deadline)
            try:
                if not self.healthy(candidate.connection) or time.monotonic() - candidate.created_at > 60:
                    raise PoolUnavailable("Database connection requires fresh admission")
                self.validate(candidate)
                entry = candidate
                break
            except Exception:
                self.discard(candidate)
                if attempt:
                    raise PoolUnavailable("Database connection is not admitted for this worker") from None
        try:
            yield entry.connection
        finally:
            if not self.healthy(entry.connection):
                self.discard(entry)
            else:
                with self.condition:
                    close = self.closed
                    if not close:
                        self.idle.append(entry)
                        self.condition.notify()
                if close:
                    self.discard(entry)

    def close(self):
        with self.condition:
            self.closed, idle = True, self.idle
            self.idle = []
            self.condition.notify_all()
        for entry in idle:
            self.discard(entry)
