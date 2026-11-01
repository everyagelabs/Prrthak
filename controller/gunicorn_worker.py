"""Bounded TLS/header/body deadlines without trusting forwarded identities."""
import heapq
import socket
import threading
import time

from gunicorn.workers.gthread import ThreadWorker


class Deadlines:
    def __init__(self):
        self.condition = threading.Condition()
        self.heap, self.active = [], {}
        self.sequence, self.closed = 0, False
        threading.Thread(target=self._run, daemon=True).start()

    def arm(self, connection, seconds):
        with self.condition:
            self.sequence += 1
            ticket = self.sequence
            self.active[ticket] = connection
            heapq.heappush(self.heap, (time.monotonic() + seconds, ticket))
            self.condition.notify()
            return ticket

    def cancel(self, ticket):
        with self.condition:
            self.active.pop(ticket, None)
            self.condition.notify()

    def close(self):
        with self.condition:
            self.closed = True
            self.condition.notify()

    def _run(self):
        while True:
            connection = None
            with self.condition:
                if self.closed:
                    return
                while self.heap and self.heap[0][1] not in self.active:
                    heapq.heappop(self.heap)
                if not self.heap:
                    self.condition.wait()
                    continue
                deadline, ticket = self.heap[0]
                remaining = deadline - time.monotonic()
                if remaining > 0:
                    self.condition.wait(remaining)
                    continue
                heapq.heappop(self.heap)
                connection = self.active.pop(ticket, None)
            if connection is not None:
                # Gunicorn clears connection.sock during ordinary close. A
                # concurrent close must not terminate the deadline collector.
                expired_socket = connection.sock
                if expired_socket is None:
                    continue
                try:
                    expired_socket.shutdown(socket.SHUT_RDWR)
                except (OSError, ValueError):
                    pass
                try:
                    expired_socket.close()
                except (OSError, ValueError):
                    pass


class BoundedThreadWorker(ThreadWorker):
    def init_process(self):
        self.deadlines = Deadlines()
        return super().init_process()

    def handle(self, connection):
        connection._prthak_header_ticket = self.deadlines.arm(connection, 20)
        connection._prthak_body_ticket = None
        try:
            return super().handle(connection)
        finally:
            self.deadlines.cancel(connection._prthak_header_ticket)
            self.deadlines.cancel(connection._prthak_body_ticket)

    def handle_request(self, request, connection):
        self.deadlines.cancel(connection._prthak_header_ticket)
        connection.sock.settimeout(30)
        # Gunicorn drains unread framed bodies before returning a keepalive
        # connection to its poller, even for GET/HEAD or unsupported methods.
        # Bound that drain too; method-based deadlines leave idle threads
        # available to an anonymous slow client indefinitely.
        has_body = any(name.upper() == "TRANSFER-ENCODING" or
                       (name.upper() == "CONTENT-LENGTH" and int(value) > 0)
                       for name, value in request.headers)
        if has_body:
            connection._prthak_body_ticket = self.deadlines.arm(connection, 30)
            connection.sock._prthak_body_read = lambda: self.deadlines.cancel(connection._prthak_body_ticket)
        else:
            connection.sock._prthak_body_read = lambda: None
        return super().handle_request(request, connection)

    def run(self):
        try:
            return super().run()
        finally:
            self.deadlines.close()
