"""Verify deadline expiry/cancellation without opening network listeners."""
import socket
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from controller.gunicorn_worker import BoundedThreadWorker, Deadlines


class FakeSocket:
    def __init__(self):
        self.closed = threading.Event()
        self.shutdown_how = None

    def shutdown(self, how):
        self.shutdown_how = how

    def close(self):
        self.closed.set()

    def settimeout(self, seconds):
        self.timeout = seconds


class WorkerDeadlineTests(unittest.TestCase):
    def setUp(self):
        self.deadlines = Deadlines()
        self.addCleanup(self.deadlines.close)
        self.connection = SimpleNamespace(sock=FakeSocket())

    def test_expiry_closes_a_stalled_connection(self):
        self.deadlines.arm(self.connection, 0.01)
        self.assertTrue(self.connection.sock.closed.wait(1))
        self.assertEqual(self.connection.sock.shutdown_how, socket.SHUT_RDWR)

    def test_gunicorn_cleared_socket_cannot_stop_subsequent_deadlines(self):
        self.deadlines.arm(SimpleNamespace(sock=None), 0.001)
        self.deadlines.arm(self.connection, 0.02)
        self.assertTrue(self.connection.sock.closed.wait(1))

    def test_cancelled_header_cannot_close_the_body_phase(self):
        header = self.deadlines.arm(self.connection, 0.01)
        self.deadlines.cancel(header)
        body = self.deadlines.arm(self.connection, 0.12)
        self.assertFalse(self.connection.sock.closed.wait(0.04))
        self.deadlines.cancel(body)
        self.assertFalse(self.connection.sock.closed.wait(0.15))

    def test_complete_json_body_releases_its_absolute_deadline(self):
        worker = object.__new__(BoundedThreadWorker)
        worker.deadlines = self.deadlines
        self.connection._prthak_header_ticket = self.deadlines.arm(self.connection, 20)
        with patch('gunicorn.workers.gthread.ThreadWorker.handle_request', return_value='handled'):
            self.assertEqual(worker.handle_request(SimpleNamespace(method='POST', headers=[('CONTENT-LENGTH', '2')]), self.connection), 'handled')
        self.assertEqual(self.connection.sock.timeout, 30)
        self.assertEqual(len(self.deadlines.active), 1)
        self.connection.sock._prthak_body_read()
        self.assertEqual(self.deadlines.active, {})

    def test_framed_bodies_are_bounded_independently_of_method(self):
        for method in ('GET', 'HEAD', 'OPTIONS', 'TRACE', 'POST'):
            for headers in ([('Content-Length', '64')], [('TRANSFER-ENCODING', 'chunked')]):
                with self.subTest(method=method, headers=headers):
                    worker = object.__new__(BoundedThreadWorker)
                    worker.deadlines = self.deadlines
                    self.connection._prthak_header_ticket = None
                    with patch('gunicorn.workers.gthread.ThreadWorker.handle_request', return_value=True):
                        worker.handle_request(SimpleNamespace(method=method, headers=headers), self.connection)
                    self.assertIn(self.connection._prthak_body_ticket, self.deadlines.active)
                    self.connection.sock._prthak_body_read()
                    self.assertEqual(self.deadlines.active, {})

    def test_no_body_does_not_limit_a_long_response(self):
        for headers in ([], [('CONTENT-LENGTH', '0')]):
            worker = object.__new__(BoundedThreadWorker)
            worker.deadlines = self.deadlines
            self.connection._prthak_header_ticket = None
            self.connection._prthak_body_ticket = None
            with patch('gunicorn.workers.gthread.ThreadWorker.handle_request', return_value=True):
                worker.handle_request(SimpleNamespace(method='GET', headers=headers), self.connection)
            self.assertEqual(self.deadlines.active, {})

    def test_parser_failure_releases_all_tickets(self):
        worker = object.__new__(BoundedThreadWorker)
        worker.deadlines = self.deadlines
        with patch('gunicorn.workers.gthread.ThreadWorker.handle', side_effect=ValueError('invalid framing')):
            with self.assertRaises(ValueError):
                worker.handle(self.connection)
        self.assertEqual(self.deadlines.active, {})
