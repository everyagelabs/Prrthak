"""Gunicorn WSGI transport retaining the real mTLS socket identity.

The existing API dispatcher owns authorization. Gunicorn owns HTTP framing,
bounded worker/thread pools, TLS handshake handling and connection lifecycle.
No forwarded certificate or identity header is accepted by this adapter.
"""
import logging
import ssl
import socket
import os
from email.message import Message
from http import HTTPStatus
from urllib.parse import urlsplit

from .app import handler_for
from .listener_address import format_listener

LOG = logging.getLogger("Prṛthak.controller")


class ResponseWriter:
    def __init__(self, limit, start_response, status, headers):
        self.size, self.limit = 0, limit
        self.start_response, self.status, self.headers = start_response, status, headers
        self.started, self.output = False, None

    def start(self):
        if not self.started:
            headers = [(key, value) for key, value in self.headers if key.lower() not in ("connection", "transfer-encoding", "keep-alive", "upgrade")]
            self.output = self.start_response(str(self.status[0]) + " " + HTTPStatus(self.status[0]).phrase, headers)
            self.started = True

    def write(self, value):
        if self.size + len(value) > self.limit:
            raise RuntimeError("Response exceeds this operation's transport limit")
        self.start()
        self.size += len(value)
        self.output(value)
        return len(value)


def application(app):
    handler_type = handler_for(app)

    def dispatch(environ, start_response):
        connection = environ.get("gunicorn.socket")
        if not isinstance(connection, ssl.SSLSocket):
            value = b'{"error":"Verified TLS is unavailable"}'
            start_response("503 Service Unavailable", [("Content-Type", "application/json"), ("Content-Length", str(len(value)))])
            return [value]
        request = object.__new__(handler_type)
        request.connection = connection
        request.client_address = (environ.get("REMOTE_ADDR", ""), int(environ.get("REMOTE_PORT") or 0))
        request.command = environ["REQUEST_METHOD"]
        request.path = environ.get("RAW_URI") or environ.get("PATH_INFO", "/") + ("?" + environ["QUERY_STRING"] if environ.get("QUERY_STRING") else "")
        request.request_version = environ.get("SERVER_PROTOCOL", "HTTP/1.1")
        request.close_connection = False
        request.rfile = environ["wsgi.input"]
        def read_body():
            value = handler_type.body(request)
            callback = getattr(connection, "_prthak_body_read", None)
            if callback:
                callback()
            return value
        request.body = read_body
        request.headers = Message()
        for key, value in environ.items():
            if key.startswith("HTTP_"):
                request.headers.add_header(key[5:].replace("_", "-"), str(value))
        for source, target in (("CONTENT_TYPE", "Content-Type"), ("CONTENT_LENGTH", "Content-Length")):
            if environ.get(source):
                request.headers.add_header(target, str(environ[source]))
        status, headers = [500], []
        writer = ResponseWriter(1024 * 1024 * 1024 + 4096 if "/platform/backups/" in request.path else 64 * 1024 * 1024, start_response, status, headers)
        request.wfile = writer
        def begin_response(code, message=None):
            if writer.started:
                raise RuntimeError("Response was already streamed; close this connection")
            status[0] = int(code)
            headers.clear()
            writer.size = 0
        request.send_response = begin_response
        request.send_header = lambda key, value: headers.append((str(key), str(value)))
        request.end_headers = lambda: None
        request.dispatch()
        writer.start()
        if request.close_connection:
            try:
                connection.shutdown(socket.SHUT_RD)
            except OSError:
                pass
        LOG.info("%s %s", request.command, urlsplit(request.path).path)

        return []

    return dispatch


def serve(app, host, port, *, certificate, private_key, ca, workers=1, threads=32, extra_binds=()):
    try:
        from gunicorn.app.base import BaseApplication
    except ImportError:
        raise RuntimeError("Production serving requires gunicorn from controller/requirements.txt") from None
    if not 1 <= workers <= 16 or not 2 <= threads <= 128:
        raise ValueError("Production HTTP workers/threads are outside supported bounds")

    def tls_context(config, factory):
        context = factory()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.verify_mode = ssl.CERT_OPTIONAL
        return context

    def worker_started(worker):
        if app.store.ha:
            try:
                metadata_max = int(os.environ.get("SEG_DB_POOL_META_MAX", "8"))
                traffic_max = int(os.environ.get("SEG_DB_POOL_TRAFFIC_MAX", "2"))
                wait_seconds = int(os.environ.get("SEG_DB_POOL_WAIT_SECONDS", "5"))
            except ValueError:
                raise ValueError("Database worker pool settings must be integers") from None
            app.store.enable_worker_pool(metadata_max, traffic_max, wait_seconds)
        app.start_jobs()

    def worker_stopped(server, worker):
        app.stop.set()
        for thread in app.threads:
            thread.join(timeout=2)
        if app.store.ha:
            app.store.close_worker_pool()

    class Production(BaseApplication):
        def load_config(self):
            address = format_listener(host, port)
            options = {"bind": [address, *extra_binds], "workers": workers, "threads": threads, "worker_class": "controller.gunicorn_worker.BoundedThreadWorker",
                       "worker_connections": 2048, "backlog": 512, "timeout": 90, "graceful_timeout": 30, "keepalive": 5,
                       "certfile": str(certificate), "keyfile": str(private_key), "ca_certs": str(ca), "cert_reqs": ssl.CERT_OPTIONAL,
                       "ssl_context": tls_context, "do_handshake_on_connect": False, "forwarded_allow_ips": "", "secure_scheme_headers": {},
                       "limit_request_line": 4094, "limit_request_fields": 100, "limit_request_field_size": 8190,
                       "post_worker_init": worker_started, "worker_exit": worker_stopped, "accesslog": None, "errorlog": "-", "loglevel": "warning"}
            for name, value in options.items():
                self.cfg.set(name, value)

        def load(self):
            return application(app)

    Production().run()
