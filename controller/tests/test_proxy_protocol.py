import io
import ipaddress
import socket
import ssl
import struct
import unittest
from unittest.mock import Mock, patch

from controller.proxy_protocol import SIGNATURE, router_client_address


class ApplianceProxyProtocolTests(unittest.TestCase):
    router = "172.18.0.3"

    def header(self, source, *, version=0x21, tlv=b""):
        address = ipaddress.ip_address(source)
        family = 0x11 if address.version == 4 else 0x21
        addresses = address.packed + address.packed + struct.pack("!HH", 43123, 8787)
        payload = addresses + tlv
        return SIGNATURE + struct.pack("!BBH", version, family, len(payload)) + payload

    def transport(self, raw, source=None):
        stream = io.BytesIO(raw)
        connection = Mock()
        connection.getpeername.return_value = (source or self.router, 43124)
        connection.recv.side_effect = lambda size: stream.read(min(size, 3))
        return connection, stream

    def resolver(self):
        return patch("controller.proxy_protocol.socket.getaddrinfo",
                     return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", (self.router, 0))])

    def test_fragmented_proxy_header_leaves_tls_bytes_unread(self):
        for source in ("192.0.2.12", "2001:db8::12"):
            with self.subTest(source=source), self.resolver():
                tls = b"\x16\x03\x01 TLS ClientHello"
                connection, stream = self.transport(self.header(source, tlv=b"\x04\x00\x00") + tls)
                self.assertEqual(router_client_address(connection), (source, 43123))
                self.assertEqual(stream.read(), tls)

    def test_local_health_check_uses_the_router_address(self):
        connection, _ = self.transport(SIGNATURE + struct.pack("!BBH", 0x20, 0, 0))
        with self.resolver():
            self.assertEqual(router_client_address(connection), (self.router, 43124))

    def test_forged_address_from_another_peer_is_rejected_before_reading(self):
        connection, _ = self.transport(self.header("192.0.2.12"), source="172.18.0.4")
        with self.resolver(), self.assertRaises(ssl.SSLError):
            router_client_address(connection)
        connection.recv.assert_not_called()

    def test_truncated_and_wrong_protocol_headers_are_rejected(self):
        valid = self.header("192.0.2.12")
        for raw in (valid[:-1], valid[:15], self.header("192.0.2.12", version=0x31),
                    SIGNATURE + struct.pack("!BBH", 0x21, 0x31, 0)):
            with self.subTest(raw=raw), self.resolver(), self.assertRaises(ssl.SSLError):
                router_client_address(self.transport(raw)[0])
