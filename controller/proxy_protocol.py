"""Receive the appliance router's PROXY v2 header before starting TLS."""

import ipaddress
import socket
import ssl
import struct


ROUTER_PROXY_PORTS = {"management": 18787, "control": 18788, "discovery": 18789}
SIGNATURE = b"\r\n\r\n\0\r\nQUIT\n"
TRANSPORT = {0x11: (4, 12), 0x21: (16, 36)}


def read_exact(connection, length):
    data = bytearray()
    while len(data) < length:
        block = connection.recv(length - len(data))
        if not block:
            raise ssl.SSLError("Incomplete appliance router header")
        data.extend(block)
    return data


def router_client_address(connection):
    """Accept metadata only on a private listener and from the Docker router."""
    peer = connection.getpeername()[:2]
    try:
        # The Compose service alias is resolved afresh after router recreation.
        addresses = socket.getaddrinfo("router.", None, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror:
        raise ssl.SSLError("Appliance router address is unavailable") from None
    if {address[4][0] for address in addresses} != {peer[0]}:
        raise ssl.SSLError("Untrusted appliance router peer")

    header = read_exact(connection, 16)
    version, family, length = struct.unpack("!BBH", header[12:])
    if header[:12] != SIGNATURE or version not in (0x20, 0x21):
        raise ssl.SSLError("Invalid appliance router header")
    payload = read_exact(connection, length)
    if version == 0x20:
        # A LOCAL header carries no originating client address.
        return peer
    width, required = TRANSPORT.get(family, (0, 0))
    if not width or length < required:
        raise ssl.SSLError("Invalid appliance router address")
    address = str(ipaddress.ip_address(bytes(payload[:width])))
    port = struct.unpack_from("!H", payload, 2 * width)[0]
    return address, port
