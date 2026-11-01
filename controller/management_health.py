"""Fresh management-path evidence for an exact pending firewall transaction.

The endpoint never chooses a probe destination. Addresses, ports and source
allowlists come from a current reviewed rollout or bounded learning authority. Operators must
explicitly configure this controller as an approved management vantage point.
"""
from __future__ import annotations

import ipaddress
import os
import re
import socket
import threading
import time

from .store import stamp


class ManagementHealthUnavailable(RuntimeError):
    pass


class ManagementHealth:
    def __init__(self, source_ip=None, target_cidrs=None, timeout=2.0):
        self.source_ip = source_ip if source_ip is not None else os.environ.get("SEG_MANAGEMENT_PROBE_SOURCE_IP", "")
        configured = target_cidrs if target_cidrs is not None else os.environ.get("SEG_MANAGEMENT_PROBE_TARGET_CIDRS", "").split(",")
        self.target_cidrs = [ipaddress.ip_network(value.strip(), strict=False) for value in configured if value.strip()]
        if self.source_ip:
            self.source_ip = str(ipaddress.ip_address(self.source_ip))
        if any(network.prefixlen == 0 for network in self.target_cidrs):
            raise ValueError("Management probe target CIDRs must be explicitly scoped; /0 is forbidden")
        self.timeout = min(3.0, max(0.1, timeout))
        self.slots = threading.BoundedSemaphore(8)

    def _targets(self, approved):
        if not self.source_ip or not self.target_cidrs:
            raise ManagementHealthUnavailable("Configure an approved management probe source IP and target CIDRs before enforcement")
        source = ipaddress.ip_address(self.source_ip)
        allowed_sources = [ipaddress.ip_network(value, strict=False) for value in approved["management_sources"]]
        if not any(source in network for network in allowed_sources):
            raise ManagementHealthUnavailable("This controller probe source is outside the endpoint's pinned management sources")
        ports = approved["ssh_ports"]
        if not ports or len(ports) > 8 or any(isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535 for port in ports):
            raise ManagementHealthUnavailable("Between one and eight discovered SSH ports are required for management checks")
        targets = []
        for value in approved["ips"]:
            address = ipaddress.ip_address(value)
            if address.version != source.version or address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified or address.is_reserved:
                continue
            if any(address in network for network in self.target_cidrs):
                targets.append(str(address))
        targets = sorted(set(targets))
        if not targets:
            raise ManagementHealthUnavailable("No approved endpoint address is within this management probe's configured target CIDRs")
        # One explicit management address is enough to prove a path per port;
        # fail closed rather than scan multiple interfaces or infer a fallback.
        return targets[0], sorted(set(ports))

    def _ssh(self, target, port, deadline):
        family = socket.AF_INET6 if ipaddress.ip_address(target).version == 6 else socket.AF_INET
        connection = socket.socket(family, socket.SOCK_STREAM)
        try:
            connection.settimeout(min(self.timeout, max(0.01, deadline - time.monotonic())))
            connection.bind((self.source_ip, 0))
            connection.connect((target, port))
            source_ip = connection.getsockname()[0]
            banner = b""
            while len(banner) < 1024 and time.monotonic() < deadline:
                connection.settimeout(min(self.timeout, max(0.01, deadline - time.monotonic())))
                packet = connection.recv(min(256, 1024 - len(banner)))
                if not packet:
                    break
                banner += packet
                if any(line.rstrip(b"\r").startswith((b"SSH-2.0-", b"SSH-1.99-")) for line in banner.split(b"\n")[:-1]):
                    return {"target_ip": target, "port": port, "source_ip": source_ip, "ssh_banner_verified": True}
            raise ManagementHealthUnavailable("A fresh SSH protocol banner was not received from the approved management address")
        except (OSError, TimeoutError):
            raise ManagementHealthUnavailable("A fresh SSH connection from the approved management source failed") from None
        finally:
            connection.close()

    def check(self, store, server_id, payload):
        return self._check(lambda: store.verify_managed_enforcement(server_id, payload), payload,
                           ("server_id", "version", "digest", "protection_digest", "binding_digest"))

    def check_learning(self, store, server_id, payload):
        from .learning_policies import verify_assignment
        return self._check(lambda: verify_assignment(store, server_id, payload), payload,
                           ("server_id", "version", "generation", "digest", "protection_digest", "target_ips_digest", "binding_digest"))

    def _check(self, verify, payload, identity_fields):
        nonce = payload.get("nonce", "")
        if not isinstance(nonce, str) or not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", nonce):
            raise ValueError("A fresh transaction nonce of 16 to 128 characters is required")
        approved = verify()
        target, ports = self._targets(approved)
        requested_ports = payload.get("ssh_ports")
        if requested_ports != ports:
            raise ValueError("SSH health check ports must match the approved endpoint protection")
        if not self.slots.acquire(blocking=False):
            raise ManagementHealthUnavailable("Management probe capacity is busy; pending policy must remain uncommitted")
        try:
            deadline = time.monotonic() + 8
            checks = []
            for port in ports:
                if time.monotonic() >= deadline:
                    raise ManagementHealthUnavailable("Management health check deadline exceeded")
                checks.append(self._ssh(target, port, deadline))
            # A policy/tag/IP/config change during network I/O revokes the proof.
            current = verify()
            if any(current.get(key) != approved.get(key) for key in (*identity_fields, "ips", "ssh_ports", "management_sources")):
                raise ManagementHealthUnavailable("The approved endpoint changed during its management health check")
            return {key: approved[key] for key in identity_fields} | {
                "nonce": nonce, "checked_at": stamp(), "controller_ok": True,
                "status": "healthy", "ssh_checks": checks,
            }
        finally:
            self.slots.release()
