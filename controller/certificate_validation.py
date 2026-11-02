"""Offline OpenSSL validation of reviewed HTTPS identities.

Memory BIOs exercise the same TLS server-purpose, hostname and X.509 verifier
as the runtime without opening a socket or consulting network issuer services.
Only the terminal supplied issuer is trusted, so a supplied leaf cannot mask
an invalid intermediate. Private temporary material is removed on every exit.
"""
from __future__ import annotations

import os
from pathlib import Path
import ssl
import tempfile


def _handshake(server_context, client_context, hostname):
    client_in, client_out, server_in, server_out = (ssl.MemoryBIO() for _ in range(4))
    client = client_context.wrap_bio(client_in, client_out, server_hostname=hostname)
    server = server_context.wrap_bio(server_in, server_out, server_side=True)
    complete = [False, False]
    for _ in range(32):
        for index, peer in enumerate((client, server)):
            if not complete[index]:
                try:
                    peer.do_handshake()
                    complete[index] = True
                except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                    pass
        if all(complete):
            return
        for source, target in ((client_out, server_in), (server_out, client_in)):
            data = source.read()
            if data:
                target.write(data)
    raise ValueError("Strict TLS certificate validation did not complete")


def verify_server_identity(certificate_pem, private_key_pem, trust_pem, hostnames, *, partial_chain=False):
    """Verify an identity using strict runtime TLS rules, with no network I/O.

    Partial trust is limited to the existing standalone import contract, where
    the operator may explicitly pin an incomplete issuer chain or lone leaf.
    Managed appliances pass a complete chain and require its root instead.
    """
    try:
        with tempfile.TemporaryDirectory(prefix="prthak-tls-preflight-") as temporary:
            path = Path(temporary) / "identity.pem"
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w") as output:
                output.write(certificate_pem + "\n" + private_key_pem)
            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.minimum_version = ssl.TLSVersion.TLSv1_2
            server_context.load_cert_chain(path)
        # OpenSSL has loaded the identity; no key file is needed during TLS.
        for hostname in dict.fromkeys(hostnames):
            client_context = ssl.create_default_context(cadata=trust_pem)
            client_context.minimum_version = ssl.TLSVersion.TLSv1_2
            client_context.hostname_checks_common_name = False
            client_context.verify_flags |= ssl.VERIFY_X509_STRICT
            if partial_chain:
                client_context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
            else:
                client_context.verify_flags &= ~ssl.VERIFY_X509_PARTIAL_CHAIN
            _handshake(server_context, client_context, hostname)
    except ssl.SSLCertVerificationError as error:
        # OpenSSL verification diagnostics contain no private-key bytes, file
        # contents or passwords. Bound the public reason returned to the GUI.
        reason = "".join(char for char in error.verify_message if char.isprintable())[:180]
        raise ValueError("Strict TLS certificate validation failed: " + reason) from None
    except (ssl.SSLError, OSError):
        raise ValueError("Strict TLS certificate validation failed; check the certificate chain, key and supported TLS algorithms") from None
