import argparse
import ipaddress
import logging
import os
import ssl
import sys
from pathlib import Path

from .app import App, Server
from .pki import Signer, init_ca
from .seed import seed
from .store import Store
from .listener_address import split_listener, format_listener


def main():
    parser = argparse.ArgumentParser(description="Prṛthak · पृथक् development controller")
    parser.add_argument("--listen", default="127.0.0.1:8787")
    parser.add_argument("--control-listen", help="Dedicated endpoint policy/authorization TLS listener")
    parser.add_argument("--discovery-listen", help="Dedicated endpoint inventory/enrollment/traffic TLS listener")
    parser.add_argument("--appliance-router-proxy", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--data-dir", default=".local/controller")
    parser.add_argument("--demo", action="store_true", help="Loopback-only, synthetic fleet, no authentication")
    parser.add_argument("--init-ca", action="store_true", help="Create local development CA and localhost server certificate, then exit")
    parser.add_argument("--cert")
    parser.add_argument("--key")
    parser.add_argument("--ca")
    parser.add_argument("--ca-key")
    parser.add_argument("--retention-hours", type=int, default=24)
    parser.add_argument("--ha", action="store_true", help="Use shared PostgreSQL metadata and traffic storage; never fall back to SQLite")
    parser.add_argument("--controller-id", default=os.environ.get("SEG_CONTROLLER_ID"))
    parser.add_argument("--site", default=os.environ.get("SEG_CONTROLLER_SITE") or os.environ.get("SEG_SITE", "local"))
    parser.add_argument("--http-backend", choices=("gunicorn", "development"), default="gunicorn")
    parser.add_argument("--http-workers", type=int, default=os.environ.get("SEG_HTTP_WORKERS"))
    parser.add_argument("--http-threads", type=int, default=os.environ.get("SEG_HTTP_THREADS", "32"))
    args = parser.parse_args()
    from .channels import listeners
    try:
        listener_channels = listeners(args.listen, args.control_listen, args.discovery_listen)
    except ValueError as error:
        parser.error(str(error))
    if args.demo and args.control_listen:
        parser.error("Synthetic demo uses its loopback combined listener only")
    if args.control_listen and args.http_backend != "gunicorn":
        parser.error("Separated TLS listeners require the production Gunicorn transport")
    if args.appliance_router_proxy and (args.demo or not args.control_listen):
        parser.error("Appliance router forwarding requires separated production TLS listeners")
    if args.http_workers is None:
        args.http_workers = 2 if args.ha else 1
    os.umask(0o077)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if args.init_ca:
        try:
            path = init_ca(args.data_dir)
        except ValueError as error:
            parser.error(str(error))
        print(f"Development PKI created in {path}; certificates cover localhost only.")
        return
    from .runtime_integrity import verify_installed, IntegrityError
    try:
        verify_installed()
    except IntegrityError as error:
        parser.error(str(error))
    try:
        host, port = split_listener(args.listen)
    except ValueError:
        parser.error("--listen must be host:port or [IPv6]:port")
    if not 1 <= args.retention_hours <= 8760:
        parser.error("Retention must be 1 to 8760 hours")
    if args.demo:
        try:
            loopback = host == "localhost" or ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = False
        if not loopback:
            parser.error("Demo mode is restricted to a loopback address")
    else:
        if not all((args.cert, args.key, args.ca)):
            parser.error("Production mode requires --cert, --key, and --ca; use --demo for local synthetic preview")
        from .auth import EntraConfig
        try:
            entra = EntraConfig.from_env()
        except ValueError as error:
            parser.error(str(error))
        if not entra.enabled:
            tokens = [os.environ.get(f"SEG_{role}_TOKEN", "") for role in ("SUPER_ADMIN", "ADMIN", "READ_ONLY")]
            present = [token for token in tokens if token]
            # Fresh HTTPS installations use the change-only local bootstrap
            # account. Legacy lab tokens remain optional, never required.
            if present and not any(os.environ.get(f"SEG_{role}_TOKEN") for role in ("SUPER_ADMIN", "ADMIN")):
                parser.error("A legacy token configuration needs an Admin or Super Admin token")
            if any(len(token) < 32 for token in present) or len(set(present)) != len(present):
                parser.error("Configured role tokens must be distinct random secrets of at least 32 characters")
    if os.environ.get("PRTHAK_SUPERVISED_CHILD") != "1":
        from .platform import PlatformManager
        from .platform_runtime import RuntimeSupervisor
        RuntimeSupervisor(args.data_dir, PlatformManager(args.data_dir), sys.argv[1:]).run()
        return
    metadata_dsn = os.environ.get("SEG_DATABASE_URL", "")
    traffic_dsn = os.environ.get("SEG_TRAFFIC_DATABASE_URL", "")
    if args.ha:
        if args.demo:
            parser.error("HA mode cannot use demo or local SQLite state")
        if not metadata_dsn or not traffic_dsn:
            parser.error("--ha requires both SEG_DATABASE_URL and SEG_TRAFFIC_DATABASE_URL")
        from .postgres import PostgresStore
        try:
            expected = os.environ.get("SEG_EXPECTED_DEPLOYMENT_ID")
            epoch_text = os.environ.get("SEG_EXPECTED_DEPLOYMENT_EPOCH")
            epoch = int(epoch_text) if epoch_text else None
            store = PostgresStore(metadata_dsn, traffic_dsn, args.retention_hours, deployment_id=expected, epoch=epoch)
        except (RuntimeError, ValueError) as error:
            parser.error(str(error))
    else:
        if metadata_dsn or traffic_dsn:
            parser.error("Shared database configuration requires --ha; refusing implicit SQLite fallback")
        store = Store(args.data_dir, args.retention_hours)
    signer = Signer(args.ca, args.ca_key) if args.ca and args.ca_key else None
    if args.demo:
        seed(store)
    app = App(store, demo=args.demo, signer=signer, controller_id=args.controller_id, site=args.site, state_dir=args.data_dir, controller_certificate=args.cert, controller_private_key=args.key, application_listen=args.listen)
    app.listener_channels = listener_channels
    if app.platform:
        from .application_port import record_observed
        record_observed(app.platform, args.listen)
    if not args.demo and args.http_backend == "gunicorn":
        from .production_http import serve
        from .proxy_protocol import ROUTER_PROXY_PORTS
        app.router_proxy_channels = {port: name for name, port in ROUTER_PROXY_PORTS.items()} if args.appliance_router_proxy else {}
        print(f"Prṛthak controller: https://{format_listener(host, port)} · Gunicorn · verified endpoint mTLS", flush=True)
        serve(app, host, port, certificate=args.cert, private_key=args.key, ca=args.ca, workers=args.http_workers, threads=args.http_threads, extra_binds=[value for value in (args.control_listen, args.discovery_listen) if value], router_proxy_ports=tuple(app.router_proxy_channels))
        return
    if not args.demo and os.environ.get("PRTHAK_APPLIANCE") == "1":
        parser.error("Installed appliances require the production Gunicorn transport")
    server = Server((host, port), app)
    if not args.demo:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(args.cert, args.key)
        context.load_verify_locations(args.ca)
        # Enrollment and dashboard use TLS without client cert. Endpoint APIs require a verified cert.
        context.verify_mode = ssl.CERT_OPTIONAL
        server.socket = context.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
    app.start_jobs()
    scheme = "http" if args.demo else "https"
    print(f"Prṛthak · पृथक् controller: {scheme}://{format_listener(host, port)}", flush=True)
    if args.ha:
        print(f"Shared PostgreSQL HA · node {app.controller_id} · site {app.site}", flush=True)
    print("SYNTHETIC DEMO · no real endpoints or firewall changes" if args.demo else "TLS enabled · endpoint APIs require enrolled client certificates", flush=True)
    try:
        server.serve_forever(poll_interval=0.3)
    except KeyboardInterrupt:
        pass
    finally:
        app.stop.set()
        server.server_close()
        for thread in app.threads:
            thread.join(timeout=2)


if __name__ == "__main__":
    main()
