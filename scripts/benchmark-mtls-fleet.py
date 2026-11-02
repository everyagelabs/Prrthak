#!/usr/bin/env python3
"""Real HTTPS/mTLS Gunicorn benchmark with distinct virtual endpoint identities.

Uses only disposable private state and loopback networking. It does not execute
5,000 Linux agents, touch firewalld, contact a DC, or establish a fleet soak/failover
certification. Optional PostgreSQL DSNs must name new prthak_test_http_* databases.
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
from collections import Counter, defaultdict
from datetime import timedelta
import hashlib
import http.client
import ipaddress
import importlib.metadata
import json
import math
import os
import platform
from pathlib import Path
import secrets
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from controller.app import App
from controller.pki import Signer, init_ca
from controller.store import Store, digest, now, parse_time, stamp
from controller.endpoint_certificates import record_issued
from controller.policy_signing import verify


def percentile(values, fraction):
    values = sorted(values)
    return round(values[min(len(values)-1, max(0, math.ceil(len(values)*fraction)-1))] * 1000, 3) if values else None


def seed_retained_history(store, identities, count):
    """Retain expired full-fleet history outside timers through canonical writes."""
    if not 0 <= count <= 100:
        raise ValueError('Retained history must contain 0..100 expired sessions')
    written = 0
    with store.lock, store.meta() as db:
        for index in range(count):
            value = {'id': str(uuid.uuid4()), 'server_ids': list(identities), 'status': 'expired',
                     'selection_mode': 'explicit', 'policy_action': 'suggest',
                     'observation_kinds': ['allowed', 'denied'], 'ports': [{'port': 443, 'protocol': 'tcp'}],
                     'starts_at': stamp(now() - timedelta(days=31)), 'expires_at': stamp(now() - timedelta(days=30)),
                     'created_by': 'private-retained-history-fixture'}
            written += len(json.dumps(value, separators=(',', ':')).encode())
            store._put(db, 'sessions', value)
    return {'expired_sessions': count, 'endpoint_memberships': len(identities) * count,
            'canonical_bytes': written, 'seeded_before_phase_timers': True}


def verify_changed_policy(policy, previous_receipt, expected_services):
    """A refreshed signature/304 alone is not a successfully delivered edit."""
    if not previous_receipt or policy.get("version", -1) <= previous_receipt[0] or policy.get("digest") == previous_receipt[1]:
        raise RuntimeError("Edited policy did not advance the endpoint version and digest")
    expected = {(row["port"], row["protocol"]): set(row["sources"]) for row in expected_services}
    actual = {}
    for row in policy.get("services", []):
        key = (row.get("port"), row.get("protocol"))
        if key in actual:
            raise RuntimeError("Edited policy contains duplicate service rows")
        actual[key] = set(row.get("sources", []))
    if actual != expected:
        raise RuntimeError("Edited policy source/service matrix was not delivered exactly")


def verify_direct_authority(policy, identity, fingerprint, epoch=""):
    """Demand current, compact direct Admin evidence, not merely HTTP success."""
    enforcement = policy.get("enforcement", {})
    proof = enforcement.get("approval_proof") or {}
    subject = proof.get("requester") or {}
    scope = proof.get("scope") or {}
    if (enforcement.get("authorized") is not True or enforcement.get("confirmation_count") != 1
            or proof.get("scheme") != "prthak-maker-checker-v1" or proof.get("mode") != "single_admin" or proof.get("stage") != "approved"
            or enforcement.get("approved_version") != policy.get("version") or enforcement.get("approved_digest") != policy.get("digest")
            or proof.get("requester") != proof.get("submitted_by") or subject != proof.get("approved_by")
            or subject.get("role") != "admin" or subject.get("auth_config") != fingerprint
            or proof.get("provider_authority") != {"fingerprint":fingerprint,"epoch":epoch}
            or scope.get("server_ids") != [identity] or scope.get("kind") != "managed_policy"
            or proof.get("binding_digest") != digest({key:value for key,value in proof.items() if key!="binding_digest"})
            or "pilot" in proof or len(json.dumps(proof,separators=(",",":"))) > 16384):
        raise RuntimeError("Current exact per-host single_admin authorization was not delivered")


def verify_observation_lease(policy, identity, addresses, expected_deployment_id=None):
    """Check delivery of a passive lease without inventing native witnesses."""
    lease = policy.get("policy_verification") or {}
    required = {"schema_version", "id", "deployment_id", "server_id", "version", "digest", "approval_id", "protection_digest", "target_ips_digest", "ports", "starts_at", "expires_at", "window_seconds"}
    enforcement = policy.get("enforcement") or {}
    ports = sorted((service["protocol"], service["port"]) for service in policy.get("services", []) if service.get("mode", policy.get("mode")) == "enforce")
    if (set(lease) != required or lease["schema_version"] != 1 or lease["server_id"] != identity
            or any(lease[key] != policy[key] for key in ("version", "digest"))
            or lease["approval_id"] != enforcement.get("approval_id")
            or lease["protection_digest"] != enforcement.get("protection_digest")
            or lease["target_ips_digest"] != digest(sorted(set(addresses)))
            or expected_deployment_id is not None and lease["deployment_id"] != expected_deployment_id
            or lease["window_seconds"] != 600
            or any(not isinstance(lease[key], str) or not 1 <= len(lease[key]) <= 128 for key in ("id", "deployment_id"))
            or not isinstance(lease["ports"], list) or not 1 <= len(lease["ports"]) <= 64
            or sorted((port.get("protocol"), port.get("port")) for port in lease["ports"]) != ports
            or parse_time(lease["expires_at"]) - parse_time(lease["starts_at"]) != timedelta(seconds=600)
            or parse_time(lease["expires_at"]) <= now()):
        raise RuntimeError("Exact endpoint-bound passive verification lease was not delivered")


def seeded_person(store, config, oid, role):
    """Trusted private session fixture, never a real Microsoft sign-in."""
    from controller.auth import EntraAuth, SESSION_COOKIE
    auth = EntraAuth(store, config, provider=object())
    raw = secrets.token_urlsafe(32)
    identifier = config.tenant_id + ":" + oid
    with store.lock, store.meta() as db:
        store._put(db,"auth_users",{"id":identifier,"tenant_id":config.tenant_id,"object_id":oid,"enabled":True,"role":role,"display_name":"Private capacity "+role})
        store._put(db,"auth_sessions",{"id":hashlib.sha256(raw.encode()).hexdigest(),"user_id":identifier,"config":config.fingerprint,"created_at":stamp(),"expires_at":stamp(now()+timedelta(hours=4))})
    principal = auth.authenticate({"Cookie":SESSION_COOKIE+"="+raw})
    return principal, {"Cookie":SESSION_COOKIE+"="+raw,"X-CSRF-Token":principal["csrf_token"],"Origin":config.origin}


def run(args):
    # Never inherit live service/tenant/cluster credentials into a benchmark.
    metadata_dsn = os.environ.get(args.metadata_dsn_env, "")
    traffic_dsn = os.environ.get(args.traffic_dsn_env, "")
    for name in list(os.environ):
        if name.startswith(("SEG_", "PRTHAK_")):
            os.environ.pop(name)
    token = secrets.token_urlsafe(40)
    result = {"virtual_identities": args.agents, "cycles_per_identity": args.cycles,
              "actual_agent_processes": 0, "kernel_traffic_collected": False,
              "transport": "Gunicorn bounded gthread, real TLS and unique registered mTLS certificates",
              "worker_class":"controller.gunicorn_worker.BoundedThreadWorker",
              "backend": args.backend, "concurrent_virtual_clients": args.concurrency,
              "http_workers": args.workers, "http_threads_per_worker": args.threads,
              "cadence": args.cadence, "policy_services": 2, "approved_sources_per_service": args.policy_sources,
              "authorization_mode":args.authorization_mode,
              "verification_lease_delivery": args.verification_capable,
              "native_verification_witnesses_generated": False,
              "administrative_identity_fixture":"Persisted private Entra-shaped Admin session; no live Microsoft sign-in/token exchange" if args.authorization_mode=="single-admin" else "Legacy private token monitor fixture",
              "actual_midrun_policy_edit": args.change_policy, "configured_control_interval_seconds": args.control_interval_seconds,
              "changed_policy_poll_window_seconds": args.poll_window_seconds,
              "postgres_worker_pool": {"metadata_max":args.db_pool_meta_max,"traffic_max":args.db_pool_traffic_max,"wait_seconds":args.db_pool_wait_seconds},
              "environment": {"machine":platform.machine(),"system":platform.system(),"python":platform.python_version(),"openssl":ssl.OPENSSL_VERSION,"logical_cpus":os.cpu_count(),"shared_development_host":True},
              "software":{name:importlib.metadata.version(name) for name in ("gunicorn","cryptography")},
              "source_files_sha256_at_launch":{str(path.relative_to(ROOT)):hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted((ROOT/"controller").glob("*.py"))},
              "fixture_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "control_interval_target_seconds": 60, "phase_results": [],
              "boundaries": ["Virtual identities are not Linux agent processes", "No firewall/enforcement/SSH/systemd tests", "Certificates and inventory are seeded before measurement; enrollment storm excluded", "No WAN latency, site failover or long-duration soak", "Flow/discovery payloads are explicitly synthetic", "PostgreSQL mode uses two private databases on one instance; replication and synchronous WAN commits are not exercised"]}
    with tempfile.TemporaryDirectory(prefix="prthak-http-scale-") as temporary:
        directory = Path(temporary)
        reservation=socket.socket();reservation.bind(("127.0.0.1",0));port=reservation.getsockname()[1];reservation.close()
        pki = init_ca(directory / "issuer")
        state = directory / "controller"
        state.mkdir(parents=True, exist_ok=True, mode=0o700)
        signer = Signer(pki / "ca.pem", pki / "ca-key.pem")
        if args.backend == "postgresql":
            import psycopg
            from psycopg.conninfo import conninfo_to_dict
            from controller.postgres import PostgresStore
            names = [conninfo_to_dict(value).get("dbname", "") for value in (metadata_dsn, traffic_dsn)]
            if not all(name.startswith("prthak_test_http_") for name in names) or names[0] == names[1]:
                raise ValueError("Use two distinct new prthak_test_http_* databases through the named environment variables")
            for dsn in (metadata_dsn, traffic_dsn):
                with psycopg.connect(dsn) as connection:
                    if connection.execute("SELECT COUNT(*) FROM pg_tables WHERE schemaname='public'").fetchone()[0]:
                        raise ValueError("PostgreSQL benchmark databases must be empty")
            # Match the installed appliance's authority order: establish protected
            # material before switching to HA. A fresh HA store must never mint a
            # replacement authority if its protected state has disappeared.
            bootstrap=App(Store(directory/"authority-bootstrap"),signer=signer,tokens={"super_admin":token},controller_id="private-http-scale",site="private-fixture",state_dir=state,controller_certificate=pki/"controller.pem",controller_private_key=pki/"controller-key.pem")
            bootstrap.platform.policy_signer().public_trust()
            store = PostgresStore(metadata_dsn, traffic_dsn)
        else:
            store = Store(state)
        app = App(store, signer=signer, tokens={"super_admin": token}, controller_id="private-http-scale", site="private-fixture", state_dir=state,
                  controller_certificate=pki / "controller.pem", controller_private_key=pki / "controller-key.pem")
        trust = app.platform.policy_signer().public_trust()
        principal=None;admin_headers={"Authorization":"Bearer "+token};setup_headers=dict(admin_headers);provider_environment={}
        fixture_origin="https://127.0.0.1:"+str(port)
        if args.authorization_mode=="single-admin":
            from controller.auth import EntraAuth, EntraConfig
            config=EntraConfig(str(uuid.uuid4()),str(uuid.uuid4()),fixture_origin+"/api/v1/auth/callback",secrets.token_urlsafe(32))
            app.auth=EntraAuth(store,config,provider=object())
            store.approval_auth_fingerprint=config.fingerprint;store.approval_tenant_id=config.tenant_id
            principal,admin_headers=seeded_person(store,config,str(uuid.uuid4()),"admin")
            _,setup_headers=seeded_person(store,config,str(uuid.uuid4()),"super_admin")
            epoch=secrets.token_hex(32)
            with store.lock,store.meta() as db:store._put(db,"maintenance_settings",{"id":"controller_provider_authority","fingerprint":config.fingerprint,"epoch":epoch})
            provider_environment={"SEG_ENTRA_TENANT_ID":config.tenant_id,"SEG_ENTRA_CLIENT_ID":config.client_id,"SEG_ENTRA_REDIRECT_URI":config.redirect_uri,"SEG_ENTRA_CLIENT_SECRET":config.client_secret,"PRTHAK_PROVIDER_EPOCH":epoch}
            result["policy_actor_role"]="admin"
            result["human_auth_boundary"]="The policy PUT uses actual HTTPS cookie/session/CSRF authorization against the seeded Admin; OIDC/MFA itself is outside this benchmark"
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
        ca = x509.load_pem_x509_certificate((pki / "ca.pem").read_bytes())
        ca_key = serialization.load_pem_private_key((pki / "ca-key.pem").read_bytes(), None)
        clients = directory / "clients"
        clients.mkdir(mode=0o700)
        namespace = uuid.uuid4()
        identities = [str(uuid.uuid5(namespace, str(index))) for index in range(args.agents)]
        reports = {}
        capabilities = ["learning_discovery_v1", "learning_auto_allow_v1", "agent_polling_config_v1", "managed_ipsets_v1", "learning_ipsets_v1", "signed_assignments_v1", "approval_mode_proof_v1", "traffic_capture_v1"]
        if args.verification_capable:
            capabilities.append("policy_verification_v1")
        started = time.monotonic()
        with store.lock, store.meta() as db:
            if store._all(db, "servers") or store._all(db, "policies"):
                raise RuntimeError("Disposable benchmark store was not empty")
            for index, identity in enumerate(identities):
                key = ec.generate_private_key(ec.SECP256R1())
                certificate = x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, identity)])).issuer_name(ca.subject).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now()-timedelta(minutes=1)).not_valid_after(now()+timedelta(days=30)).add_extension(x509.BasicConstraints(ca=False,path_length=None),True).add_extension(x509.KeyUsage(True,False,False,False,False,False,False,False,False),True).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),False).add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),False).add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),False).sign(ca_key,hashes.SHA256())
                pem = certificate.public_bytes(serialization.Encoding.PEM)
                (clients / (identity + ".crt")).write_bytes(pem)
                (clients / (identity + ".key")).write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
                (clients / (identity + ".key")).chmod(0o600)
                address = str(ipaddress.IPv4Address("10.230.0.1")+index)
                report = {"hostname": "virtual-"+str(index), "ips": [address], "os": "virtual-linux-fixture", "os_version": "not-a-real-endpoint", "agent_version": "0.9.0-virtual-fixture", "capabilities": capabilities,
                          "listeners": [{"port": 2022,"protocol":"tcp","address":"0.0.0.0","process":"sshd","service":"SSH"}, {"port":8443,"protocol":"tcp","address":"0.0.0.0","process":"private-fixture","service":"HTTPS"}],
                          "firewalld_state":"running","firewalld_version":"synthetic","firewall_backend":"synthetic","discovery_performed":False,"discovery_interval_seconds":900,"control_interval_seconds":60,"apply_status":"preview","applied_version":0,"collector_status":"off"}
                if args.authorization_mode=="single-admin":
                    protected={"management_sources":["192.0.2.0/24"],"ssh_ports":[2022],"controller_url":fixture_origin,"management_probe_url":fixture_origin+"/api/v1/agent/enforcement/check","zone":"public"}
                    report["protection"]={**protected,"digest":digest(protected),"ready":True,"blockers":[]}
                    report["agent_version"]="0.9.0-virtual-fixture"
                reports[identity] = report
                server = {"id": identity, **report, "tags":{},"_metadata_overrides":{"tags":{}},"location_id":None,"location_source":{"type":"unassigned"},"tag_sources":{},"expected_services":[],"desired_version":0,"status":"healthy","created_at":stamp(),"last_seen":stamp(),"last_discovery_at":stamp()}
                if args.authorization_mode=="single-admin":
                    server["tags"]={"application":"http-fleet"};server["_metadata_overrides"]={"tags":{"application":"http-fleet"}}
                record_issued(store, db, server, pem.decode())
                store._put(db,"servers",server)
                if (index+1)%500 == 0:
                    print(json.dumps({"prepared_registered_certificates":index+1}),flush=True)
            store.compile_all(db)
        fixture_policy = store.save_policy({"name":"Private fixture two-service source policy","mode":"enforce" if principal else "monitor","selector":{"application":"http-fleet"} if principal else {},"services":[{"port":port,"protocol":"tcp","sources":[str(ipaddress.IPv4Address(base)+index)+"/32" for index in range(args.policy_sources)]} for port,base in ((8443,"10.232.0.1"),(5432,"10.233.0.1"))]},principal["actor"] if principal else "private-benchmark-fixture",principal=principal)
        result['retained_learning_history'] = seed_retained_history(store, identities, args.retained_learning_sessions)
        result["private_setup_seconds"] = round(time.monotonic()-started,3)
        environment = dict(os.environ, PRTHAK_SUPERVISED_CHILD="1", SEG_SUPER_ADMIN_TOKEN=token, PYTHONUNBUFFERED="1", **provider_environment)
        if args.backend == "postgresql":
            environment.update(SEG_DATABASE_URL=metadata_dsn, SEG_TRAFFIC_DATABASE_URL=traffic_dsn,
                               SEG_DB_POOL_META_MAX=str(args.db_pool_meta_max),SEG_DB_POOL_TRAFFIC_MAX=str(args.db_pool_traffic_max),SEG_DB_POOL_WAIT_SECONDS=str(args.db_pool_wait_seconds))
        command = [sys.executable,"-m","controller","--listen","127.0.0.1:"+str(port),"--data-dir",str(state),"--cert",str(pki/"controller.pem"),"--key",str(pki/"controller-key.pem"),"--ca",str(pki/"ca.pem"),"--ca-key",str(pki/"ca-key.pem"),"--controller-id","private-http-scale","--site","private-fixture","--http-backend","gunicorn","--http-workers",str(args.workers),"--http-threads",str(args.threads)]
        if args.backend == "postgresql":
            command.append("--ha")
        log = (directory/"controller.log").open("wb")
        process = subprocess.Popen(command, cwd=ROOT, env=environment, stdout=log, stderr=log, start_new_session=True)
        context = ssl.create_default_context(cafile=str(pki/"ca.pem"))
        stats_lock = threading.Lock()
        samples = defaultdict(list)
        statuses = Counter()
        retries = Counter()
        failures = []
        etags = {}
        receipt_keys = {}
        authority_receipts = {}
        def request(connection, operation, method, path, value=None, headers=None):
            body = json.dumps(value,separators=(",",":")).encode() if value is not None else None
            request_headers={"Content-Type":"application/json", **(headers or {})}
            began = time.monotonic()
            for attempt in range(4):
                try:
                    connection.request(method,path,body,request_headers)
                    response=connection.getresponse()
                    raw=response.read(8*1024*1024+1)
                    status=response.status
                    response_headers=dict(response.getheaders())
                    if len(raw)>8*1024*1024:
                        raise ValueError("Oversized HTTP response")
                    if status in (429,503) and attempt<3:
                        with stats_lock:retries[operation]+=1
                        time.sleep(.1*(attempt+1))
                        continue
                    with stats_lock:
                        samples[operation].append(time.monotonic()-began)
                        statuses[str(status)]+=1
                    if status not in (200,201,202,304):
                        raise RuntimeError("HTTP"+str(status)+" "+raw[:200].decode(errors="replace"))
                    return status,json.loads(raw) if raw else None,response_headers
                except (OSError,http.client.HTTPException) as error:
                    connection.close()
                    if attempt>=3:
                        raise
                    with stats_lock:retries[operation]+=1
                    time.sleep(.1*(attempt+1))
        def connect(identity=None):
            selected=ssl.create_default_context(cafile=str(pki/"ca.pem"))
            if identity is not None:
                selected.load_cert_chain(clients/(identity+".crt"),clients/(identity+".key"))
            return http.client.HTTPSConnection("127.0.0.1",port,context=selected,timeout=args.timeout)
        try:
            deadline=time.monotonic()+40
            while time.monotonic()<deadline:
                if process.poll() is not None:
                    raise RuntimeError("Private Gunicorn process exited before readiness")
                connection=http.client.HTTPSConnection("127.0.0.1",port,context=context,timeout=2)
                try:
                    connection.request("GET","/readyz");response=connection.getresponse();raw=response.read()
                    if response.status==200 and json.loads(raw).get("status")=="ready":break
                except (OSError,http.client.HTTPException):
                    pass
                finally:connection.close()
                time.sleep(.1)
            else:raise RuntimeError("Private Gunicorn readiness did not succeed")
            print(json.dumps({"gunicorn_ready":True,"registered_identities":args.agents}),flush=True)
            if args.control_interval_seconds != 60:
                admin=connect()
                try:
                    request(admin,"polling_profile_setup","POST","/api/v1/platform/agent-settings",{"expected_revision":0,"defaults":{"control_interval_seconds":args.control_interval_seconds,"discovery_interval_seconds":900},"rules":[]},setup_headers)
                finally:admin.close()
            session=None
            learners=set(identities[:min(args.learning_agents,args.agents)])
            for cycle in range(args.cycles):
                if cycle==args.cycles-1 and learners and args.flow_events:
                    admin=connect()
                    try:
                        _,session,_=request(admin,"learning_setup","POST","/api/v1/learning",{"server_ids":sorted(learners),"ports":[{"port":8443,"protocol":"tcp"}],"selection_mode":"manual","duration_seconds":3600,"policy_action":"observe","observation_kinds":["accepted_connection","denied_packet"]},admin_headers)
                    finally:admin.close()
                phase_started=time.monotonic()
                changed_phase=args.change_policy and cycle==1
                verified_changes=0
                verified_authorities=0
                verified_observation_leases=0
                publication_seconds=0.0
                if changed_phase:
                    # Exercise the actual administrative mutation route, including
                    # compile/history/publication, inside the delivery budget.
                    changed_services=[{**row,"sources":list(row["sources"])} for row in fixture_policy["services"]]
                    for index,row in enumerate(changed_services):
                        row["sources"][0]="198.19."+str(index)+".1/32"
                    admin=connect()
                    try:
                        _,fixture_policy,_=request(admin,"policy_update","PUT","/api/v1/policies/"+fixture_policy["id"],{"expected_revision":fixture_policy["revision"],"name":fixture_policy["name"],"mode":fixture_policy["mode"],"selector":fixture_policy["selector"],"services":changed_services},admin_headers)
                    finally:admin.close()
                    publication_seconds=time.monotonic()-phase_started
                discovery=set(identities[:min(args.discovery_agents,args.agents)]) if cycle==args.cycles-1 else set()
                def one(identity):
                    nonlocal verified_changes,verified_authorities,verified_observation_leases
                    connection=connect(identity)
                    try:
                        report=dict(reports[identity])
                        if identity in discovery:
                            report.update(discovery_performed=True,discovered_at=stamp())
                        _,receipt,_=request(connection,"report","POST","/api/v1/agent/report",report,{"X-Agent-ID":"untrusted-header-must-not-be-identity","X-Forwarded-For":"192.0.2.99"})
                        if receipt["server_id"]!=identity:
                            raise RuntimeError("mTLS endpoint identity binding failed")
                        status,policy,headers=request(connection,"policy","GET","/api/v1/agent/policy",headers={"If-None-Match":etags[identity]} if identity in etags else {})
                        changed_receipt=False
                        if changed_phase and status!=200:
                            raise RuntimeError("Edited policy incorrectly returned an unchanged response")
                        if status==200:
                            if policy["server_id"]!=identity:raise RuntimeError("Policy endpoint binding failed")
                            verify(policy,trust)
                            if args.authorization_mode=="single-admin":
                                verify_direct_authority(policy,identity,config.fingerprint,epoch)
                                authority_receipts[identity]={key:policy[key] for key in ("version","digest","enforcement")}
                                if args.verification_capable:
                                    verify_observation_lease(policy, identity, report["ips"], fixture_policy["deployment"]["id"])
                                    authority_receipts[identity]["services"] = policy["services"]
                                    authority_receipts[identity]["mode"] = policy["mode"]
                                    authority_receipts[identity]["policy_verification"] = policy["policy_verification"]
                                    with stats_lock:verified_observation_leases+=1
                                with stats_lock:verified_authorities+=1
                            if changed_phase:
                                verify_changed_policy(policy,receipt_keys.get(identity),changed_services)
                                with stats_lock:verified_changes+=1
                            etags[identity]=headers.get("ETag",headers.get("Etag",""))
                            polling=policy.get("polling_settings") or {}
                            if polling.get("control_interval_seconds") != args.control_interval_seconds:
                                raise RuntimeError("Signed policy does not carry the tested control interval")
                            receipt=(policy["version"],policy["digest"],policy["mode"],polling.get("version"),polling.get("digest"))
                            changed_receipt=receipt_keys.get(identity)!=receipt
                            receipt_keys[identity]=receipt
                            # Mirror the non-enforcing agent's meaningful outcome
                            # receipt. A refreshed signature alone has no new result.
                            report["managed_enforcement"]={"status":"preview","version":policy["version"],"digest":policy["digest"],"last_good_version":0,"last_good_digest":"","updated_at":stamp()}
                            if polling:
                                report["polling_settings"]={"version":polling["version"],"digest":polling["digest"],"status":"applied"}
                                report["control_interval_seconds"]=polling["control_interval_seconds"]
                                report["discovery_interval_seconds"]=polling["discovery_interval_seconds"]
                        if status==304 and args.authorization_mode=="single-admin":
                            verify_direct_authority(authority_receipts.get(identity,{}),identity,config.fingerprint,epoch)
                            if args.verification_capable:
                                verify_observation_lease(authority_receipts[identity], identity, report["ips"], fixture_policy["deployment"]["id"])
                                with stats_lock:verified_observation_leases+=1
                            with stats_lock:verified_authorities+=1
                        if session and identity in learners:
                            at=stamp();events=[]
                            for number in range(args.flow_events):
                                denied=number%2==1
                                ipv6=number%4>=2
                                source=str((ipaddress.IPv6Address("2001:db8:231::1") if ipv6 else ipaddress.IPv4Address("10.231.0.1"))+number)
                                events.append({"event_id":hashlib.sha256((session["id"]+identity+str(number)).encode()).hexdigest(),"source_ip":source,"port":8443,"protocol":"tcp","verdict":"denied" if denied else "allowed","count":1,"first_seen":at,"last_seen":at,"capture_kind":"denied_packet" if denied else "accepted_connection","capture_backend":"nflog" if denied else "conntrack","count_unit":"packets" if denied else "connections","address_family":"ipv6" if ipv6 else "ipv4"})
                            request(connection,"flow_ingest","POST","/api/v1/agent/flows",{"batch_id":"virtual-"+str(cycle)+"-"+identity,"session_id":session["id"],"events":events})
                        report["discovery_performed"]=False
                        if args.cadence=="strict" or changed_receipt:
                            request(connection,"report","POST","/api/v1/agent/report",report)
                        reports[identity]=report
                        return True
                    except Exception as error:
                        with stats_lock:
                            failures.append({"operation":"virtual_cycle","error":type(error).__name__+": "+str(error)[:250]})
                        return False
                    finally:connection.close()
                completed,successful=0,0
                with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
                    futures=[]
                    polling_started=time.monotonic()
                    for index,identity in enumerate(identities):
                        if changed_phase and args.poll_window_seconds:
                            remaining=polling_started+args.poll_window_seconds*index/len(identities)-time.monotonic()
                            if remaining>0:time.sleep(remaining)
                        futures.append(executor.submit(one,identity))
                    for future in as_completed(futures):
                        successful+=int(future.result());completed+=1
                        if completed%500==0:print(json.dumps({"cycle":cycle+1,"completed":completed}),flush=True)
                elapsed=time.monotonic()-phase_started
                phase={"cycle":cycle+1,"identities":args.agents,"successful_cycles":successful,"seconds":round(elapsed,3),"cycles_per_second":round(successful/elapsed,2),"covers_60_second_cycle_target":successful==args.agents and elapsed<=60,"discovery_reports":len(discovery),"synthetic_flow_events":len(learners)*args.flow_events if session else 0}
                if args.authorization_mode=="single-admin":
                    phase["verified_current_direct_authorities"]=verified_authorities
                    if verified_authorities!=args.agents:failures.append({"operation":"direct_authority_delivery","error":"Not every identity received its current compact direct Admin authority"})
                if args.verification_capable:
                    phase["verified_passive_observation_leases"] = verified_observation_leases
                    if verified_observation_leases != args.agents:
                        failures.append({"operation": "observation_lease_delivery", "error": "Not every identity received its exact passive observation lease"})
                if changed_phase:
                    phase.update(actual_policy_edit=True,publication_seconds=round(publication_seconds,3),poll_window_seconds=args.poll_window_seconds,verified_updated_identities=verified_changes,exact_source_matrices_verified=verified_changes==args.agents)
                    if verified_changes!=args.agents:
                        failures.append({"operation":"changed_policy_delivery","error":"Not every identity received the exact updated source/service matrix"})
                result["phase_results"].append(phase)
                print(json.dumps(phase),flush=True)
            if session:
                deadline=time.monotonic()+30
                while time.monotonic()<deadline:
                    with store.traffic() as db:
                        row=db.execute("SELECT COUNT(*) FROM batches WHERE processed=0").fetchone()
                        pending=int(row[0])
                    if not pending:break
                    time.sleep(.25)
                result["flow_batches_pending_after_drain"]=pending
                with store.traffic() as db:
                    retained=db.execute("SELECT COUNT(*),COALESCE(SUM(count),0) FROM flows WHERE session_id=?",(session["id"],)).fetchone()
                result["synthetic_flow_rows_retained"]=int(retained[0])
                result["synthetic_capture_format"]="traffic_capture_v1_dual_stack_mixed_units"
                with store.traffic() as db:
                    units={row[0]:int(row[1]) for row in db.execute("SELECT count_unit,COALESCE(SUM(count),0) FROM flows WHERE session_id=? GROUP BY count_unit",(session["id"],))}
                expected_units={"connections":len(learners)*((args.flow_events+1)//2),"packets":len(learners)*(args.flow_events//2)}
                expected_units={unit:count for unit,count in expected_units.items() if count}
                result["synthetic_counts_by_unit"]=units
                if units!=expected_units:failures.append({"operation":"typed_flow_units","error":"Accepted connection and denied packet totals were not preserved separately"})
                result["synthetic_event_count_retained"]=int(retained[1])
                expected=len(learners)*args.flow_events
                if pending or int(retained[0])!=expected or int(retained[1])!=expected:
                    failures.append({"operation":"flow_drain","error":"Accepted synthetic flow events were not exactly retained within the 30-second drain bound"})
            result["request_statuses"]=dict(statuses)
            result["retries"]=dict(retries)
            result["failures"]=failures[:20]
            result["failure_count"]=len(failures)
            result["operations"]={name:{"count":len(values),"p50_ms":percentile(values,.5),"p95_ms":percentile(values,.95),"p99_ms":percentile(values,.99)} for name,values in samples.items()}
            result["all_http_cycles_succeeded"]=not failures
            result["all_cycle_targets_met"]=all(phase["covers_60_second_cycle_target"] for phase in result["phase_results"])
            result["live_inventory_count"]=len(store.servers())
        except Exception:
            log.flush()
            print((directory/"controller.log").read_text(errors="replace")[-2500:],file=sys.stderr)
            raise
        finally:
            if process.poll() is None:
                os.killpg(process.pid,signal.SIGTERM)
                try:process.wait(timeout=40)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=10)
            log.close()
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agents",type=int,default=5000)
    parser.add_argument("--cycles",type=int,default=2)
    parser.add_argument("--concurrency",type=int,default=64)
    parser.add_argument("--workers",type=int,default=1)
    parser.add_argument("--threads",type=int,default=32)
    parser.add_argument("--timeout",type=int,default=15)
    parser.add_argument("--cadence",choices=("adaptive","strict"),default="adaptive",help="adaptive mirrors the native agent; strict always sends a second report for comparison")
    parser.add_argument("--authorization-mode",choices=("monitor","single-admin"),default="monitor",help="single-admin seeds a current local Entra session, saves symbolic enforce intent and measures its real signed per-host authority; never contacts Microsoft")
    parser.add_argument("--change-policy",action="store_true",help="Edit the real source policy before cycle2; include compile/publication and verify all new versions/digests/sources")
    parser.add_argument("--verification-capable",action="store_true",help="Advertise current verification-capable agents and verify their signed passive leases; no kernel witnesses or firewall enforcement are simulated")
    parser.add_argument('--retained-learning-sessions', type=int, default=0, help='Seed 0..100 expired full-fleet sessions before timing; exercises history-independent delivery')
    parser.add_argument("--poll-window-seconds",type=float,default=0,help="Spread cycle2 polls across this window AFTER the edit is published; timer also includes publication")
    parser.add_argument("--control-interval-seconds",type=int,default=60,help="Set and verify the actual controller polling profile; 30 leaves processing headroom inside a60s delivery budget")
    parser.add_argument("--require-target",action="store_true",help="Fail if any complete cycle misses60seconds, even when HTTP calls succeed")
    parser.add_argument("--db-pool-meta-max",type=int,default=16)
    parser.add_argument("--db-pool-traffic-max",type=int,default=4)
    parser.add_argument("--db-pool-wait-seconds",type=int,default=5)
    parser.add_argument("--policy-sources",type=int,default=20)
    parser.add_argument("--learning-agents",type=int,default=100)
    parser.add_argument("--flow-events",type=int,default=100)
    parser.add_argument("--discovery-agents",type=int,default=100)
    parser.add_argument("--backend",choices=("sqlite","postgresql"),default="sqlite")
    parser.add_argument("--metadata-dsn-env",default="PRTHAK_HTTP_TEST_METADATA_DSN")
    parser.add_argument("--traffic-dsn-env",default="PRTHAK_HTTP_TEST_TRAFFIC_DSN")
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    if not 0 <= args.retained_learning_sessions <= 100:
        parser.error('Retained history must contain 0..100 expired sessions')
    if args.verification_capable and args.authorization_mode != "single-admin":
        parser.error("Observation-lease delivery requires the exact single-admin publication fixture")
    if not 1<=args.agents<=20000 or not 1<=args.cycles<=10 or not 1<=args.concurrency<=256 or not 1<=args.workers<=8 or not 2<=args.threads<=128 or not 1<=args.timeout<=120 or not 1<=args.policy_sources<=1000 or not 0<=args.learning_agents<=1000 or not 0<=args.flow_events<=2000 or not 0<=args.discovery_agents<=args.agents:
        parser.error("Benchmark arguments exceed bounded fixture limits")
    if args.change_policy and args.cycles<2 or not math.isfinite(args.poll_window_seconds) or not 0<=args.poll_window_seconds<=60 or not 5<=args.control_interval_seconds<=3600:
        parser.error("A policy edit requires at least2cycles, bounded0..60spoll window and5..3600scontrol interval")
    if not 1<=args.db_pool_meta_max<=64 or not 1<=args.db_pool_traffic_max<=16 or not 1<=args.db_pool_wait_seconds<=15:
        parser.error("Database pools must use metadata1..64, traffic1..16 and wait1..15seconds")
    value=run(args)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
    print(json.dumps(value,sort_keys=True),flush=True)
    if not value["all_http_cycles_succeeded"] or args.require_target and not value["all_cycle_targets_met"]:
        raise SystemExit(1)


if __name__=="__main__":main()
