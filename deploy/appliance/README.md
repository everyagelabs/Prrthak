# Prṛthak local appliance

Use the same Git checkout and installer on each Linux management host. The
installer builds the controller and PostgreSQL 16/Patroni images, pulls the
official etcd and HAProxy images, and installs a small root-owned service
manager. The controller runs as UID 10001 and never receives the Docker socket.

```sh
cp .env.example .env
chmod 600 .env
# Edit DATA_ROOT, NODE_ID, SITE and the reachable NODE_IP for this host.
sudo scripts/install-controller.sh --env-file .env
```

Prerequisites are genuine Linux systemd, a root-owned Python 3.9+ interpreter,
local Docker Engine, and Compose v2. Install the container runtime from the
official distribution/vendor instructions first. RHEL and Ubuntu hosts use the
same container stack; this does not certify their SELinux or native fencing
configuration. The installer never disables firewalld/UFW or opens host ports.

The initial HTTPS origin defaults to `https://<NODE_IP>:8787`. The installer
prints the private **file location** of the initial Super Admin token. The
initial self-signed CA is at `DATA_ROOT/config/controller/pki/ca.pem`. Trust or
review its fingerprint before login/join; a cluster password does not replace
TLS identity verification. Configure a permanent DNS origin and certificate in
Settings. Set unique node IDs/sites/IPs on the Noida, Pune and cloud hosts.

`--validate-only` parses the private `.env` without executing it and reports no
secrets. It does not install packages, test Docker or start services.
`--no-start` stages the installation. Reinstallation preserves existing private
identity and requires stopping the local manager first. A changed DATA_ROOT
must use the reviewed storage operation rather than silently pointing a live
installation at another directory.

Optional initial Entra settings are listed in `.env.example`. Supply the tenant,
client, exact HTTPS callback, first Super Admin object ID and a private client
secret file together. The installer validates the complete shape with the real
bundled `EntraConfig`; it does not claim a live Microsoft sign-in succeeded.
The source file must be owned and mode 0600. Its contents are copied to
`DATA_ROOT/config/controller/entra-client-secret` as UID 10001, mode 0600.
Runtime settings contain only the mounted secret-file path, never the raw secret
or original host path. A raw secret in the private `.env` is also accepted and
imported into the same protected file. Reinstallation preserves the configured
provider and refuses unreviewed secret/provider changes. Clear the initial
secret input fields after import when reinstalling from the preserved settings.
Configure a second independent Entra Super Admin in Users & Access before
production enforcement.

`SEG_HTTP_WORKERS` and `SEG_HTTP_THREADS` are optional initial overrides.
Workers default to AUTO (1 with standalone SQLite, 2 after PostgreSQL HA
activation); threads default to 32. Explicit ranges are 1..16 workers and
2..128 threads. Unset workers stay unset so activation can select the HA default.
Interrupted first installation retains a private pending identity: only the
same installer-owned node settings may resume its staged root. Unknown nonempty
roots and another node's pending installation remain blocked.

The Platform GUI can change this node's published dashboard/API port through a
reviewed `public-port` transaction. Ports 1..65535, including 443, are supported
when free; SSH and the configured database/backend/cluster ports are reserved.
The router still listens on container port 8787, and controller/backend/database
ports keep their existing values and privileges. The manager checks both Docker
publications and local socket occupancy, journals the exact old mapping,
recreates only its router, then verifies the approved TLS name/leaf and readiness
through the new port before committing. Interrupted/expired mutation phases and
failed candidate checks restore and verify the old mapping. The failed review
is held; a fresh review is required to retry. Unknown external edits block
compensation instead of being overwritten.
If an initial prepare request was never accepted, a cancellation-only record
freshly proves the exact old publication and fences that operation ID against
late delivery. It changes no mapping, revision or prior committed journal.
Cancellation IDs are retained without eviction; the bounded store fails closed
for explicit review when full.

The action preserves the stable controller origin, Entra callback, agent URLs
and external load-balancer configuration. Review and acknowledge those routing
dependencies before applying; no external reachability is inferred from the
local TLS check. This changes the owned Docker publication and issues no
firewalld/UFW commands. GUI-owned values persist in protected `installed.json`,
`application-port.json` and a port export in `gui-overrides.env`; the original
user `.env` is not edited. Candidate and committed ports remain distinct in
manager status. The actual Compose fixture can be rerun with
`python3 deploy/appliance/validate_public_port.py --context YOUR_PRIVATE_CONTEXT`;
it uses generated named-volume TLS material and temporary loopback ports, and a
TLS readiness backend rather than a full controller/identity-provider test.

## Initial setup and membership

Only the authenticated setup controller and router start initially. Shared
database configuration is **waiting for voters** until the approved manifest
contains three distinct-site database/etcd voters. Additional management
controllers are not limited to three and do not automatically become voters.
All three voters receive PostgreSQL copies; one PostgreSQL primary accepts
writes, with strict synchronous replication to at least one standby. This is
one database cluster shared by all controllers.

Use Settings to create the cluster or join an existing reachable controller
using its IP, shared cluster password and verified HTTPS trust. Private peer
material uses the controller's authenticated enrollment/sealing protocol.
Database/etcd mutual TLS uses dedicated internal issuing trust, separate from
endpoint enrollment trust. An endpoint certificate must not authorize DCS or
Patroni administration.

Database start requires an explicitly approved `/dev/watchdog0` matching its
kernel watchdog device, and rejects softdog/software/dummy watchdog identities.
Initial bootstrap requires all three authenticated etcd voters; restarting an
initialized copy requires surviving majority quorum. The manager never creates
an independent writable database when quorum or fencing is unavailable.
Patroni remains configured with `watchdog.mode=required`. Real watchdog reset,
site partition, fencing and recovery tests on the intended infrastructure are
required before production. Cloud hosts without a suitable watchdog remain
blocked as database voters until a validated fencing adapter is available.

Configuration writes private files and returns
`requires_service_start=true, requires_service_restart=true`. A completed start
job means the service command was accepted. Activation waits for fresh
authenticated health observations: a unique primary, etcd quorum and a
streaming synchronous replica. Health older than 45 seconds is unavailable.

## Storage and credentials

`DATA_ROOT` must be a dedicated root-owned subdirectory of `/var/lib`, `/mnt`,
`/srv` or `/data`, with no symlinks or ancestors writable by other users. It
contains controller state/vault, database data, etcd data, backups, private
configuration, journals and build contexts. Docker's engine/image/log cache and
the operating system's service journal remain under their runtime locations.
Only the boot pointer `/etc/prthak/data-root`, public manager code/service unit
and ephemeral `/run/prthak-appliance` socket/lease are outside DATA_ROOT.

The GUI storage review is bound to the exact source, target, revision and a
short-lived confirmation nonce. Migration stops owned services, rejects
foreign Docker writers and external tablespace/symlink paths, confirms watchdog
disarm, copies and verifies file checksums/permissions/ownership, fsyncs, and
atomically changes the boot pointer. It preserves the original directory.
Failures before pointer commit retain the old source; failures after commit
leave the verified new pointer for explicit recovery. Nothing copies live
PGDATA. Back up and validate the chosen filesystem/mount before moving a voter.

Initial replication passwords are set during real database bootstrap. Active
password edits use the coordinated rotation protocol: prepare on all three,
change the role on the observed primary, reload all three, authenticate a new
replication connection from each, then finalize. The fixed helper accepts the
password only through stdin and issues fixed SCRAM role operations. After any
role-change intent, failures resume forward; they never silently restore an old
password. Ordinary configure/storage operations are blocked during a pending
rotation. The GUI must keep a password pending until every final ACK arrives.

## Local manager API

The root manager listens only on `/run/prthak-appliance/manager.sock` (0660,
root/group 10001) with a private bearer token. The socket/token directory is
mounted read-only into the controller. It supports `GET /v1/status`,
`POST /v1/jobs`, and `GET /v1/jobs/<32-hex-id>`. Supported actions are status,
start, stop, restart, configure, storage-review, storage-move and the fixed
replication-rotation phases. The fixed `web-tls` action accepts only a public
certificate chain/name, validates the exact live backend leaf, syntax-checks
and restarts only the owned router, and verifies strict routed TLS/readiness
and the leaf fingerprint before completing. It preserves/recovers the previous
public router files on failure. Corporate imports need a complete public
issuer/root chain; an old CA-issued bootstrap leaf can use retained trusted
issuers. No web-tls request carries a private key or changes endpoint issuance.
Services are limited to controller, database,
etcd, router or all. There is no arbitrary command, image, mount or remote
Docker action in the request API.

`internal-tls` and `restore-databases` are fixed journaled protocols described in
[Lifecycle and native acceptance](LIFECYCLE_AND_ACCEPTANCE.md). Internal renewal
preserves the registered key/issuer. Database recovery stages derived empty
targets and preserves originals; the controller coordinates all writer/profile
barriers. Suspension denies future delivery but does not securely revoke a
former CA holder. Protected-state loss requires matching recovery, never an
invented replacement authority.

Every job requires `request_id` as a durable idempotency key. The same key and
payload return the prior job; a changed payload is rejected. Interrupted jobs
are held for review, not blindly repeated. Rotation journals separately allow
safe phase resumption with a new attempt ID. Delayed terminal rotation IDs
cannot authorize a new password change.

## Validation evidence

`tests/test_appliance_installer.py` covers private env parsing, permission/path
guards, real authenticated Unix HTTP, idempotency, interrupted configuration,
quorum/watchdog guards, stopped storage copy/failure retention and credential
rotation failure/retry barriers. These tests mock host Docker/service changes.

Build the public-only test images with
`python3 deploy/appliance/build_validation_images.py --context <test-context>`.
`validate_images.py --context <test-context>` checks the actual images,
Compose schema and strict HTTPS through HAProxy to the nonroot controller.
`validate_cluster.py --context <test-context>` checks actual three-node etcd
mutual TLS, PostgreSQL/Patroni primary plus two replicas, SCRAM application
login, synchronous writes and replicated read-only copies. `--rotation` also
drives real local rotation journals, SQL, mTLS reloads and new authentication.
`--coordinator` runs the shared coordinator against the same real PostgreSQL
cluster and manager adapters through a test-only private mTLS helper transport.
All containers/volumes/networks are disposable; no host ports or data bind
mounts are used. Test fixture watchdog is explicitly off; production guards are
unchanged. This is wiring evidence, not native watchdog/site-loss validation.

The actual fixed web-TLS action, rollback and bootstrap-leaf restoration also
pass using real HTTPS sockets and HAProxy in a disposable isolated container:

```sh
docker --context <test-context> run --rm --network none --cap-drop ALL \
  --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER \
  --security-opt no-new-privileges:true prthak-appliance-router-action-test
```

These narrowly scoped file capabilities apply only to the private test
filesystem. Its Engine transport controls one HAProxy process instead of host
Docker Compose. No host mounts, Docker socket, devices or firewall capabilities
are used. The corporate-chain smoke additionally proves wrong-DNS rejection and
that an unknown corporate leaf alone cannot anchor HAProxy trust.

Primary references: [Patroni replication modes](https://patroni.readthedocs.io/en/latest/replication_modes.html),
[Patroni watchdog](https://patroni.readthedocs.io/en/latest/watchdog.html),
[Patroni configuration](https://patroni.readthedocs.io/en/latest/yaml_configuration.html),
[etcd transport security](https://etcd.io/docs/v3.6/op-guide/security/),
[HAProxy 2.8 configuration](https://docs.haproxy.org/2.8/configuration.html), and
[PostgreSQL 16 replication](https://www.postgresql.org/docs/16/warm-standby.html).
