# Managed database cluster installer

The GUI platform worker calls `controller.ha_setup.Provisioner`. This installs
real PostgreSQL, Patroni and etcd services on explicitly supplied dedicated hosts.
It does not turn independent per-site databases into multiple writers. Controller
activation, application-data migration and L4 ingress are separate platform jobs.

The initial installer supports **Ubuntu 24.04 AMD64** and its signed official
Ubuntu repositories. The package adapter uses PostgreSQL 16, `patroni`,
`python3-etcd`, `python3-psycopg2`, `etcd-server` and `etcd-client`. ARM64 database
installation is blocked because Ubuntu's packaged etcd 3.4 reports that platform
as unsupported. This restriction does not change endpoint/controller ARM64 or
RHEL support. Do not force `ETCD_UNSUPPORTED_ARCH` to bypass it.

Provide three independently located etcd voters: two database hosts and a third
quorum-only witness. Each SSH host key must be verified independently and pinned
as its complete public key. Each login uses a vault-managed private key and root
or passwordless sudo for the fixed helper. Password login, agent forwarding,
arbitrary commands, caller-supplied package URLs and arbitrary filesystem paths
are unavailable.

The two database hosts need an explicitly approved, already configured Linux
watchdog character device. It must be inactive before adopting an empty host.
The helper does not load `softdog`, disable rebooting, change kernel watchdog
options or take over an active watchdog. Patroni runs with `watchdog.mode=required`
and `safety_margin=-1`; absent fencing blocks promotion. Test the actual selected
hardware/hypervisor reset behavior before admitting production workloads.
[Patroni watchdog behavior](https://patroni.readthedocs.io/en/latest/watchdog.html).

Replication uses `synchronous_mode=true` and `synchronous_mode_strict=true`. With
two database hosts, losing the sole synchronous standby blocks commits. The
witness holds coordination state, not a third copy of application data. No fixed
RPO/RTO or zero-loss guarantee is implied; cancellation and simultaneous failures
still require an evaluated recovery policy.
[Patroni replication modes](https://patroni.readthedocs.io/en/latest/replication_modes.html).

Peer and client etcd traffic use TLS with certificates required on both channels.
Patroni uses the etcd3 API and its own mTLS HTTPS API. PostgreSQL requires TLS and
SCRAM authentication. Replication validates the server certificate; application
connections select the writable server from both node IPs with `verify-full` and
`target_session_attrs=read-write`. Each node certificate includes its actual IP.
[etcd transport security](https://etcd.io/docs/v3.4/op-guide/security/),
[PostgreSQL client TLS](https://www.postgresql.org/docs/16/libpq-ssl.html).

Allow the required network paths through the approved network controls before
provisioning: etcd TCP 2379/2380 among the three voters, Patroni TCP 8008 among
database hosts, PostgreSQL TCP 5432 between database hosts and from the configured
controller source CIDRs, and pinned SSH from the provisioning controller. The
helper does not rewrite the host firewall or network interfaces.

The operation inspects every target before installing anything. Existing
unmanaged database/DCS data, conflicting ports, a foreign setup journal, unsupported
architecture, missing watchdog or invalid local node IP blocks the job. It
prevents package post-install scripts from creating an unrelated default
PostgreSQL cluster. It configures all voters before starting databases and never
reports `ready` until authenticated quorum, exactly one fenced primary, a
streaming synchronous replica and both application database roles are verified.

Configuration and keys live under `/etc/prthak-cluster`. Data and private durable
journals live under `/var/lib/prthak-cluster`. The fixed units are
`prthak-etcd.service` and `prthak-patroni.service`. A node-local lock serializes
mutations. Configuration writes have a private recovery snapshot: a failure
restores the previous files. Preview validates an interrupted snapshot without
mutating it, then a fresh GUI review binds its digest before recovery and service
startup. Unknown, corrupt or foreign snapshots block the operation. Retrying an
owned install does not upgrade packages. Failures
retain initialized data; the installer never deletes a data directory, invokes
`force-new-cluster`, blindly promotes a replica or rewrites etcd membership.

The temporary package auto-start guard has a separate private durable backup.
After an interrupted install, retry restores the original guard or removes only
the exact temporary guard created by this installer. If an operator changed that
file in the meantime, the retry blocks instead of overwriting it.

Install/retry refuses a different credential-material digest on an established
node. It cannot silently rotate its CA, node key or database role passwords while
the old service is still running. Credential rotation requires a separate
reviewed operation; it is not part of this initial installer.

DR installation asks for an existing node IP, a one-time Super Admin join code,
the cluster CA pin and the target SSH pin. Consuming the code produces the trusted
`JoinAuthorization` object used by the provisioner. A join is limited to the
predeclared DR host in the reviewed topology. An IP address alone does not grant
trust. A lost etcd member or a changed IP requires a separate reviewed,
quorum-backed member-replacement operation; this initial installer refuses it.

The backup helper produces private custom-format dumps on the authenticated
primary with checksums. It reports `off_node_retained=false` and
`compatible_point=false`: the platform backup worker must encrypt/export them,
and coordinated quiescing is required for a compatible cross-database recovery
point. It does not call a pair of independent dumps a completed HA backup.

The platform worker supplies the private material provider and durable public
progress callback. Public results contain phase/status/checks only. CA signing
keys stay in the controller vault. Selected per-node private keys and role secrets
travel only through authenticated SSH stdin. Private database connection fields
are returned only by `private_connection_fields` for the trusted activation
worker, never by `apply`, `preview` or `status`.

## Validation and remaining deployment gates

Run the focused suite with `python3 -m unittest controller.tests.test_ha_setup -v`.
It exercises pinned transport construction, private key lifetime, real local PKI
generation, unsafe topology rejection, empty-node guards, sequencing, role and
quorum readiness, configuration rollback/interruption recovery, credential retry
binding and trusted DR joins. These are not a three-host infrastructure test.

The package capability check on 2026-10-30 installed the signed Ubuntu packages
in isolated containers and verified PostgreSQL **16.15**, Patroni **3.2.2** and
etcd **3.4.30**, including the etcd3/psycopg2 imports. Both native ARM64 package
availability and the supported AMD64 package build were checked. The production
installer rejects ARM64 before mutation; its etcd warning was not overridden.
The actual packaged Patroni configuration validator accepted the generated
required-watchdog/mTLS/strict-sync schema with a local TCP reachability placeholder.
That parser check did not establish an authenticated DCS or a running database.

An opt-in smoke is reproducible on a disposable Docker context with native AMD64
or compatible emulation and Docker volume-subpath support:

```sh
docker --context YOUR_TEST_CONTEXT build --platform linux/amd64 -f deploy/cluster/Dockerfile.smoke -t prthak-ha-node-test:ubuntu24-amd64 deploy/cluster
python3 deploy/cluster/smoke_docker.py --context YOUR_TEST_CONTEXT --evidence .local/ha-node-test/daemon-smoke.log
```

It uses an internal network, PostgreSQL-user containers with all Linux
capabilities dropped, no host ports, public-only bind mounts and temporary PKI in
private Docker volumes. Its first check requires the unchanged production
watchdog setting to refuse promotion without a device. It subsequently changes
only the disposable fixture copies to `watchdog=off` to test actual TLS, strict
synchronous replication, application roles, SQL replication and minority-quorum
behavior. That second stage cannot certify fencing. All task-created containers,
networks and credential volumes are removed, including on failure.

The attempted AMD64 daemon run on the available ARM host accepted the generated
etcd configuration and loaded the certificates, but failed before quorum:
etcd/bbolt's initial 10 GiB memory mapping returned `ENOMEM` under emulation.
**No successful quorum, replication, required-watchdog promotion or infrastructure
failover result is claimed from that run.** A native Ubuntu 24.04 AMD64 three-host
acceptance test with the selected real watchdog/reset device remains a deployment
gate. No supplied real target hosts or production cluster were configured.

<sub>Created by Pratik Srivastava</sub>
