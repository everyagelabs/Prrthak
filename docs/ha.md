# Prṛthak · पृथक्: controller HA and recovery (0.6)

Use the same reviewed Git checkout and local installer on every management host. The default 0.6 appliance combines a nonroot controller, local TLS router and a restricted root service manager. Three controllers in independent sites also serve as PostgreSQL 16/Patroni and etcd voters. Additional management controllers have no three-node limit. This runbook replaces the earlier dedicated SSH database-installer flow as the default setup.

This remains a lab release. Actual private three-node TLS/replication wiring and local rotation phases have passed; the fixture explicitly disabled its watchdog. Native watchdog resets, real host/site partitions, fencing, production RPO/RTO, full RHEL enforcement and real 5,000-endpoint load remain acceptance gates. Controller HA never authorizes endpoint firewall enforcement.

## Prepare each host

| Prerequisite | What the operator supplies |
| --- | --- |
| Platform | Genuine Linux with systemd, a root-owned Python 3.9+ interpreter, Docker Engine and Compose v2. Install the runtime using approved vendor/distribution instructions. The controller and database runtimes are containerized. Ubuntu and RHEL use the same installer; this is not distribution/SELinux/fencing certification. |
| Identity | A unique NODE_ID, reachable private IPv4 NODE_IP and correct SITE. Distinct voter sites must represent independent failure domains. Time synchronization and a recovery console are required. |
| Storage | A dedicated durable DATA_ROOT beneath /var/lib, /mnt, /srv or /data. It and its existing ancestors must be root-owned, without writable-by-others ancestors or symlinks. Validate capacity, filesystem, mount persistence and backup destinations. |
| Trust and access | Super Admin access, the reviewed release, protected initial tokens/cluster password, verified HTTPS fingerprints and a plan for stable DNS/TLS. Keep endpoint issuance trust separate from internal database/etcd/Patroni trust. |
| Native fencing | Each of the three database voters needs an explicitly approved /dev/watchdog0. Software/softdog/dummy identities are refused; required-mode Patroni fencing is not disabled by production setup. An approved hardware or virtual-hardware watchdog still needs actual reset/fencing validation. A host without suitable fencing cannot be accepted as a database voter. |
| Private routes | Controller/router HTTPS 8787 or the chosen published port; peer-router/controller backend HTTPS 8786; PostgreSQL TLS 5432; etcd client 2379 and peer 2380; Patroni mTLS 8008. Scope each path to its participants; backend 8786 is private. No installer disables firewalld/UFW or opens the host firewall. |

The installer builds the controller and PostgreSQL/Patroni images, pulls official etcd/HAProxy images and installs the local manager. Provide approved access to the required registries/repositories or pre-staged artifacts. The controller runs as UID 10001 and receives no Docker socket or arbitrary host-command interface.

## Install the same release everywhere

At Noida 81, Pune, AWS and subsequent management sites, run the same commands from the reviewed checkout:

```sh
cp .env.example basic.env
chmod 600 basic.env
# Edit DATA_ROOT, NODE_ID, SITE and the reachable NODE_IP for THIS host.
sudo scripts/install-controller.sh --env-file basic.env
```

`basic.env` is a private local filename; `.env.example` is the supplied template. The installer parses values as data and never sources the file. Do not commit populated files. `NODE_IP=auto` detects an address; verify peer reachability or set it explicitly. The default initial origin is `https://<NODE_IP>:8787`. Set a stable permanent HTTPS origin/certificate through Settings and validate the resulting route before endpoint rollout.

The installer reports the private **file location** of the initial Super Admin token, never its value. The initial public CA is `DATA_ROOT/config/controller/pki/ca.pem`. Obtain/review its fingerprint through a trusted channel before login. `--validate-only` validates environment settings without installation/start; `--no-start` stages the host. Reinstallation preserves existing private identity. A changed live DATA_ROOT requires the reviewed storage workflow, not a path override.

Optional initial CLUSTER_PASSWORD and EXISTING_NODE_IP values do not remove peer trust review. A join password must not be transmitted automatically to an unverified address. The full operator flow is below; see [the appliance reference](../deploy/appliance/README.md) for exact local paths and manager constraints.

## Create the cluster and join by IP

1. On the first authenticated setup controller, open **Settings → Controller cluster**. Set the cluster name, this node's site/address, the intended stable origin and a shared cluster password. Cluster passwords are 16–256 characters; initial replication passwords are 32–128 printable ASCII characters. Empty password fields preserve existing values.
2. Install the same release on a new empty host. Sign in with its temporary local Super Admin access and choose **Join existing cluster**. Supply an existing controller's reachable IP/HTTPS URL and the shared cluster password. Before sending any password, the controller obtains only that peer's public TLS certificate.
3. Independently compare the displayed fingerprint with the trusted existing controller. Review the exact local node/site/IP and type the displayed **TRUST … AND JOIN** phrase. Only this approval permits the password request. Private enrollment replies are sealed to the joining node's persistent RSA key and bound to its identity.
4. The first three eligible registrations in distinct sites become database/etcd voters. An early registration sharing an existing voter site becomes management-only; it does not take that site's second vote. Once three voters exist, all later registrations are management controllers. There is no three-controller cap and no silent fourth voter.
5. Approve and validate native fencing on every voter. Pending configuration is staged while fewer than three voters exist. Initial database bootstrap requires all three authenticated etcd voters. Service start and configuration jobs are not proof of database readiness: wait for fresh quorum observations, one primary and a streaming synchronous replica.
6. The original source controller alone migrates its stopped SQLite state to the fresh shared databases. Both namespaces must have matching deployment/epoch/import identity and READY markers. Row counts and canonical contents are verified before committing the private active profile and restarting. Retired SQLite is fenced; shared storage failure never activates an alternate local writer.
7. Other controllers adopt the existing shared deployment and authentication. Local setup/account state can be preserved privately, but inventory, policy, learning authority and traffic are never merged from another populated source. Confirm node/site heartbeats and both shared dependencies before adding a controller to client routing.

Before database activation, membership changes go through the original bootstrap controller. Once shared PostgreSQL is active, an authorized healthy peer can resume the same key-bound enrollment with the same member sync secret/public certificate. Reusing another node's ID, key, IP or site is refused. Replacing a registered identity requires an explicit replacement workflow. New enrollment waits while a replication-password rotation is pending.

## Three database copies, one writer

All three voters hold PostgreSQL copies and etcd state; this is not the older two-database-plus-witness layout. There is one PostgreSQL primary, strict synchronous replication and at least one required eligible synchronous standby. Metadata and traffic are separate databases on this authoritative cluster. Additional management controllers use these same writer endpoints.

Strict synchronous commits can wait when no eligible synchronous standby survives. A majority of etcd voters does not alone guarantee database write availability, fencing correctness or a fixed recovery time. Do not promote independent per-site databases, place SQLite on NFS, or disable the native watchdog to bypass a blocker. A cloud host without a suitable validated watchdog can serve management, but cannot be treated as an accepted voter.

Database, etcd and Patroni mutual TLS use a dedicated internal CA. Endpoint-issued client certificates are rejected under that internal trust. The endpoint issuing key belongs only to authorized controller enrollment, not to the node manager. Every ready controller must preserve endpoint trust and the stable application-server trust required by existing agents.

## Site-local routing: Noida 81, Pune and AWS

Use site-local ready controller pools and explicit fallback routes. For example:

| Clients | Preferred local pool | Reviewed fallback |
| --- | --- | --- |
| Noida 81 | Noida management controllers | Pune, then AWS as designed |
| Pune | Pune management controllers | Noida, then AWS as designed |
| AWS | AWS management controllers | An approved reachable DC pool |

The appliance generates a local TLS router and can retain preferred/fallback controller URLs. This does not provision redundant external load balancers, global DNS failover, cloud routes or VIP ownership. Arrange those services separately, with site affinity where required, and measure actual failover. One stable endpoint origin avoids reconfiguring every agent after controller loss; another site must present the same trusted hostname/chain and preserve endpoint mTLS.

Forward agent TLS through an L4 TCP route so the serving controller verifies the enrolled client certificate. Do not trust forwarded client-certificate headers or forged endpoint identity headers. Browser, enrollment and readiness requests do not require an endpoint certificate globally; endpoint routes enforce mTLS individually. A controller-process outage leaves committed endpoint rules intact, and temporary learning expires locally.

| Health path | Meaning |
| --- | --- |
| /healthz | Process liveness; can succeed while shared storage is unavailable. |
| /readyz | Required dependency readiness; returns 503 on dependency failure. Use verified TLS probes for routing. |
| /api/v1/cluster | Authenticated shared controller/node/site state. |
| Settings service/cluster health | Actual local manager and authenticated peer observations; health older than 45 seconds is unavailable. |

Readiness is not a write-durability test. Strict synchronous writes can wait even when a database still answers read probes. Exercise real application commits, endpoint enrollment and existing-certificate policy requests through each intended route before production admission.

## Operate the appliance from Settings

Only Super Admin can change appliance/platform configuration. Admin and Read Only access do not grant host service authority.

- **Services:** review and type the exact start/stop/restart confirmation for controller, database, etcd, router or all owned services. The restricted root manager rechecks dependencies/quorum. Accepted/staged commands remain distinct from verified healthy services.
- **Storage:** review the actual source/target path and type the exact phrase. The manager stops owned writers, rejects foreign Docker bindings and unsafe symlinks/tablespaces, verifies watchdog disarm, copies and checks contents/permissions/ownership, fsyncs and atomically changes the boot pointer. It preserves the old directory. No live PGDATA copy is performed; moving one voter still requires a maintenance/recovery plan.
- **Replication password:** an active edit queues a shared rotation; it is not an environment-only change. All three voters stage without reload, the observed primary changes the SQL role, all voters reload and authenticate a genuinely new replication connection, then all finalize. Progress/ACKs/errors stay visible. After durable role-change intent, recovery proceeds forward; it never blindly restores an old password. Ordinary configure/storage work is held while pending. Existing/identical active passwords need no rotation; leave the field blank to preserve them.
- **TLS certificate:** review PEM or PKCS#12 import (with a private password when needed), or generate a hostname/SAN leaf. Corporate certificates need a complete public issuer/root chain, supplied or completed from known trust. A lone corporate leaf can pass a leaf-pinned local probe yet fail the appliance router's CA validation; do not activate it as a complete corporate identity. The preview verifies certificate/key compatibility, identity, validity and TLS usage. Existing issuing trust is retained where possible; a literal new self-signed identity requires explicit trust-change acknowledgement. Apply queues supervised restart/readiness validation and retains a rollback pair. Verify actual HTTPS and the intended hostname through the router too. This does not silently rotate the endpoint issuing CA.
- **Agent polling:** set global control/discovery defaults and optional server/group/tag overrides. Supported agents report version/digest outcomes. Each interval resolves independently by priority, explicit server, group, then tag specificity. These settings cannot enable enforcement, widen firewall access or replace endpoint credentials.

Endpoint NAT is an address-reporting limit, not a routing feature. Inventory `server.ips` comes only from the authenticated agent payload; the control connection's translated peer address never substitutes for it. Reservations retain `ips:[]`, proposed `planned_ips` and `address_status:planned_unverified` until an authenticated agent report arrives. Traffic `source_ip` remains the exact source observed by the destination kernel. Recovering an application client's pre-NAT address needs separate mappings/logs; neither a reported IP nor a shared NAT address proves unique workload identity.

DATA_ROOT contains controller state/vault, database and etcd data, backups, configuration and operation journals. Docker engine/image/log storage and the OS service journal remain in their runtime locations. Preserve `/etc/prthak/data-root` and the protected state consistently; changing only the boot pointer is not a recovery procedure.

GUI HTTPS replacement is separate from endpoint and internal service identities. Endpoint leaves support authenticated renewal in the 30-day window, 24-hour tracked overlap, exact registry revocation and one-time recovery credentials. Internal database/etcd/Patroni leaves use the dedicated internal CA, 90-day lifetime and 30-day renewal window, with exact served-fingerprint verification and rollback. Settings reports actual leaf/runtime state. Internal suspension blocks sync/renewal/routing admission but does not revoke copied DB credentials or a compromised issuing CA; full secure decommission requires fenced offline CA/all-secret recovery. When corporate web HTTPS and endpoint issuers differ, preinstall the public endpoint issuer CA and configure endpoint_ca_cert separately from ca_cert. Neither endpoint renewal nor recovery trusts replacement roots from responses.

## Automatic backups and safe demo cleanup

Settings → Backups creates real SQLite snapshots or PostgreSQL custom dumps and supports inspect, authenticated download and structural restore validation. Schedule daily/weekly runs or a 1–168 hour interval, choose an IANA timezone (default Asia/Kolkata), and retain 1–365 successful scheduled archives. Weekly weekday is Monday 0 through Sunday 6. Schedules survive restart, catch up one missed slot and elect one shared due-slot worker across controllers. No overlapping local backup is assumed successful.

Retention removes only owned scheduled archives after a verified successful replacement; manual and pre-cleanup backups are retained. Archive files remain local to the controller that executes the job. Another controller cannot silently download unavailable local bytes. Replicate protected recovery copies independently, or use an explicitly shared protected archive directory as designed.

Archives are private 0600 database data and include sensitive accounts, identities, policies, audit and traffic. They **exclude** PKI/issuing keys, the controller Vault and active profile, vault.key, environment, Entra secrets and the backup directory. Preserve these separately through an approved protected recovery process. GUI restore validation checks archive/component hashes, SQLite integrity/schema or the PostgreSQL dump catalogue. It does not restore a live deployment.

Settings → Demo data previews proven eligible synthetic fixtures and dependencies, then requires the exact typed phrase and a verified automatic backup before deletion. Real hosts, shared/manual records, edited/legacy fixtures without proven seed origin, accounts and audit are preserved. Mixed dependencies block unsafe cleanup. Successful removal disables default reseeding after restart. A preview is not deletion.

## Supervised database recovery in the GUI

Settings → Recovery requires a complete verified archive on the current controller, an incident reason, matching current PKI/Vault/active profile and the live safety ledger. One current authorized Entra Super Admin completes two explicit confirmations of the immutable digest/nonce-bound review, including its exact phrase. The actor must remain enabled; no different reviewer or pilot mode is required. Shared-token/demo authority cannot authorize production recovery. Membership, epoch/profile or archive changes invalidate the review; another nonterminal recovery cannot be overwritten.

The supervisor fences/drains controller writers and preserves old databases/protected rollback material before releasing verified candidates. PostgreSQL uses per-controller fence/profile/private-readiness barriers and one authoritative deployment epoch; source databases remain fenced. Temporary fixed-helper errors retry the same immutable phase with durable 5/10/20/40/60-second backoff, without a five-attempt dead-end. A binding/digest/permanent safety mismatch stays blocked. Do not require an imaginary GUI Resume action while every public child is intentionally drained.

Public HTTPS/API/readiness may be unavailable or 503 during the hold; a private nonce-ready probe cannot authorize other APIs. Reconnect, sign in again with Entra and inspect durable status/receipts/errors for verified completion. A queued job or dashboard disconnect establishes no restore outcome. Sessions, unused credentials, pending approvals and automatic learning are invalidated; higher desired versions require fresh policy review. Current revocations, disabled users, retired identities and immutable policy/audit history are retained. Older PG archives without canonical data hashes are structural-only for this flow.

Archive-only or lost live safety/private state blocks online recovery. Preserve separately protected database and PKI/Vault/key/profile/auth recovery copies; the GUI does not invent a replacement CA or claim complete offline DR. Original databases are retained for controlled rollback, never exposed as a second authoritative writable deployment.

## Verification and recovery gates

Local tests cover genuine SQLite/Vault/crypto, encrypted peer enrollment, no password before fingerprint approval, stable cross-controller retries and managed PostgreSQL identity guards. Eight original PostgreSQL platform acceptance cases checked fixed-table IDs/canonical hashes, queues/receipts, populated/foreign target refusal, retired-source fences and a real offline two-database dump/restore. Additional real-PG tests cover scheduling and replication-coordinator concurrency with separate store adapters; simulated actuators in those protocol tests are distinct from the actual cluster wiring evidence below.

Current 0.6 evidence adds independent identity-backed approval, signed policy/package trust, actual private notification transports, native endpoint lifecycle and real supervised HTTPS recovery. The final 0.6 implementation baseline passed 528 controller tests, 150 integration checks and 201 dashboard tests with genuine PostgreSQL acceptance; Go regular/race/vet and make check pass. Isolated tests do not certify physical site recovery or a production fleet.

The disposable private cluster validates actual etcd mTLS, PostgreSQL 16/Patroni with one primary/two replicas, strict TLS SCRAM application writes, synchronous streaming and read-only replicated rows. The full shared coordinator passed against that same actual cluster using matching READY/epoch guards and separate real PostgreSQL stores: all-three prepare, one primary SQL role mutation, authenticated Patroni reloads, genuinely new replication authentication from every copy, exact final ACKs and updated private controller materials. Durable real local-manager jobs were used. No raw new password appeared in shared metadata, audit or public progress. Test-only fixed-helper mTLS transport is absent from production database images; no host ports or Docker-socket mounts were used by these fixtures. This is isolated integration evidence, not a deployed customer cluster.

Actual normal CLI/Gunicorn HTTPS SQLite recovery retained the parent, drained the entire old child group, restored a real database pair and resumed a crash between file swaps. The private nonce-ready probe returned 200 while public readiness/APIs stayed 503; it could not bypass API authorization. Verified release returned public 200 and the old session returned 401. Real isolated PG coordinator barriers used three fake fixed-manager/process actuators; separately the actual three-node PG 16/etcd/Patroni restore helper proved fenced-source markers, empty derived databases, restricted restore, a new epoch/readback and retained originals. These separate fixtures are not a combined physical WAN/native-fencing acceptance.

The fixture explicitly turns its watchdog off only in generated test configuration. Production renders required watchdog mode and rejects software/softdog/dummy identities. Therefore this evidence does **not** validate actual watchdog reset, promotion/fencing under partition, real site loss, production RPO/RTO, full RHEL enforcement, live Entra/MFA or real 5,000-endpoint capacity. Hardware or approved virtual-hardware watchdogs still require those actual failure tests. Record all acceptance outcomes before the 20-host pilot and fleet rollout. See [Linux evidence](linux-validation.md), [scale boundaries](scale-validation.md) and [the appliance validation commands](../deploy/appliance/README.md#validation-evidence).

For recovery, fence every writer, restore metadata and traffic to compatible points, restore the matching protected trust/Vault/profile state and verify enrollment/policy/history before reopening ingress. Never expose a second writable restored copy alongside the authoritative deployment. Release rollback requires a schema-compatible reviewed version. Former primaries require the approved rewind/rebuild/switchover procedure; reconnecting an old writer is not failback.

## Advanced appendix: externally operated or historical deployments

The files in `deploy/ha/` remain reviewable examples for an externally operated PostgreSQL service, L4 HAProxy routing and the earlier constrained SSH provisioning path. They are not the default 0.6 same-installer instructions. The historical GUI provisioner targets dedicated Ubuntu 24.04 AMD64 nodes with **two PostgreSQL hosts and one etcd-only witness**, pinned SSH host keys and fixed-helper privilege. Do not mix that witness topology or its configuration with the new three-copy appliance cluster.

For an externally operated HA service, supply both private metadata and traffic writer DSNs, verified TLS and the exact managed deployment identity/epoch when applicable. Shared dependency failures never fall back to SQLite. Every node uses the same release, endpoint issuing trust and Entra application settings. Keep database secrets in protected environment/profile files, not process arguments. PostgreSQL connections must preserve the sessions used for background leadership locks; transaction/statement pooling is unsuitable for those locks.

`deploy/ha/haproxy-active-active.cfg.example`, `haproxy-dc-dr.cfg.example`, `prthak-controller.service` and environment examples require explicit operator adaptation, trusted readiness checks and actual installed-package validation. Do not start a preconfigured --ha template against a blank setup. The older bound one-time DR join-code interface remains an advanced compatibility path; the normal appliance GUI uses shared cluster-password joining with explicit peer trust review.

Primary references: [PostgreSQL 16 replication](https://www.postgresql.org/docs/16/warm-standby.html), [Patroni synchronous replication](https://patroni.readthedocs.io/en/latest/replication_modes.html), [Patroni watchdog](https://patroni.readthedocs.io/en/latest/watchdog.html), [etcd transport security](https://etcd.io/docs/v3.6/op-guide/security/), and [HAProxy 2.8 configuration](https://docs.haproxy.org/2.8/configuration.html).
