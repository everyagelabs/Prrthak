# Controller VM requirements and 5,000-server profile

1 November 2026 · 0.8.0 pilot candidate. These allocations are engineering starting recommendations, not certified hardware minima or a WAN/site-failover guarantee. DC deployment and native OS acceptance are deferred. The installer runs the controller/router on every management node; an approved database voter additionally runs PostgreSQL/Patroni and etcd on that same VM.

| VM use | vCPU | RAM | OS / Docker disk | Separate DATA_ROOT SSD |
| --- | ---: | ---: | ---: | ---: |
| 20-server pilot / setup node | 4 | 8 GiB | 80 GiB | 100 GiB |
| 5,000-server management-only controller | 8 | 16 GiB | 80 GiB | 100 GiB |
| 5,000-server combined controller + database voter | 8 | 32 GiB | 80 GiB | 300 GiB initially |

For the managed HA database, provide **three approved voter VMs**; each stores a full database copy. Additional management-only controllers can be added. Each surviving controller pool must be sized for the assigned load after a node/site fails, rather than dividing 5,000 evenly and assuming the failed site's share disappears. Site placement, quorum, redundant ingress and failover remain a deployment design/acceptance task.

Use SSD storage with predictable durable-write latency and at least 1 Gb/s networking. DATA_ROOT includes metadata, traffic history, configuration, PKI, journals and local backups. Docker images/logs remain on the OS/Docker disk. Traffic retention, learning concurrency, rule snapshots, version history, WAL and retained original/candidate databases during recovery determine growth. Measure them and retain free space for recovery; 300 GiB is not a guaranteed traffic-retention capacity. Off-node backup storage is additional.

Controller hosts need genuine Linux systemd, a root-owned system Python **3.9+**, Docker Engine and Compose v2. The image supplies the controller's Python runtime and dependencies. RHEL 9 or Ubuntu 26.04 are reasonable target hosts for the intended native validation. A RHEL 8 controller host needs an approved root-owned Python 3.9+ interpreter selected with `PRTHAK_INSTALL_PYTHON`; its default Python 3.6 is insufficient. The static RHEL/Ubuntu endpoint agent has no Python runtime dependency. Database voters additionally require the hypervisor/host's approved real watchdog exposed at `/dev/watchdog0`; the installer does not substitute software fencing.

## Runtime profile and connection budget

For the initial 5,000-server PostgreSQL profile, use the existing AUTO worker selection (two workers after HA activation), 32 HTTP threads per worker and bounded database pools:

| Settings → Setup field | Starting value |
| --- | ---: |
| HTTP workers | AUTO (blank) |
| Threads per worker | 32 |
| Metadata connections per worker | 8 |
| Traffic connections per worker | 2 |
| Connection wait | 5 seconds |

Run the verified installer with `--gui-setup`, then review these public settings in the GUI. The fixed manager writes protected configuration; manual `.env` editing is not required. AUTO keeps the setup SQLite node at one worker and selects two for the installed PostgreSQL runtime. Existing values are preserved on reinstall. Explicit overrides must match the validated storage/runtime configuration. Database pooling starts only inside running PostgreSQL workers after fork. It does not cache authorization or assignment authority; every transaction checks the current namespace/epoch and retains its durability and locking rules.

The compiled default pool caps are 16 metadata and 4 traffic connections per worker; the profile above deliberately lowers them to 8/2 when several controllers share one database instance. Budget the maximum across **all** controllers, both databases and every worker:

```text
application connection ceiling = controllers × workers × (metadata cap + traffic cap)
```

Three controllers × two workers × (8 + 2) gives 60 application connections before job leadership, monitoring, replicas and administration. Keep explicit reserve and verify PostgreSQL `max_connections` on the primary. More management controllers require revisiting that budget; increasing workers without considering database sessions can reduce availability. Gunicorn's [worker/thread model](https://gunicorn.org/design/) explains why workers and threads are different concurrency controls. PostgreSQL's [resource settings](https://www.postgresql.org/docs/16/runtime-config-resource.html) describe database memory tradeoffs; the dedicated-database shared-buffer guideline must not be applied blindly to a combined controller/voter VM.

## Policy freshness profile

A 60-second polling interval can consume the entire 60-second delivery budget before processing starts. In **Platform settings → Agent polling**, review and save:

- Global control interval: **30 seconds**.
- Discovery interval: **900 seconds**.
- Any server/group/tag overrides within the required delivery scope: control interval at most 30 seconds.

Verify those endpoints report the current polling version/digest before relying on this profile. Existing intervals and overrides are not silently changed. This shortens polling to leave processing headroom; it does not lengthen polling to disguise controller load.

For the selected **1–20 pilot endpoints**, the reviewed pilot preset uses **30-second control / 60-second discovery**. It changes only that explicit selection; fleet defaults remain 30/900 and unrelated overrides remain intact. Check each endpoint's applied polling receipt. The faster discovery preset is for pilot evaluation, not evidence of a measured fleet-wide discovery/CPU budget.

Optional per-port hit monitoring is disabled by default and separate from temporary learning. It can retain a rolling 1–24 hours of bounded observations without creating access grants. Discovery every 60 seconds, continuous capture and high source cardinality all need fresh CPU/RAM/storage measurement. Historical passive agent measurements in [agent resources](agent-resources.md) predate 0.7 and do not qualify these workloads.

The capacity acceptance uses a real administrative policy edit, includes compilation/publication, verifies each endpoint's advanced version/digest and complete source matrix, and spreads checks across a full 30-second polling window. It also exercises conditional polling and a bounded mixed discovery/traffic workload. Results and exact source/configuration provenance belong in the [capacity runbook](controller-capacity-5000.md). A successful local workload establishes that measured configuration; it does not prove native firewall application, human approval time, 5,000 simultaneous learning collectors or a universal 60-second network SLA.

All controllers share the PostgreSQL writer. Controller site affinity does not make remote database writes local. Synchronous replication and inter-site RTT/fsync latency affect publication/reporting; measure actual quorum placement, commit latency and the failover configuration before admitting the DC topology to the same freshness target.

## Connectivity and installation source

| Path | Port / purpose |
| --- | --- |
| Browser to management origin | HTTPS 8787 by default, or the approved management LB mapping |
| Agent policy, authorization, configuration witnesses and renewal | mTLS control listener 8788 by default |
| Agent enrollment, inventory, flow and hit uploads | Discovery listener 8789 by default; token/CSR enrollment, then endpoint mTLS |
| Controller/router peers | Configured backend port, initially 8786 |
| Approved database routing | 5433 router; 5432 PostgreSQL among approved nodes |
| Database quorum/internal health | 2379/2380 etcd and 8008 Patroni among approved nodes |
| Endpoint inbound control | No inbound agent listener; discovery and firewalld commands run locally |

The installed split profile uses three actual TLS listeners with route admission based on the accepting socket; a caller-supplied header cannot choose a privileged channel. Legacy combined mode remains explicit compatibility behavior. Use DNS, time synchronization, trusted hostname certificates and a TCP/L4 route preserving endpoint mTLS. Restrict database/quorum ports to approved nodes. Port changes are reviewed GUI operations; external LB/DNS routing and retained old aliases remain operator prerequisites until endpoint migration receipts are verified.

Existing Entra provider/secret/callback changes and joined-profile convergence use GUI-supervised migration with the authorized Super Admin's verified candidate sign-in, exact Save/Apply, per-controller readiness and retained rollback context. This does not complete live Entra/DC acceptance. An authorized Admin's ordinary server/tag/policy Save takes effect directly after existing endpoint opt-ins and health/scope guards. There is no second-person requirement or bounded approval mode. Explicit imported deny/restrictive actions, restrictive learned edits/removal and destructive recovery retain extra confirmations by the same actor. User and privileged platform operations remain Super Admin responsibilities. See [authentication and provider migration](authentication.md).

**Git is optional.** Install from a reviewed source checkout or the verified controller installation archive. The running controller and endpoint agent do not need Git. The installer builds/pulls container images and packages, so it needs approved registry/repository access or a separately prepared image-distribution process; the archive is not a complete offline image installer. Optional inert RPM/DEB endpoint packages only deliver the verified release under a versioned /opt directory; the family installer and GUI kit remain the activation path. See [controller installation](controller-installation.md), [RHEL/Ubuntu agent installation](linux-agent-installation.md), [native package delivery](native-agent-packages.md) and [0.7 review status](review-remediation-0.7.md).
