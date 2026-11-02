# 5,000-server controller capacity

## Current 0.15 Local / SAML acceptance - 2 November 2026

Both new human account sources retain the 60-second ordinary policy-delivery target on the isolated profile below. Each uses 5,000 virtual mTLS endpoint identities and 100 expired full-fleet learning sessions: 19,533,300 canonical bytes / 500,000 indexed memberships seeded before timing.

| Provider | Initial delivery | Policy edit + full 30 s polling window | Mixed discovery / observations |
| --- | ---: | ---: | ---: |
| Local | 22.535 s | **34.325 s** | 16.482 s |
| SAML | 23.345 s | **35.345 s** | 17.525 s |

Local publication took 4.312 s and SAML 5.310 s, included in their totals. All three phases verify every endpoint's exact current provider, actor, role, credential version or SAML epoch, changed source matrix/version/digest and passive observation lease. Both runs had zero final failures. Transient retries were Local 4 policy / 2 report and SAML 6 ingest / 6 report. Each retained 5,000 connection plus 5,000 denied-packet observations with no pending batch.

Profile: 2 workers x 32 threads, 64 concurrent clients, metadata/traffic pools 8/2, 30-second control / 900-second full discovery, PostgreSQL 16.15 on the shared ARM64 development host. The private instance used max_connections 100, shared_buffers 128 MB and synchronous_commit on. All 488 frozen source files, signed runtime manifest and three compiled binaries were unchanged; four owned databases were removed and pre-existing databases/roles preserved. The final runtime manifest SHA-256 was `792d9309e02441d6abb790444cd2d93135e56ea9cefbc8395d93bf3b4844d2fb`.

Public records: [Local](../output/capacity/controller-5000-0.15-local-result.json) and [SAML](../output/capacity/controller-5000-0.15-saml-result.json). Certificate/inventory/history and human credential/session preparation are outside phase timers. These persist canonical test identities without a real IdP/MFA exchange; the separate HTTPS tests exercise real password and locally signed SAML login. This is not 5,000 native agent processes, firewall application, WAN/HA, enrollment storms, largest source matrices or endurance acceptance. Reproduce with `--authorization-mode single-admin --authentication-provider local` or `saml`, `--verification-capable --retained-learning-sessions 100` and the isolated PostgreSQL/profile flags below.

## Historical 0.14 retained-history acceptance - 2 November 2026

The ten-finding remediation passed with 5,000 current virtual mTLS identities,
including 100 expired full-fleet learning sessions retained before measurement:
19,533,300 canonical bytes and 500,000 indexed endpoint memberships. The result
checks exact current contributor authority and signed passive observation leases
for every endpoint rather than fabricating native enforcement success.

| Phase | Verified identities | Elapsed |
| --- | ---: | ---: |
| Initial signed delivery and receipts | 5,000 | 20.060 s |
| Actual Admin policy PUT, publication and full 30 s polling window | 5,000 | **33.792 s** |
| Warm polling, 100 discovery reports and 10,000 typed observations | 5,000 | 16.462 s |

Publication took 3.779 seconds, included in the total. Zero final failures;
four policy and two report retries. All 10,000 observations were retained as
5,000 connection and 5,000 denied-packet records, with no pending batch after
drain. Policy/report/ingest p95 was 146.016/220.991/4081.771 ms. Runtime hashes
remained unchanged and both owned databases were removed.

Profile: two workers x 32 threads, 64 clients, metadata/traffic pools 8/2,
30-second control / 900-second full discovery and private PostgreSQL 16.15 on
the shared ARM64 development host. Certificate/inventory/history preparation
is outside phase timers. The [public result](../output/capacity/controller-5000-0.14-result.json)
records workload, source hashes and cleanup. Reproduce using the command below
with `--verification-capable --retained-learning-sessions 100`.

This adds retained-history coverage; it does not qualify native 5,000-host
firewall application, full audit/traffic-history endurance, simultaneous native
collectors, largest policies, enrollment storms, WAN/HA or live Entra.

## Historical 0.13 acceptance · 2 November 2026

The bulk-verification build passed with 5,000 current verification-capable
virtual mTLS identities. Every cycle checked each signed policy's exact
per-host authorization and observation lease, including the bulk-run ID,
endpoint/IP/protection/version/digest and complete port scope. Certificate and
inventory preparation are outside the phase timers.

| Phase | Verified identities | Elapsed |
| --- | ---: | ---: |
| Initial signed delivery and receipts | 5,000 | 18.971 s |
| Actual Admin policy PUT, publication and full 30 s polling window | 5,000 | **33.743 s** |
| Warm polling, 100 discovery reports and 10,000 typed observations | 5,000 | 13.780 s |

Publication took 3.731 seconds, included in the total. There were zero final
failures, four transient policy retries and two report retries. Exactly 5,000
connection and 5,000 denied-packet observations were retained separately, with
no pending batch after drain. Policy/report/ingest p95 was
109.581/180.261/4014.072 ms. Runtime source hashes remained unchanged; both fresh
owned fixture databases were removed.

Profile: two workers × 32 threads, 64 clients, metadata/traffic pools 8/2,
30-second control / 900-second full discovery, private PostgreSQL 16.15 on the
shared ARM64 development host. Add `--verification-capable` to the reproduction
command below. The [public result](../output/capacity/controller-5000-0.13-result.json)
records exact hashes, settings, observation-lease accounting and cleanup.

This profile delivers real signed leases without fabricating native readback
or traffic-witness success. It does not measure 5,000 native agents enforcing
rules, 5,000 concurrent kernel collectors/witness uploads, largest policy
matrices, large-history endurance, registration storms, live Entra, DC/WAN/HA
or actual endpoint installation. Native acceptance remains separate.

## Historical 0.12 acceptance · 2 November 2026

The complete-history/GUI source-set build passed the same isolated delivery
profile with 5,000 fresh virtual mTLS identities. Certificate/inventory
preparation is outside the phase timers.

| Phase | Verified identities | Elapsed |
| --- | ---: | ---: |
| Initial signed delivery and receipts | 5,000 | 25.289 s |
| Actual Admin policy PUT, publication and full 30 s polling window | 5,000 | **35.079 s** |
| Warm polling, 100 discovery reports and 10,000 typed observations | 5,000 | 28.682 s |

Publication took 2.199 seconds, included in the total. Every changed version,
digest, source matrix and current single-Admin authority was verified. There
were zero final failures and six transient report retries. Exactly 5,000
connection and 5,000 denied-packet observations were retained in separate units,
with no pending batch after drain. Policy/report/ingest p95 was
166.399/409.120/4280.757 ms. Runtime hashes remained unchanged and both fresh
owned fixture databases were removed.

Profile: two workers × 32 threads, 64 clients, metadata/traffic pools 8/2,
30-second control / 900-second full discovery, private PostgreSQL 16.15 on a
shared ARM64 development host. The [public result](../output/capacity/controller-5000-0.12-result.json)
records workload, source hashes and cleanup. This measures ordinary policy
delivery, not 5,000 native agents applying firewall changes, source-set
maintenance, large traffic/audit-history queries, registration storms, live
Entra, DC/WAN/HA or endurance. Native endpoint acceptance remains deferred.

## Historical 0.11 acceptance · 2 November 2026

The endpoint/health build passed the same isolated policy-delivery profile with
fresh current-runtime registry/key claims and 5,000 virtual mTLS identities.
Certificate/inventory preparation is outside the phase timers.

| Phase | Verified identities | Elapsed |
| --- | ---: | ---: |
| Initial signed delivery and receipts | 5,000 | 15.850 s |
| Actual Admin policy PUT, publication and full 30 s polling window | 5,000 | **31.869 s** |
| Warm polling, 100 discovery reports and 10,000 typed observations | 5,000 | 13.229 s |

Publication took 1.857 seconds, included in the total. Every changed version,
digest, source matrix and current single-Admin authority was verified. There
were zero final failures, six transient policy retries and four report retries.
Exactly 5,000 connection and 5,000 denied-packet observations were retained in
separate units, with no batch pending after drain. Policy/report/ingest p95 was
88.335/178.072/3292.471 ms. Runtime source hashes remained unchanged; both fresh
owned fixture databases were removed.

Profile: two workers × 32 threads, 64 clients, metadata/traffic pools 8/2,
30-second control / 900-second full discovery, private PostgreSQL 16.15 on a
shared ARM64 development host. The [public result](../output/capacity/controller-5000-0.11-result.json)
records workload, source hashes and cleanup. This does not measure 5,000 native
fast-check agents/collectors, actual firewalld changes, startup enrollment storms,
large alert-history endurance, live Entra, DC/WAN/HA or native OS acceptance.

## Historical 0.10 acceptance · 2 November 2026

The reusable-enrollment build retains the 60-second ordinary policy-delivery target on the isolated profile below. This uses fresh current-runtime certificate registry/key claims and 5,000 virtual mTLS identities; certificate preparation is outside the phase timers. It does not measure a legacy-registry migration or an enrollment storm.

| Phase | Verified identities | Elapsed |
| --- | ---: | ---: |
| Initial signed delivery and receipts | 5,000 | 20.085 s |
| Actual Admin policy PUT, publication and full 30 s polling window | 5,000 | **32.097 s** |
| Warm polling, 100 discovery reports and 10,000 typed observations | 5,000 | 24.571 s |

Publication took 1.980 seconds, included in the total. All versions, exact source matrices and current single-Admin authorities were verified. There were zero final failures, two transient policy retries and eight transient report retries. Exactly 5,000 connection observations and 5,000 denied-packet observations were retained separately, with no pending batch after drain. Policy/report/ingest p95 was 128.102/326.131/5723.804 ms. Source hashes were unchanged and both owned fixture databases were removed.

Profile: two workers × 32 threads, 64 clients, metadata/traffic pools 8/2, 30-second control / 900-second discovery, private PostgreSQL 16.15 on the shared ARM64 host. The [public current result](../output/capacity/controller-5000-0.10-result.json) records hashes, settings, workload and cleanup. This is policy delivery and synthetic ingestion, not native firewalld, 5,000 simultaneous registrations/collectors, live Entra, WAN/HA or endurance qualification.

## Historical 0.9 acceptance · 2 November 2026

The typed-capture build passed all three phases on real Gunicorn HTTPS/mTLS and two fresh private PostgreSQL databases. Each phase verified all 5,000 virtual certificate identities and their current single-Admin authority. The actual Admin policy edit changed the source matrix, version and digest; compilation/publication and the full 30-second polling window are included.

| Phase | Verified identities | Elapsed |
| --- | ---: | ---: |
| Initial signed delivery and receipts | 5,000 | 17.253 s |
| Actual Admin policy PUT, publication and full 30 s polling window | 5,000 | **31.971 s** |
| Warm polling, 100 discovery reports and 10,000 typed synthetic observations | 5,000 | 14.686 s |

Publication took 1.960 seconds, included in the total. There were zero final failures, four transient policy retries and four transient report retries. The mixed workload retained exactly **5,000 conntrack-format connection observations and 5,000 NFLOG-format denied-packet observations**, half IPv6, as separate units; no flow batch remained pending. Controller source hashes were unchanged, and both owned fixture databases were dropped. Policy/report/ingest p95 was 91.844/192.955/3988.419 ms.

The profile remains two workers × 32 threads, 64 concurrent clients, metadata/traffic pools 8/2 per worker, 30-second control and 900-second discovery on a shared ARM64 development host and PostgreSQL 16.15. The [public machine-readable 0.9 result](../output/capacity/controller-5000-0.9-result.json) records the exact fixture/source hashes, workload, settings and cleanup. The historical records below remain unchanged.

This verifies ordinary policy delivery and typed ingestion, not kernel collection by 5,000 native agents, live Entra sign-in, whole-server default-deny application, HA replication, WAN/DC routing or endurance. Native RHEL/Ubuntu and real deployment acceptance remain deferred. Reproduce with the current benchmark's `--authorization-mode single-admin` and the profile below, always using two new empty disposable databases.

## Historical 0.8 acceptance · 1 November 2026

The whole-server-default-deny build retains the ordinary direct-Admin delivery target on the same isolated ARM64/Gunicorn/private-PostgreSQL profile below.

| Phase | Verified identities | Elapsed |
| --- | ---: | ---: |
| Initial signed delivery and receipts | 5,000 | 17.176 s |
| Actual Admin policy PUT, publication and full 30 s polling window | 5,000 | **32.157 s** |
| Warm polling, 100 discovery reports and 10,000 synthetic events | 5,000 | 17.576 s |

Publication took 2.143 seconds, included in the total. All changed versions, exact source matrices and current single-Admin proof scopes were verified. All phases met 60 seconds, with zero final failures, six transient report retries, all 10,000 events retained and no pending flow batch. Source hashes remained unchanged; two fresh owned databases were dropped afterward.

This measures ordinary per-port delivery to 5,000 virtual certificate identities, not 5,000 native agents applying whole-server deny. Dedicated deny reviews remain exact, byte-bounded snapshots for explicit canary scopes. Native enforcement, Entra sign-in, WAN, failover and endurance acceptance remain separate. Record: `.local/capacity/results-direct-080-pilot-1.json`; reproduction uses the same command/profile below with a fresh database namespace.

## Historical 0.7 acceptance · 1 November 2026

The final direct-Admin build passed the local 60-second delivery target. This is a shared ARM64 development host, real Gunicorn HTTPS/mTLS and private PostgreSQL 16.15; it is not native firewall or WAN/DC qualification.

| Phase | Verified identities | Elapsed |
| --- | ---: | ---: |
| Initial signed delivery and receipts |5,000|16.978 s|
| Actual Admin policy PUT, compile/publication and full 30 s polling window |5,000|31.947 s|
| Warm polling, 100 discovery reports and 10,000 synthetic events |5,000|21.827 s|

Publication took 1.932 seconds, included in 31.947 seconds. All 5,000 updated version/digest/source matrices and exact current single-Admin proof scopes were verified; a signature refresh or 304 could not substitute for the changed intent. The Admin used a persisted private Entra-shaped session with real HTTPS/CSRF; no Microsoft sign-in/token exchange was performed. A separate Super session configured polling only and did not approve the policy change.

All cycles succeeded with zero final failures, two transient policy retries and six transient report retries, 10,000 retained synthetic flow events and no pending batch after drain. Policy/report/flow p95 was 111.734/304.024/1727.770 ms. Both fresh owned databases were removed. Controller source hashes were unchanged during measurement.

Profile: 5,000 virtual certificate identities; 2 workers × 32 threads; 64 concurrent clients; per-worker metadata/traffic pools 8/2 with 5 s lease wait; control 30 s; adaptive reports; 20 sources per service; PostgreSQL max_connections 100, shared_buffers 64 MiB and synchronous_commit on. There was one PostgreSQL instance; synchronous cross-site replication was not exercised. No actual Linux agent processes, firewalld, SSH health witnesses, enrollment storm, failover or endurance workload ran.

Reproduce with `scripts/benchmark-mtls-fleet.py --authorization-mode single-admin --change-policy --control-interval-seconds 30 --poll-window-seconds 30` plus the isolated PostgreSQL/profile flags described below (separate every option and its value with a space). The fixture asserts both complete delivery and current exact authorization. Production hardware and network acceptance remain required.

Candidate `v0.7.0-pilot.3` includes the Linux command-lease fix and strict-compatible joined-controller certificate issuance. This fresh measurement records and verifies all 62 controller source hashes for that candidate.

## Historical development result · 31 October 2026

31 October 2026. The requested local capacity target passes on the frozen source/configuration below. DC deployment, native endpoint OS validation, WAN/quorum behavior and production acceptance remain deferred. This is delivery of versioned, signed policy intent and receipts; native firewalld application is outside this workload.

## Result

| Phase | Complete identities | Elapsed | 60-second target |
| --- | ---: | ---: | --- |
| Initial signed policy delivery and receipts | 5,000 | **14.255 s** | Pass |
| Actual API policy edit, publication and a full 30-second polling window | 5,000 | **30.684 s** | Pass |
| Warm polling plus discovery and synthetic traffic | 5,000 | **9.791 s** | Pass |

The policy edit used `PUT /api/v1/policies/{id}` and changed the actual source allowlist on both services. Its **0.676-second compilation/publication** is inside the 30.684-second total. Every identity received a newer version, a changed digest and the exact complete updated IPv4 service/source matrix; a refreshed signature or 304 could not satisfy the assertion. Acknowledgement requests also completed. The first polling phase had already verified the signed 30-second control profile.

There were **zero failures and zero retries**, exactly 5,000 inventory records, all 10,000 accepted synthetic flow rows/events retained and no pending flow batch after drain. The mixed phase included 100 fresh discovery reports and 100 learners sending 100 events each. Across all phases, policy-request p95 was **70.524 ms**, report p95 **144.880 ms** and flow-ingest p95 **102.030 ms**. Controller sources were unchanged during the run. The two fresh owned PostgreSQL databases were removed afterward.

This is a stronger acceptance than the older fixture's first fetch of preseeded policies. The previous audit's one-worker run missed its target at 123.853/84.086 seconds. Those results are preserved; the different worker configuration and enhanced fixture mean these are not a controlled claim that one code change alone explains the timing ratio.

## What changed

- PostgreSQL workers reuse bounded physical connections after fork. Each borrow uses exclusive socket ownership, a fresh transaction/snapshot, current primary/login/database admission and namespace/epoch checks. Statement/lock/idle limits apply from libpq startup, before the first admission query. Sockets age out after 60 seconds between borrows. Master initialization and injected test connectors do not share worker sockets.
- Stable-address reports write the final canonical server record once. New/changed addresses retain metadata reconciliation and full compilation. Separate SQLite writers serialize before reading, fixing reproduced tag/compiled-policy loss and retired-server resurrection races.
- Repeated healthy evaluations do not rewrite unchanged server rows. Offline, recovery, expiry, firewall-service and badge transitions remain evaluated and durable.
- Endpoint certificate admission reads the exact current registry row with enrollment existence rather than decoding the full firewall/source snapshot. Actual leaf validity and registry revocation remain checked on every request, including before conditional 304 responses.

No authority/signature cache, skipped revocation check, polling slowdown, dropped flow data or automatic firewall grant was introduced.

## Exact validated profile

| Setting | Value |
| --- | --- |
| Gunicorn | 2 bounded threaded workers × 32 threads |
| Metadata / traffic pool per worker | 8 / 2; bounded 5-second lease wait |
| Actual central control / discovery profile | 30 / 900 seconds |
| Virtual client concurrency | 64 |
| Policies | Two monitor services, 20 literal sources per service |
| Storage | Metadata/traffic databases on one private PostgreSQL 16.15 instance |
| PostgreSQL | `max_connections=100`, `shared_buffers=64MB`, `synchronous_commit=on` |
| Development host | Shared macOS ARM64, 10 logical CPUs, Python 3.12.14 |
| Transport | Gunicorn 25.3.0, real TLS and distinct enrolled mTLS certificates |

The workload uses 5,000 authenticated virtual identities, not 5,000 Linux processes. Certificate preparation, initial polling-profile setup and readiness are outside phase timers. The changed phase includes policy publication and conservative spreading of polls over 30 seconds after publication. Source/code/workload hashes and exact request accounting are in the [machine-readable result](../output/capacity/controller-5000-result.json).

## Apply the configuration

Use the [VM and connection-budget recommendations](controller-vm-requirements.md). Initial installer settings:

```dotenv
SEG_HTTP_WORKERS=
SEG_HTTP_THREADS=32
SEG_DB_POOL_META_MAX=8
SEG_DB_POOL_TRAFFIC_MAX=2
SEG_DB_POOL_WAIT_SECONDS=5
```

AUTO selects one worker for setup SQLite and two for the active PostgreSQL runtime. In **Platform settings → Agent polling**, review/save global control **30 seconds** and discovery **900 seconds**, then verify current endpoint receipts. Check group/tag/server overrides too. A retained 60-second polling interval leaves no processing headroom for a total 60-second freshness budget; existing settings are not silently overwritten.

To reproduce, use two new empty disposable `prthak_test_http_*` databases and private environment DSNs as described in the [HTTP fixture runbook](mtls-scale-validation.md):

```sh
python3 scripts/benchmark-mtls-fleet.py --backend postgresql \
  --agents 5000 --cycles 3 --concurrency 64 --workers 2 --threads 32 \
  --db-pool-meta-max 8 --db-pool-traffic-max 2 --db-pool-wait-seconds 5 \
  --control-interval-seconds 30 --change-policy --poll-window-seconds 30 \
  --learning-agents 100 --flow-events 100 --discovery-agents 100 \
  --require-target --output /private/controller-5000-result.json
```

The command fails when a complete cycle misses 60 seconds or a delivered source matrix/version/digest is wrong. Never point it at an existing controller database. The isolated wrapper's cleanup record confirms two owned databases created/dropped and no reuse of existing data.

## Boundaries

Real inter-site latency, synchronous replication/quorum, load-balancer failures, enrollment storms, largest supported policy matrices, 5,000 simultaneous traffic collectors, long soaks and native firewall installation/rollback are separate measurements. All sites share a PostgreSQL writer; additional controller VMs do not remove database/WAN constraints. The [upstream/vendor VA findings](security-assessment-2026-10-31.md) remain open. A measured capacity pass does not grant security or production clearance.
