# HTTPS/mTLS fleet capacity fixture

The subsequent capacity/installer freeze passes the stronger actual-edit test: **14.255 s initial delivery, 30.684 s for a real policy edit including publication and 30 seconds of polling spread, and 9.791 s mixed traffic/discovery**, for all 5,000 identities with zero failures/retries. It uses two workers, bounded 8/2 database pools and an actual 30-second central control profile. See [the current measured profile](controller-capacity-5000.md) and [VM sizing](controller-vm-requirements.md). The earlier checkpoints below, including the failed one-worker audit run, remain historical evidence.

`scripts/benchmark-mtls-fleet.py` exercises the real Gunicorn HTTPS listener,
endpoint certificate registry, report handling, signed policy responses,
conditional policy checks and asynchronous traffic ingestion. It uses a new
private CA and a distinct registered client certificate for every virtual server.
Forged identity and forwarded-address headers must not change the authenticated
endpoint identity. A received policy is verified against the fixture's pinned
Ed25519 public trust.

The default fixture has two monitor services with 20 approved sources per
service. Every cycle sends a report and policy check. The first changed-policy
cycle also acknowledges the preview/polling receipt immediately. Subsequent
unchanged cycles mirror the native agent's one-report/one-policy cadence;
refreshed signatures alone do not create another receipt. `--cadence strict`
keeps the earlier two-report comparison available.

The last cycle starts observation on 100 virtual servers, ingests 100 synthetic
events from each and performs 100 fresh inventory reports while other virtual
servers continue polling. Accepted events must drain within 30 seconds and the
retained row count and summed event count must exactly match the expected total.
Failures, retries, response codes, per-operation latency percentiles and completed
cycles per second are emitted as JSON. Preparation is excluded from HTTP timing.
The result also records SHA256 fingerprints of controller sources and the
fixture, plus transport/cryptography versions. Freeze sources before collecting
comparison results; running workers do not hot-reload later edits.

## Recorded development results, 31 October 2026

The following table preserves earlier checkpoints. The final frozen-source
measurement appears in its own section below.

All rows below used 5,000 distinct registered mTLS identities, 64 concurrent
virtual clients, PostgreSQL metadata/traffic databases on one local instance,
two monitor services with 20 approved sources each, and three complete cycles.
The mixed cycle included 100 fresh discovery reports and 10,000 flow events.
The shared ARM64 macOS development host had 10 logical CPUs; this was not a
dedicated benchmark host or the intended DC hardware.

| Controller source / workers | First changed-policy cycle | Steady cycle | Mixed learning/discovery cycle |
| --- | ---: | ---: | ---: |
| Earlier snapshot, 1 worker × 32 threads | 70.056 s | 42.609 s | 49.429 s |
| Earlier snapshot, 2 workers × 32 threads | 34.654 s | 20.916 s | 26.275 s |
| Fingerprinted snapshot before bounded worker, 2 workers × 32 threads | 47.529 s | 29.724 s | 32.707 s |
| Final bounded-worker snapshot, 2 workers × 32 threads | 32.371 s | 29.559 s | 36.772 s |

Every run completed without an HTTP failure or retry and retained exactly
10,000 flow rows / summed events, with no pending batch after drain. That checkpoint
snapshot used Gunicorn 25.3.0, Python 3.12.14, cryptography 50.0.2 and OpenSSL
3.5.8. Its 20,000 reports had p95 618.486 ms; its 15,000 policy checks had p95
214.531 ms. The bounded worker enforces bounded TLS/header/body reads while
preserving the real mTLS socket. Those checkpoint source/result fingerprints are in the private run artifact
`.local/http-scale-5000-postgresql-current.json`.

The first one-worker cycle **missed** the 60-second target. All three two-worker
runs met it for all three cycles, including changed-policy acknowledgements.
That snapshot contains a signer-factory cache absent from the earlier
snapshots, but the shared-host timings do not establish a causal speedup. Use
these measurements to choose a DC test configuration, then measure actual
replication latency, workload and resource headroom before setting rollout limits.

## Final frozen-source matched checkpoint, 31 October 2026

The final audit ran **once** after the catalogue/read bounds, review-construction
limits and final controller source freeze. It used the same HTTP/workload
settings as the preserved pre-F02 checkpoint: **5,000 distinct registered mTLS
identities, two cycles, one Gunicorn worker × 32 threads, 64 virtual clients,
adaptive cadence and two monitor services with 20 approved sources each**.
The second cycle included 100 fresh inventory reports and 100 learning clients
posting 100 events each. These are virtual identities, not 5,000 Linux processes;
no live enforcement was requested.

| Checkpoint | First changed-policy cycle | Warm mixed learning/discovery cycle | 60-second target |
| --- | ---: | ---: | --- |
| Preserved pre-F02 result | 57.772 s | 26.709 s | Both met in that earlier run |
| Final frozen-source result | **123.853 s** | **84.086 s** | **Both missed** |

All 5,000 identities completed each final cycle successfully. The measured rates
were 40.37 and 59.46 completed cycles/second. This final configuration **does not
satisfy a 60-second cycle for 5,000 identities** on this shared development host.
Zero request errors establish functional completion, not capacity clearance.
The timing difference alone does not identify a source regression, database
bottleneck or host-contention cause; no causal profile was collected. Earlier
two-worker measurements above are preserved historical evidence and do not
replace a final-source production-sizing run.

The workload ran on ARM64 macOS/Python 3.12.14, Gunicorn 25.3.0,
cryptography 50.0.2 and OpenSSL 3.5.8, using a private local PostgreSQL 16.15
instance with `max_connections=100`, `shared_buffers=64MB` and
`synchronous_commit=on`. The earlier artifact does not record these PostgreSQL
settings, so only the HTTP/workload configuration is verified as matched.
The 7.169-second certificate/inventory preparation and controller readiness are
excluded from the phase timings. “First” means the first changed-policy/receipt
cycle, not a flushed operating-system or database cache.

| Final operation | Requests | p95 latency | p99 latency |
| --- | ---: | ---: | ---: |
| Agent reports | 15,000 | 1,200.833 ms | 2,408.955 ms |
| Policy checks | 10,000 | 797.237 ms | 1,315.049 ms |
| Synthetic flow ingestion | 100 | 891.745 ms | 897.535 ms |

Per-phase request accounting is derived from the unchanged fixture and exact
successful totals; latency samples were aggregated across both cycles. The
learning-session setup request completed before the warm phase timer.

| Phase | Reports | Policy checks | Flow posts | Learning setup | HTTP 200 / 201 / 202 / 304 |
| --- | ---: | ---: | ---: | ---: | --- |
| First changed-policy cycle | 10,000 | 5,000 | 0 | 0 | 15,000 / 0 / 0 / 0 |
| Warm mixed cycle | 5,000 | 5,000 | 100 | 1, outside timer | 7,259 / 1 / 100 / 2,741 |

The final result has **zero failures and zero retries**, exactly **5,000 visible
inventory records**, and **10,000 retained flow rows / summed events**, with no
pending ingestion batch after drain. Both uniquely named disposable PostgreSQL
databases were removed by reconnecting through the preserved private admin DSN;
no existing inventory/database was reused or reset.

The current result/log are
`.local/security-audit/mtls-fleet-5000.{json,log}`. The earlier result/log remain
unchanged as `mtls-fleet-5000-before-f02.{json,log}`. Cleanup evidence is
`mtls-fleet-5000-cleanup.json`. The fixture SHA256 remains
`630f927c22173ec1ed0a206cbb1ed42c9f0ecffa87029917720b77990404702d`.
Every controller module hash at launch matched the unchanged source after the
run and the controller source verified in final validation image
`sha256:728dcdaa5fc20ed3e6f3a85267474c044918f0cc2abfc154d5227ecc3fdfe631`.
This is source equivalence: the workload ran on the host Python runtime,
not inside that Linux validation image. The JSON preserves complete per-file
hashes and prior-result provenance.

No source change, retuning or repeat was performed after this result. The real
20-server pilot, native OS matrix, WAN/replicated-database capacity, mass rollout
workload and long-duration endurance gates remain open.

## Reproduce on isolated test hardware

Install the controller dependencies in a private virtual environment, then run:

```sh
python3 scripts/benchmark-mtls-fleet.py --agents 5000 --cycles 3 \
  --concurrency 64 --workers 2 --threads 32 --learning-agents 100 \
  --flow-events 100 --discovery-agents 100 --output /private/test-results.json
```

SQLite mode uses only a temporary directory. For PostgreSQL, first create two
**empty disposable** databases whose different names start with
`prthak_test_http_`. Set `PRTHAK_HTTP_TEST_METADATA_DSN` and
`PRTHAK_HTTP_TEST_TRAFFIC_DSN` through protected environment configuration and add
`--backend postgresql`. The fixture refuses a database containing public tables;
it does not erase or reuse an existing deployment. Protected controller authority
is bootstrapped before the private fixture connects to HA metadata. Remove only
these disposable databases after saving the results.

The test binds an ephemeral loopback port, creates no external enrollment tokens
and touches no real endpoint, DC firewall or existing inventory. Its private
keys and local SQLite fixtures are removed when its owned Gunicorn process exits.
It never changes the inherited production configuration or reuses its secrets.

## Measurement boundaries

These are virtual authenticated identities, **not 5,000 Linux agent processes**.
Certificates and initial inventory are prepared before measurement. The test
does not measure enrollment storms, kernel log collection, native firewalld,
SSH/systemd recovery, WAN latency, load-balancer failure, synchronous database
replication or a long-duration soak. PostgreSQL mode uses two databases on one
instance. Maximum-size source bundles and simultaneous mass policy rollouts
need their own workload profiles. Native RHEL 8/9 and Ubuntu 26.04 acceptance
remain separate requirements before the real 20-server pilot.
Large firewall-snapshot dashboard payloads and interactive browser rendering
are separate workloads and are not exercised by this endpoint polling fixture.

## Fleet inventory payload regression

Fleet lists and overview responses now contain a firewall snapshot summary;
canonical rules are fetched for one endpoint when its detail is opened. Common
rules use bounded SHA256-cursor pages, and plan lists contain recent summaries
whose full review/result evidence is fetched separately. Read Only users can use
the read-only query endpoint; the existing mutation restrictions still apply.
Query filters affect displayed scope only. Change previews and authorization
always read the server's canonical stored evidence.

The browser renders 200 server rows per page, 50 common rules per page and 100
endpoint choices per review page, retaining the complete explicit selection
across pages. Counts and combined filters still apply to the whole matched fleet.
Common-rule aggregation streams canonical snapshots with a bounded page
accumulator and does not acquire the metadata writer lock.

The focused regression used a virtual SQL view representing 5,000 hosts with
200 canonical firewall rules each, avoiding a huge persisted fixture. The raw
fleet would exceed 300 MiB. On actual private PostgreSQL, the final overview was
3,473,367 bytes and a seven-rule common page was 2,064,193 bytes; full canonical
single-host detail remained intact. The virtual-view computation took 8.721 s
for overview and 7.539 s for the common page on the shared development host.
These are separate payload/streaming measurements, not part of the earlier
HTTPS cycle timings. Their source changes postdate that benchmark's recorded
fingerprints. Native DC browser/load tests remain necessary for deployment sizing.

Results from a shared development machine show a measured workload on that
machine; they are not a production capacity guarantee. Repeat with the real DC
hardware, intended database quorum/replication settings and site latency. Keep
polling jitter and stage enrollment/rollouts; do not synchronize all 5,000 hosts.

<sub>Created by Pratik Srivastava</sub>
