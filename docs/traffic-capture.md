# Traffic capture in 0.9

Prṛthak distinguishes **accepted transport connections**, **denied packets** and
**historical sampled journal logs**. Their counts have different units and are
never added into one connection or packet total. The destination is the selected
endpoint; sources and exact TCP/UDP ports remain bound to that endpoint's scope.

This is bounded evidence, not a complete packet ledger, application-request log
or proof that an application completed a transaction. Source addresses are what
the endpoint kernel observed; upstream NAT can hide the original client.

## Choose the scope in the dashboard

Temporary learning and continuous monitoring are separate workflows:

| Workflow | Duration | Access-policy behavior |
|---|---|---|
| Learning · observe | Finite selected window | Evidence and recommendations; no automatic grants |
| Learning · auto-allow | Finite selected window | Adds exact eligible source/port grants within the initiating Admin's authorized scope and local endpoint opt-ins |
| Continuous port hit monitoring | Until explicitly stopped, with 1–24-hour retained history | Observation only; never creates learned or access policies |

New reviews require an upgraded endpoint advertising `traffic_capture_v1`.
Select **Accepted transport connections**, **Denied packets**, or both; both
start selected to preserve the requested any-hit learning behavior. Fresh
learning discovery still freezes each host's own eligible selected ports.
Monitoring freezes its explicit endpoints/ports and current group/tag membership.

**Auto-allow includes denied first-hits when denied-packet capture is selected.**
A blocked client or scanner can therefore become allowed on the selected port.
An observation does not make a source trustworthy. The existing explicit Admin
auto-allow action and local enforcement/learning opt-ins authorize this behavior;
there is no additional approver or per-hit confirmation. SSH/controller
protections, exact port scope, source validation, capacity and rollback guards
remain mandatory. Whole-server default deny holds learned-access mutations.

Stop or learning expiry ends new automatic additions. Committed learned grants
remain until their separate reviewed edit/removal. Stopping capture is distinct
from removing an access policy.

## What each backend establishes

| Evidence | Backend | Verdict / count unit | Limit |
|---|---|---|---|
| `accepted_connection` | Conntrack netlink | `allowed` / `connections` | Confirmed inbound transport state, not an application-success assertion; a NEW entry alone is insufficient |
| `denied_packet` | NFLOG | `denied` / `packets` | A record from a verified supported terminal deny path, not every packet denied anywhere on the host |
| Historical `legacy_log` | Kernel journal | Historical reported verdict / `log_records` | Sampled log observation; an old `allowed` or `denied` string is not upgraded into conntrack/NFLOG evidence |

IPv4 and IPv6 support is reported separately for each backend. Unsupported
firewalld/NFLOG functionality, ambiguous rule paths or missing privileges produce
an explicit unsupported/error state and coverage gap. Typed capture does not
silently fall back to journal sampling. Older firewalld versions may lack the
required NFLOG rule support even when conntrack observation is available.

Only reviewed ports and live capture scopes are admitted. Continuous monitoring
uses fresh signed leases of at most 120 seconds; cached assignments and 304s do
not extend capture. Controller loss therefore stops local monitoring when its
lease expires. NFLOG sidecars limit records to 200/second per rule, port and IP
family; omitted records are not counted, so total loss remains unknown. Conntrack
uses an 8,192-event queue and a non-evicting 32,768-identity ledger rather than a
20-events/second limiter. Queues and spools are bounded. Netlink loss, rate limits,
outages and storage pressure can leave gaps.

Read the backend/family receipts, errors and gaps before interpreting the
last-hour view. `lost_events:null` means **unknown**, not zero. Missing or stale
receipts do not establish complete coverage. A zero-hit window does not prove
that no client attempted a connection. Service/process labels remain inventory
context rather than authenticated workload identity.

## Managed rule priorities

Lower numerical firewalld rich-rule priority is evaluated first. The owned
managed layout reserves distinct priorities so a proved accept precedes its
observation sidecar and terminal reject:

| Bank | Accept | NFLOG sidecar | Reject |
|---|---:|---:|---:|
| Canonical | -31000 | -30999 | -30998 |
| Staged candidate | -31004 | -31003 | -31002 |

The sidecars are log-only. They do not accept, drop or reject traffic themselves.
They are installed only where the agent can establish the exact supported deny
path and ownership. Unknown, foreign or legacy rule layouts are not called
verified denied-packet capture. Legacy generations can require an explicitly
reviewed refresh; until then the coverage gap stays visible. No blanket
all-denied-packets or complete-ledger claim is made.

## API and replay contract

New learning requests and monitor previews store a reviewed
`observation_kinds:["accepted_connection","denied_packet"]` subset. The list is
bound into signed endpoint assignments and automatic-learning authority. New
scopes reject metadata-free events; an older agent must be upgraded. Historical
stored scopes with that field **omitted** retain their journal-only contract and
canonical retry bytes. Their histories and already committed policies are not
rewritten.

Learning batches use Discovery-channel mTLS `POST /api/v1/agent/flows`;
continuous-monitor batches use `POST /api/v1/agent/hits`. Each typed event carries:

```json
{
  "event_id": "<64 lowercase hexadecimal characters>",
  "source_ip": "2001:db8::25",
  "port": 443,
  "protocol": "tcp",
  "verdict": "denied",
  "count": 1,
  "first_seen": "2026-11-02T10:00:00Z",
  "last_seen": "2026-11-02T10:00:00Z",
  "capture_kind": "denied_packet",
  "capture_backend": "nflog",
  "count_unit": "packets",
  "address_family": "ipv6"
}
```

Kind/backend/unit/verdict combinations must match the table above. Typed events
have count one and one observation timestamp; the source must match its declared
family. Scoped IPv6 and IPv4-mapped IPv6 are refused rather than silently
converted. Standard native IPv4 and global IPv6 CIDRs retain their existing
canonical policy representation.

Durable admission deduplicates stable event IDs across batch retries. Reusing an
ID for changed evidence is rejected. Queued events do not appear as processed
aggregates. After raw learning retention, nonpublishing identity/digest
tombstones prevent replay until the original session upload deadline; retained
evidence continues to support review/export. CSV appends capture kind, backend,
unit and family while preserving the existing columns. Separate evidence kinds
retain separate rows even for the same source/port pair.

`learning_coverage` and each `hit_monitoring` receipt may include:

```json
{
  "capture_backends": [
    {"backend":"nflog","status":"unsupported","ipv4":false,"ipv6":false,
     "lost_events":null,"error":"Native terminal path is unavailable"}
  ],
  "capture_gaps": ["Denied-packet coverage is unavailable on this endpoint"]
}
```

Backend statuses are `active`, `off`, `unsupported` or `error`. Coverage and
telemetry never authorize access. Overview `capture_counts` separates
`connections`, `packets` and `log_records` within its bounded relationship view;
the compatibility `observed_events` field counts legacy log records only.

## Evidence boundary

Code-level and isolated SQLite/PostgreSQL/IPv6/interop checks belong to the 0.9
release record. Published 0.8 test totals and capacity measurements do not
validate changed 0.9 code. Native RHEL/Ubuntu, real workload/endurance, live
organization Entra and DC/WAN/fencing acceptance remain separate. Synthetic demo
hosts show unsupported native capture and explicit demo gaps; historical seeded
rows remain legacy examples and are never relabelled as real kernel evidence.

<sub>Created by Pratik Srivastava</sub>
