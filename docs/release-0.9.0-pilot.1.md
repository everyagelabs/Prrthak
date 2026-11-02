# 0.9.0-pilot.1 · Capture and code hardening

2 November 2026. This release changes new traffic-learning and monitored-port scopes to native conntrack/NFLOG evidence and closes the reviewed first-party certificate, supervision, private-path and IPv6 validation gaps. DC deployment and native OS acceptance remain deferred.

## Traffic evidence

- New scopes require an upgraded agent reporting `traffic_capture_v1`. Conntrack accepted transport observations and verified terminal NFLOG denied-packet records remain separate, with their own count units and IP family. TCP establishment/reply and UDP confirmation are transport facts, not application success.
- New reviews select accepted connections, denied packets or both. Both preserves the user-selected any-hit behavior. Explicit per-port auto-allow can therefore grant a denied source within the approved scope; the GUI warns about that behavior. No second person or additional mandatory consent mode is introduced.
- Historical scopes omitting the new selector retain explicitly labelled legacy journal records. New typed scopes refuse metadata-free downgrade. New collection does not silently fall back to kernel journal logging.
- Stable identities, cross-batch conflict checks, connection lifecycle dedup and redacted retention tombstones prevent repeated uploads/dumps from recounting evidence. Backend/family status, unknown losses, saturation and unsupported native contexts are visible. This is not a complete packet ledger.
- NFLOG sidecars are log-only, lease-bound, bounded in lifetime and installed only where the exact terminal reject path can be proved. They are removed under the mutation lease before access changes and compensation. Unmanaged/ambiguous/direct/NAT contexts and legacy priority layouts report gaps instead of guessed verdicts.

See [capture workflow, units and boundaries](traffic-capture.md). Discovery still polls at 900 seconds fleet-wide; DC definitions remain dashboard-managed, policy authority remains single-Admin, and enforcement remains inbound-only.

## Other code fixes

- Strict offline TLS preflight checks chain, SAN hostname, key and server purpose before vault/review persistence, before queuing and again before runtime TLS staging. Malformed current or pre-upgrade queued material cannot stop/replace the live certificate first.
- Certificate uploads fence stale FileReader results, cancellation, mode/identity changes and late preview responses. Private uploaded material cannot cross sign-out or overwrite a newer file/review.
- A durable per-command fence survives supervisor/owner death. If full process-tree drain is unproven, rollback and further writes remain explicitly blocked. A new kernel boot supplies automatic orphan-clear proof; no PID/FD disappearance is treated as proof.
- Private journal/lock paths reject unsafe ancestors, aliases, foreign ownership and links. Descriptor-based reads enforce size bounds before allocation. New access transactions enforce retained-history/count/free-space budgets; pending/uncertain history and recovery remain intact. There is no blind journal deletion.
- Shared source validation rejects scoped and IPv4-mapped IPv6 representations before masking, while preserving native IPv4/IPv6 CIDRs and historical digest bytes. Actual IPv6 listener addressing no longer double-brackets or selects an IPv4 socket; GUI port changes preserve valid IPv6 URLs.

## Validation record

| Check | Result |
| --- | --- |
| Full controller with real private PostgreSQL | 898 passed; zero skipped |
| Full private-PostgreSQL/HTTPS/installer integration | 291 passed; one Linux-kernel-only case skipped on macOS |
| Final Linux Python 3.13 integration | 257 passed; 35 PostgreSQL-only skips, covered by the separate PostgreSQL run; final ARM64 binary and all snapshot hashes unchanged |
| Dashboard | 302 passed |
| Go | Final full Linux ARM64 race/vet, affected native regressions and Linux cross-build passed |
| Final native controller/agent bridge | 14 passed, including simulated sync and endpoint-configuration recovery |
| Actual IPv6 transport | IPv6 HTTP and HTTPS/mTLS enrollment, reports, policy and three-listener isolation passed |
| Isolated Linux firewalld capture | IPv4/IPv6 × TCP/UDP × accepted/denied packet cases and private NFLOG-group rebind passed |
| Signed Python-to-Go capture interoperability | Both/accepted-only/denied-only and historical omitted scopes, negative mutations and quiet-connection dedup passed |
| Helper supervision | Supervisor/owner death, detached delayed writers, uncertain recovery fences and bounded private journal paths passed |
| 5,000 virtual certificate identities | Actual Admin edit + publication + full 30-second poll window **31.971 seconds**; zero final failures; all 10,000 typed observations retained separately |
| Release runtime integrity | Signed controller/appliance startup and modified-byte rejection before import passed |
| Source/dependencies | Bandit zero HIGH; eight pinned Python dependencies and Go source scan reported no known applicable advisories |

The PostgreSQL runs preserved existing databases/roles and removed only their new owned fixtures. Final Linux validation used an immutable public-only snapshot and agent SHA-256 `359d4908aaae63c198004ae1d6bf178061284ef4751b0df17ac84aeb92676218`; later changes were documentation and public capacity evidence only. The kernel fixtures use disposable isolated networking, not a DC endpoint. No real server firewall is changed.

The [fresh 0.9 capacity record](controller-capacity-5000.md) separates the 5,000 connection observations from 5,000 denied-packet observations, including IPv6. It measures delivery and synthetic ingestion on one private PostgreSQL instance; it is not a native collection, live Entra, WAN, HA or endurance test.

The exact source commit is resolved by [the candidate tag](https://github.com/everyagelabs/Prrthak/tree/v0.9.0-pilot.1) and embedded clean-source provenance in detached package signatures. Remote [CI validation](https://github.com/everyagelabs/Prrthak/actions/workflows/ci.yml) is recorded independently of local acceptance. The signed payloads use the existing development release authority, not an organization-approved production signer.

## Deployment and vendor boundary

Native RHEL 8/9, Ubuntu 26.04, real Entra/MFA, bastion routes, LB/NAT/WAN/quorum/fencing, backup restore and workload/endurance acceptance remain operator-run gates before the real 20-server enforcement pilot. Resource bounds do not establish active collector CPU/RAM guarantees. The passive resource baseline is historical.

Recorded vendor image advisories remain open. The upstream 3.6 branch still lists 3.6.17 as pending; a source change here is not a vendor patch. See [the upstream release record](https://github.com/etcd-io/etcd/blob/main/CHANGELOG/CHANGELOG-3.6.md), [vendor advisory disposition](security-assessment-0.7.md) and [development release trust](release-integrity.md). Green CI does not mean a clean VA or production certification.
