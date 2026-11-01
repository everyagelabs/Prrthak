# Managed source-policy enforcement: lab milestone

Prṛthak can reconcile reviewed inbound TCP/UDP source allowlists through firewalld. The fleet design target is **5,000 endpoints**. This milestone is an opt-in lab release; the 20-server pilot has not started.

## Scope and rule ownership

Each managed service gets source-specific accepts followed by a reject for other sources, for both IPv4 and IPv6. Negative rich-rule priorities take effect before ordinary broad zone service/port allows. This is stronger than merely adding a source allow beside an existing `any` allow. Only selected managed ports change. Existing established connections retain the kernel's stateful treatment; this release does not revoke conntrack sessions or enforce egress, forwarding or container traffic.

The agent owns exact nonce-labelled rich rules. It preserves unrelated configuration and uses no reload, flush or runtime-to-permanent copy. Unsupported direct rules, passthroughs/chains, ambiguous priorities, overlapping policy objects, source-bound zones, multiple active zones, incomplete inventory and active UFW block enforcement. The known default IPv6 host policy is accepted only after its full structure matches the supported definition. An agent managing its own controller's API ingress port is refused.

Small bundles use at most **64 canonical rich rules per endpoint**. Agent 0.6 adds a source-set adapter for larger bundles, with up to 128 rich rules, 32 distinct source sets per family, 10,000 entries per set and 40,000 entries in one bundle. SSH management CIDRs join only the actual SSH service sources. Large changes fill a separate inactive IPv4/IPv6 bank with bulk entry operations and read it back before staged rules reference it. Each mutation retains exact prior entries in the independent rollback journal. The empty source banks require a separately reviewed initial maintenance activation because firewalld exposes permanent-only set creation; policy application never reloads firewalld. Missing banks, references from unrelated rules and excessive capacity block mutation. See [source-bank setup and evidence](ipset-enforcement.md).

## Review and activation

1. Install in preview mode, verify auto-enrollment and discovery, and assign the endpoint's tags and saved location.
2. Pin restricted management CIDRs in the endpoint's root-owned configuration. Discover actual SSH listeners; do not assume port 22. Missing SSH identity or `/0` management CIDRs blocks enforcement.
3. Configure a controller management vantage point as described below. Keep `enforce: false` until lab activation is intended.
4. Use the GUI to prepare and locally apply a signed endpoint configuration kit when enabling `enforce: true`. Keep restricted management sources and every actual SSH listener protected; an Admin policy save never elevates the daemon's local opt-ins.
5. Save the enforced policy as an authorized Admin. Normal policy/group/tag changes publish affected exact intent directly. An explicit Apply current bundles action is also available for selected endpoints; there is no separate requester/checker workflow or approval-mode setting.
6. The agent verifies the signed endpoint identity, version/digest, protected configuration, target IP set and current authority, then stages and checks the change. Missing opt-in, stale protection, failed health or unsupported context blocks application. Only an actual matching agent result establishes enforcement. Deny/restrictive imported changes, restrictive learned edits/removal and destructive database recovery retain their explicit two-step confirmations by the same authorized actor.


`allow_firewall_changes` independently controls the older imported-rule editing adapter. It is not a substitute for managed-policy authorization. Simulation and the demo cannot generate management health proof.

## Controller and SSH health

Every controller that can serve an enforcement health request must have a route from an explicitly approved management source:

```sh
SEG_MANAGEMENT_PROBE_SOURCE_IP=10.90.0.5
SEG_MANAGEMENT_PROBE_TARGET_CIDRS=10.40.0.0/16,10.50.0.0/16
```

The source must be a local address on that controller and fall inside the endpoint's pinned `management_sources`. Target CIDRs must be scoped; `/0` is forbidden. Only exact endpoint addresses approved in the rollout are eligible. Loopback, link-local, multicast, unspecified and reserved destinations are refused. Scope the target CIDRs to the intended management interfaces; the first eligible approved address is used, without scanning fallback addresses. Every discovered SSH port must be reachable there.

The endpoint establishes a **new mTLS connection** and sends a fresh per-check nonce to `POST /api/v1/agent/enforcement/check`. The controller revalidates the authorization, opens a **new TCP connection** from the configured source to each actual SSH port, and requires a complete SSH protocol banner. It revalidates the authorization after network I/O. The endpoint checks the response identity, version, digests, nonce, timestamp, local target address and source CIDR. A TCP-open result from an unrelated service is insufficient. This proves SSH protocol reachability from this vantage point, not interactive login credentials or every operator's network path.

Health is checked before mutation, after runtime staging and after final reconciliation. A missing vantage configuration fails before installation. Outbound controller traffic remains stateful; the agent does not create an unrestricted inbound HTTPS exemption.

## Commit and independent rollback

Before mutation, the agent records a private durable journal and arms a separate systemd transient timer/service. It verifies that the timer is active. Runtime staging has higher priority than the committed generation, so a restrictive source change can be evaluated while the previous rules still exist. Permanent changes occur after staged health succeeds. Every mutation is journalled before execution and read back afterward. Final health and both configuration scopes must pass before the durable commit record is written.

The normal rollback deadline is 120 seconds. The independent service survives termination of the main agent. It verifies the original boot/process identity and transaction nonce, fences a still-applying process, takes the mutation lock and compensates exact changes in reverse order. On Linux, a private same-binary subreaper retains the mutation lease while draining and reaping command descendants, including detached grandchildren. Killing only the main agent is insufficient evidence of a completed fence. Committed or already restored generations are no-ops. The boot clock guards deadlines against wall-clock adjustment. Startup recovery checks journals before accepting another policy. Imported-rule uncertainty remains blocking across restarts until the exact original baseline is verified.

Rollback reports the attempted version, reason and last-good version/digest. Failed approvals are held across restart; a fresh administrative approval or a new reviewed version is required to retry a failed transaction. If firewalld itself cannot accept restoration, the agent reports incomplete rollback; recovery must be confirmed by read-back, not inferred from issuing commands.

## Version history and removal

Policy configuration revisions and each server's effective bundles have append-only application history. Outcomes are stored separately, preserving the immutable bundle. Restoring an earlier policy configuration creates a **new revision** and, when effective rules change, a higher effective version. The authorized Admin action publishes the new exact bundle, subject to current endpoint protection and delivery checks. Failed changes remain held until an explicit fresh action; restoring history never fabricates an applied outcome. Source selectors resolve current approved inventory; restoring a configuration does not resurrect old IP ownership. Replayed lower versions or a different digest at the same committed version are rejected by the endpoint.

Switching the final enforced policy to monitoring, or removing it, requires an explicit **Remove Prṛthak-managed rules** review for previously managed hosts. Successful cleanup removes owned rules and resumes the existing legacy firewall configuration. It does not erase unrelated rules. Disabling the local enforcement switch leaves previously committed restrictions in place until reviewed cleanup.

## Before the 20-server pilot

Do not enable endpoint enforcement or automatic learning on controller, database
or load-balancer infrastructure during this pilot. Native ingress protection
must first cover the real public/backend ports and LB/SNAT topology. The public
controller URL alone cannot establish every local ingress port behind a separate
load balancer. Process display names are not SSH protection authority; verified
root executable/system-service discovery or explicit local protected SSH ports
are required.

Run the lab matrix on the actual RHEL and Ubuntu releases, CPU architectures, firewalld backends, systemd/polkit permissions and SELinux configurations selected for deployment. Test IPv6 traffic, restart/reload, certificate failure/expiry, stalled commands, agent termination, interrupted permanent writes and failed compensation. Verify management access from the real bastion networks and check backups/recovery. The local validation record is in [linux-validation.md](linux-validation.md); [scale-validation.md](scale-validation.md) states exactly what the synthetic benchmark measures.

Entra identities and direct authorized-Admin publication, signed assignment envelopes, managed certificate lifecycle, bounded Gunicorn HTTPS, reviewed notifications and supervised recovery are implemented. Native RHEL 8/9 and target Ubuntu/systemd, real management routes, live Entra/MFA, native database-host watchdog/fencing, physical WAN/site failure and provider/fleet acceptance remain deployment gates. Actual Ubuntu 26.04/firewalld 2.3.1 source-set checks use disposable containers and test health/timer callbacks; retained Ubuntu 24.04 systemd rollback evidence is separate. None of these checks starts a pilot or certifies production. See [0.6 evidence](release-0.6.md).
