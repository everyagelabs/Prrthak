# Existing firewalld rules and unexpected-port observations

Prṛthak imports each endpoint's firewalld configuration separately from its intended microsegmentation policies. Existing rules are observed facts; editing a dashboard policy does not silently replace them. Saved locations are administrator-created catalogue identities; application/server groups follow approved central tags or explicit membership. The supplied demo locations and firewall rules are synthetic examples.

The **Services** catalogue (`/services`) stores reusable flat sets of 1–100 exact TCP/UDP ports. These are controller policy definitions, separate from imported firewalld named-service definitions. A policy row can use one saved service group or one port/protocol and attach its own union of CIDRs, an AND tag selector and multiple existing source server groups. The controller expands each row without mixing unrelated port/source combinations. Overlapping enforce rows union enforcing sources only; monitor rows cannot widen them.

Before a global service-group edit, inspect its affected policies and effective host impact. Edits require the loaded revision and update catalogue history, policy port snapshots and intended bundles atomically. Host versions advance only if access changes; renames do not advance them. Used service groups and server groups referenced as sources cannot be deleted until their policy references are removed. Historical snapshots retain actual ports/revisions; restoring old policy configuration resolves today's saved group and current membership. Ordinary authorized Admin changes publish per-port intent directly, subject to endpoint opt-ins and safety checks. On a whole-server default-deny host, a changed effective bundle requires a fresh dedicated downtime acknowledgement; the last working rules remain active until then.

## Inventory and common rules

The agent collects runtime and permanent firewalld state during inventory discovery. The Firewall page groups exact matching rules across hosts, with the zone, scopes, host count, action, and editability. Runtime changes affect the current firewall; permanent changes survive reload/restart. A change must explicitly select its scopes. No automatic reload or runtime-to-permanent copy is performed.

Supported editing covers named services, ports, validated rich rules, bounded INPUT direct rules and local port redirects. Permanent zone-target replacement is staged explicitly; it does not change the runtime target or reload firewalld. Unsupported routing/NAT, policy objects, bindings and ambiguous configurations remain visible with a view-only reason. An `ACCEPT` target can represent unrestricted access even if the list of open ports is empty. Identical text is not a guarantee of identical effective access: interfaces, sources, zone selection, other rules and named service definitions also matter. [firewalld command reference](https://firewalld.org/documentation/man-pages/firewall-cmd.html), [rich-rule ordering](https://firewalld.org/documentation/man-pages/firewalld.richlanguage.html).

Only complete, fresh inventories are eligible for change planning. A failed collection preserves the last successful inventory and marks it incomplete/stale. Exact fingerprints, rather than a rule's table position, identify the selected entries.

## Review, confirmation and rollout

An administrator chooses explicit hosts, an exact common rule, runtime/permanent scope, and a replacement or removal. Preparing a draft does not change any endpoint. The review shows before/after entries and matched/unmatched hosts. The plan freezes target identities, inventory fingerprints and intended operations.

For deny/reject/drop or potentially restrictive changes, the same current authorized Admin completes two explicit confirmations; the second uses a rotated nonce and exact typed challenge. Normal supported additions use one reviewed Apply action. Scope/digest binding, replay protection, current roles/sessions and inventory/target checks remain in effect. No second administrator or selectable approval mode is required. Shared-token/demo authority remains lab-only.

Confirmed work reaches agents through their normal authenticated policy polling. Use the endpoint-configuration GUI and signed private kit to enable the separate `allow_firewall_changes` local opt-in. No manual JSON editing is required.

Without this setting the endpoint returns a preview result. This setting is independent of managed source-policy `enforce`; that adapter now has a separate exact-approval, management-health and independent rollback workflow described in [managed-enforcement.md](managed-enforcement.md).

The endpoint checks approval count, expiration and a freshly read inventory before execution. Supported operations use typed `firewall-cmd` arguments, save a local private backup, add replacements before removing old entries, and verify the result. Failure triggers reversal of only this operation's recorded mutations. The endpoint refuses unsafe management-access changes and unsupported rule contexts. Unrelated rules and global settings remain intact. Per-host results distinguish applied, preview, conflict and failed outcomes; a global plan is not an atomic transaction across all hosts. Imported mutations and automatic learned grants are held while whole-server default deny or its removal remains active; see [the dedicated ingress workflow](whole-server-default-deny.md).

Backups and rollback attempts do not guarantee packet-level availability or connectivity under every local firewall writer. Validate the supported platform/rule matrix and management paths in a lab before enabling live imported-rule changes. Certificate authentication, explicit admin confirmation, endpoint opt-in and read-back are separate checks.

## Optional unexpected-port monitor

This observer is separate from temporary application traffic learning. Use the endpoint-configuration GUI to prepare and apply a signed kit enabling the unexpected-port monitor. The underlying opt-in is:

```json
{
  "unexpected_port_monitor_enabled": true,
  "probe_log_rate_per_second": 5
}
```

It installs only its own runtime log-only instrumentation, with a 120-second firewalld timeout and periodic renewal. It never changes `LogDenied`, opens ports, blocks a source, flushes rules, or disables UFW. It reads only its own kernel-log prefix and checks a fresh local socket inventory before calling a port non-listening. Forwarded traffic and loopback sources are excluded. Missing kernel logs or failed socket checks produce unavailable coverage rather than invented alerts. Shutdown removes exact owned instrumentation; the native timeout limits residual logging after a crash.

Observations include source/destination IP, protocol/port, first/last observed times, checked-listener time and observed packet count. A bounded private disk spool retains stable event IDs until the controller explicitly acknowledges them. Replayed IDs do not increment counts twice. Records older than 24 hours or beyond spool capacity are discarded with loss diagnostics.

The controller produces an unexpected-port alert and groups repeated hits from the same source/host/service within an hour. Five distinct destination ports from one source toward one endpoint inside a five-minute observation window produce a possible multi-port-probe alert. These are investigation signals, not proof of lateral movement, a completed connection, or compromise. Misconfigured clients and health checks can produce similar observations.

Logging is rate limited and coverage is sampled. Busy traffic, firewall-manager behavior, journal access, dropped logs, maintenance windows and local bind/address changes can affect visibility. The dashboard reports enabled/active/error/degraded state and losses. This is host ingress TCP/UDP observation, not complete east-west network detection or application-layer inspection.

Automatic service discovery for learning requires agent 0.3.0 with `learning_discovery_v1`. It asks every selected endpoint for a fresh scan and freezes each host's own eligible TCP/UDP ports, optionally intersected with an exact `port_filter` such as 443/tcp. Cached preview, pending/offline/error/no-selected-listener status and another endpoint's display-union ports do not authorize instrumentation. Unknown/loopback-only binds are excluded. An explicit manual-port mode remains available. The session budget runs from the request, including discovery delays, so assess actual coverage rather than assuming a full requested hour. Observe mode uses bounded log-only learning instrumentation and leaves access unchanged; the optional unexpected-port monitor remains independent.

Agent0.4 adds explicit `policy_action=auto_allow` for exact observed sources on selected services. It creates a separate accept-only learning-owned overlay, visible under Policies, and never authorizes a normal managed bundle. Both local `enforce` and `learning_auto_allow` must be enabled; complete protected configuration, fresh SSH/controller witness, mutation locking, durable owned rollback journal and independent systemd watchdog are required. Sources remain exact host /32-/128. Legacy agents retain 64 tuples; capable 0.6 agents use separate prepared banks for up to 10,000 exact source/port tuples across 64 services. SSH and local controller ingress ports are protected. Pending/blocked/error/rollback states do not mean applied. Existing broad rules retain their effect until separately reviewed removal.

The initiating Admin's auto-allow session action authorizes its selected endpoints and exact port selection. Fresh discovery freezes each host's eligible ports before automatic additions begin, without a separate initial approval request. Only that active scope can authorize new exact source/port entries; protected management ports remain excluded. Committed entries persist after collection stops. Manual learned grants and safe additions use exact preview followed by one Admin Apply; restrictive edits/removal retain two explicit same-actor confirmations. Applied edits suppress regeneration; cleanup stays pending until exact endpoint acknowledgement. Mutating failures hold the auto grant until explicit review. Evidence can be applied to frozen server/group membership or exported as CSV; sampled observations do not prove authentication or connection success.
