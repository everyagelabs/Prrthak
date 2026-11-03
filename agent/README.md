# Prṛthak (पृथक्) endpoint agent · 0.9 source

**पृथक् · Central service discovery and firewall policy automation**

A lightweight Go standard-library-only endpoint agent for RHEL and Ubuntu hosts running systemd and firewalld. It makes outbound authenticated HTTPS requests; it has no listening network socket. No Go runtime is needed on endpoints.

**Managed policy defaults to preview.** With `enforce=true`, restricted local management sources, a configured controller management vantage and an exact signed Admin-authorized assignment, the agent installs owned ingress source rules. It stages runtime changes, proves fresh controller/actual SSH connectivity, commits both scopes and keeps an independent systemd rollback service armed until durable success. Immutable history and new-version restore are available in the controller. Agent 0.6 supports bounded dual-bank ipsets for larger source groups, retaining the 64-rule small-bundle adapter. Unsupported contexts block changes. See [the enforcement guide](../docs/managed-enforcement.md), [source-set preparation](../docs/ipset-enforcement.md) and [independent assignment/package signatures](../docs/policy-signing.md). This is a lab release; the 20-server pilot has not started.

Implemented:

- Identity-only mTLS enrollment using a reusable fleet enrollment key or an optional one-use token, a locally generated ECDSA CSR and the configured bootstrap CA; certificate keys and cached state have mode 0600. The same fleet setup installs across many servers, with a separate identity for each; see [fleet enrollment](../docs/fleet-enrollment.md).
- Fresh full service/OS/firewall discovery at every startup/restart and every 15 minutes (`discovery_interval_seconds: 900`). A bounded native Linux socket snapshot checks for listener changes every 5 seconds; verified changes trigger `ss -H -lntup` process identification and an immediate report (normally about 5–10 seconds plus delivery). Unsupported/failed checks retain full discovery as fallback. Listeners include owning process/PID, service identity and application/systemd unit where available. New GUI/fleet defaults use 30-second control/report polling; legacy configuration can retain older intervals. Firewalld state and UFW detection remain separate runtime checks.
- Versioned policy polling with ETag; JSON validation; local cached policy and human-readable preview plan. Existing firewall access survives controller outages.
- Optional temporary learning and continuous monitoring with separate conntrack accepted-transport and terminal NFLOG denied-packet evidence. New scopes require `traffic_capture_v1`; both kinds default selected, with separate count units and explicit backend/family/loss receipts. Historical omitted-kind scopes retain sampled journal capture. Unsupported typed backends never silently fall back. See [0.9 traffic capture](../docs/traffic-capture.md). UFW is never disabled automatically.
- Automatic learning advertises `learning_discovery_v1` and performs a fresh scan for each pending session request. Each endpoint receives only its own frozen discovered ports; no assumed 22/80 list or another host's port union is instrumented. Explicit manual-port sessions remain available.
- Optional `learning_auto_allow_v1` installs a separate accept-only overlay from exact observed source/port/protocol tuples when the session and endpoint explicitly opt in. It does not approve ordinary managed policies or introduce reject rules.
- Locally enforced expiry, exact owned-rule cleanup at shutdown/startup, bounded durable file spool, idempotent batch IDs, and session coverage with rate-limit/gap diagnostics. Firewalld runtime rule timeout is an additional expiry safeguard.
- Simulation mode uses synthetic listeners and never invokes any OS/firewall commands; it does not fabricate traffic events.

## Runtime versus optional helper prerequisites

The static Go endpoint and stock POSIX-shell installer require no Python or Python cryptography package. `scripts/prepare-managed-ipsets.py` is a separate one-time administrative helper: Python **3.6+** standard library plus `firewall-cmd`; it does not import cryptography. Its empty permanent definitions still need separately reviewed runtime activation.

`scripts/verify-release.py` runs on an administration workstation **before extraction**. Its syntax floor is Python **3.8+**; use this release's supported `cryptography>=44` with Ed25519, and prefer an approved Python **3.10+** tool environment. The tested cryptography 50.0.2 requires Python>=3.9 (excluding3.9.0/3.9.1). RHEL 8's default Python 3.6 cannot run this verifier; do not add a Python dependency to the running endpoint to imply otherwise. Signing tools import the controller modules and use the controller Python 3.10+/requirements environment. The controller-appliance host installer separately requires Python 3.9+, Docker and Compose; its image supplies the controller runtime.

## Build and run

```sh
cd agent
go test ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o bin/seg-agent-linux-amd64 ./cmd/seg-agent
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o bin/seg-agent-linux-arm64 ./cmd/seg-agent
```

The server does **not** need a manual dashboard entry. Prepare a reviewed configuration using the canonical paths in `config.example.json`, the trusted controller CA, and one private single-use bootstrap token. Then run the installer on the endpoint:

```sh
sudo install -d -m 0700 /etc/seg-agent
sudo install -o root -g root -m 0600 /path/to/downloaded-enrollment-token /etc/seg-agent/enrollment-token
sudo ./scripts/install-agent.sh --ca-file /path/to/controller-ca.crt \
  --token-file /etc/seg-agent/enrollment-token \
  ./agent/bin/seg-agent-linux-amd64 ./agent/config.example.json
```

The token file must be a root-owned regular file with permissions 0600 or 0400; a regular user’s mode 0600 download must first be copied with the root ownership shown above. For arm64 use the matching binary. The installer validates the actual HTTPS origin, CA and token or existing identity, installs protected bootstrap artifacts, and **enables and starts/restarts the systemd service automatically**. The endpoint generates and persists its own unique key/CSR, enrolls with mTLS, discovers hostname/IP addresses/listening services and reports them immediately. The server then appears in the dashboard automatically. Business tags and its saved DC/cloud location come only from central dashboard assignments; neither token defaults nor agent configuration supplies them. New token requests reject nonempty tags/location, and legacy token defaults are ignored. A central exact-IP CSV profile or subnet-to-DC mapping prepared before installation can take effect when the endpoint reports its addresses. Otherwise it remains untagged/unassigned until an administrator edits it.

If the controller or network is temporarily unavailable, the service remains active and retries bootstrap with exponential backoff (5 seconds through 5 minutes plus jitter). An interrupted enrollment retries the same persisted CSR/hostname, allowing the controller to recover the original identity without creating duplicate servers. The installer reports either dashboard-ready status or pending automatic retries. Readiness is tied to the configured controller and a fresh service-instance generation, so an old daemon’s successful report cannot satisfy a new installation/restart. Private key, CSR and certificate artifacts are committed atomically without overwriting a different existing identity; malformed existing credentials produce an explicit bootstrap error. `seg-agent --config /etc/seg-agent/config.json --status` shows persisted registration readiness; `journalctl -u seg-agent.service -f` shows progress. Tokens still require trusted provisioning; automatic enrollment does not mean unauthenticated enrollment. A token can also be supplied through protected `SEG_ENROLLMENT_TOKEN`/`SEG_ENROLLMENT_TOKEN_FILE` environment input to the installer; it is copied to a root-only file and never placed on a command line. After enrollment, the unused bootstrap file can be removed because the persisted mTLS identity is used on subsequent starts.

An existing different configuration causes the installer to stop before changes; pass `--replace-config` only after reviewing the replacement. The previous config is preserved as `config.json.previous`. `--no-start` stages an enabled but stopped service; on a live host it requires an already stopped unit. `--root /absolute/staging-root --no-start` packages files and an enablement symlink without touching live systemd. `--check-config` performs a non-networking credential preflight; `--install-check` also checks the paths supported by the stock systemd sandbox. Packages `iproute`/`iproute2`, `firewalld`, and systemd journal access are required for real discovery/learning. The installer does not enable firewalld or disable UFW. Test the supported distribution/firewalld versions in your lab first.

## Central tags and location

Create saved DC/cloud names in the dashboard before assigning them. A server has one saved location and any number of custom business tags. Administrators can edit one endpoint, select multiple Servers rows for a reviewed bulk update, import an exact-IP CSV profile for a current/future endpoint, or create a subnet-to-location mapping. CSV imports and profile removal have separate preview/apply steps; the CSV dialog also lists imported profiles and their current/future bindings. No business-label fields are needed on the endpoint.

Manual overrides take priority over CSV profiles, followed by a subnet location or unassigned. The most specific subnet wins for each address; addresses resolving to different DCs produce a conflict. Subnet rules do not supply tags. A manual tag removal remains in force until its key is reset to automatic. An explicitly unassigned manual location is also pinned until returned to automatic. Agent reports and discovered process names cannot change these choices.

Dynamic group membership follows effective central tags/location. An authorized membership change compiles and publishes recalculated exact intent directly. Local enforcement opt-ins, current signed authority, protection, health and rollback checks remain mandatory.

The dashboard Services catalogue reuses named exact port sets, such as Web with `80/tcp` and `443/tcp`. These groups contain 1–100 distinct TCP/UDP ports, with no ranges or nesting. Policy rows may reference a service group and union CIDRs, an AND source-tag selector and multiple existing server groups. The controller expands that row to exact per-port source rules before delivery, preserving unrelated rows' source alignment. The agent still receives flat services; the catalogue never grants local firewall authority. An authorized source membership or port edit can publish a new exact effective version, subject to the same endpoint safeguards. Monitor sources cannot broaden an enforced port.

Service identity comes from the actual owning executable/systemd unit, rather than a conventional port label: `sshd` or `dropbear` on TCP 2022 is reported as **SSH**, and `nginx` on 8443 is **Nginx**. `/proc/PID/cgroup` identifies the owning systemd service when accessible. A bounded numeric-address socket-unit fallback recognizes socket-activated SSH before `sshd` exists; ambiguous mappings remain unknown. Unidentified owners are labeled **Unknown service**. The listener `application` field means the owning executable or unit; administrator-managed host application tags such as `billing` remain separate.

A scan attempt, including a failed attempt, reports `discovery_performed:true` until the controller successfully acknowledges that snapshot. HTTP retries reuse the pending inventory and original successful `discovered_at` without repeating `ss`. After acknowledgement, ordinary cached heartbeats explicitly report `discovery_performed:false` and retain the original timestamp/listeners. Reports also include `discovery_interval_seconds: 900`. A failed scan preserves the last successful inventory/timestamp, delivers its error as an unacknowledged attempt, then retries scanning on the next control interval. The discovery scheduler runs independently from policy polling; temporary learning expiry is unchanged.

`seg-agent --config /etc/seg-agent/config.json --scan-now` requests an immediate scan from the existing running agent without creating another endpoint identity or restarting it. `seg-agent --config /etc/seg-agent/config.json --once` always performs a fresh discovery and policy sync for a stopped/manual instance, without starting learning instrumentation. The persistent systemd service is required for traffic learning and timely cleanup. `--version` prints the capability boundary.

## Automatic learning and upgrades

**New 0.9 capture scopes require an upgraded `traffic_capture_v1` endpoint**, in
manual-port and discovery modes. Older capability notes below explain retained
historical discovery scopes, not a way to bypass new capture validation.
Historical journal logs remain readable; they are not relabelled as verified
connections or denied packets. NFLOG availability depends on the installed
firewalld/kernel context and may report unsupported even on an upgraded agent.

Agent **0.3.0** reports `agent_version` and `capabilities:["learning_discovery_v1"]`. Upgrade selected endpoints before choosing automatic discovery in the dashboard; an older/missing capability rejects automatic session creation with an upgrade/manual-mode message. Preserve `/var/lib/seg-agent` identity/state and the reviewed config during the usual matching-binary installation, restart the service, and verify its new report. Manual mode supports an explicit common list of 1–100 ports for older agents. Earlier dashboard versions prefilled `22/tcp` and `80/tcp`; automatic discovery assumes neither exists.

Automatic mode starts with explicit selected endpoint IDs and pending discovery assignments. After receiving one, the running agent performs a fresh listener scan, tags the pending snapshot with `learning_discovery_session_ids`, and retains it across HTTP retries until acknowledged. Only a successful scan at/after the session start can freeze that endpoint's scope. Network listeners on wildcard or known non-loopback addresses qualify. Unknown bind addresses and loopback-only binds are excluded; an unknown owning process alone does not exclude a listener with a known network bind. The controller projects only the endpoint's frozen ports back to it. Ports discovered later wait for another learning session.

Pending, offline, discovery-error and no-network-listener states are visible in the dashboard. Pending or empty assignments install no learning rules. Failed scans retry while time remains; a scan with more than 100 eligible ports reports an error and requires an explicit smaller manual selection. A successful empty scan records no listeners without fabricating observations. The requested expiry runs from session creation, so discovery and outage time reduce usable coverage. A one-hour request does not promise a full hour of collected events. Local expiry and stop cleanup remain enforced, and observation itself never opens ports. Explicit Admin-enabled auto-allow can create separate exact-source allowances as described below.

For the local controller demo, create a separate config with a loopback HTTP controller, absolute writable state directory, `interval_seconds:5`, and `demo_agent_id:"simulated-rhel-01"`. Run `seg-agent --config /path/to/demo.json --simulate --simulate-hostname simulated-rhel-01`. The demo endpoint identity is rejected by a real controller.

## Temporary learning with automatic source allows

The default session action is **Observe**. To permit automatic source policies on a real endpoint, explicitly configure both local switches and keep the management baseline accurate:

```json
{
  "enforce": true,
  "learning_auto_allow": true,
  "management_sources": ["10.20.0.0/24"],
  "zone": "public"
}
```

Then start a controller learning session with `policy_action: "auto_allow"` and explicit consent. The initiating Admin action authorizes that session’s selected endpoints and ports. After fresh discovery, the controller freezes each host’s exact eligible scope and activates automatic additions without another person or separate approval request. Local opt-ins and protected-path checks remain mandatory. The session can select only TCP 443 from a server listening on 22, 80 and 443: discovery still reports all actual listeners, but that session instruments only its frozen 443 selection. The agent advertises `learning_auto_allow_v1`; older agents cannot receive automatic grants.

Only exact **source IP → protocol → port** observations from that endpoint and active session can create automatic accepts. IPv4 sources become `/32`, IPv6 sources `/128`; no subnet is inferred. New typed scopes bind selected observation kinds and verified supported inbound capture paths; historical journal parsing requires nonempty `IN` and empty `OUT`. Evidence is stored privately and survives ordinary spool/restart recovery. Sources observed on port 80 cannot authorize port 443. Loopback, link-local, unspecified, multicast, scoped and mapped-address sources cannot authorize grants. Protected SSH ports and local controller ingress are excluded.

Automatic learning trusts sources within the selected kinds, including scans and blocked first-hits when denied-packet capture is selected. Both kinds default selected, preserving the requested any-hit behavior; the existing explicit Admin/local opt-ins authorize it without another approver. A conntrack transport observation does **not** prove authentication or application success. NFLOG packets and connection counts have separate units. Loss, unsupported backends, outages and finite windows prevent a complete dependency inventory. Use Observe when this automatic trust is unsuitable.

The controller saves durable learning policies that can be reviewed, edited and deleted. These policies have their own generation and reported applied state. The endpoint installs only owned accept rules, before its managed rejects, and preserves unrelated services and ordinary managed policy approvals. Both scopes are queried after application. A fresh mTLS controller/SSH witness and independent systemd rollback service protect each transaction. Local opt-ins, exact endpoint/IP/protection bindings and one-zone checks apply. Agent 0.6's `learning_ipsets_v1` allows up to 10,000 exact source/port tuples using separate additive source banks; legacy agents retain 64 exact grants. Initial bank setup and per-family source-set bounds still apply. If a mutated auto grant fails, the whole session grant is held; another incidental hit cannot retry it. An explicit reviewed update or a new session is required.

Stopping or expiring learning removes temporary logging but preserves already committed allow policies. New late auto additions are refused. An authorized Admin edit/removal reconciles only this overlay; it cannot remove unrelated rules. Turning a local opt-in off freezes updates and retains the last committed accepts, so use a reviewed controller deletion while enabled to remove them. Controller outages preserve committed state. `learning_allow_outcome` distinguishes the desired generation from `applied_generation`/`applied_digest`; receiving a policy is never reported as applying it.

The private transaction history lives under `state_dir/learning-allow/transactions`. Exact `PRTL` rules include a low-rate debug log marker for ownership, independently from the temporary traffic collector. Do not delete pending journals or run simulation with production state; simulation refuses real mutation history. RHEL enforcement still requires licensed RHEL VM validation before any pilot; public UBI repositories do not include the firewalld daemon.

## Imported firewalld inventory and approved changes

Full inventory scans read runtime and permanent zone services, ports, rich rules, targets, interfaces and sources. Direct rules and policy objects are visible as view-only configuration. Named-service ports are resolved from actual service definitions; a custom `ssh` definition using port 2022 is not treated as port 22. Snapshot entries have stable scope-specific fingerprints and logical keys so the controller can compare common rules across a selected fleet.

Inventory is bounded to 1,500 entries and 512 KiB. Incomplete reads retain the prior snapshot with an error and view-only status. Exact locally owned log-only learning/probe instrumentation is excluded from the approval digest; unrelated or access-changing rules are included. Advanced rich rules, direct/overlapping active policies, source-bound/multiple active zones and target-ACCEPT contexts require manual review. The actual default IPv6 host-control policy is accepted as non-overlapping only when its full normalized target, priority, bindings, empty TCP/UDP fields and exact four ICMPv6 accept rules match the verified definition; a familiar name alone is never trusted. Its policy object remains view-only, and protocol-wide rich changes are excluded under that exemption. The adapter does not claim that changing a listed port overrides an unrelated acceptance path.

The default is read-only:

```json
{
  "allow_firewall_changes": false,
  "management_sources": ["10.20.0.0/24"]
}
```

After endpoint-level opt-in and controller approval, supported plans can replace/remove existing services, ports and a bounded simple rich-rule subset. Scope must explicitly name runtime or permanent; changing both requires both operations. Every write requires confirmation, and deny or restricting changes—including removal of a deny rule—require two confirmations independently checked by the endpoint. An expired plan, changed snapshot, missing opt-in, unsupported context or unsafe management change is refused or reported as preview; it is never reported as applied.

Before writing, the agent reads a fresh snapshot and saves a private mode 0600 snapshot/inverse journal under `state_dir/firewall-changes`. Replacements add the new value before removing the old value. Each primitive is queried after application; completed mutations are compensated in reverse on failure. Outcomes are persisted and replayed idempotently. Unknown interrupted command ownership or failed rollback requires local review rather than a blind success report. Out-of-band root/configuration tools can still race with firewalld changes; precondition/read-back failures remain visible.

The agent detects actual SSH listeners, including custom ports and supported socket-activation metadata. Removing an SSH/broad allowance requires an independent surviving management allowance. A new broad deny matching SSH, or one overlapping configured management sources, is refused. Keep management CIDRs accurate. The adapter does not disable UFW, reload/flush firewalld, copy runtime to permanent or execute arbitrary shell input. Extended capabilities support exact bounded INPUT direct rules, local port redirects and staged permanent zone-target replacement. They require matching runtime/permanent evidence and management protection; unsupported routing, NAT and policy-object contexts stay view-only.

## Communication and discovery settings

Use the controller’s Agent polling settings for timing overrides. For endpoint URLs, management scope and security opt-ins, create an Admin-authorized signed configuration kit in Platform → Setup and apply it locally with the verified family installer. This does not silently enable enforcement. `/etc/seg-agent/config.json` remains the protected technical configuration; the agent reads it at service start. These settings are independent of a temporary traffic-learning duration. Business tags and DC/location are configured in the dashboard, not this file:

| Setting | Default | Accepted value / purpose |
| --- | --- | --- |
| `controller_url` | HTTPS origin selected during installation | One HTTPS origin, for example `https://prthak.example.internal`; omit `/api/v1`, credentials, query strings and fragments. |
| `interval_seconds` | `60` | `5`–`3600` seconds for heartbeat and versioned policy synchronization, with a small retry/poll jitter. |
| `discovery_interval_seconds` | `900` | `60`–`86400` seconds for full listener/process/application inventory. Startup and an explicit scan run immediately. |
| `request_timeout_seconds` | `15` | `1`–`120` seconds for each controller HTTP request. |
| `ca_cert` | `/etc/seg-agent/controller-ca.crt` | Independently trusted controller web HTTPS CA. TLS verification stays enabled. |
| `endpoint_ca_cert` | empty; falls back to `ca_cert` | Separate trusted public endpoint issuer when it differs from web HTTPS. Preinstall it before preflight; `--ca-file` copies web trust only. |
| `certificate` / `private_key` | `/var/lib/seg-agent/agent.crt` / `/var/lib/seg-agent/agent.key` | Persisted node-specific mTLS identity. Preserve these across controller failover and routine upgrades. |
| `enrollment_token_file` | `/etc/seg-agent/enrollment-token` | Private fleet or one-use bootstrap credential. Existing valid mTLS identity is reused afterward. |
| `state_dir` | `/var/lib/seg-agent` | Private cache, pending enrollment, readiness, approved-change backups and traffic spool directory. |
| `enforce` | `false` | Opt-in for reviewed managed source enforcement. Requires exact approval, protected management baseline and fresh health proof. |
| `management_sources` | deployment-specific | Restricted, root-configured management CIDRs. `/0` cannot authorize managed enforcement. |
| `management_probe_url` | controller origin + `/api/v1/agent/enforcement/check` | Same authenticated controller origin/path only; no arbitrary external witness. |
| `learning_auto_allow` | `false` | Additional local opt-in for scoped accept-only learning policies; also requires `enforce=true` and an explicit Auto allow session. |
| `allow_firewall_changes` | `false` | Independent opt-in for exact confirmed edits to imported existing rules. |
| `allow_host_default_deny` | `false` | Independent opt-in for the dedicated whole-server ingress workflow; requires managed enforcement and `learning_auto_allow=false`. Each push still needs the GUI's current exact downtime acknowledgement. |

Whole-server default deny requires a compatible controller/agent and is configured
through a signed GUI-generated endpoint kit. It retains declared SSH/network
controls, enforces both address families and uses the managed transaction and
rollback path. See [the complete workflow](../docs/whole-server-default-deny.md).

Every report includes the configured `control_interval_seconds`, even when service inventory is cached. The controller derives the offline threshold as the greater of 180 seconds or three times that interval, so a longer configured polling interval does not cause a false offline alert.

For example, the relevant part of a reviewed configuration can be:

```json
{
  "controller_url": "https://prthak.example.internal",
  "interval_seconds": 60,
  "discovery_interval_seconds": 900,
  "request_timeout_seconds": 15,
  "ca_cert": "/etc/seg-agent/controller-ca.crt",
  "state_dir": "/var/lib/seg-agent"
}
```

Validate the complete saved configuration, then restart to apply it:

```sh
sudo /usr/local/bin/seg-agent --config /etc/seg-agent/config.json --check-config
sudo systemctl restart seg-agent.service
sudo /usr/local/bin/seg-agent --config /etc/seg-agent/config.json --status
```

Use one stable load-balancer HTTPS name for an HA controller fleet. Every backend must present a certificate valid for that name and share the endpoint trust/signing configuration. A controller-node failover then requires no endpoint URL, identity or timing changes. A deliberate CA or identity change is a credential migration rather than a normal URL edit.

Runtime credential paths are configurable. The stock installer intentionally checks its canonical paths against the stock systemd sandbox; customizing the writable `state_dir`/identity paths also requires a reviewed systemd `ReadWritePaths` change. `ProtectHome=yes` prevents reading credentials from home directories. If installation created `/etc/seg-agent/bootstrap.env`, its `SEG_ENROLLMENT_TOKEN_FILE` value overrides the JSON token-file path: update or remove that protected override when changing the bootstrap path. `SEG_ENROLLMENT_TOKEN` has precedence over either file setting. Token values belong in protected files/environment inputs, never in command-line arguments or committed JSON.

## Operational limitations

Traffic is observed only after a learning assignment has been successfully fetched. A controller outage does not extend the learning expiry. Starting collection does not open any port. Firewalld logging can be rate-limited; coverage declares that collection is rate-limited and counts represent observed packets/events. An initially established connection may not hit the logging chain. A short learning session cannot establish that an unseen source is unnecessary. IPv4 and IPv6 source records are parsed, but namespace/container forwarding is outside this first release.

Flow delivery retries use stable persisted batch IDs. Historical journal records may replay after a crash between capture and cursor persistence, so their exact counts are not guaranteed. New typed events use stable scope-bound IDs and durable controller deduplication; backend loss and gaps still limit completeness. Spool capacity is bounded. Batches rejected with permanent HTTP 400/403/404/410 responses and corrupt JSON batches are quarantined so later sessions can continue uploading; per-session dropped-event counts and a persisted spool diagnostic expose that loss. Quarantine retains at most 20 rejected payloads. Network failures, HTTP 429 and server errors remain queued for retry. Batches older than 24 hours are discarded with a loss diagnostic. Expiry, stop and shutdown perform bounded final journal reads using retained session cutoffs; recently stopped controller assignments should include `stopped_at` so post-stop logs are excluded. A cancellation can take up to one policy polling interval to reach an endpoint. Agent 0.6 supports authenticated certificate renewal/recovery, registry revocation and independent Ed25519 assignment/package verification. These do not establish target-host, live-tenant or native site-failure acceptance; see the lifecycle/trust section below.


## 0.6 credential and assignment trust

`ca_cert` pins the controller HTTPS server chain. `endpoint_ca_cert` optionally pins a **different endpoint issuing CA**; empty uses `ca_cert` for same-CA installations. If HTTPS uses a corporate/public CA while endpoint leaves use the private enrollment issuer, set `endpoint_ca_cert=/etc/seg-agent/endpoint-ca.crt` and install that trusted **public** issuer certificate there before installer preflight. The stock `--ca-file` option copies web HTTPS trust only. Never copy an issuing private key to an endpoint.

```sh
sudo install -d -m 0700 /etc/seg-agent
sudo install -o root -g root -m 0644 ./endpoint-issuer-ca.pem \
  /etc/seg-agent/endpoint-ca.crt
# Set endpoint_ca_cert in the reviewed config before install-agent.sh.
```

Endpoint leaves last 90 days and renew through authenticated mTLS in the 30-day window. Registry overlap is tracked for 24 hours; old/revoked identities do not gain authority through a forwarded header. Super Admin can revoke exact identities or issue a 15-minute one-time recovery token. Renewal/recovery verifies the locally pinned issuer; roots from the response cannot replace it. Recovery does not itself revoke an earlier compromised certificate. Preserve private state and inspect actual native reconnect/receipt status.

Ed25519 assignment public trust is a third independent pin: protected `policy_signing_trust_file`, or explicit `policy_signing_keys` plus `policy_signing_deployment_id`. First authenticated enrollment may pin initial trust when none exists, but never silently replaces an existing pin. The agent verifies the complete exact signed assignment before caching or mutation. Signature expiry/invalid replacement blocks new writes and preserves committed firewall policy. An optional controller offline provider serves independently reviewed artifacts with no online signing-key fallback. See [independent signing operations](../docs/policy-signing.md).

Before extracting/installing current packages, verify their Ed25519 signature with independently obtained release public trust using `scripts/verify-release.py` on an administration workstation. Packages without a configured dedicated release signer are labelled unsigned lab material; checksums and an adjacent downloaded public key alone do not authenticate a release.

Deploy the updated controller before these agents. Signed assignments are bound to the enrolled certificate identity and carry a durable monotonic `assignment_generation` for the complete assignment, independently of the compiled firewall policy version. The agent rejects missing, stale or divergent signed generations and retains stopped learning-session cutoffs. Backup recovery preserves the controller's current assignment-generation high-water records.

For the pilot, do not enable endpoint enforcement or automatic learning on controller, database or load-balancer infrastructure. A controller behind a load balancer may use local ingress ports that differ from the configured public URL; native ingress-protection acceptance for that topology remains required. An inferred SSH display name alone grants no management exception: trusted executable/system-service evidence or an explicitly configured local `protected_ssh_ports` entry is required.

A current authorized local or SSO Admin’s normal Save/Apply publishes exact intent directly. No second person, approval-mode selector, 20-host approval scope or seven-day approval-mode expiry is required. Deny/restrictive imported changes and restrictive learned edits/removal retain two explicit confirmations by the same actor, using current nonces and the final typed challenge. Endpoint local opt-ins, signed identity/scope bindings, current authority, management health, durable journals and rollback still gate mutation. Only Super Admin manages application users and privileged platform settings; destructive database recovery retains two explicit same-Super-Admin confirmations. Shared-token/demo flows remain labelled lab fixtures.

See [endpoint discovery, preparation and health](../docs/endpoint-discovery-and-preparation.md) for fast-check bounds, offline alerts and the optional schema-3 dependency/UFW assessment workflow.


## Local and SSO controller users

The current endpoint payload is stamped 0.16.0. Local, Entra OIDC and SAML user roles are managed by the controller; human passwords are never sent to endpoints. Existing 0.14 agents remain protocol-compatible with this login addition and do not need reinstallation solely for it. See [current authentication](../docs/local-and-saml-login.md).

<sub>Created by Pratik Srivastava</sub>
