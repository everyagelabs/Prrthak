# Source-set preparation entirely through the GUI

Prṛthak 0.12 prepares the owned firewalld source banks through the authenticated
agent. There is no additional SSH command, Python helper or hand-edited endpoint
configuration in this workflow. Ordinary policies with at most 64 rich rules
can still use the existing small-rule adapter.

## Prerequisites configured in the GUI

In **Install agent**, enter the restricted **Management source IPs/CIDRs** that
are permitted to verify SSH/controller connectivity. This pins protection
metadata while the initial agent remains monitor-only; it does not open ports
or enable enforcement. Configure the controller management-probe source and
target CIDRs through **Settings**. The probe must reach the endpoint's actual
discovered SSH port from a pinned source. Blank protection sources deliberately
leave maintenance blocked. Existing installations retain their local pins;
ordinary policy changes cannot replace them.
An existing agent without pins needs the GUI-generated endpoint configuration
kit and its local apply workflow first. Source-set maintenance cannot populate
those local trust/protection settings. Entering the pins during initial GUI
setup avoids that separate configuration step.

The agent must advertise `source_bank_preparation_v1`, use independently pinned
signed assignments and trusted mTLS, and report a fresh configuration/protection
snapshot. UFW remains preserved. Unsupported/uncertain firewall contexts must
be resolved before activation, rather than silently adopted.

## Assess, review and activate

1. Open **Servers → Source-set preparation**, or the source-set section of an
   individual server's detail drawer. Select explicit servers or saved groups.
   Each maintenance request freezes at most 100 current endpoints; future group
   members are not implicitly included.
2. Click **Assess**. The agent reads the current firewall and owned banks.
   Assessment performs no firewall mutation. The GUI shows the actual returned
   counts, freshness and blockers. Assigned work is not labelled prepared.
3. Request a review of the assessed endpoints. The review freezes the complete
   baseline, addresses, policy/configuration and protection bindings. A changed
   context or assessment older than three minutes requires reassessment.
4. Read the reload/maintenance impact, type **PREPARE SOURCE BANKS**, and manually
   tick the initially unchecked downtime acknowledgement. The same current
   Entra Admin confirms; no second approver is required. Closing/changing the
   review or identity resets consent.
5. The agent prepares missing definitions and activates them, then reports its
   verified result. The GUI distinguishes assigned, preparing, prepared,
   blocked, rolled back and error. Read Only can inspect assessments/status but
   cannot request or authorize maintenance.

```mermaid
sequenceDiagram
    participant Admin as Entra Admin / GUI
    participant API as Controller
    participant Agent as Local endpoint agent
    participant FW as firewalld
    Admin->>API: Assess exact selected endpoints
    API-->>Agent: Signed read-only assessment assignment
    Agent->>FW: Inspect baseline and owned source banks
    Agent-->>API: Bounded assessment receipt + blockers
    API-->>Admin: Fresh assessment and exact maintenance review
    Admin->>API: Typed phrase + manually checked downtime acknowledgement
    API-->>Agent: Signed exact preparation authority
    Agent->>API: Fresh authorization + SSH/controller health
    Agent->>FW: Journal owned empty definitions; controlled reload
    Agent->>API: Fresh post-activation SSH/controller health
    Agent-->>API: Prepared or verified rollback/error receipt
    API-->>Admin: Actual endpoint outcome
```

## Safety and ownership

firewalld creates these definitions in permanent configuration; a reload loads
them into runtime. Reload also activates permanent policy, so the agent first
requires supported semantic equivalence of runtime/permanent access settings.
It does not overwrite permanent policy with runtime state. Active/default
service definitions with unverified include/helper/module dependencies and
global configuration changed since daemon startup block activation. Unchanged
inactive stock services are permitted. Ambiguous loaded configuration is not
treated as safe. Permanent interface bindings must be a same-zone subset of
runtime bindings; runtime-only bindings must use the protected default zone.
Supported runtime-only bindings are recorded and verified/restored without
permanently pinning them. See the official [runtime/permanent model](https://firewalld.org/documentation/configuration/runtime-versus-permanent.html)
and [firewall-cmd interface](https://firewalld.org/documentation/man-pages/firewall-cmd.html).

Only the canonical 256 Prṛthak managed/learning bank names are provisioned.
Existing definitions/entries are preserved, and conflicting or foreign objects
block preparation. Newly created empty definitions carry transaction ownership
markers. A competing writer's object cannot be deleted as a rollback shortcut.
Preparation does not edit allow/deny rules, change local enforcement opt-ins,
flush connection state, perform complete-reload or migrate UFW.

The shared configuration/mutation leases fence competing upgrades and firewall
transactions. An independent ten-minute watchdog is armed before writes, with a nine-minute
operation deadline and progress reports during long phases. Failed
health/activation restores only the transaction's owned changes; uncertain
rollback remains an error. Once the controller admits a potentially mutating
operation, expiry or a new assessment cannot erase that uncertainty. Only a
matching verified outcome can release it. Database recovery invalidates pending
maintenance authority and reviews, and retirement blocks unresolved operations.

Existing already-authorized policy intent may resume on a later normal poll
once its banks are ready; source-set preparation itself grants no access and
does not authorize another policy. Normal large-policy updates continue using
inactive banks and do not reload firewalld.

Native RHEL/Ubuntu package/kernel/systemd acceptance and actual DC deployment
remain deferred. Fake-command and isolated Linux checks are separate evidence,
not a promise that every existing firewall layout can be changed safely.
