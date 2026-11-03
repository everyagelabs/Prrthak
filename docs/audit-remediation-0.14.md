# Ten audit findings addressed in 0.14

2 November 2026. This pass addresses the ten confirmed findings from the review of source `d4aa466`. The user selected these fixes before broader roadmap development. Native RHEL/Ubuntu and DC acceptance remain deferred.

| Finding | Resulting behavior | Regression evidence |
| --- | --- | --- |
| F01 Signed startup and branding | The runtime manifest binds the current application and Airtel Payments Bank footer. Normal CI checks its signature, exact files, version, bootstrap and privileged manager before regressions. The new candidate retains old immutable tags. | Real signed-source check; modified-footer/bootstrap/version rejection; signed image startup and tamper-before-import checks. |
| F02 Revoked merged-policy author | Every contributing enforcing intent and its current author/provider must remain valid. Indexed ID lookups compare canonical writer-derived intent headers and proof hashes; invalid merged approvals are retired. | Two-author disable/demotion, control-health admission, SQLite/PostgreSQL and actual HTTPS/mTLS checks. |
| F03 Restart failure during configuration rollback | Durable `restart_pending` retains the generation fence and failure until restart succeeds. The independent watchdog retries failures. Exact restored files permit fresh startup without deadlocking its restart helper. | Restart failure/retry, stale generation, changed files and startup recovery tests. |
| F04 Deletion by another Admin | The current authenticated Admin authorizes exact ordinary cleanup even when the former author was disabled. DELETE returns its deployment reference. Whole-server deny remains separately guarded. | Current-actor cleanup, actual cookie/CSRF DELETE, Python-to-Go signed cleanup proof and shared dashboard rollout activation. |
| F05 Denied capture after learned access | Exact locally recorded learned rules and matching source-set contents are read back in both scopes before admitting their ordering. Prefix lookalikes, missing rules, missing ledgers and foreign sets stay blocked. | Rich-rule/source-set ownership and drift regressions; isolated dual-stack and IPv4-only capture checks. |
| F06 Cached enforcement after local opt-out | Read-only drift checks continue under the managed lease. Historical last-good intent cannot supply fresh generation/verification anchors or an Applied receipt. Unknown rule presence remains omitted rather than fabricated. | Removed-rule, busy/recovery, startup-cache and explicit host-deny removal checks. |
| F07 Retained-history polling cost | Normalized per-endpoint learning targets select eligible active/recent-stop scopes before JSON decoding. Canonical history remains available. Upgrade and recovery derive the index without reviving stopped capture. Empty stores remain empty for safe initial migration. | SQLite/PostgreSQL expiry, fractional time, backfill, migration, restore and history-exclusion checks; 5,000-identity fixture extended with 100 expired full-fleet sessions. |
| F08 Late metadata completions | Identity, modal and request generations fence previews, file reads, profile loads, applies and errors. Newer drafts survive old completions; CSRF refresh alone preserves the current review. | File A/B ordering, modal replacement/close, identity changes, stale apply/error and real shared-shell tests. |
| F09 Incomplete large review | Frozen assignment plans are paged at 100 rows, including later rows up to the 10,000-row bound. Pagination never narrows the authorized plan or changes its nonce. | 200-row and 10,000-row navigation, final-row visibility, exact plan/nonce and Read Only protection. |
| F10 Current installation guidance | Current controller/agent/native-package examples use 0.14.0. Current authority wording uses one Admin and retains the dedicated downtime tick. A new illustrated PDF/HTML guide covers the current workflows, ports, roles and sizing. | Package contents, guide render/text review and shared workflow regressions. Historical guides remain labeled. |

The new learning-target index is a derived cache. Empty database initialization does not create a business-state marker. Initial SQLite-to-PostgreSQL import still refuses populated foreign targets, and recovery rebuilds the cache only after stopping restored learning sessions. Policy intent headers remain separate from canonical policy bytes, preserving source-matrix limits and immutable policy records.

Direct Admin publication does not remove endpoint opt-ins, exact source/protection binding, management health, local journaling or rollback. Revoking a contributor blocks new admission; it does not automatically delete already-installed rules. Ordinary deletion remains pending until the endpoint reports its actual cleanup outcome.

The [release record](release-0.14.0-pilot.1.md) binds final aggregate validation and artifacts. The [current illustrated guide](guide/prthak-pilot-0.14.0.pdf) and [GUI runbook](pilot-gui-installation.md) describe operator steps.

Broader roadmap items remain separate: canary orchestration, scheduled policy windows, traffic what-if, fleet upgrades, specialized SIEM output, tiered retention, encrypted backup payloads, local rescue tooling and organization-approved signing. Passing this remediation does not establish native/DC readiness or a clean VA.

© 2026 Airtel Payments Bank. All rights reserved.

<sub>Created by Pratik Srivastava</sub>
