# Illustrated deployment and onboarding guides

## Start here with the simple picture guides

The **0.17 controller guide** has nine picture-led steps plus two reference sheets: [browser edition](simple/controller-installation.html) or [PDF](simple/controller-installation.pdf). One command detects RHEL 9 or Ubuntu 26.04 and prepares missing Python/Docker/Compose dependencies, then configuration continues in the GUI.

The **0.17 agent guide** has nine picture-led steps plus two reference sheets: [browser edition](simple/agent-installation.html) or [PDF](simple/agent-installation.pdf). One command detects RHEL 8/9 or Ubuntu 26.04, validates the GUI kit and signed agent, prepares missing dependencies, preserves firewall activity and starts the monitor-only agent. It covers reusable fleet setup, private transfer, discovery, central tags, resource allowances and checks. The [plain runbook](../installation-commands.md) has the same copyable commands.

[Features in simple language](../features-in-simple-language.md) maps all 48 requirement groups through seven original diagrams. Every new guide page and current Markdown document carries the author note. Historical PDF/HTML exports and signed release archives remain unchanged.

Screenshots are actual v0.17 local synthetic preview captures, explicitly labelled. For the 0.18 archive names, expanded agent profiles and current commands, use the [current command sheets](../installation-commands.md) and [agent OS table](../linux-agent-installation.md). Diagrams explain workflows and do not certify native OS, live IdP or DC acceptance. Setup downloads stay disabled in the synthetic preview. Native RHEL/Ubuntu validation and the real pilot remain deployment work.

Rebuild the new assets with `scripts/build-simple-guide-diagrams.py`, then `scripts/build-simple-installation-guides.py`, using approved Python with Pillow and ReportLab. `simple/verification.json` records artifact hashes, original captures, pixel-preserving crops and layout measurements. HTML embeds every image, includes copyable commands, and can be read without a server.

## Historical 0.14 illustrated baseline

The unchanged **0.14.0 illustrated pilot guide** remains available as [PDF](prthak-pilot-0.14.0.pdf) and [self-contained HTML](prthak-pilot-0.14.0.html). It covers its recorded components, ports, GUI configuration, one-command installation, central metadata review, per-port learning, safe publication, rollout evidence, sizing and platform operations. Its diagrams explain workflows; they are not relabeled historical screenshots or native acceptance evidence. The historical builder is `scripts/build-current-pilot-guide.py`; do not overwrite the archived edition to represent later behavior.

## Authentication screens added after the pilot baseline

The 0.14.0 PDF and HTML above remain unchanged. They do not illustrate the new Local + SSO login forms, first-login password replacement or SAML provider configuration. Use [Local and SAML login](../local-and-saml-login.md) and [current authentication](../authentication.md) for those workflows. Existing sign-in imagery is baseline evidence, not a new authentication validation claim.

## Historical 0.6 edition

> **Historical 0.6 edition.** Its screenshots and approval instructions predate the current direct-Admin workflow. Use [current requirements](../requirements-delivery-map.md), [authentication](../authentication.md), [managed enforcement](../managed-enforcement.md) and [API contract](../api-contract.md) for current operations. No second person or approval-mode selector is required; only the documented risky/destructive actions retain two explicit same-actor confirmations. The historical PDF is unchanged. The HTML has only this current-workflow warning added; its original verification record remains historical, not a new render attestation.

- `prthak-deployment-guide.html` is self-contained: embedded CSS, native SVG diagrams and base64 original product captures. It needs no server or external image assets to read.
- `../../output/pdf/prthak-deployment-onboarding-guide.pdf` is the fixed **37-page 0.6 lab edition**, with 10.5-point body text, 9.1-point table text and chapter bookmarks.
- `screenshots.json` records actual capture paths, focused viewports and provenance. Current 0.6 frames show staged forms, empty queues, disabled external delivery and demo-blocked recovery and port changes. No live Entra approval, real endpoint change, private certificate material or provider send is represented.
- Retained earlier captures are labelled **Retained synthetic UI**; current captures are labelled **Synthetic demonstration**. Inline viewports reuse unchanged source pixels, while the HTML gallery includes complete originals and detailed provenance.
- `images/*.svg` are original code-native engineering diagrams. The actual bilingual application wordmark is used as SVG in HTML and as its previously rendered, correctly shaped asset in PDF. The Airtel Payments Bank organizational image is unchanged; provenance remains in `dashboard/assets/README.md`.
- `layout-metrics.json` measures every PDF page. The builder rejects overflow. `verification.json` records the final artifact hash, render checks and evidence limits.

## Regeneration

Use Python 3.10+ with ReportLab and Pillow. Supply DejaVuSans, DejaVuSans-Bold and DejaVuSansMono TTF files, setting `PRTHAK_GUIDE_FONT_DIR` if the bundled default font path differs. Poppler and pypdf support render/text QA.

```sh
PRTHAK_GUIDE_FONT_DIR=/path/to/dejavu-fonts python3 scripts/build-illustrated-guide.py
```

For HTML only, add `--html-only`. Regeneration never starts a controller, contacts Entra or changes firewall rules. In a new PDF-authoring task, follow the PDF skill operation marker before the first edit/create command. The 0.6 edit marker was recorded once; layout iterations reuse that operation.

## What the edition covers

The guide keeps complete prerequisite ports, same-installer/private-basic.env setup, single-tenant Entra and exactly three roles, automatic or reserved onboarding, canonical agent files, dashboard-only metadata, policy-row source alignment and fresh per-host exact-port learning. It explains /8-/16-/24 longest prefix, exact-CIDR uniqueness and ambiguous IP/DC ownership; no TCP peer, forwarded or planned address becomes a live agent address.

Operator chapters cover prepared source banks and no live policy reload, independent requester/checker authority, Ed25519 assignments and archive verification, optional offline signing, separate web/endpoint/signing trust, certificate lifecycle, reviewed notifications and two-Super-Admin supervised database recovery. Reviewed current-node application-port changes preserve the configured application/SSO origin and require explicit external-dependency acknowledgement; desired/queued state never claims a verified listener. Existing cluster/storage/services, backup/schedule/demo cleanup, replication rotation and central polling workflows remain included. Original controller/policy/learning status and actual runtime results remain distinct.

The static Go endpoint and stock POSIX installer require no Python. The optional source-bank helper supports Python 3.6+ stdlib/firewall-cmd. Archive verification has a Python 3.8+ syntax floor and release cryptography>=44 dependency floor; use approved Python 3.10+ administration tooling. RHEL 8 default Python 3.6 is not a verifier environment. These helper prerequisites do not add Python to the running endpoint.

## Evidence and acceptance

Actual Ubuntu 26.04 ARM64 discovery/mTLS/identity reuse and actual firewalld 2.3.1 source-bank transactions passed in disposable containers. The latter uses explicit health/timer callbacks and does not certify native kernel/systemd behavior. Retained Ubuntu 24.04.4 ARM64/systemd/firewalld 2.1.1 evidence includes the full controller/Go mTLS/HTTP/SSH wire and independent SIGKILL-triggered agent rollback; it is a distinct fixture.

Private evidence includes real TLS webhook/SMTP semantics, actual compiled Go-client loopback same-CA and separate web/endpoint-CA renewal/revocation/two fresh-key recoveries, real HTTPS PEM/PKCS#12 replacement/restart/rollback and actual three-node internal-leaf rollover. Real CLI/Gunicorn HTTPS SQLite recovery retained the parent, drained the old child group, resumed a pair-swap crash and enforced private readiness, public 503 and old-session 401 barriers. Shared-PG coordinator barriers and actual three-node restore helpers were separate fixtures. Transient helper retry preserves the same immutable phase; permanent safety mismatches stay blocked.

Four actual CLI/Gunicorn tests passed: HTTPS handover with the same supervisor/persisted restart with original `--listen`, occupied-target rejection, failed-candidate verified HTTPS restoration and demo HTTP review/apply denial. A separate real Compose/public-router fixture covered mapping/commit/retry/conflict/rollback. Those local results do not prove external routing or Microsoft sign-in.

The 5,000-identity Gunicorn/mTLS workload and separate large-inventory projection/pagination measurements are described in `docs/mtls-scale-validation.md`. They are virtual/private workloads, not 5,000 Linux processes, physical WAN/quorum/soak or DC browser acceptance. The original illustrated-guide baseline passed 528 controller tests, 150 integration checks and 201 dashboard tests, with all five PostgreSQL acceptance flags enabled; Go regular/race/vet and make check pass. Exact UI totals are omitted from the fixed guide, and no test total establishes deployment approval.

The unchanged 37-page PDF/HTML remains that historical baseline. The [31 October security addendum](../security-assessment-2026-10-31.md) records the later frozen-source results: 653 controller tests, 183 integration cases (182 passed, one Mac/Linux-kernel skip), 230 dashboard tests and the twelve application-code remediations. Vendor/container findings remain open. `verification.json` preserves original guide hashes/layout evidence and records this addendum separately; the PDF has not been relabeled as a post-audit or VA-cleared export.

A local project release-signing authority is not organization-approved or independently distributed. Before DC use, adopt its public fingerprint through an approved process. Native licensed RHEL 8/9 and target Ubuntu/systemd, native database-host watchdog reset/fencing, physical site/WAN failure, live Entra/MFA, real providers and measured pilot/RPO/RTO remain external acceptance. No real 20-server pilot or production readiness is claimed. Missing current PKI/Vault/live safety ledger blocks online recovery; complete compromised-CA recovery is separately fenced and offline.

Source references: current code and tests; README; authentication, security, architecture, HA, API, managed-enforcement, policy-signing, Linux, source-set and capacity runbooks; agent sample and installer. See `docs/release-0.6.md` for the release/evidence summary.

<sub>Created by Pratik Srivastava</sub>
