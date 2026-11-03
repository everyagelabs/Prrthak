# Appliance image hardening and database compatibility

This record covers candidate **v0.16.0-pilot.1**. The prior candidate retained 1,102 vulnerability rows across the controller, database, router and etcd images, including 218 HIGH and two CRITICAL rows. Most came from Debian packages with no reported vendor fix. The earlier reports remain historical evidence; they are not relabeled as new scans.

## What changed

The controller and database now use the digest-pinned official **PostgreSQL 16.15 / Alpine 3.24** base. The controller runs Alpine's Python 3.14 with the same application requirements, including SAML/xmlsec/lxml. Its PostgreSQL dump/restore clients remain major version 16. The database retains PostgreSQL 16 and Patroni; UID/GID 999, the configured PostgreSQL binary path, nonroot execution and protected persistent storage are preserved. The controller still runs as UID 10001.

The router uses the digest-pinned supported **HAProxy 3.2 / Alpine 3.24** image. The quorum service is a **Prṛthak security rebuild of etcd 3.6.16**, not a claim that the upstream release image changed. Its exact upstream commit, source archive checksum, builder/runtime digests and dependency changes are recorded in [etcd build inputs](../deploy/appliance/etcd-build-inputs.json). All three binaries—etcd, etcdctl and etcdutl—retain their Go build/module metadata and run as UID 10002.

The etcd rebuild changes `golang.org/x/net` to `v0.62.0` and `golang.org/x/crypto` to `v0.58.1-0.20261009181718-2f1f834330b2`. These bind the reviewed fixes, including [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932), without altering the upstream consensus/storage source. The installer builds this pinned recipe and records the resulting immutable image ID for service activation. No administrator compiles or edits configuration manually.

## Database migration boundary

**A Debian/glibc PostgreSQL data directory must not be reused physically by the Alpine/musl database runtime.** Locale/collation behavior can differ even when PostgreSQL's major version is unchanged; a clean image scan is not evidence of index or collation compatibility. PostgreSQL documents the effects of [collation version changes](https://www.postgresql.org/docs/16/collation.html#COLLATION-MANAGING-VERSIONS).

For an existing appliance, create and download a verified **logical backup through GUI Backups while the old appliance is running**. Preserve that appliance and its release for recovery. Prepare a fresh appliance/storage using the normal one-command installer and GUI configuration, then use **GUI Recovery** to inspect, review and restore the logical archive. Review the restored inventory and policies before directing endpoints or the LB to it. Do not replace old database images or copy their physical data directories into the new runtime. An existing HA cluster requires a coordinated logical migration of its database voters; mixing libc runtimes is not a rolling physical upgrade.

The fixed manager refuses unmarked nonempty database storage before image/service activation and reports the reason in platform status. Its runtime marker lives outside PGDATA so initialization still receives an empty directory. Refusal preserves existing files; it does not initialize, delete or convert them. New database-voter membership also requires the matching runtime profile from authenticated controller/manager state. A user-supplied GUI label cannot establish database compatibility. Native SSH-managed database deployment remains its separate workflow and is not mislabeled as an Alpine appliance.

GUI Recovery deliberately preserves the destination's current authentication and trust/security identity. It is not automatic migration of old enrollment certificates, CA keys, DNS/LB origins or IdP registrations. Review those identities and the supported endpoint configuration/trust transition before moving an existing estate; keep the original controller available for rollback.

Fresh pilot installations use the new runtime directly. The deferred DC deployment/native OS work is still required before using real infrastructure; the compatibility guard is not a claim that a live organization migration has been performed.

## Scan and test evidence

CI builds and scans all four complete images with the same digest-pinned Trivy scanner. It preserves full JSON evidence and fails on **every vulnerability row**, including LOW, UNKNOWN and unfixed advisories. Missing, malformed, end-of-life or incomplete image reports also block the gate. There are no severity filters, advisory allowlists, ignore-unfixed flags, VEX overrides or package/build-metadata removal to obtain a passing result.

The [public scan summary](../output/security/appliance-0.16-scan-summary.json) records each exact ARM64 image index, scanned configuration digest, verified filesystem binding, package-inventory count, raw-report hash, scanner and vulnerability-database version. Each of the four images reports **zero advisory rows**. Final runtime validation is recorded in the [release validation](release-0.16.0-pilot.1.md). A zero-finding scan is scoped to the actual images, architecture and vulnerability database recorded there; it is not a guarantee against future or unknown vulnerabilities. Tagged-build CI continues to reject new findings on later releases.

The reusable [etcd TLS validator](../deploy/appliance/validate_etcd.py) exercises nonroot/read-only operation, client/peer mTLS, unauthenticated and wrong-CA refusal, quorum operations, leader loss/rejoin and snapshot save/status/restore. Controller, database and router validation additionally covers the required Python imports, signed startup/tamper rejection, verified HTTPS, backups and supported HA operations. Live organization IdP, native RHEL/Ubuntu and physical DC acceptance remain deferred.

© 2026 Airtel Payments Bank. All rights reserved.
