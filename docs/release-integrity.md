# Release integrity and source control

Prṛthak protects installed release bytes with signatures and startup checks. This is integrity protection, not complete code encryption: browser JavaScript is delivered to the browser, and a server's root administrator can replace its operating system or trust anchors.

The Go endpoint is compiled. Controller containers run as a restricted user with a read-only application filesystem. The appliance records the built controller/database image IDs and pins vendor router/quorum image digests. GUI configuration, inventory, policies, PKI and journals live in the protected data root and remain intentionally mutable.

## What startup verifies

- An Ed25519 release manifest binds exact controller modules, dashboard assets and bootstrap bytes. The image bootstrap verifies those bytes **before importing application modules**.
- The host-manager service uses the pinned controller image to check its installed manager hash before starting the privileged process.
- A canonical endpoint installation checks the signed agent binary and systemd unit against separately pinned public release trust. The installer verifies candidate bytes before replacing them and keeps the existing release pin on upgrades.
- Detached archive signatures bind the exact filename, size and SHA-256. Signature verification must use public trust obtained through an independently approved channel. A public key downloaded alongside an untrusted archive does not establish trust.

Checks reject modified bytes, unknown signers, unsafe paths and inappropriate writable files. They do not prevent an authorized root user from replacing the verifier itself. They also do not make learned clients trustworthy or replace firewall approval, drift detection and rollback.

## Candidate signing authority

The 0.14 pilot candidate continues using development public key ID `98ba67b3670c9d3514867d645be89b81`. Its private seed is outside the source tree and Documents; it is never committed, packaged, sent to image builders or stored on deployed controllers. Signing tools reject source-local and known synchronized-folder key locations.

This development authority is **not an organizational offline or hardware signer**. Before production distribution, the release owner must choose and independently approve that authority, protect its private key outside controller hosts, and distribute the public pin through trusted operational tooling. Existing installations must not silently replace their release pin. Online per-deployment policy signing is a separate authority and remains part of the controller's security boundary.

## Traceable publication

The repository CI runs a public-key-only committed-runtime consistency check on every branch/PR run, controller, dashboard, Go race/static checks, installer/integration fixtures, source credential checks, dependency audits and tagged image assessment. The consistency check includes runtime, bootstrap, privileged manager and version metadata so a branding edit cannot silently break signed startup. Tagged build candidates are labelled unsigned and are gated on regression, source-security and image-assessment jobs. No signing seed is kept in CI.

The image report retains advisories without vendor fixes. Its automated gate rejects available high/critical fixes; a passing gate does not mean the images have no advisories. Native OS, live Entra, actual firewall rollback and DC/quorum/fencing acceptance remain separate gates.

External release signing records the clean checkout's commit and exact tag in each detached manifest. A dirty or unknown checkout has no claimed exact source commit. Git probes are bound to the requested checkout, ignoring ambient repository-routing variables. Historical artifacts do not acquire source provenance retroactively.

See [review remediation](review-remediation-0.7.md), [policy signing](policy-signing.md) and [pilot installation](pilot-gui-installation.md).

<sub>Created by Pratik Srivastava</sub>
