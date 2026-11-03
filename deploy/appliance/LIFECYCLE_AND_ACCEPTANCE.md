# Internal identity, recovery and native acceptance

Internal PostgreSQL/etcd/Patroni trust is separate from endpoint enrollment and
public HTTPS trust. Registered nodes receive 90-day leaves; authenticated
reconciliation renews the same registered key/CA when 30 days remain. New leaves
cover only the exact node IP/ID and local appliance aliases. Expiry, issuer,
key, SAN and TLS client/server usages are verified; there is no insecure TLS
fallback. Private cross-process locks prevent first-boot workers from minting
different internal issuers, synchronization seeds or node identities.
Missing or invalid registered identity/authority pointers never generate
replacement trust. Active profiles, issued-node caches, retained signing seeds
and a persistent CA/sync marker trigger matching protected-state recovery.

The fixed `internal-tls` manager protocol persists prepare, activate, verify and
commit phases. It updates only owned leaf files, signals Patroni/PostgreSQL,
restarts only an already-running router and proves the exact new fingerprint on
fresh etcd client/peer, PostgreSQL and Patroni TLS connections. etcd loads its
certificate on new connections. Patroni HTTPS reload is asynchronous, so both
forward proof and rollback wait boundedly for the exact fingerprint. An ordinary
configure cannot replace internal trust or the registered key. A failed new
leaf restores and verifies the previous leaf only while that old identity is
still valid. Otherwise recovery retains the new valid leaf and resumes forward.
Stopped services stay stopped; their outcome is **staged**, not runtime verified.
Pending identity transactions block unrelated appliance mutations.

Suspension requires a fresh, exact typed review. It denies password resume,
synchronization and renewal, and removes the member from web routing. It neither
removes a fixed quorum voter nor revokes copies of credentials already held by
that member. Controllers hold highly trusted cluster material: CRL-only
revocation cannot securely remove a compromised CA holder. Secure decommission
is explicitly gated on fenced offline recovery, internal CA/sync/database-secret
replacement and a newly verified fixed quorum. Live cross-CA rotation is not
silently implemented. When the CA has fewer than 120 days remaining, new leaf
issuance blocks for reviewed offline issuer recovery.

The fixed `restore-databases` action is the **host staging component** of the
reviewed controller recovery coordinator. It verifies both original namespace
markers are `FENCED_RECOVERY` for the exact recovery ID/fence digest and that the
new epoch is higher. Preparation adds only derived target database HBA entries.
The observed primary creates absent, empty `prthak_restore_<32hex>_metadata` and
`..._traffic` databases owned by the existing restricted application roles. A
lost creation reply can adopt only an exactly bound empty candidate. A foreign
or populated candidate is refused. The helper never accepts SQL, archive paths,
database names, DSNs or passwords from the request.

The controller coordinator validates the immutable backup and performs
`pg_restore --no-owner --no-privileges --single-transaction --exit-on-error` as
the non-superuser application owners. It verifies complete data/schema safety
overlays, new namespace identity/epoch and all controller protected profile ACKs.
Only then may the manager finalize the derived database names. It makes fresh
verified TLS/application-owner connections and preserves the original databases
and their old HBA entries, allowing the source recovery ledger to reconnect.
It does not stop controller containers, drop/overwrite old databases, unfence
source writers, rotate secrets or claim a complete deployment restore by itself.
Interrupted phases resume their exact private journal; another restore cannot
silently replace a pending operation.

## Reproducible disposable wiring checks

These commands build from a public-source allowlist. Their generated private
credentials remain in disposable named volumes, with internal networks, no host
ports, no host directory/socket/device mounts and cleanup on completion.

```sh
python3 deploy/appliance/build_validation_images.py --context YOUR_PRIVATE_CONTEXT
python3 deploy/appliance/validate_cluster.py --context YOUR_PRIVATE_CONTEXT --internal-tls
python3 deploy/appliance/validate_cluster.py --context YOUR_PRIVATE_CONTEXT --restore
```

The internal-TLS check exercised actual etcd 2379/2380, PostgreSQL 5432 and
Patroni 8008 leaf replacement on all three voters, injected verification failure
and old-leaf rollback, durable commit/retry and surviving one-primary/two-replica
quorum. The restore check exercised actual source fences, primary-only empty
creation, restricted-owner custom-dump restore, exact new namespace readback and
retained originals. The test-only fixed mTLS bridge replaces Docker exec/signals;
the service TLS and SQL operations are real. This host staging test does not
substitute for the controller supervisor/profile coordination test.

Only generated fixture Patroni configurations turn watchdog **off**. Production
rendering and start guards keep it **required**. These tests do not certify
hardware watchdogs, real site loss, RHEL/SELinux policy or fleet-scale load.

## Infrastructure acceptance before a pilot

Use a dedicated three-site lab with the intended disks, network, operating
systems, watchdog device and fencing/power controls. Preserve a verified backup,
matching PKI/vault/profiles and a tested independent recovery path. Set measurable
RPO/RTO objectives and nominate an independent reviewer before injecting faults.

The collector is read-only. It never opens/arms/feeds the watchdog, injects a
fault, changes networking or approves production. Run it on every database voter
before testing and after each relevant checkpoint:

```sh
sudo python3 deploy/appliance/acceptance.py --scenario baseline \
  --output /var/tmp/prthak-acceptance/noida-before.json
sudo python3 deploy/appliance/acceptance.py --scenario watchdog_reset \
  --before /var/tmp/prthak-acceptance/noida-before.json \
  --external-evidence /var/tmp/prthak-acceptance/reset-console.log \
  --output /var/tmp/prthak-acceptance/noida-after-reset.json
```

Record concurrent acknowledged writes and independent probes of **every** old
and candidate primary throughout each fault. Use approved lab tooling to test:

1. Loss of one controller while the same endpoint origin remains reachable.
2. PostgreSQL process loss and recovery without independent writable copies.
3. Patroni freeze while PostgreSQL can still answer: prove the real watchdog
   resets/fences the old writer before any successor accepts writes. A clean
   service stop or paused whole database container is not this test.
4. Minority and majority site/network partitions, including a live isolated old
   primary. The minority must never remain an independent writable primary.
5. Complete loss of each single site, then rejoin/catch-up without force-promote,
   unsafe rewind, lost acknowledged writes or disabled certificate validation.
6. A restore drill with both databases, matching protected configuration/PKI,
   durable writer fences, new epoch/profiles and endpoint policy continuity.

Bind before/after evidence by deployment identity and hashes; the watchdog reset
checkpoint additionally checks that the same victim has a new kernel boot ID.
Attach actual console/power/network logs and write-probe results. The collector
always reports `hardware_fencing_validated=false` and `production_approved=false`:
a healthy after-snapshot alone cannot prove absence of split brain during a
fault. The independent reviewer must reconcile the complete timeline, observed
RPO/RTO, root cause and recovery results before approving the 20-server pilot.

Primary behavior references: [etcd TLS reload](https://etcd.io/docs/v3.6/op-guide/security/),
[Patroni reload](https://patroni.readthedocs.io/en/latest/rest_api.html),
[PostgreSQL 16 TLS reload](https://www.postgresql.org/docs/16/ssl-tcp.html), and
[PostgreSQL restore privileges](https://www.postgresql.org/docs/16/app-pgrestore.html).

<sub>Created by Pratik Srivastava</sub>
