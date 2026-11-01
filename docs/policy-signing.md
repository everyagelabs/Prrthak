# Independent assignment and release signatures

Controller assignments use Ed25519 keys separated from HTTPS and issuing PKI.
Every signed envelope binds the deployment ID, endpoint ID, policy version,
source lists, enforcement authority, learning authority, imported changes,
discovery/learning assignments and polling intent. The endpoint verifies the
signature and compares the decoded full typed assignment before caching or
mutating. Mutating endpoints without valid pinned signing trust report a
protection blocker.

Signatures use the domain `prthak-policy-assignment-v1`, stable five-minute
issuance buckets and 30-minute validity. Conditional policy responses include
the signature in their ETag, so a connected agent refreshes before expiry.
Controller outages preserve already committed firewall rules and do not allow
unsigned replacement policy.

The endpoint also binds every assignment, including cached 304 responses, to its
actual enrolled certificate CN. The complete unsigned assignment carries a
durable per-endpoint `assignment_generation` and `assignment_digest`, separately
from the effective firewall version. Unchanged polling reads the existing guard;
changed assignments publish under the shared database writer serialization.
Received lower or divergent generations and reactivation/prolongation of a
stopped learning session are rejected. Recovery retains the current
`assignment_guard:` high-water records; it does not rewind these counters with
an older archive. A cold first publication or changed assignment may wait for
that writer; only an already published unchanged assignment has the read-only
fast path. Deploy the updated controller before the corresponding 0.6 agents.

The public trust manifest contains `deployment_id` and up to 8 pinned key-ID /
base64 Ed25519 public-key pairs. Operator-provided config wins; otherwise an
authenticated enrollment may pin the initial manifest in
`STATE_DIR/policy-signing-trust.json`. Existing trust is never silently replaced
by a later TLS/enrollment response. Public-key rotation requires explicit
operator distribution of an overlap manifest, verifying adoption, changing the
signer, then retiring the old key. Obtain the initial public trust through an
independent trusted channel for separation from controller TLS enrollment.

Offline signing keys are 32-byte private seeds, protected mode 0600. HA controllers
need the same deployment signing authority; provisioning unrelated keys per
controller would cause failover rejection. Keep offline backups separately from
database archives. Controller-specific configuration/export and reviewed key
distribution remain administrative operations; a certificate change is not
authorization to trust a new assignment signer.

For separation from a compromised controller process, select the optional
`OfflinePolicySigner` provider: it has only public trust and exact independently
signed artifacts, with no private seed or online fallback. Export and review the
complete unsigned assignment on an approved administration path, then run
`scripts/sign-assignment.py` on an isolated signing workstation with the exact
`SIGN REVIEWED ASSIGNMENT` confirmation. Transfer its protected artifact through
the approved process. Changed sources, authorities, polling intent or expired
validity require a fresh artifact. Online signing with a separate TLS key alone
does not protect against a controller that can access that signing seed.

## Signed Linux packages

Provision a dedicated release-signing key outside source control. To create a
new key explicitly and sign existing archives:

```sh
python3 scripts/sign-release.py --key-file /protected/release.seed --create-key \
  dist/prthak-agent-0.6.0-linux-amd64.tar.gz \
  dist/prthak-agent-0.6.0-linux-arm64.tar.gz
```

For repeat builds set `PRTHAK_RELEASE_SIGNING_KEY_FILE=/protected/release.seed`
before `scripts/package-agent.py`. Without that key the packager labels its
outputs as unsigned lab packages. Never generate a new ephemeral key on each
build and treat the adjacent public file as trusted automatically.

Before extraction/install, on an administrator's workstation with Python and
cryptography, use an independently obtained public manifest:

```sh
python3 scripts/verify-release.py --public-trust-file /trusted/release-public.json \
  --signature dist/prthak-agent-0.6.0-linux-amd64.tar.gz.signature.json \
  dist/prthak-agent-0.6.0-linux-amd64.tar.gz
```

The verifier binds exact archive bytes, size and filename to the
`prthak-package-manifest-v1` signature. A changed archive, unknown key or writable
public trust file fails before extraction. The public verifier is not an excuse
to execute an unverified newly downloaded agent binary.
