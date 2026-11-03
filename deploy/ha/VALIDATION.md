# HA template validation

On 2026-10-30 both profiles passed the official Docker image `haproxy:2.8-alpine`, running HAProxy **2.8.31-5260599**. The pulled image digest was:

```text
sha256:4ab80f6d7c64bda25a906840c181e1518a34f856df9f714582a6a4cabb3d38b2
```

The validation containers had no network, no published ports and read-only mounts/filesystem. A temporary generated public CA was mounted at the configured CA path. The test command was equivalent to:

```sh
docker run --rm --network none --read-only \
  -v /absolute/test/ca.pem:/etc/haproxy/prthak-controller-ca.pem:ro \
  -v /absolute/repo/deploy/ha/haproxy-active-active.cfg.example:/usr/local/etc/haproxy/haproxy.cfg:ro \
  haproxy:2.8-alpine haproxy -c -f /usr/local/etc/haproxy/haproxy.cfg
```

The same command with `haproxy-dc-dr.cfg.example` also returned:

```text
Configuration file is valid
```

This is syntax/trust-file parsing verification. Actual backend TLS/HTTP connectivity, client-certificate passthrough, LB failover, database promotion and site loss were not exercised by these containers. Replace all placeholders and validate the final configuration on the installed target package before rollout. See `docs/ha.md` for the application/PostgreSQL acceptance coverage and deployment drills.

<sub>Created by Pratik Srivastava</sub>
