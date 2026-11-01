# Synthetic 5,000-server storage/compiler validation

On 30 October 2026, `scripts/benchmark-fleet.py` completed against a disposable SQLite store and isolated PostgreSQL 16 databases. Both runs used 5,000 synthetic inventory records, a 20-member source group, four explicitly seeded DC/cloud catalogue entries, eight request workers and 5,000 operations per measured path. These are direct controller storage calls, without HTTP or mTLS.

| Check | SQLite | PostgreSQL 16 |
| --- | ---: | ---: |
| Initial effective-policy compile | 0.261 s | 0.457 s |
| Unchanged compile; no version increments | 0.098 s | 0.114 s |
| One source IP change; all 5,000 affected bundles updated | 0.263 s | 0.535 s |
| Exact two-step review of all 5,000 synthetic targets | 0.808 s | 2.376 s |
| Authorized policy assignments | 3,488.170/s | 768.160/s |
| Policy assignment p95 | 3.644 ms | 15.086 ms |
| Cached inventory heartbeats | 737.790/s | 383.250/s |
| Heartbeat p95 | 32.374 ms | 36.178 ms |

The test asserted 10,000 retained bundle-history rows after initial compilation and source-change fan-out. Source selector resolution uses tag indexes and a per-compilation cache. Unchanged bundles are not rewritten. PostgreSQL policy reads use read-only MVCC transactions instead of taking the global writer advisory lock. Agent authorization reads indexed per-host approval rows; it never parses the entire fleet rollout preview on every poll. This benchmark exposed and led to removal of that repeated whole-fleet JSON parsing.

At a 60-second control interval, 5,000 agents produce about 83.33 sync cycles per second before jitter. The current agent reports before its policy check and again after processing, so budget approximately **166.67 report calls and 83.33 policy checks per second**, plus discovery/learning/other work. The table measures each storage path separately; it does not establish combined end-to-end capacity or production headroom.

The machine used ARM64 Python 3.12.14. PostgreSQL used the project's local Unix socket with `max_connections=40` and `shared_buffers=32MB`. Host cache, storage, CPU contention and database configuration affect results. Reproduce on deployment hardware before sizing controllers.

```sh
python3 scripts/benchmark-fleet.py --servers 5000 --operations 5000
```

For PostgreSQL, install the optional driver and provide `SEG_TEST_DATABASE_URL` and `SEG_TEST_TRAFFIC_DATABASE_URL` pointing to **new empty databases named `prthak_test_scale_*`**. The script refuses populated metadata stores or other database names. It does not connect to real endpoints. Use `--backend postgresql` and optionally `--output /path/to/result.json`.

The run excludes network latency, TLS handshakes, 5,000 real processes, endpoint rule capacity, burst enrollment, temporary flow ingestion, simultaneous sustained traffic, long-duration soak, dashboard browser performance, database promotion and multi-site failure. The 20-server pilot and 5,000-server deployment remain unstarted. This is a measured development baseline, not fleet certification.
