# Endpoint agent resource evidence

31 October 2026. These are measurements of the exact existing Linux ARM64 agent binary in one disposable Ubuntu 26.04 container. They are a small passive baseline, not an endpoint sizing guarantee or native RHEL acceptance.

The 95-second run used actual `ss` and firewalld read discovery, enrollment, mTLS and signed policy polling. Simulation was off. The fixture had one loopback listener and an empty policy; enforcement and learning were off. Control/discovery intervals were the default 60/900 seconds. Three reports and two policy checks completed. Ubuntu userspace used the shared validation VM's Linux 6.8 kernel; systemd on a native target host was not exercised.

| Measurement | Observed value |
| --- | ---: |
| Agent median resident memory after startup | 10.42 MiB |
| Agent maximum resident memory / high-water mark | 12.50 MiB |
| Agent plus active read-command helpers, sampled memory peak | 56.79 MiB |
| Agent-only average CPU after startup | 0.046% of one core |
| Agent plus completed read-command helpers, average CPU after startup | 0.216% of one core |
| Agent plus helpers, average CPU including startup across the full run | 1.675% of one core |

The post-startup CPU window was 64.893 seconds; the complete sampled window was 94.946 seconds. CPU percentages are averages against one core, not peak limits. RSS is resident memory, not proportional shared-memory accounting; summing child RSS can count shared pages twice. Sampling can miss short peaks. The Go process's own high-water mark is separate from the sampled process-tree peak. Controller, firewalld and D-Bus daemons, kernel firewall/source-set memory and journal storage are excluded.

The recorder used a wrong report-field key for its optional firewall-state column, leaving that column null. The fixture independently asserted a real successful `firewall-cmd --state` before starting the agent; the null column is not presented as a firewall-state measurement. Full method, binary/image hashes, command assertions and cleanup are in the [probe report](../.local/security-audit/agent-resources.md), [raw measurements](../.local/security-audit/agent-resources.json) and [probe source](../.local/security-audit/agent-resources.py). The temporary image/container and state were removed. No installed host or DC endpoint was changed.

The binaries occupy **7.81 MiB on amd64** and **7.19 MiB on ARM64** on disk. Disk size is different from runtime memory. The current systemd unit has no `CPUQuota`, `MemoryHigh` or `MemoryMax`; the measurements are not enforced limits.

Active traffic learning/log bursts, managed enforcement and rollback, large source sets, outages, long-running behavior and native RHEL 8/9 or Ubuntu systemd hosts remain unmeasured. These require workload-specific profiling before selecting resource limits. Ordinary traffic is filtered by firewalld's kernel rules; the agent does not proxy application packets. Temporary learning adds kernel/journal event processing.

For an agent-process spot check on a target Linux host:

```sh
agent_pid=$(systemctl show --property MainPID --value seg-agent.service)
ps -p "$agent_pid" -o pid,etime,pcpu,rss,args
```

`rss` is KiB and `%CPU` is a process lifetime average. This spot check omits helper processes and does not replace full service/cgroup and learning-load measurements.
