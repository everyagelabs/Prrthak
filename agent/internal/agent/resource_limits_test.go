package agent

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestAgentResourceDropInRequiresExactOwnedTemplate(t *testing.T) {
	page := int64(os.Getpagesize())
	for _, requireVolume := range []bool{false, true} {
		expected := agentResourceLimits{cpuPercent: 40, memory: agentMemoryLimit / page * page, volume: requireVolume, legacy: requireVolume}
		raw := expected.render()
		got, err := parseAgentResourceLimits(raw)
		if err != nil || got != expected {
			t.Fatalf("installer drop-in rejected: got %+v, %v", got, err)
		}
		for _, unowned := range []string{
			string(raw) + "ExecStartPre=/bin/false\n",
			strings.Replace(string(raw), "40%", "41%", 1),
			strings.Replace(string(raw), "CPUQuota=", "CPUWeight=", 1),
			strings.Replace(string(raw), "--verify-agent-resource-limits", "--run-agent-upgrade", 1),
		} {
			if _, err = parseAgentResourceLimits([]byte(unowned)); err == nil {
				t.Fatalf("modified drop-in accepted: %q", unowned)
			}
		}
	}
}

func TestAgentResourceLegacyCgroupRequiresActualCPUAndMemoryMembership(t *testing.T) {
	mounts := "31 29 0:27 / /sys/fs/cgroup/cpu,cpuacct rw - cgroup cgroup rw,cpu,cpuacct\n" +
		"32 29 0:28 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n"
	cpu, memory := legacyAgentControllerMounts(mounts)
	if cpu != "/sys/fs/cgroup/cpu,cpuacct" || memory != "/sys/fs/cgroup/memory" {
		t.Fatalf("legacy controller paths: %q and %q", cpu, memory)
	}
	group := "/system.slice/seg-agent.service"
	bound := "10:cpu,cpuacct:" + group + "\n8:memory:" + group + "\n"
	if !legacyAgentCgroupMembership(bound, group) {
		t.Fatal("exact legacy memberships were not recognized")
	}
	unbound := "10:cpu,cpuacct:" + group + "\n8:memory:/system.slice/another.service\n"
	if legacyAgentCgroupMembership(unbound, group) {
		t.Fatal("another service's memory cgroup was accepted")
	}
}

func TestAgentResourceCPUUsesEveryOnlineLogicalCPUAndChecksEffectiveQuota(t *testing.T) {
	count, err := parseOnlineResourceCPUs("0-3,8,10-12\n")
	if err != nil || count != 8 {
		t.Fatalf("online CPU count: %d %v", count, err)
	}
	for _, invalid := range []string{"", "0-3,3", "0-2,1-2", "3-0", "0-1000000"} {
		if _, err = parseOnlineResourceCPUs(invalid); err == nil {
			t.Fatalf("invalid online CPU list accepted: %q", invalid)
		}
	}
	limits := agentResourceLimits{cpuPercent: count * 5, memory: 1999998976}
	if err = verifyAgentCgroupLimits("40000 100000\n", "1999998976\n", limits); err != nil {
		t.Fatal(err)
	}
	for _, values := range [][2]string{
		{"max 100000", "1999998976"},
		{"50000 100000", "1999998976"},
		{"40000 100000", "max"},
		{"40000 100000", "2000000001"},
	} {
		if err = verifyAgentCgroupLimits(values[0], values[1], limits); err == nil {
			t.Fatalf("unsafe active resource values accepted: %v", values)
		}
	}
}

func TestAgentStorageCapRequiresDedicatedFullFilesystemWithoutNestedMounts(t *testing.T) {
	root := "24 0 8:2 / / rw - ext4 /dev/first rw\n"
	dedicated := "32 24 8:3 / /var/lib/seg-agent rw - xfs /dev/second rw\n"
	if !validAgentStateMount(root + dedicated) {
		t.Fatal("dedicated state volume rejected")
	}
	for _, mounts := range []string{
		root,
		root + strings.Replace(dedicated, "8:3 / ", "8:3 /subdir ", 1),
		root + strings.Replace(dedicated, "8:3", "8:2", 1),
		root + dedicated + "36 32 8:4 / /var/lib/seg-agent/spool rw - ext4 /dev/third rw\n",
		root + strings.Replace(dedicated, "xfs", "nfs", 1),
	} {
		if validAgentStateMount(mounts) {
			t.Fatalf("non-dedicated state storage accepted: %q", mounts)
		}
	}
}

func TestAgentUpgradeAcceptsOnlyVerifiedResourceDropIn(t *testing.T) {
	stock := "NeedDaemonReload=no\nFragmentPath=" + upgradeUnit + "\nDropInPaths="
	verified := func() error { return nil }
	if err := checkLoadedAgentUnit(stock+agentResourceDropIn, true, verified); err != nil {
		t.Fatal(err)
	}
	if err := checkLoadedAgentUnit(stock+agentResourceDropIn, false, verified); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"", agentResourceDropIn + " /run/unowned.conf", "/run/unowned.conf"} {
		if err := checkLoadedAgentUnit(stock+value, true, verified); err == nil {
			t.Fatalf("unverified resource setup accepted: %q", value)
		}
	}
	if err := checkLoadedAgentUnit(stock+agentResourceDropIn, false, func() error { return errors.New("owner changed") }); err == nil {
		t.Fatal("a resource drop-in path passed without trusted bytes")
	}
}
