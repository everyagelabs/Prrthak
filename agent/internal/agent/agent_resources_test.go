package agent

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestAgentResourceCPUUsesWholeHostCapacity(t *testing.T) {
	sampler := agentResourceSampler{}
	at := time.Now()
	if sampler.cpuSample(1_000_000, 8, at) != nil {
		t.Fatal("a first CPU reading without a baseline was reported")
	}
	// 19.2 CPU-seconds during 60 elapsed seconds on eight CPUs is 4%.
	sample := sampler.cpuSample(20_200_000, 8, at.Add(time.Minute))
	if sample == nil || sample.Value != 400 {
		t.Fatalf("expected 4%% of the whole host, got %+v", sample)
	}
	if sampler.cpuSample(21_000_000, 4, at.Add(2*time.Minute)) != nil ||
		sampler.cpuSample(1_000, 4, at.Add(3*time.Minute)) != nil {
		t.Fatal("a changed CPU count or restarted cgroup must reset the baseline")
	}
}

func TestAgentResourceCgroupCountersRequireNativeServiceMembership(t *testing.T) {
	root := t.TempDir()
	group := "system.slice/seg-agent.service"
	for path, value := range map[string]string{
		group + "/cpu.stat":                          "usage_usec 5320\nuser_usec 2320\nsystem_usec 3000\n",
		group + "/memory.current":                    "1599000000\n",
		"cpu,cpuacct/" + group + "/cpuacct.usage":    "8999000\n",
		"memory/" + group + "/memory.usage_in_bytes": "1600000000\n",
	} {
		filename := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cpu, cpuOK, memory, memoryOK := agentCgroupCounters(root, "0::/"+group)
	if !cpuOK || !memoryOK || cpu != 5320 || memory != 1599000000 {
		t.Fatalf("cgroup v2 counters were not measured: %d %t %d %t", cpu, cpuOK, memory, memoryOK)
	}
	cpu, cpuOK, memory, memoryOK = agentCgroupCounters(root, "2:cpu,cpuacct:/"+group+"\n3:memory:/"+group)
	if !cpuOK || !memoryOK || cpu != 8999 || memory != 1600000000 {
		t.Fatalf("cgroup v1 counters were not measured: %d %t %d %t", cpu, cpuOK, memory, memoryOK)
	}
	if _, cpuOK, _, memoryOK = agentCgroupCounters(root, "0::/system.slice/other.service"); cpuOK || memoryOK {
		t.Fatal("a different service cgroup produced resource values")
	}
}

func TestAgentStorageUsesAllocatedBlocksWithoutFollowingLinks(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	file := filepath.Join(root, "spool")
	if err := os.WriteFile(file, make([]byte, 8192), 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Link(file, filepath.Join(root, "same-inode")); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(outside, filepath.Join(root, "other-directory")); err != nil {
		t.Fatal(err)
	}
	expected := uint64(info.Sys().(*syscall.Stat_t).Blocks) * 512
	value, ok := allocatedStateBytes(root, time.Now().Add(time.Second), 3)
	if !ok || value != expected {
		t.Fatalf("expected %d allocated bytes from one file, got %d valid=%t", expected, value, ok)
	}
	if _, ok := allocatedStateBytes(root, time.Now().Add(time.Second), 2); ok {
		t.Fatal("a partial directory measurement was marked valid")
	}
}
