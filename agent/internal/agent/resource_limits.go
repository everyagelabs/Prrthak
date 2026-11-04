package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

const (
	agentResourceDropIn = "/etc/systemd/system/seg-agent.service.d/50-prthak-resource-limits.conf"
	agentCgroupRoot     = "/sys/fs/cgroup"
	agentStateVolume    = "/var/lib/seg-agent"
	agentMemoryLimit    = 2_000_000_000
	agentStorageLimit   = 10_000_000_000
)

type agentResourceLimits struct {
	cpuPercent int64
	memory     int64
	volume     bool
	legacy     bool
}

func (limits agentResourceLimits) render() []byte {
	unit, argument := "", ""
	if limits.volume {
		unit = "[Unit]\nRequiresMountsFor=" + agentStateVolume + "\n\n"
		argument = " --require-state-volume"
	}
	memoryDirective := "MemoryMax"
	if limits.legacy {
		memoryDirective = "MemoryLimit"
	}
	return []byte(fmt.Sprintf("%s[Service]\nCPUQuota=%d%%\n%s=%d\nExecStartPre=+%s --verify-agent-resource-limits%s\n",
		unit, limits.cpuPercent, memoryDirective, limits.memory, upgradeHelper, argument))
}

var agentResourceValues = regexp.MustCompile(`(?m)^CPUQuota=([1-9][0-9]{0,7})%\nMemory(Max|Limit)=([1-9][0-9]{0,9})$`)

func parseAgentResourceLimits(raw []byte) (agentResourceLimits, error) {
	var limits agentResourceLimits
	match := agentResourceValues.FindSubmatch(raw)
	if len(match) == 4 {
		limits.cpuPercent, _ = strconv.ParseInt(string(match[1]), 10, 64)
		limits.memory, _ = strconv.ParseInt(string(match[3]), 10, 64)
		limits.legacy = string(match[2]) == "Limit"
		limits.volume = bytes.HasPrefix(raw, []byte("[Unit]\n"))
	}
	if limits.cpuPercent < 5 || limits.cpuPercent%5 != 0 || limits.memory > agentMemoryLimit ||
		limits.memory <= agentMemoryLimit-int64(os.Getpagesize()) || !bytes.Equal(raw, limits.render()) {
		return agentResourceLimits{}, errors.New("the Prthak resource drop-in is not an exact installer-owned configuration")
	}
	return limits, nil
}

func readAgentLimitFile(path string, limit int64) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if int64(len(raw)) > limit {
		return "", errors.New("resource control file exceeds its read bound")
	}
	return string(raw), err
}

func parseOnlineResourceCPUs(raw string) (int64, error) {
	var count int64
	previous := int64(-1)
	for _, item := range strings.Split(strings.TrimSpace(raw), ",") {
		firstText, lastText, span := strings.Cut(item, "-")
		first, err := strconv.ParseInt(firstText, 10, 32)
		if err != nil || first <= previous {
			return 0, errors.New("online Linux CPU list is invalid")
		}
		last := first
		if span {
			last, err = strconv.ParseInt(lastText, 10, 32)
			if err != nil || last < first {
				return 0, errors.New("online Linux CPU range is invalid")
			}
		}
		count += last - first + 1
		previous = last
	}
	if count < 1 || count > 1_000_000 {
		return 0, errors.New("online Linux CPU count is outside the supported bound")
	}
	return count, nil
}

func currentAgentResourceLimits(volume bool) (agentResourceLimits, error) {
	if runtime.GOOS != "linux" {
		return agentResourceLimits{}, errors.New("agent resource limits require native Linux systemd")
	}
	controllers, err := readAgentLimitFile(filepath.Join(agentCgroupRoot, "cgroup.controllers"), 4096)
	fields := " " + strings.Join(strings.Fields(controllers), " ") + " "
	legacy := false
	if err == nil {
		if !strings.Contains(fields, " cpu ") || !strings.Contains(fields, " memory ") {
			return agentResourceLimits{}, errors.New("resource limits require enabled cgroup v2 CPU and memory controllers")
		}
	} else {
		if _, _, err = agentLegacyControllerMounts(); err != nil {
			return agentResourceLimits{}, err
		}
		legacy = true
	}
	online, err := readAgentLimitFile("/sys/devices/system/cpu/online", 65536)
	if err != nil {
		return agentResourceLimits{}, errors.New("host online logical CPU count is unavailable")
	}
	count, err := parseOnlineResourceCPUs(online)
	if err != nil {
		return agentResourceLimits{}, err
	}
	page := int64(os.Getpagesize())
	return agentResourceLimits{cpuPercent: 5 * count, memory: agentMemoryLimit / page * page, volume: volume, legacy: legacy}, nil
}

func readOwnedAgentResourceLimits() (agentResourceLimits, error) {
	raw, err := runtimeRead(agentResourceDropIn, 4096, 0)
	if err != nil {
		return agentResourceLimits{}, err
	}
	return parseAgentResourceLimits(raw)
}

func configuredAgentResourceLimits() (agentResourceLimits, error) {
	configured, err := readOwnedAgentResourceLimits()
	if err != nil {
		return configured, err
	}
	expected, err := currentAgentResourceLimits(configured.volume)
	if err != nil {
		return configured, err
	}
	if configured != expected {
		return configured, errors.New("host CPU count, page size or cgroup hierarchy changed; reapply the reviewed agent resource limits")
	}
	return configured, nil
}

// PrepareAgentResourceLimits returns the only accepted drop-in template.
// The installer validates the bundle before it writes the returned bytes.
func PrepareAgentResourceLimits(ctx context.Context, volume bool) ([]byte, error) {
	if _, err := os.Lstat(agentResourceDropIn); err == nil {
		existing, err := readOwnedAgentResourceLimits()
		if err != nil {
			return nil, err
		}
		volume = volume || existing.volume // A reinstall never silently drops storage protection.
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	limits, err := currentAgentResourceLimits(volume)
	if err != nil {
		return nil, err
	}
	if volume {
		if err := verifyAgentStateVolume(ctx); err != nil {
			return nil, err
		}
	}
	return limits.render(), nil
}

func validAgentStateMount(mounts string) bool {
	device := ""
	lines := strings.Split(mounts, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		if strings.HasPrefix(fields[4], agentStateVolume+"/") {
			return false
		}
		if fields[4] == agentStateVolume {
			separator := strings.Index(line, " - ")
			if device != "" || fields[3] != "/" || separator < 0 {
				return false
			}
			fs := strings.Fields(line[separator+3:])
			if len(fs) < 1 || (fs[0] != "ext4" && fs[0] != "xfs") {
				return false
			}
			device = fields[2]
		}
	}
	if device == "" {
		return false
	}
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 5 && fields[2] == device && fields[4] != agentStateVolume {
			return false
		}
	}
	return true
}

func verifyAgentStateVolume(ctx context.Context) error {
	mounts, err := readAgentLimitFile("/proc/self/mountinfo", 1<<20)
	if err != nil || !validAgentStateMount(mounts) {
		return errors.New("strict storage limits require a dedicated ext4 or XFS filesystem mounted at /var/lib/seg-agent without nested mounts")
	}
	output, err := exec.CommandContext(ctx, "/usr/bin/stat", "--file-system", "--format=%S %b", agentStateVolume).Output()
	fields := strings.Fields(string(output))
	if err != nil || len(fields) != 2 {
		return errors.New("dedicated agent filesystem capacity could not be verified")
	}
	block, blockErr := strconv.ParseUint(fields[0], 10, 64)
	count, countErr := strconv.ParseUint(fields[1], 10, 64)
	if blockErr != nil || countErr != nil || block == 0 || count == 0 || count > agentStorageLimit/block {
		return errors.New("the dedicated agent filesystem must have a verified capacity of at most 10,000,000,000 bytes")
	}
	return nil
}

func verifyAgentCgroupLimits(cpu, memory string, limits agentResourceLimits) error {
	fields := strings.Fields(cpu)
	if len(fields) != 2 {
		return errors.New("active agent CPU quota could not be verified")
	}
	quota, quotaErr := strconv.ParseInt(fields[0], 10, 64)
	period, periodErr := strconv.ParseInt(fields[1], 10, 64)
	if quotaErr != nil || periodErr != nil || period < 1000 || period > 1_000_000 ||
		quota <= 0 || quota > 1_000_000_000_000 || quota*100 != period*limits.cpuPercent {
		return errors.New("active agent CPU quota differs from the reviewed limit")
	}
	actualMemory, err := strconv.ParseInt(strings.TrimSpace(memory), 10, 64)
	if err != nil || actualMemory != limits.memory {
		return errors.New("active agent memory cap differs from the reviewed limit")
	}
	return nil
}

func legacyAgentControllerMounts(mounts string) (cpu, memory string) {
	for _, line := range strings.Split(mounts, "\n") {
		before, after, found := strings.Cut(line, " - ")
		mount, fs := strings.Fields(before), strings.Fields(after)
		if !found || len(mount) < 6 || len(fs) != 3 || fs[0] != "cgroup" || mount[3] != "/" ||
			filepath.Dir(mount[4]) != agentCgroupRoot || strings.Contains(mount[4], "\\") {
			continue
		}
		for _, controller := range strings.Split(fs[2], ",") {
			switch controller {
			case "cpu":
				cpu = mount[4]
			case "memory":
				memory = mount[4]
			}
		}
	}
	return cpu, memory
}

func agentLegacyControllerMounts() (string, string, error) {
	raw, err := readAgentLimitFile("/proc/self/mountinfo", 1<<20)
	cpu, memory := legacyAgentControllerMounts(raw)
	if err != nil || cpu == "" || memory == "" {
		return "", "", errors.New("agent resource limits require native cgroup CPU and memory controllers")
	}
	return cpu, memory, nil
}

func legacyAgentCgroupMembership(raw, expected string) bool {
	var cpu, memory bool
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.SplitN(line, ":", 3)
		if len(fields) != 3 || fields[2] != expected {
			continue
		}
		for _, controller := range strings.Split(fields[1], ",") {
			cpu = cpu || controller == "cpu"
			memory = memory || controller == "memory"
		}
	}
	return cpu && memory
}

func verifyLegacyAgentCgroupLimits(membership, group string, limits agentResourceLimits) error {
	if !legacyAgentCgroupMembership(membership, group) {
		return errors.New("the resource guard is not in the expected agent CPU and memory cgroups")
	}
	cpuRoot, memoryRoot, err := agentLegacyControllerMounts()
	if err != nil {
		return err
	}
	cpu, memory := filepath.Join(cpuRoot, group), filepath.Join(memoryRoot, group)
	quota, quotaErr := readAgentLimitFile(filepath.Join(cpu, "cpu.cfs_quota_us"), 128)
	period, periodErr := readAgentLimitFile(filepath.Join(cpu, "cpu.cfs_period_us"), 128)
	cap, capErr := readAgentLimitFile(filepath.Join(memory, "memory.limit_in_bytes"), 128)
	hierarchy, hierarchyErr := readAgentLimitFile(filepath.Join(memory, "memory.use_hierarchy"), 128)
	if quotaErr != nil || periodErr != nil || capErr != nil || hierarchyErr != nil || strings.TrimSpace(hierarchy) != "1" {
		return errors.New("native agent cgroup v1 CPU or hierarchical memory limits are unavailable")
	}
	return verifyAgentCgroupLimits(strings.TrimSpace(quota)+" "+strings.TrimSpace(period), cap, limits)
}

// VerifyAgentResourceLimits is the signed ExecStartPre guard, running in the
// agent service's own cgroup before collection or policy work is allowed.
func VerifyAgentResourceLimits(ctx context.Context, requireVolume bool) error {
	// Validate the canonical root helper, its independent signed manifest and
	// the stock service bytes even when no managed upgrade is pending.
	if _, _, _, err := agentUpgradeWorkerConfig(); err != nil {
		return err
	}
	limits, err := configuredAgentResourceLimits()
	if err != nil {
		return err
	}
	if limits.volume != requireVolume {
		return errors.New("agent storage guard differs from the reviewed configuration")
	}
	raw, err := readAgentLimitFile("/proc/self/cgroup", 65536)
	if err != nil {
		return err
	}
	group := "/system.slice/" + upgradeUnitName
	if limits.legacy {
		if err = verifyLegacyAgentCgroupLimits(raw, group, limits); err != nil {
			return err
		}
	} else {
		if strings.TrimSpace(raw) != "0::"+group {
			return errors.New("the resource guard is not running in the expected native agent cgroup")
		}
		path := filepath.Join(agentCgroupRoot, group)
		cpu, cpuErr := readAgentLimitFile(filepath.Join(path, "cpu.max"), 128)
		memory, memoryErr := readAgentLimitFile(filepath.Join(path, "memory.max"), 128)
		if cpuErr != nil || memoryErr != nil {
			return errors.New("native agent cgroup v2 CPU/memory controls are unavailable")
		}
		if err = verifyAgentCgroupLimits(cpu, memory, limits); err != nil {
			return err
		}
	}
	if limits.volume {
		return verifyAgentStateVolume(ctx)
	}
	return nil
}
