package agent

import (
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const AgentResourceCapability = "agent_resource_usage_v1"

type resourceMeasurement struct {
	Value      uint64    `json:"value"`
	ObservedAt time.Time `json:"observed_at"`
}

type agentResourceUsage struct {
	CPU     *resourceMeasurement `json:"cpu_basis_points,omitempty"`
	Memory  *resourceMeasurement `json:"memory_bytes,omitempty"`
	Storage *resourceMeasurement `json:"storage_bytes,omitempty"`
}

type agentResourceSampler struct {
	lastSample, lastStorage time.Time
	cpuAt                   time.Time
	cpuUsec                 uint64
	cpuCount                int
	current                 agentResourceUsage
}

func (s *agentResourceSampler) sample(stateDir string, at time.Time) *agentResourceUsage {
	if runtime.GOOS != "linux" {
		return nil
	}
	if s.lastSample.IsZero() || at.Sub(s.lastSample) >= time.Minute {
		s.lastSample = at
		s.current.CPU, s.current.Memory = nil, nil
		if membership, err := readProcessCgroup(os.Getpid()); err == nil {
			cpu, cpuOK, memory, memoryOK := agentCgroupCounters("/sys/fs/cgroup", membership)
			if memoryOK {
				s.current.Memory = &resourceMeasurement{Value: memory, ObservedAt: at.UTC()}
			}
			count := onlineCPUCount("/proc/stat")
			if cpuOK && count > 0 {
				s.current.CPU = s.cpuSample(cpu, count, at)
			} else {
				s.cpuAt = time.Time{}
			}
		} else {
			s.cpuAt = time.Time{}
		}
	}
	if s.lastStorage.IsZero() || at.Sub(s.lastStorage) >= 5*time.Minute {
		s.lastStorage = at
		s.current.Storage = nil
		if value, ok := allocatedStateBytes(stateDir, time.Now().Add(250*time.Millisecond), 20000); ok {
			s.current.Storage = &resourceMeasurement{Value: value, ObservedAt: at.UTC()}
		}
	}
	result := s.current
	return &result
}

func (s *agentResourceSampler) cpuSample(usec uint64, count int, at time.Time) *resourceMeasurement {
	previousAt, previousUsec, previousCount := s.cpuAt, s.cpuUsec, s.cpuCount
	s.cpuAt, s.cpuUsec, s.cpuCount = at, usec, count
	if previousAt.IsZero() || previousCount != count || usec < previousUsec || !at.After(previousAt) {
		return nil
	}
	capacity := at.Sub(previousAt).Seconds() * float64(count) * 1_000_000
	basisPoints := math.Round(float64(usec-previousUsec) / capacity * 10_000)
	if basisPoints < 0 || basisPoints > 10_000 {
		return nil
	}
	return &resourceMeasurement{Value: uint64(basisPoints), ObservedAt: at.UTC()}
}

func agentCgroupCounters(root, membership string) (uint64, bool, uint64, bool) {
	var cpu, memory uint64
	var cpuOK, memoryOK bool
	for _, line := range strings.Split(membership, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		group := parts[2]
		if !filepath.IsAbs(group) || filepath.Clean(group) != group || filepath.Base(group) != "seg-agent.service" {
			continue
		}
		group = strings.TrimPrefix(group, "/")
		switch {
		case parts[0] == "0" && parts[1] == "":
			directory := filepath.Join(root, group)
			if data, err := os.ReadFile(filepath.Join(directory, "cpu.stat")); err == nil {
				for _, row := range strings.Split(string(data), "\n") {
					fields := strings.Fields(row)
					if len(fields) == 2 && fields[0] == "usage_usec" {
						value, err := strconv.ParseUint(fields[1], 10, 64)
						cpu, cpuOK = value, err == nil
						break
					}
				}
			}
			if value, ok := resourceCounter(filepath.Join(directory, "memory.current")); ok {
				memory, memoryOK = value, true
			}
		default:
			for _, controller := range strings.Split(parts[1], ",") {
				switch controller {
				case "cpuacct":
					for _, mount := range []string{"cpu,cpuacct", "cpuacct,cpu", "cpuacct"} {
						if value, ok := resourceCounter(filepath.Join(root, mount, group, "cpuacct.usage")); ok {
							cpu, cpuOK = value/1000, true
							break
						}
					}
				case "memory":
					if value, ok := resourceCounter(filepath.Join(root, "memory", group, "memory.usage_in_bytes")); ok {
						memory, memoryOK = value, true
					}
				}
			}
		}
	}
	return cpu, cpuOK, memory, memoryOK
}

func resourceCounter(path string) (uint64, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	return value, err == nil
}

func onlineCPUCount(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	count := 0
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "cpu") {
			break
		}
		if len(line) > 3 && line[3] >= '0' && line[3] <= '9' {
			count++
		}
	}
	return count
}

func allocatedStateBytes(path string, deadline time.Time, maximumEntries int) (uint64, bool) {
	if !filepath.IsAbs(path) || filepath.Clean(path) == "/" {
		return 0, false
	}
	paths := []string{filepath.Clean(path)}
	seen := make(map[[2]uint64]bool)
	var blocks uint64
	for len(paths) > 0 {
		if time.Now().After(deadline) {
			return 0, false
		}
		next := paths[len(paths)-1]
		paths = paths[:len(paths)-1]
		fd, err := syscall.Open(next, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if os.IsNotExist(err) && next != filepath.Clean(path) {
			continue
		}
		if err != nil {
			return 0, false
		}
		directory := os.NewFile(uintptr(fd), next)
		for {
			entries, err := directory.ReadDir(64)
			if err != nil && !errors.Is(err, io.EOF) {
				directory.Close()
				return 0, false
			}
			for _, entry := range entries {
				maximumEntries--
				if maximumEntries < 0 || time.Now().After(deadline) {
					directory.Close()
					return 0, false
				}
				info, statErr := entry.Info()
				if os.IsNotExist(statErr) {
					continue
				}
				if statErr != nil {
					directory.Close()
					return 0, false
				}
				stat, ok := info.Sys().(*syscall.Stat_t)
				if !ok || stat.Blocks < 0 {
					directory.Close()
					return 0, false
				}
				if !info.IsDir() && !info.Mode().IsRegular() {
					continue
				}
				key := [2]uint64{uint64(stat.Dev), uint64(stat.Ino)}
				if !seen[key] {
					seen[key] = true
					blocks += uint64(stat.Blocks)
					if info.IsDir() {
						paths = append(paths, filepath.Join(next, entry.Name()))
					}
				}
			}
			if errors.Is(err, io.EOF) {
				break
			}
		}
		directory.Close()
	}
	return blocks * 512, true
}
