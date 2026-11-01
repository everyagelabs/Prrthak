package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type CommandRunner interface {
	Run(context.Context, string, ...string) (string, error)
}
type ExecRunner struct{}
type limitedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.limit {
		return 0, errors.New("command output exceeded safety limit")
	}
	return b.Buffer.Write(p)
}
func (ExecRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd, e := fencedCommand(ctx, managedLeaseFromContext(ctx), name, args...)
	if e != nil {
		return "", fmt.Errorf("%s failed: %w", name, e)
	}
	var out limitedBuffer
	out.limit = 4 << 20
	cmd.Stdout = &out
	cmd.Stderr = &out
	e = runFencedCommand(cmd)
	if e != nil {
		return out.String(), fmt.Errorf("%s failed: %w", name, e)
	}
	return out.String(), nil
}

var socketAddress = regexp.MustCompile(`^(.*):([0-9]+)$`)
var processPattern = regexp.MustCompile(`users:\(\("([^"]+)"`)
var processPIDPattern = regexp.MustCompile(`users:\(\("([^"]+)",pid=([0-9]+)`)

func ParseSockets(text string) []Listener {
	listeners := []Listener{}
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		proto := fields[0]
		if proto != "tcp" && proto != "udp" {
			continue
		}
		m := socketAddress.FindStringSubmatch(fields[4])
		if len(m) != 3 {
			continue
		}
		port, e := strconv.Atoi(m[2])
		if e != nil || port < 1 || port > 65535 {
			continue
		}
		addr := strings.Trim(m[1], "[]")
		proc := ""
		if p := processPattern.FindStringSubmatch(line); len(p) == 2 {
			proc = p[1]
		}
		key := fmt.Sprintf("%s|%s|%d", proto, addr, port)
		if seen[key] {
			continue
		}
		seen[key] = true
		listener := Listener{Port: port, Protocol: proto, Address: addr, Process: proc, Service: ServiceName(proc, "")}
		if match := processPIDPattern.FindStringSubmatch(line); len(match) == 3 {
			if pid, e := strconv.Atoi(match[2]); e == nil && pid > 0 && pid <= 2147483647 {
				listener.PID = pid
			}
		}
		if proc != "" {
			listener.Application = proc
		}
		listeners = append(listeners, listener)
	}
	sort.Slice(listeners, func(i, j int) bool {
		a, b := listeners[i], listeners[j]
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		return a.Address < b.Address
	})
	return listeners
}
func readKeyValues(path string) map[string]string {
	m := map[string]string{}
	b, e := os.ReadFile(path)
	if e != nil {
		return m
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			m[strings.TrimSpace(parts[0])] = strings.Trim(strings.TrimSpace(parts[1]), "\"'")
		}
	}
	return m
}
func Discover(ctx context.Context, runner CommandRunner, simulate bool, hostname string) Report {
	if simulate {
		if hostname == "" {
			hostname = "simulated-rhel-01"
		}
		return Report{Hostname: hostname, IPs: []string{"10.80.0.21"}, OS: "rhel", OSVersion: "9 (simulated)", FirewalldVersion: "simulated", FirewallBackend: "nftables", FirewalldState: "running", Listeners: []Listener{
			{Port: 2022, Protocol: "tcp", Address: "0.0.0.0", Process: "sshd", PID: 1202, Service: "SSH", Application: "sshd.service", SystemdUnit: "sshd.service"},
			{Port: 80, Protocol: "tcp", Address: "0.0.0.0", Process: "nginx", PID: 1203, Service: "Nginx", Application: "nginx.service", SystemdUnit: "nginx.service"}}, CollectorStatus: "off"}
	}
	h, _ := os.Hostname()
	r := Report{Hostname: h, IPs: []string{}, Listeners: []Listener{}, FirewallBackend: "unknown", FirewalldState: "unknown", CollectorStatus: "off"}
	kv := readKeyValues("/etc/os-release")
	r.OS = kv["ID"]
	r.OSVersion = kv["VERSION_ID"]
	interfaces, _ := net.InterfaceAddrs()
	for _, addr := range interfaces {
		ip, _, e := net.ParseCIDR(addr.String())
		if e == nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
			r.IPs = append(r.IPs, ip.String())
		}
	}
	sort.Strings(r.IPs)
	sockets, e := runner.Run(ctx, "ss", "-H", "-lntup")
	if e != nil {
		r.DiscoveryError = e.Error()
	} else {
		r.Listeners = ParseSockets(sockets)
		var sockets []SocketBinding
		if text, e := runner.Run(ctx, "systemctl", "list-sockets", "--all", "--no-legend", "--no-pager", "--plain"); e == nil {
			sockets = ParseSystemdSockets(text)
		}
		r.Listeners = EnrichListeners(r.Listeners, readProcessCgroup, sockets)
	}
	if s, e := runner.Run(ctx, "firewall-cmd", "--version"); e == nil {
		r.FirewalldVersion = strings.TrimSpace(s)
	}
	if s, e := runner.Run(ctx, "firewall-cmd", "--state"); e == nil {
		r.FirewalldState = strings.TrimSpace(s)
	} else {
		r.FirewalldState = "not-running"
	}
	if kv := readKeyValues("/etc/firewalld/firewalld.conf"); kv["FirewallBackend"] != "" {
		r.FirewallBackend = kv["FirewallBackend"]
	}
	if s, _ := runner.Run(ctx, "ufw", "status"); strings.Contains(strings.ToLower(s), "status: active") {
		r.UFWActive = true
	}
	return r
}
