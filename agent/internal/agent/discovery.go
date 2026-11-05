package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type CommandRunner interface {
	Run(context.Context, string, ...string) (string, error)
}
type ExecRunner struct{}
type commandOutputLimitKey struct{}
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
	if limit, ok := ctx.Value(commandOutputLimitKey{}).(int); ok && limit > 0 && limit < out.limit {
		out.limit = limit
	}
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

func validListenerInterface(name string) bool {
	if name == "" || len(name) > 15 || name == "." || name == ".." || !utf8.ValidString(name) || strings.ContainsAny(name, "/:") {
		return false
	}
	for _, character := range name {
		if unicode.IsSpace(character) || unicode.IsControl(character) {
			return false
		}
	}
	return true
}

// ss appends a bound interface to IPv4 addresses on recent iproute2 releases.
// IPv4 has no scoped address syntax, so compare its canonical address with
// inet_diag while retaining actual IPv6 scope in the reported listener.
func normalizeListenerAddress(address string) (string, bool) {
	if strings.HasPrefix(address, "[") {
		// Interface names may themselves contain brackets, including in
		// [IPv6%interface]. Validate the enclosing-bracket form first.
		if strings.HasSuffix(address, "]") {
			if canonical, ok := normalizeListenerHost(address[1:len(address)-1], true); ok {
				return canonical, true
			}
		}
		// ss also emits [IPv6]%interface. A scope in both places is invalid.
		closing := strings.Index(address, "]%")
		if closing < 0 || strings.Contains(address[1:closing], "%") {
			return "", false
		}
		return normalizeListenerHost(address[1:closing]+address[closing+1:], true)
	}
	return normalizeListenerHost(address, false)
}

func normalizeListenerHost(address string, bracketed bool) (string, bool) {
	if address == "*" && !bracketed {
		return address, true
	}
	base, zone, scoped := strings.Cut(address, "%")
	if scoped && !validListenerInterface(zone) {
		return "", false
	}
	// Preserve ss's IPv6 wildcard spelling when it also reports a bound
	// interface. The kernel snapshot represents the same wildcard as ::.
	if base == "*" && scoped && !bracketed {
		base = "::"
	}
	parsed, err := netip.ParseAddr(base)
	if err != nil || bracketed && !parsed.Is6() {
		return "", false
	}
	if parsed.Is4() {
		return parsed.String(), true
	}
	if scoped {
		parsed = parsed.WithZone(zone)
	}
	return parsed.String(), true
}

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
		addr, validAddress := normalizeListenerAddress(m[1])
		if !validAddress {
			continue
		}
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
	listeners, e := DiscoverListeners(ctx, runner)
	if e != nil {
		r.DiscoveryError = e.Error()
	} else {
		r.Listeners = listeners
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
