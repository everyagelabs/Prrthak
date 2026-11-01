package agent

import (
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unicode"
)

// Service identity comes from the owning executable or an observed systemd unit,
// never from a conventional port number. Host application tags are unrelated.
var processServices = map[string]string{
	"sshd": "SSH", "dropbear": "SSH", "nginx": "Nginx", "httpd": "Apache HTTP Server", "apache2": "Apache HTTP Server",
	"postgres": "PostgreSQL", "postmaster": "PostgreSQL", "mysqld": "MySQL", "mariadbd": "MariaDB", "redis-server": "Redis", "redis": "Redis",
	"mongod": "MongoDB", "haproxy": "HAProxy", "named": "BIND DNS", "dnsmasq": "Dnsmasq", "unbound": "Unbound DNS",
	"java": "Java application", "node": "Node.js application", "nodejs": "Node.js application", "python": "Python application", "python3": "Python application", "dotnet": ".NET application",
	"prometheus": "Prometheus", "grafana": "Grafana", "grafana-server": "Grafana", "kubelet": "Kubelet", "etcd": "etcd",
}
var unitServices = map[string]string{"ssh": "SSH", "sshd": "SSH", "dropbear": "SSH", "nginx": "Nginx", "apache2": "Apache HTTP Server", "httpd": "Apache HTTP Server", "postgresql": "PostgreSQL", "postgres": "PostgreSQL", "mysql": "MySQL", "mysqld": "MySQL", "mariadb": "MariaDB", "redis": "Redis", "redis-server": "Redis", "mongod": "MongoDB", "haproxy": "HAProxy", "named": "BIND DNS", "dnsmasq": "Dnsmasq", "unbound": "Unbound DNS", "prometheus": "Prometheus", "grafana-server": "Grafana", "grafana": "Grafana", "etcd": "etcd"}

func ServiceName(process, unit string) string {
	name := strings.ToLower(filepath.Base(process))
	if service := processServices[name]; service != "" {
		return service
	}
	base := strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(unit), ".service"), ".socket")
	base = strings.SplitN(base, "@", 2)[0]
	if service := unitServices[base]; service != "" {
		return service
	}
	return "Unknown service"
}
func UnitFromCgroup(text string) string {
	for _, line := range strings.Split(text, "\n") {
		fields := strings.SplitN(line, ":", 3)
		if len(fields) != 3 {
			continue
		}
		parts := strings.Split(fields[2], "/")
		for i := len(parts) - 1; i >= 0; i-- {
			name := parts[i]
			if strings.HasSuffix(name, ".service") && len(name) <= 256 {
				if decoded, e := strconv.Unquote(`"` + name + `"`); e == nil {
					name = decoded
				}
				return name
			}
		}
	}
	return ""
}
func readProcessCgroup(pid int) (string, error) {
	if pid < 1 || pid > 2147483647 {
		return "", fmt.Errorf("invalid process ID")
	}
	file, e := os.Open(fmt.Sprintf("/proc/%d/cgroup", pid))
	if e != nil {
		return "", e
	}
	defer file.Close()
	b, e := io.ReadAll(io.LimitReader(file, 65536))
	return string(b), e
}

type SocketBinding struct {
	Address     string
	Port        int
	SocketUnit  string
	ServiceUnit string
}

func safeUnit(name, suffix string) bool {
	return len(name) <= 256 && strings.HasSuffix(name, suffix) && strings.IndexFunc(name, func(r rune) bool { return r == '/' || unicode.IsSpace(r) || unicode.IsControl(r) }) < 0
}

// systemctl list-sockets is intended for human use. Only its unambiguous exact
// three-column numeric IP socket rows are accepted; Unix paths, spaces and extra
// columns are skipped. Unit identity is never inferred from a port alone.
func ParseSystemdSockets(text string) []SocketBinding {
	out := []SocketBinding{}
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 || !safeUnit(fields[1], ".socket") || !safeUnit(fields[2], ".service") {
			continue
		}
		match := socketAddress.FindStringSubmatch(fields[0])
		if len(match) != 3 {
			continue
		}
		host := strings.Trim(match[1], "[]")
		if host != "*" {
			if _, e := netip.ParseAddr(host); e != nil {
				continue
			}
		}
		port, e := strconv.Atoi(match[2])
		if e != nil || port < 1 || port > 65535 {
			continue
		}
		out = append(out, SocketBinding{host, port, fields[1], fields[2]})
	}
	return out
}
func addressMatches(a, b string) bool {
	if a == b {
		return true
	}
	if a == "*" {
		return b == "0.0.0.0" || b == "::"
	}
	if b == "*" {
		return a == "0.0.0.0" || a == "::"
	}
	return false
}
func EnrichListeners(listeners []Listener, readCgroup func(int) (string, error), sockets []SocketBinding) []Listener {
	units := map[int]string{}
	for i := range listeners {
		item := &listeners[i]
		if item.PID > 0 {
			unit, seen := units[item.PID]
			if !seen {
				if text, e := readCgroup(item.PID); e == nil {
					unit = UnitFromCgroup(text)
				}
				units[item.PID] = unit
			}
			item.SystemdUnit = unit
		}
		if item.SystemdUnit == "" && (item.Process == "systemd" || item.Process == "" || ServiceName(item.Process, "") == "Unknown service") {
			candidate := ""
			ambiguous := false
			for _, binding := range sockets {
				if binding.Port == item.Port && addressMatches(item.Address, binding.Address) {
					if candidate != "" && candidate != binding.ServiceUnit {
						ambiguous = true
						break
					}
					candidate = binding.ServiceUnit
				}
			}
			if !ambiguous {
				item.SystemdUnit = candidate
			}
		}
		item.Service = ServiceName(item.Process, item.SystemdUnit)
		item.ProtectedSSH = trustedSSHListener(*item)
		if item.SystemdUnit != "" {
			item.Application = item.SystemdUnit
		} else {
			item.Application = item.Process
		}
	}
	return listeners
}

// Display names are descriptive, not privileged management authority. Linux
// process comm and user service names are controlled by application users.
func trustedSSHListener(item Listener) bool {
	if item.Protocol != "tcp" || item.PID < 1 || item.Service != "SSH" {
		return false
	}
	before := processIdentity(item.PID)
	if before == "" {
		return false
	}
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", item.PID))
	if err != nil {
		return false
	}
	root := false
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			root = len(fields) == 5 && fields[1] == "0" && fields[2] == "0" && fields[3] == "0" && fields[4] == "0"
		}
	}
	if !root {
		return false
	}
	executable, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", item.PID))
	if err != nil || !filepath.IsAbs(executable) || strings.HasSuffix(executable, " (deleted)") {
		return false
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return false
	}
	name := filepath.Base(executable)
	if name != "sshd" && name != "dropbear" && !(item.PID == 1 && name == "systemd" && unitServices[strings.TrimSuffix(item.SystemdUnit, ".service")] == "SSH") {
		return false
	}
	for path := executable; ; path = filepath.Dir(path) {
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return false
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return false
		}
		if path == string(filepath.Separator) {
			break
		}
	}
	return processIdentity(item.PID) == before
}

func protectedSSHListener(item Listener, c Config) bool {
	if item.Protocol != "tcp" {
		return false
	}
	if item.ProtectedSSH {
		return true
	}
	for _, port := range c.ProtectedSSHPorts {
		if port == item.Port {
			return true
		}
	}
	return false
}
