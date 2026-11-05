package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

const maxPrivateNetworkNamespaces = 8

type privateNamespaceHandle struct {
	proof         privateNamespaceProof
	path, pinPath string
	pid           int
	pinned        *os.File
}

type privateNamespaceProof struct {
	Namespace string
	PIDs      []int
	StartTime string
	Topology  string
}

// Prove host coverage without assuming that a systemd service name makes its
// private namespace safe. Only namespaces with a single loopback interface,
// loopback addresses and kernel loopback routes may coexist. The agent itself
// never changes namespace: nsenter runs bounded, read-only child commands.
func networkNamespace(ctx context.Context, commands CommandRunner, root string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return "", errors.New("network namespace inspection canceled or exceeded its time bound; assess again")
	}
	under := func(path string) string { return filepath.Join(root, strings.TrimPrefix(path, "/")) }
	if root == "" {
		under = func(path string) string { return path }
	}
	host, err := os.Readlink(under("/proc/self/ns/net"))
	if err != nil || !validNetworkNamespaceID(host) {
		return "", errors.New("host network namespace could not be verified")
	}
	init, err := os.Readlink(under("/proc/1/ns/net"))
	if err != nil || host != init {
		return "", errors.New("agent is not in the host network namespace")
	}
	for _, path := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(under(path)); err == nil {
			return "", errors.New("containerized agents cannot claim whole-host isolation")
		}
	}
	before, err := privateNamespaceInventory(ctx, under, host)
	if err != nil {
		return "", err
	}
	names := make([]string, 0, len(before))
	for name := range before {
		names = append(names, name)
	}
	sort.Strings(names)
	handles := []privateNamespaceHandle{}
	defer func() {
		for _, handle := range handles {
			_ = handle.pinned.Close()
		}
	}()
	for _, namespace := range names {
		if err := ctx.Err(); err != nil {
			return "", errors.New("private namespace inspection exceeded its time bound; assess again")
		}
		pids := before[namespace]
		pid := pids[0]
		path := under("/proc/" + strconv.Itoa(pid))
		start, err := namespaceProcessStart(path, pid)
		if err != nil {
			return "", namespaceProofError(namespace, pid, err)
		}
		pinned, err := os.Open(filepath.Join(path, "ns/net"))
		if err != nil {
			return "", namespaceProofError(namespace, pid, errors.New("cannot pin namespace; check agent permissions and assess again"))
		}
		// Keep the descriptor open through both topology reads. The child opens
		// this retained fd through procfs rather than resolving a reusable PID.
		pinPath := "/proc/" + strconv.Itoa(os.Getpid()) + "/fd/" + strconv.FormatUint(uint64(pinned.Fd()), 10)
		handles = append(handles, privateNamespaceHandle{proof: privateNamespaceProof{Namespace: namespace, PIDs: pids, StartTime: start}, path: path, pinPath: pinPath, pid: pid, pinned: pinned})
	}
	// Inspect the entire inventory twice while retaining every pin. A change
	// in an earlier namespace during a later namespace's first inspection
	// must be caught by its second sweep, even when PIDs/inodes stay stable.
	for sweep := 0; sweep < 2; sweep++ {
		for i := range handles {
			handle := &handles[i]
			if err := handle.identity(); err != nil {
				return "", namespaceProofError(handle.proof.Namespace, handle.pid, err)
			}
			topology, err := privateNamespaceTopology(ctx, commands, handle.pinPath)
			if err != nil {
				return "", namespaceProofError(handle.proof.Namespace, handle.pid, err)
			}
			if sweep == 0 {
				handle.proof.Topology = topology
			} else if handle.proof.Topology != topology {
				return "", namespaceProofError(handle.proof.Namespace, handle.pid, errors.New("namespace topology changed between inventory sweeps; assess again"))
			}
		}
		for _, handle := range handles {
			if err := handle.identity(); err != nil {
				return "", namespaceProofError(handle.proof.Namespace, handle.pid, err)
			}
		}
	}
	proofs := make([]privateNamespaceProof, 0, len(handles))
	for _, handle := range handles {
		proofs = append(proofs, handle.proof)
	}

	after, err := privateNamespaceInventory(ctx, under, host)
	if err != nil {
		return "", err
	}
	if directApprovalDigest(before) != directApprovalDigest(after) {
		return "", errors.New("private network namespace membership changed during assessment; assess again")
	}
	if current, err := os.Readlink(under("/proc/self/ns/net")); err != nil || current != host {
		return "", errors.New("host network namespace changed during assessment")
	}
	if current, err := os.Readlink(under("/proc/1/ns/net")); err != nil || current != host {
		return "", errors.New("init network namespace changed during assessment")
	}
	for _, path := range []string{"/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding"} {
		raw, err := os.ReadFile(under(path))
		if err != nil || strings.TrimSpace(string(raw)) != "0" {
			return "", errors.New("forwarding/router mode requires a separately validated isolation adapter")
		}
	}
	return directApprovalDigest(map[string]any{"host_namespace": host, "loopback_only_namespaces": proofs}), nil
}

func validNetworkNamespaceID(value string) bool {
	if !strings.HasPrefix(value, "net:[") || !strings.HasSuffix(value, "]") {
		return false
	}
	number := strings.TrimSuffix(strings.TrimPrefix(value, "net:["), "]")
	n, err := strconv.ParseUint(number, 10, 64)
	return err == nil && n != 0 && strconv.FormatUint(n, 10) == number
}

func namespaceProofError(namespace string, pid int, err error) error {
	return fmt.Errorf("private network namespace %s (PID %d) is not proven loopback-only: %w", namespace, pid, err)
}

func privateNamespaceInventory(ctx context.Context, under func(string) string, host string) (map[string][]int, error) {
	entries, err := os.ReadDir(under("/proc"))
	if err != nil || len(entries) > 20000 {
		return nil, errors.New("process namespace inventory cannot be bounded and verified")
	}
	result := map[string][]int{}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, errors.New("process namespace inventory canceled or exceeded its time bound; assess again")
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid < 1 {
			continue
		}
		namespace, err := os.Readlink(under("/proc/" + entry.Name() + "/ns/net"))
		if err != nil || !validNetworkNamespaceID(namespace) {
			return nil, fmt.Errorf("network namespace for PID %d is unreadable or changed; assess again", pid)
		}
		if namespace != host {
			result[namespace] = append(result[namespace], pid)
			if len(result) > maxPrivateNetworkNamespaces {
				return nil, errors.New("more than eight private network namespaces require a separately validated isolation adapter")
			}
		}
	}
	for namespace := range result {
		sort.Ints(result[namespace])
	}
	return result, nil
}

func namespaceProcessStart(path string, pid int) (string, error) {
	file, err := os.Open(filepath.Join(path, "stat"))
	if err != nil {
		return "", errors.New("process identity is unreadable or exited; assess again")
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 8193))
	if err != nil || len(raw) > 8192 {
		return "", errors.New("process identity exceeds its inspection bound")
	}
	text := string(raw)
	closing := strings.LastIndexByte(text, ')')
	if !strings.HasPrefix(text, strconv.Itoa(pid)+" (") || closing < 0 {
		return "", errors.New("process identity is malformed")
	}
	fields := strings.Fields(text[closing+1:])
	if len(fields) < 20 {
		return "", errors.New("process start time is unavailable")
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || start == 0 {
		return "", errors.New("process start time is invalid")
	}
	return strconv.FormatUint(start, 10), nil
}

func (handle privateNamespaceHandle) identity() error {
	current, err := os.Readlink(filepath.Join(handle.path, "ns/net"))
	if err != nil || current != handle.proof.Namespace {
		return errors.New("process namespace changed during inspection; assess again")
	}
	currentStart, err := namespaceProcessStart(handle.path, handle.pid)
	if err != nil || currentStart != handle.proof.StartTime {
		return errors.New("process restarted or exited during inspection; assess again")
	}
	pinnedInfo, pinErr := handle.pinned.Stat()
	currentInfo, currentErr := os.Stat(filepath.Join(handle.path, "ns/net"))
	if pinErr != nil || currentErr != nil || !os.SameFile(pinnedInfo, currentInfo) {
		return errors.New("pinned namespace identity changed during inspection")
	}
	return nil
}

func privateNamespaceTopology(ctx context.Context, commands CommandRunner, pinPath string) (string, error) {
	read := func(args ...string) (string, error) {
		commandCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		commandCtx = context.WithValue(commandCtx, commandOutputLimitKey{}, 65536)
		text, err := commands.Run(commandCtx, "nsenter", append([]string{"--net=" + pinPath, "--", "ip"}, args...)...)
		if err != nil || commandCtx.Err() != nil {
			return "", errors.New("read-only nsenter/ip inspection failed; install util-linux/iproute and check agent namespace permissions")
		}
		if len(text) > 65536 {
			return "", errors.New("namespace topology exceeds its 64 KiB bound")
		}
		return text, nil
	}
	addresses, err := read("-j", "address", "show")
	if err != nil {
		return "", err
	}
	links, err := loopbackNamespaceAddresses(addresses)
	if err != nil {
		return "", err
	}
	routes := map[string]any{}
	for _, family := range []string{"-4", "-6"} {
		raw, err := read("-j", family, "route", "show", "table", "all")
		if err != nil {
			return "", err
		}
		rows, err := loopbackNamespaceRoutes(raw, family)
		if err != nil {
			return "", err
		}
		routes[family] = rows
	}
	return directApprovalDigest(map[string]any{"loopback": links, "routes": routes}), nil
}

func namespaceKnownFields(row map[string]any, fields string) bool {
	for field := range row {
		if !slices.Contains(strings.Fields(fields), field) {
			return false
		}
	}
	return true
}

func namespaceUint(value any, positive bool) bool {
	decimal, ok := counterDecimal(value)
	if !ok {
		return false
	}
	n, err := strconv.ParseUint(decimal, 10, 32)
	return err == nil && (!positive || n > 0)
}

func loopbackNamespaceAddresses(raw string) (map[string]any, error) {
	rows, err := nativeJSONArray(raw)
	if err != nil || len(rows) != 1 {
		return nil, errors.New("namespace must contain exactly one loopback interface; extra or unreadable links require review")
	}
	row, ok := rows[0].(map[string]any)
	if !ok || !namespaceKnownFields(row, "ifindex ifname flags mtu qdisc operstate linkmode group txqlen link_type address broadcast addr_info promiscuity allmulti min_mtu max_mtu num_tx_queues num_rx_queues gso_max_size gso_max_segs tso_max_size tso_max_segs gro_max_size gso_ipv4_max_size gro_ipv4_max_size") || row["ifname"] != "lo" || row["link_type"] != "loopback" || row["ifindex"] != json.Number("1") {
		return nil, errors.New("namespace contains a non-loopback or unsupported interface")
	}
	for key, choices := range map[string][]any{
		"address": {"00:00:00:00:00:00"}, "broadcast": {"00:00:00:00:00:00"},
		"qdisc": {"noqueue", "noop"}, "operstate": {"UNKNOWN", "DOWN"},
		"linkmode": {"DEFAULT"}, "group": {"default", json.Number("0")},
	} {
		if value, present := row[key]; present && !slices.Contains(choices, value) {
			return nil, errors.New("unexpected private loopback interface metadata")
		}
	}
	for _, key := range []string{"mtu", "txqlen"} {
		if value, present := row[key]; present && !namespaceUint(value, key == "mtu") {
			return nil, errors.New("invalid private loopback interface limit")
		}
	}
	// Recent iproute2/kernel readback includes offload and queue telemetry on
	// ordinary loopback. These fields cannot introduce a link or route; retain
	// them in the reviewed digest, with strict numeric bounds and no promiscuous
	// or all-multicast mode. Unknown fields are still rejected above.
	for _, key := range []string{"promiscuity", "allmulti"} {
		if value, present := row[key]; present && value != json.Number("0") {
			return nil, fmt.Errorf("unsupported private loopback %s mode", key)
		}
	}
	for _, key := range []string{"min_mtu", "max_mtu", "num_tx_queues", "num_rx_queues", "gso_max_size", "gso_max_segs", "tso_max_size", "tso_max_segs", "gro_max_size", "gso_ipv4_max_size", "gro_ipv4_max_size"} {
		if value, present := row[key]; present && !namespaceUint(value, key == "num_tx_queues" || key == "num_rx_queues") {
			return nil, fmt.Errorf("invalid private loopback %s telemetry", key)
		}
	}
	flags, ok := row["flags"].([]any)
	if !ok || len(flags) == 0 || len(flags) > 3 {
		return nil, errors.New("loopback interface flags are unavailable")
	}
	seen := map[string]bool{}
	for _, flag := range flags {
		value, ok := flag.(string)
		if !ok || seen[value] || !slices.Contains([]string{"LOOPBACK", "UP", "LOWER_UP"}, value) {
			return nil, errors.New("unexpected private loopback interface flags")
		}
		seen[value] = true
	}
	if !seen["LOOPBACK"] {
		return nil, errors.New("private interface is not kernel loopback")
	}
	addresses, ok := row["addr_info"].([]any)
	if !ok || len(addresses) > 2 {
		return nil, errors.New("private loopback address inventory is unavailable or unsupported")
	}
	seenAddresses := map[string]bool{}
	for _, value := range addresses {
		addr, ok := value.(map[string]any)
		if !ok || !namespaceKnownFields(addr, "family local prefixlen scope label valid_life_time preferred_life_time noprefixroute") || addr["scope"] != "host" {
			return nil, errors.New("unsupported private loopback address metadata")
		}
		local, ok := addr["local"].(string)
		if !ok || seenAddresses[local] || local != "127.0.0.1" && local != "::1" || local == "127.0.0.1" && (addr["family"] != "inet" || addr["prefixlen"] != json.Number("8")) || local == "::1" && (addr["family"] != "inet6" || addr["prefixlen"] != json.Number("128")) {
			return nil, errors.New("namespace contains a non-loopback or unsupported address")
		}
		if label, present := addr["label"]; present && label != "lo" {
			return nil, errors.New("private loopback address has an unexpected label")
		}
		if flag, present := addr["noprefixroute"]; present {
			if _, boolean := flag.(bool); !boolean || local != "::1" || addr["family"] != "inet6" {
				return nil, errors.New("invalid private IPv6 loopback noprefixroute flag")
			}
		}
		for _, key := range []string{"valid_life_time", "preferred_life_time"} {
			if value, present := addr[key]; present && value != "forever" && !namespaceUint(value, false) {
				return nil, errors.New("invalid private loopback address lifetime")
			}
		}
		seenAddresses[local] = true
	}
	return row, nil
}

func loopbackNamespaceRoutes(raw, family string) ([]any, error) {
	rows, err := nativeJSONArray(raw)
	if err != nil || len(rows) > 8 {
		return nil, errors.New("private namespace routes are unreadable or exceed the supported loopback layout")
	}
	for _, value := range rows {
		row, ok := value.(map[string]any)
		if !ok || !namespaceKnownFields(row, "type dst dev protocol scope prefsrc flags table metric pref") || row["dev"] != "lo" || row["protocol"] != "kernel" {
			return nil, errors.New("namespace has a non-loopback, gateway or unsupported route")
		}
		destination, ok := row["dst"].(string)
		prefix, err := netip.ParsePrefix(destination)
		if err != nil {
			addr, addrErr := netip.ParseAddr(destination)
			if !ok || addrErr != nil {
				return nil, errors.New("namespace has a default or malformed route")
			}
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		if family == "-4" && (!prefix.Addr().Is4() || prefix.Bits() < 8 || !netip.MustParsePrefix("127.0.0.0/8").Contains(prefix.Addr())) || family == "-6" && (prefix.Addr() != netip.IPv6Loopback() || prefix.Bits() != 128) {
			return nil, errors.New("namespace has a non-loopback or default route")
		}
		if kind, present := row["type"]; present && kind != "local" && kind != "unicast" && !(family == "-4" && kind == "broadcast") {
			return nil, errors.New("unsupported private loopback route type")
		}
		if table, present := row["table"]; present && table != "local" && table != "main" && table != json.Number("254") && table != json.Number("255") {
			return nil, errors.New("unexpected private loopback routing table")
		}
		if scope, present := row["scope"]; present && scope != "host" && scope != "link" {
			// RHEL 10 reports kernel's local ::1/128 route as scope global.
			// The scope word does not make this exact loopback route external.
			localIPv6 := family == "-6" && prefix.Addr() == netip.IPv6Loopback() && prefix.Bits() == 128 && row["type"] == "local" && (row["table"] == "local" || row["table"] == json.Number("255"))
			if scope != "global" || !localIPv6 {
				return nil, errors.New("unexpected private loopback route scope")
			}
		}
		if source, present := row["prefsrc"]; present && !(family == "-4" && source == "127.0.0.1" || family == "-6" && source == "::1") {
			return nil, errors.New("non-loopback preferred route source")
		}
		if flags, present := row["flags"]; present {
			items, ok := flags.([]any)
			if !ok || len(items) != 0 {
				return nil, errors.New("unexpected private loopback route flags")
			}
		}
		if metric, present := row["metric"]; present && !namespaceUint(metric, false) {
			return nil, errors.New("invalid private loopback route metric")
		}
		if preference, present := row["pref"]; present && preference != "low" && preference != "medium" && preference != "high" {
			return nil, errors.New("invalid private loopback route preference")
		}
	}
	return rows, nil
}
