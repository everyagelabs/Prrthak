package agent

// Fast discovery is deliberately a bounded kernel snapshot comparison, not a
// claim that Linux supplies reliable new-listener notifications on every distro.
// Full discovery remains the fallback and still owns firewall inventory age.
import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

const FastDiscoveryCapability = "fast_listener_discovery_v1"
const fastDiscoveryInterval = 5 * time.Second
const maxFastListenerRecords = 8192

var errFastDiscoveryUnsupported = errors.New("native listener snapshots are unavailable")

type FastDiscoveryReport struct {
	Backend         string     `json:"backend"`
	Status          string     `json:"status"`
	IntervalSeconds int        `json:"interval_seconds"`
	CheckedAt       time.Time  `json:"checked_at"`
	LastChangeAt    *time.Time `json:"last_change_at,omitempty"`
	Error           string     `json:"error,omitempty"`
}

type listenerSnapshot struct {
	fingerprint string
	ports       map[string]bool
	bindings    map[string]bool
}

func newListenerSnapshot(records []string, ports map[string]bool) (listenerSnapshot, error) {
	if len(records) > maxFastListenerRecords {
		return listenerSnapshot{}, errors.New("native listener snapshot exceeds its record limit")
	}
	sort.Strings(records)
	hash := sha256.New()
	for _, record := range records {
		hash.Write([]byte(record))
		hash.Write([]byte{0})
	}
	return listenerSnapshot{fingerprint: hex.EncodeToString(hash.Sum(nil)), ports: ports}, nil
}

func listenerPortSet(rows []Listener) map[string]bool {
	result := map[string]bool{}
	for _, row := range rows {
		result[fmt.Sprintf("%s/%d", row.Protocol, row.Port)] = true
	}
	return result
}

func listenerBindingKey(protocol string, port int, address string) string {
	if canonical, ok := normalizeListenerAddress(address); ok {
		address = canonical
	}
	// ss uses * for an unspecified IPv6 address; IPv4 remains 0.0.0.0.
	if address == "*" {
		address = "::"
	}
	if parsed, err := netip.ParseAddr(address); err == nil {
		address = parsed.WithZone("").String()
	}
	return fmt.Sprintf("%s/%d/%s", protocol, port, address)
}

func listenerBindingSet(rows []Listener) map[string]bool {
	result := map[string]bool{}
	for _, row := range rows {
		result[listenerBindingKey(row.Protocol, row.Port, row.Address)] = true
	}
	return result
}

func sameListenerPorts(left, right map[string]bool) bool {
	if len(left) != len(right) {
		return false
	}
	for key := range left {
		if !right[key] {
			return false
		}
	}
	return true
}

func (a *Agent) fastDiscoveryStatus(now time.Time, err error) {
	a.fastDiscoveryReport.Backend = "inet_diag"
	a.fastDiscoveryReport.IntervalSeconds = int(fastDiscoveryInterval / time.Second)
	a.fastDiscoveryReport.CheckedAt = now
	a.fastDiscoveryReport.Status = "active"
	a.fastDiscoveryReport.Error = ""
	if err != nil {
		a.fastDiscoveryReport.Status = "error"
		if errors.Is(err, errFastDiscoveryUnsupported) {
			a.fastDiscoveryReport.Status = "unsupported"
		}
		message := err.Error()
		if len(message) > 1024 {
			message = message[:1024]
		}
		a.fastDiscoveryReport.Error = message
	}
}

// fastDiscoveryTick runs only in the daemon's serial loop. It owns no worker or
// permanent socket, never mutates a firewall, and cannot leak a --once collector.
// Its bool requests a report only after a verified listener refresh (or a
// changed failed-refresh receipt). Probe failures do not assert missing ports.
func (a *Agent) fastDiscoveryTick(ctx context.Context, now time.Time) bool {
	if !a.fastDiscoveryEnabled || a.Simulate || !a.nextFastDiscovery.IsZero() && now.Before(a.nextFastDiscovery) {
		return false
	}
	a.nextFastDiscovery = now.Add(fastDiscoveryInterval)
	probe := a.listenerSnapshot
	if probe == nil {
		probe = nativeListenerSnapshot
	}
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	snapshot, err := probe(bounded)
	a.fastDiscoveryStatus(now, err)
	if err != nil {
		return false
	}
	// Establish a baseline before the initial full scan. A later socket change
	// cannot be hidden by taking the first baseline after that scan.
	if a.fastListenerFingerprint == "" {
		a.fastListenerFingerprint = snapshot.fingerprint
		return false
	}
	if snapshot.fingerprint == a.fastListenerFingerprint || a.inventory == nil || a.discoveryDue(now) {
		return false
	}
	rows, err := DiscoverListeners(bounded, a.Commands)
	if err == nil && !sameListenerPorts(snapshot.ports, listenerPortSet(rows)) {
		err = errors.New("listener inventory changed during its refresh; previous listeners retained")
	}
	if err == nil && snapshot.bindings != nil && !sameListenerPorts(snapshot.bindings, listenerBindingSet(rows)) {
		err = errors.New("listener bindings changed during their refresh; previous listeners retained")
	}
	if err == nil {
		var verified listenerSnapshot
		verified, err = probe(bounded)
		if err == nil && verified.fingerprint != snapshot.fingerprint {
			err = errors.New("native listener snapshot changed during its refresh; previous listeners retained")
		}
	}
	if err != nil {
		a.fastDiscoveryStatus(now, err)
		// Keep the successful full/listener timestamp and listeners. Publish a
		// failed scan once so the controller treats stale observations as unknown.
		message := a.fastDiscoveryReport.Error
		if a.inventory.DiscoveryError == message {
			return false
		}
		a.inventory.DiscoveryError = message
		a.lastDiscoveryAttempt = now
		a.discoverySequence++
		a.discoveryPending = true
		return true
	}
	a.fastListenerFingerprint = snapshot.fingerprint
	a.inventory.Listeners = rows
	a.inventory.DiscoveryError = ""
	a.inventory.LearningDiscoverySessionIDs = nil
	a.lastDiscoveryAttempt = now
	a.lastDiscoverySuccess = now
	a.discoverySequence++
	a.discoveryPending = true
	changed := now
	a.fastDiscoveryReport.LastChangeAt = &changed
	return true
}

// DiscoverListeners refreshes service/process identity without reading OS,
// interfaces or firewalld inventory. A failed/malformed ss read is not empty.
func DiscoverListeners(ctx context.Context, runner CommandRunner) ([]Listener, error) {
	text, err := runner.Run(ctx, "ss", "-H", "-lntup")
	if err != nil {
		return nil, err
	}
	if len(text) > 4*1024*1024 {
		return nil, errors.New("listener inventory exceeds its byte limit")
	}
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 || (fields[0] != "tcp" && fields[0] != "udp") || len(ParseSockets(line)) != 1 {
			return nil, errors.New("listener inventory contains an incomplete or unsupported row")
		}
	}
	rows := ParseSockets(text)
	if len(rows) > maxFastListenerRecords {
		return nil, errors.New("listener inventory exceeds its record limit")
	}
	var sockets []SocketBinding
	if text, err := runner.Run(ctx, "systemctl", "list-sockets", "--all", "--no-legend", "--no-pager", "--plain"); err == nil {
		sockets = ParseSystemdSockets(text)
	}
	return EnrichListeners(rows, readProcessCgroup, sockets), nil
}
