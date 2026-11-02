package agent

// Typed capture is opt-in through a freshly signed exact session/monitor scope.
// Old journal observations keep their old wire shape and never acquire a verdict.
import (
	"errors"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

const TrafficCaptureCapability = "traffic_capture_v1"
const captureAccepted = "accepted_connection"
const captureDenied = "denied_packet"

var errCaptureScope = errors.New("native capture scope replacement refused")

func validTypedCapture(flow Flow, id string) bool {
	source, err := netip.ParseAddr(flow.SourceIP)
	if err != nil || source.Is4In6() || source.Zone() != "" || flow.AddressFamily != captureFamily(source) || !validDigest(id) || flow.Count != 1 || !flow.FirstSeen.Equal(flow.LastSeen) {
		return false
	}
	return flow.CaptureKind == captureAccepted && flow.CaptureBackend == "conntrack" && flow.CountUnit == "connections" && flow.Verdict == "allowed" || flow.CaptureKind == captureDenied && flow.CaptureBackend == "nflog" && flow.CountUnit == "packets" && flow.Verdict == "denied"
}
func captureKindsKey(kinds []string) string {
	copyKinds := append([]string{}, kinds...)
	sort.Strings(copyKinds)
	return strings.Join(copyKinds, ",")
}

type CaptureBackendReport struct {
	Backend    string `json:"backend"`
	Status     string `json:"status"`
	IPv4       bool   `json:"ipv4"`
	IPv6       bool   `json:"ipv6"`
	LostEvents *int   `json:"lost_events"`
	Error      string `json:"error"`
}
type TrafficCaptureCoverage struct {
	Backends []CaptureBackendReport `json:"capture_backends,omitempty"`
	Gaps     []string               `json:"capture_gaps,omitempty"`
}
type capturedFlow struct {
	Flow
	DestinationIP       string
	ConnectionStartedAt time.Time
	ReceivedAt          time.Time
	CaptureEpoch        string
	RulePrefix          string
	VerificationOnly    bool
}
type capturePortScope struct {
	Port            Port
	Kind            string
	StartsAt        time.Time
	ExpiresAt       time.Time
	Deadline        time.Time
	RequireBirth    bool
	BusinessSources *verificationSourceMatcher
}

func captureScopeLive(scope capturePortScope, at time.Time) bool {
	return !at.Before(scope.StartsAt) && at.Before(scope.ExpiresAt) && (scope.Deadline.IsZero() || time.Now().Before(scope.Deadline))
}
func scopedCaptureCoverage(kinds []string, coverage TrafficCaptureCoverage) TrafficCaptureCoverage {
	result := TrafficCaptureCoverage{}
	for _, backend := range coverage.Backends {
		if backend.Backend == "conntrack" && captureKindSelected(kinds, captureAccepted) || backend.Backend == "nflog" && captureKindSelected(kinds, captureDenied) {
			result.Backends = append(result.Backends, backend)
		}
	}
	for _, gap := range coverage.Gaps {
		if strings.Contains(gap, "NFLOG") && !captureKindSelected(kinds, captureDenied) || strings.Contains(gap, "Conntrack") && !captureKindSelected(kinds, captureAccepted) {
			continue
		}
		found := false
		for _, old := range result.Gaps {
			found = found || old == gap
		}
		if !found && len(result.Gaps) < 16 {
			result.Gaps = append(result.Gaps, gap)
		}
	}
	return result
}

type nativeCapture interface {
	Configure([]capturePortScope) error
	Drain() ([]capturedFlow, TrafficCaptureCoverage)
	Close() error
}

func validateObservationKinds(kinds []string) error {
	if kinds == nil {
		return nil
	} // Deliberate historical log-only scope.
	if len(kinds) < 1 || len(kinds) > 2 {
		return errors.New("observation_kinds needs one or both typed traffic kinds")
	}
	seen := map[string]bool{}
	for _, kind := range kinds {
		if (kind != captureAccepted && kind != captureDenied) || seen[kind] {
			return errors.New("invalid or repeated typed traffic observation kind")
		}
		seen[kind] = true
	}
	return nil
}
func captureKindSelected(kinds []string, kind string) bool {
	for _, item := range kinds {
		if item == kind {
			return true
		}
	}
	return false
}
func captureSelected(flow Flow, kinds []string, ports []Port, from, until time.Time) bool {
	if !captureKindSelected(kinds, flow.CaptureKind) || flow.FirstSeen.Before(from) || !flow.LastSeen.Before(until) {
		return false
	}
	for _, port := range ports {
		if port.Port == flow.Port && port.Protocol == flow.Protocol {
			return true
		}
	}
	return false
}
func captureFamily(address netip.Addr) string {
	if address.Is4() {
		return "ipv4"
	}
	return "ipv6"
}
func canonicalCaptureScope(scopes []capturePortScope) string {
	values := make([]string, 0, len(scopes))
	for _, s := range scopes {
		values = append(values, s.Kind+"/"+s.Port.Protocol+"/"+strconv.Itoa(s.Port.Port)+"/"+s.StartsAt.UTC().Format(time.RFC3339Nano)+"/"+s.ExpiresAt.UTC().Format(time.RFC3339Nano))
	}
	sort.Strings(values)
	return strings.Join(values, "\n")
}
