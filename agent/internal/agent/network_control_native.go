package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

func networkDirectory(stateDir string) string {
	return filepath.Join(managedDirectory(stateDir), "network-control")
}
func networkStatePath(stateDir string) string {
	return filepath.Join(networkDirectory(stateDir), "state.json")
}
func networkReportPath(stateDir string) string {
	return filepath.Join(networkDirectory(stateDir), "report.json")
}
func egressTemplatePath(stateDir string) string {
	return filepath.Join(networkDirectory(stateDir), "egress-template.json")
}

func canonicalEgressTemplate(nonce string) egressTemplate {
	return egressTemplate{SchemaVersion: 1, Nonce: nonce, Policy: egressPolicyName, Short: "Prrthak egress template owner:" + nonce, Description: egressPolicyDescription, Ingress: []string{"HOST"}, Egress: []string{"ANY"}, Priority: -30000, Target: "CONTINUE"}
}

func readEgressTemplate(stateDir string) (egressTemplate, error) {
	var result egressTemplate
	raw, err := readPrivateSetupBound(egressTemplatePath(stateDir), 16384)
	if err != nil {
		return result, errors.New("Prepare the owned outbound policy through the reviewed GUI maintenance workflow first")
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || !validManagedNonce(result.Nonce) || directApprovalDigest(result) != directApprovalDigest(canonicalEgressTemplate(result.Nonce)) {
		return result, errors.New("owned outbound policy marker is invalid")
	}
	return result, nil
}

func egressPolicyDetails(text string) ([]string, error) {
	fields := map[string]string{}
	rules := []string{}
	header := false
	rich := false
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if !header {
			parts := strings.Fields(line)
			if len(parts) < 1 || parts[0] != egressPolicyName {
				return nil, errors.New("unexpected owned policy header")
			}
			header = true
			continue
		}
		if rich && strings.HasPrefix(line, "rule ") {
			if len(line) > 2048 || len(rules) > 256 {
				return nil, errors.New("owned policy rule budget exceeded")
			}
			rules = append(rules, line)
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, errors.New("invalid owned policy fields")
		}
		key = strings.TrimSpace(key)
		if _, exists := fields[key]; exists {
			return nil, errors.New("duplicate owned policy field")
		}
		fields[key] = strings.Join(strings.Fields(value), " ")
		rich = key == "rich rules"
	}
	if !header || len(fields) != 12 || fields["priority"] != "-30000" || fields["target"] != "CONTINUE" || fields["ingress-zones"] != "HOST" || fields["egress-zones"] != "ANY" || fields["masquerade"] != "no" {
		return nil, errors.New("owned outbound policy bindings/target changed")
	}
	for _, key := range []string{"services", "ports", "protocols", "forward-ports", "source-ports", "icmp-blocks", "rich rules"} {
		if fields[key] != "" {
			return nil, errors.New("unsupported data in owned outbound policy")
		}
	}
	return egressRuleKeys(rules)
}

func egressRuleKeys(rules []string) ([]string, error) {
	result := []string{}
	for _, rule := range rules {
		tokens, err := richTokens(rule)
		if err != nil || len(tokens) < 4 || tokens[0] != "rule" {
			return nil, errors.New("unsupported owned outbound rich rule")
		}
		values := map[string]string{}
		section := ""
		for _, token := range tokens[1:] {
			if strings.Contains(token, "=") {
				key, value, ok := strings.Cut(token, "=")
				if !ok {
					return nil, errors.New("invalid outbound rule property")
				}
				name := key
				if section != "" {
					name = section + "." + key
				}
				if _, exists := values[name]; exists {
					return nil, errors.New("duplicate outbound rule property")
				}
				values[name] = value
				continue
			}
			switch token {
			case "destination", "port", "source-port", "icmp-type":
				section = token
			case "accept", "reject":
				if values["action"] != "" {
					return nil, errors.New("duplicate outbound action")
				}
				values["action"] = token
				section = ""
			default:
				return nil, errors.New("unsupported outbound rule syntax")
			}
		}
		if values["family"] != "ipv4" && values["family"] != "ipv6" || values["action"] != "accept" && values["action"] != "reject" {
			return nil, errors.New("outbound rule family/action changed")
		}
		priority, err := strconv.Atoi(values["priority"])
		if err != nil || (priority != -32760 && priority != -32000 && priority != 32000 && priority != 32760) {
			return nil, errors.New("outbound rule ownership priority changed")
		}
		for key := range values {
			switch key {
			case "family", "priority", "action", "destination.address", "port.port", "port.protocol", "source-port.port", "source-port.protocol", "icmp-type.name":
			default:
				return nil, errors.New("foreign property in owned outbound rule")
			}
		}
		if name := values["icmp-type.name"]; name != "" {
			valid := values["priority"] == "-32760" && values["action"] == "accept"
			if values["family"] == "ipv6" {
				valid = valid && (name == "neighbour-solicitation" || name == "neighbour-advertisement" || name == "router-solicitation" || name == "router-advertisement" || name == "packet-too-big")
			} else {
				valid = valid && name == "fragmentation-needed"
			}
			if !valid {
				return nil, errors.New("unsupported outbound network-control ICMP exception")
			}
		}
		if destination := values["destination.address"]; destination != "" {
			prefix, err := netip.ParsePrefix(destination)
			if err != nil || prefix.Masked().String() != destination {
				return nil, errors.New("outbound rule destination changed")
			}
		}
		for _, section := range []string{"port", "source-port"} {
			if value := values[section+".port"]; value != "" {
				port, err := strconv.Atoi(value)
				if err != nil || port < 1 || port > 65535 || values[section+".protocol"] != "tcp" && values[section+".protocol"] != "udp" {
					return nil, errors.New("outbound rule service changed")
				}
			}
		}
		result = append(result, directApprovalDigest(values))
	}
	return networkStringSet(result), nil
}

// This is deliberately not a name-only exemption. Both runtime/permanent
// bindings and complete rich-rule sets must match privately owned state.
func OwnedEgressPolicyContext(ctx context.Context, runner CommandRunner, stateDir string) error {
	_, err := readEgressTemplate(stateDir)
	if err != nil {
		return err
	}
	state, err := readNetworkState(stateDir)
	if err != nil {
		return err
	}
	expected := []string{}
	if state != nil {
		expected = state.EgressRules
	}
	return verifyOwnedEgressPolicy(ctx, runner, stateDir, expected)
}
func verifyOwnedEgressPolicy(ctx context.Context, runner CommandRunner, stateDir string, expected []string) error {
	marker, err := readEgressTemplate(stateDir)
	if err != nil {
		return err
	}
	for _, item := range [][2]string{{"--get-short", marker.Short}, {"--get-description", marker.Description}} {
		value, err := runner.Run(ctx, "firewall-cmd", "--permanent", "--policy="+egressPolicyName, item[0])
		if err != nil || strings.TrimSpace(value) != item[1] {
			return errors.New("outbound policy ownership marker does not match its native definition")
		}
	}
	for _, scope := range []string{"runtime", "permanent"} {
		text, err := runner.Run(ctx, "firewall-cmd", firewallArgs(scope, "--policy="+egressPolicyName, "--list-all")...)
		if err != nil {
			return errors.New("owned outbound policy is not active in both scopes; reviewed GUI preparation is required")
		}
		rules, err := egressPolicyDetails(text)
		if err != nil {
			return err
		}
		keys, keyErr := egressRuleKeys(expected)
		if keyErr != nil {
			return keyErr
		}
		if strings.Join(rules, "\n") != strings.Join(keys, "\n") {
			return errors.New("owned outbound rule drift detected; refusing to overwrite it")
		}
	}
	return nil
}

type networkNativeContext struct {
	Report     NetworkControlReport
	Protection Protection
	Namespace  string
	Routes     []map[string]any
}

func nativeJSONArray(text string) ([]any, error) {
	document, err := counterJSON(`{"rows":` + text + `}`)
	if err != nil {
		return nil, err
	}
	rows, ok := document["rows"].([]any)
	if !ok || len(rows) > 512 {
		return nil, errors.New("network topology output exceeds bound")
	}
	return rows, nil
}

func networkNamespace(root string) (string, error) {
	under := func(path string) string {
		if root == "" {
			return path
		}
		return filepath.Join(root, strings.TrimPrefix(path, "/"))
	}
	self, err := os.Readlink(under("/proc/self/ns/net"))
	if err != nil {
		return "", errors.New("host network namespace could not be verified")
	}
	init, err := os.Readlink(under("/proc/1/ns/net"))
	if err != nil || self != init {
		return "", errors.New("agent is not in the host network namespace")
	}
	for _, path := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(under(path)); err == nil {
			return "", errors.New("containerized agents cannot claim whole-host isolation")
		}
	}
	entries, err := os.ReadDir(under("/proc"))
	if err != nil || len(entries) > 20000 {
		return "", errors.New("process namespace inventory cannot be bounded and verified")
	}
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		namespace, err := os.Readlink(under("/proc/" + entry.Name() + "/ns/net"))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || namespace != self {
			return "", errors.New("foreign or unreadable network namespaces prevent whole-host coverage")
		}
	}
	for _, path := range []string{"/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding"} {
		raw, err := os.ReadFile(under(path))
		if err != nil || strings.TrimSpace(string(raw)) != "0" {
			return "", errors.New("forwarding/router mode requires a separately validated isolation adapter")
		}
	}
	return self, nil
}

func nativeNetworkTopology(ctx context.Context, runner CommandRunner) ([]map[string]any, error) {
	result := []map[string]any{}
	for _, family := range []string{"-4", "-6"} {
		raw, err := runner.Run(ctx, "ip", family, "-j", "rule", "show")
		if err != nil {
			return nil, errors.New("routing rule inventory unavailable")
		}
		rules, err := nativeJSONArray(raw)
		if err != nil {
			return nil, err
		}
		for _, value := range rules {
			row, ok := value.(map[string]any)
			if !ok {
				return nil, errors.New("invalid routing rule")
			}
			table := fmt.Sprint(row["table"])
			if table != "local" && table != "main" && table != "default" && table != "255" && table != "254" && table != "253" {
				return nil, errors.New("policy routing is outside validated host isolation coverage")
			}
			for _, key := range []string{"fwmark", "iif", "oif", "uidrange", "l3mdev", "not"} {
				if _, exists := row[key]; exists {
					return nil, errors.New("ambiguous routing selectors prevent host isolation")
				}
			}
		}
		raw, err = runner.Run(ctx, "ip", family, "-j", "route", "show", "table", "all")
		if err != nil {
			return nil, errors.New("route inventory unavailable")
		}
		routes, err := nativeJSONArray(raw)
		if err != nil {
			return nil, err
		}
		for _, value := range routes {
			row, ok := value.(map[string]any)
			if !ok {
				return nil, errors.New("invalid native route")
			}
			copy := map[string]any{"family": family}
			for _, key := range []string{"dst", "gateway", "dev", "prefsrc", "table", "type", "scope", "metric", "protocol"} {
				if item, exists := row[key]; exists {
					copy[key] = item
				}
			}
			result = append(result, copy)
		}
	}
	raw, err := runner.Run(ctx, "ip", "-j", "link", "show")
	if err != nil {
		return nil, errors.New("link inventory unavailable")
	}
	links, err := nativeJSONArray(raw)
	if err != nil {
		return nil, err
	}
	for _, value := range links {
		row, ok := value.(map[string]any)
		if !ok {
			return nil, errors.New("invalid native link")
		}
		info, _ := row["linkinfo"].(map[string]any)
		kind, _ := info["info_kind"].(string)
		switch kind {
		case "bridge", "veth", "macvlan", "ipvlan", "vxlan", "geneve", "tun", "tap":
			return nil, errors.New("bridges/containers/tunnels require a separately validated isolation adapter")
		}
		result = append(result, map[string]any{"link": row["ifname"], "kind": kind, "master": row["master"]})
	}
	sort.Slice(result, func(i, j int) bool { return directApprovalDigest(result[i]) < directApprovalDigest(result[j]) })
	return result, nil
}

func protectedNetworkEgress(ctx context.Context, c Config, root string, lookup func(context.Context, string, string) ([]netip.Addr, error)) ([]ProtectedEgress, error) {
	result := []ProtectedEgress{}
	seen := map[string]bool{}
	add := func(ip netip.Addr, port int, protocol, kind string) error {
		if !ip.IsValid() || ip.Is4In6() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
			return errors.New("controller/DNS address is not an unambiguous routable native IP")
		}
		bits := 128
		if ip.Is4() {
			bits = 32
		}
		row := ProtectedEgress{Destination: netip.PrefixFrom(ip, bits).String(), Port: port, Protocol: protocol, Kind: kind}
		key := directApprovalDigest(row)
		if !seen[key] {
			seen[key] = true
			result = append(result, row)
		}
		if len(result) > 60 {
			return errors.New("protected control routes exceed their bounded scope")
		}
		return nil
	}
	for _, origin := range []string{c.ControllerURL, c.ControlURL, c.DiscoveryURL} {
		if origin == "" {
			continue
		}
		parsed, err := url.Parse(origin)
		if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil {
			return nil, errors.New("trusted controller HTTPS origins are required")
		}
		port := 443
		if parsed.Port() != "" {
			port, err = strconv.Atoi(parsed.Port())
			if err != nil || port < 1 || port > 65535 {
				return nil, errors.New("invalid protected controller port")
			}
		}
		addresses, err := lookup(ctx, "ip", parsed.Hostname())
		if err != nil || len(addresses) == 0 || len(addresses) > 32 {
			return nil, errors.New("all controller origins must resolve before restrictive changes")
		}
		for _, ip := range addresses {
			if err := add(ip, port, "tcp", "controller"); err != nil {
				return nil, err
			}
		}
	}
	for _, name := range []string{"/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"} {
		path := name
		if root != "" {
			path = filepath.Join(root, strings.TrimPrefix(name, "/"))
		}
		raw, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || len(raw) > 65536 {
			return nil, errors.New("trusted DNS resolver configuration unavailable")
		}
		for _, line := range strings.Split(string(raw), "\n") {
			parts := strings.Fields(line)
			if len(parts) < 2 || parts[0] != "nameserver" {
				continue
			}
			ip, err := netip.ParseAddr(parts[1])
			if err != nil {
				return nil, errors.New("DNS resolver is not a canonical native IP")
			}
			if ip.IsLoopback() {
				continue
			}
			for _, protocol := range []string{"tcp", "udp"} {
				if err := add(ip, 53, protocol, "dns"); err != nil {
					return nil, err
				}
			}
		}
	}
	result = append(result, ProtectedEgress{Destination: "0.0.0.0/0", Port: 67, Protocol: "udp", Kind: "dhcp"}, ProtectedEgress{Destination: "::/0", Port: 547, Protocol: "udp", Kind: "dhcp"})
	sort.Slice(result, func(i, j int) bool { return directApprovalDigest(result[i]) < directApprovalDigest(result[j]) })
	return result, nil
}

func ReadNetworkControlReport(stateDir string) *NetworkControlReport {
	raw, err := readPrivateSetupBound(networkReportPath(stateDir), 65536)
	if err != nil {
		return nil
	}
	var result NetworkControlReport
	if json.Unmarshal(raw, &result) != nil || result.SchemaVersion != 1 || len(result.Blockers) > 24 || len(result.ProtectedEgress) > 64 {
		return nil
	}
	return &result
}

func (a *Agent) assessNetworkControl(ctx context.Context) (networkNativeContext, error) {
	now := a.currentTime()
	result := networkNativeContext{Report: NetworkControlReport{SchemaVersion: 1, CheckedAt: now, ConfigurationDigest: configDigest(a.Config), ProtectedEgress: []ProtectedEgress{}, Blockers: []string{}, Egress: NetworkFeatureReport{Status: "blocked"}, Quarantine: NetworkFeatureReport{Status: "blocked"}}}
	block := func(err error) (networkNativeContext, error) {
		result.Report.Blockers = append(result.Report.Blockers, boundedSourceBankError(err))
		result.Report.Egress.Error = boundedSourceBankError(err)
		result.Report.Quarantine.Error = boundedSourceBankError(err)
		return result, err
	}
	if a.Simulate || runtime.GOOS != "linux" {
		return block(errors.New("native Linux host network control is unavailable in simulation or this OS"))
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	report := Discover(ctx, a.Commands, false, "")
	report.FirewallSnapshot = CollectFirewallSnapshot(ctx, a.Commands, a.ownedFirewallObservationRules(), a.Config.StateDir)
	result.Protection = a.managedProtectionFromReport(report)
	if report.DiscoveryError != "" || !result.Protection.Ready || report.FirewallBackend != "nftables" {
		return block(errors.New("fresh native nftables/firewalld inventory and protected SSH/controller readiness are required"))
	}
	result.Report.ProtectionDigest = result.Protection.Digest
	namespace, err := networkNamespace("")
	if err != nil {
		return block(err)
	}
	result.Namespace = namespace
	routes, err := nativeNetworkTopology(ctx, a.Commands)
	if err != nil {
		return block(err)
	}
	result.Routes = routes
	protected, err := protectedNetworkEgress(ctx, a.Config, "", net.DefaultResolver.LookupNetIP)
	if err != nil {
		return block(err)
	}
	result.Report.ProtectedEgress = protected
	markerDigest := "absent"
	if marker, err := readEgressTemplate(a.Config.StateDir); err == nil {
		markerDigest = directApprovalDigest(marker)
		if err := OwnedEgressPolicyContext(ctx, a.Commands, a.Config.StateDir); err == nil {
			result.Report.Egress.Supported = true
			result.Report.Egress.Ready = true
			result.Report.Egress.Status = "ready"
		} else {
			result.Report.Egress.Error = boundedSourceBankError(err)
		}
	} else {
		result.Report.Egress.Error = boundedSourceBankError(err)
	}
	if _, err := a.Commands.Run(ctx, "nft", "--version"); err == nil {
		result.Report.Quarantine.Supported = true
	} else {
		result.Report.Quarantine.Error = "Native nft utility and kernel transaction support are required."
	}
	result.Report.ContextDigest = directApprovalDigest(map[string]any{"configuration_digest": result.Report.ConfigurationDigest, "protection_digest": result.Protection.Digest, "namespace": namespace, "routes": routes, "protected_egress": protected, "egress_template": markerDigest})
	if result.Report.Quarantine.Supported {
		state, err := readNetworkState(a.Config.StateDir)
		if err == nil {
			var handle string
			handle, err = verifyQuarantineTable(ctx, a.Commands, state.QuarantinePlan, now, state.QuarantinePlan != nil && !now.Before(state.QuarantinePlan.ExpiresAt))
			if err == nil {
				plan := quarantinePlan{Nonce: result.Report.ContextDigest[:32], ExpiresAt: now.Add(time.Minute), Protected: protected, ManagementSources: result.Protection.ManagementSources, SSHPorts: result.Protection.SSHPorts, LeaseSeconds: 60}
				var objects []map[string]any
				objects, err = quarantineNFTObjects(plan, time.Minute)
				if err == nil {
					err = runQuarantineBatch(ctx, a.Commands, a.Config.StateDir, plan.Nonce, objects, handle, true)
				}
			}
		}
		if err == nil {
			result.Report.Quarantine.Ready = true
			result.Report.Quarantine.Status = "ready"
		} else {
			result.Report.Quarantine.Error = boundedSourceBankError(err)
		}
	}
	// The peer address on the controller is never involved in any of these
	// routes. Fresh local IPs are retained for the subsequent SSH witness.
	a.inventory = &report
	a.discoverySequence++
	a.discoveryPending = true
	a.lastDiscoveryAttempt = now
	a.lastFullDiscoveryAttempt = now
	if report.DiscoveryError == "" {
		a.lastDiscoverySuccess = now
	}
	return result, nil
}
