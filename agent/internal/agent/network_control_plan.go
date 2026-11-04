package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

const egressPolicyName = "prt-egress"
const egressPolicyDescription = "Prrthak owned outbound policy v1"
const quarantineTableName = "prt_quarantine"

type egressTemplate struct {
	SchemaVersion int      `json:"schema_version"`
	Nonce         string   `json:"nonce"`
	Policy        string   `json:"policy"`
	Short         string   `json:"short"`
	Description   string   `json:"description"`
	Ingress       []string `json:"ingress"`
	Egress        []string `json:"egress"`
	Priority      int      `json:"priority"`
	Target        string   `json:"target"`
}

func descriptorDigest(value any) string {
	raw, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var result map[string]any
	if decoder.Decode(&result) != nil {
		return ""
	}
	delete(result, "plan_digest")
	delete(result, "approval_proof")
	return directApprovalDigest(result)
}

func validateNetworkDescriptor(c Config, serverID, kind, id, digest string, generation, schema int, issued, expires time.Time, ack, assess bool, proof json.RawMessage, now time.Time) error {
	if schema != 1 || !changeIDValid(id) || !validDigest(digest) || generation < 1 || int64(generation) > 2147483647 || issued.IsZero() || issued.After(now.Add(5*time.Second)) || expires.Before(issued) || expires.After(issued.Add(15*time.Minute)) || !now.Before(expires) {
		return errors.New("network control descriptor is invalid or expired")
	}
	if len(proof) == 0 {
		return errors.New("network control requires an attributed purpose-specific administrator proof")
	}
	if err := validateEndpointApproval(c, proof, serverID, now, false, kind); err != nil {
		return err
	}
	var authority endpointApprovalProof
	if json.Unmarshal(proof, &authority) != nil || authority.Mode != "single_admin" || authority.PlanID != id || authority.PlanDigest != digest {
		return errors.New("network control proof does not bind this exact descriptor")
	}
	if !assess && (!ack || !c.Enforce || !c.AllowFirewallChanges || !c.AllowHostDefaultDeny) {
		return errors.New("network control requires explicit downtime acknowledgement and all three local firewall opt-ins")
	}
	return nil
}
func validateEgressAssignment(c Config, serverID string, r *EgressAssignment, now time.Time) error {
	if r == nil {
		return errors.New("missing outbound descriptor")
	}
	assess := r.Operation == "assess"
	if !assess && r.Operation != "apply" && r.Operation != "remove" {
		return errors.New("unknown outbound operation")
	}
	if err := validateNetworkDescriptor(c, serverID, "egress_policy", r.ID, r.PlanDigest, r.Generation, r.SchemaVersion, r.IssuedAt, r.ApprovalExpiresAt, r.DowntimeAck, assess, r.ApprovalProof, now); err != nil {
		return err
	}
	if descriptorDigest(r) != r.PlanDigest {
		return errors.New("outbound descriptor content changed after its review")
	}
	if !validDigest(r.ProtectionDigest) || !validDigest(r.ContextDigest) || len(r.Services) > 64 {
		return errors.New("outbound descriptor has invalid context or service bounds")
	}
	count := 0
	for _, service := range r.Services {
		if service.Port < 1 || service.Port > 65535 || service.Protocol != "tcp" && service.Protocol != "udp" || len(service.Destinations) > 64 {
			return errors.New("outbound destinations require bounded TCP/UDP port rules")
		}
		for _, raw := range service.Destinations {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil || prefix.Addr().Is4In6() || prefix.Masked().String() != raw {
				return errors.New("outbound destination must be a canonical native IPv4/IPv6 network")
			}
			count++
		}
	}
	if count > 128 {
		return errors.New("outbound rule matrix exceeds its bounded apply budget")
	}
	return nil
}
func validateQuarantineAssignment(c Config, serverID string, r *QuarantineAssignment, now time.Time) error {
	if r == nil {
		return errors.New("missing quarantine descriptor")
	}
	assess := r.Operation == "assess"
	if !assess && r.Operation != "enable" && r.Operation != "disable" {
		return errors.New("unknown quarantine operation")
	}
	if err := validateNetworkDescriptor(c, serverID, "emergency_quarantine", r.ID, r.PlanDigest, r.Generation, r.SchemaVersion, r.IssuedAt, r.ApprovalExpiresAt, r.DowntimeAck, assess, r.ApprovalProof, now); err != nil {
		return err
	}
	if descriptorDigest(r) != r.PlanDigest || !validDigest(r.ProtectionDigest) || !validDigest(r.ContextDigest) {
		return errors.New("quarantine descriptor content/context changed after review")
	}
	if r.ExpiresAt.IsZero() || r.Operation == "enable" && (!r.ExpiresAt.After(now) || r.ExpiresAt.Before(r.IssuedAt.Add(time.Minute)) || r.ExpiresAt.After(r.IssuedAt.Add(time.Hour))) {
		return errors.New("quarantine requires an unexpired 60..3600 second lease")
	}
	return nil
}

func egressRichRules(request *EgressAssignment, protected []ProtectedEgress, sources []string, sshPorts []int) ([]string, error) {
	if request.Operation == "remove" {
		return []string{}, nil
	}
	rules := map[string]bool{}
	add := func(priority int, family, destination, port, protocol, action, sourcePort string) {
		value := fmt.Sprintf("rule family=\"%s\" priority=\"%d\"", family, priority)
		if destination != "" {
			value += " destination address=\"" + destination + "\""
		}
		if port != "" {
			value += " port port=\"" + port + "\" protocol=\"" + protocol + "\""
		}
		if sourcePort != "" {
			value += " source-port port=\"" + sourcePort + "\" protocol=\"tcp\""
		}
		value += " " + action
		rules[value] = true
	}
	for _, pin := range protected {
		prefix, err := netip.ParsePrefix(pin.Destination)
		if err != nil || pin.Port < 1 || pin.Port > 65535 || pin.Protocol != "tcp" && pin.Protocol != "udp" {
			return nil, errors.New("invalid locally derived protected outbound route")
		}
		family := "ipv6"
		if prefix.Addr().Is4() {
			family = "ipv4"
		}
		add(-32760, family, pin.Destination, strconv.Itoa(pin.Port), pin.Protocol, "accept", "")
	}
	for _, source := range sources {
		prefix, err := netip.ParsePrefix(source)
		if err != nil || prefix.Bits() == 0 {
			return nil, errors.New("management source pins must be restricted canonical networks")
		}
		family := "ipv6"
		if prefix.Addr().Is4() {
			family = "ipv4"
		}
		for _, port := range sshPorts {
			if port < 1 || port > 65535 {
				return nil, errors.New("invalid protected SSH port")
			}
			add(-32760, family, source, "", "", "accept", strconv.Itoa(port))
		}
	}
	for _, name := range []string{"neighbour-solicitation", "neighbour-advertisement", "router-solicitation", "router-advertisement", "packet-too-big"} {
		rules[`rule family="ipv6" priority="-32760" icmp-type name="`+name+`" accept`] = true
	}
	rules[`rule family="ipv4" priority="-32760" icmp-type name="fragmentation-needed" accept`] = true
	for _, service := range request.Services {
		for _, destination := range service.Destinations {
			prefix, err := netip.ParsePrefix(destination)
			if err != nil {
				return nil, err
			}
			family := "ipv6"
			if prefix.Addr().Is4() {
				family = "ipv4"
			}
			add(-32000, family, destination, strconv.Itoa(service.Port), service.Protocol, "accept", "")
		}
		if !request.DefaultDeny {
			for _, family := range []string{"ipv4", "ipv6"} {
				add(32000, family, "", strconv.Itoa(service.Port), service.Protocol, "reject", "")
			}
		}
	}
	if request.DefaultDeny {
		for _, family := range []string{"ipv4", "ipv6"} {
			add(32760, family, "", "", "", "reject", "")
		}
	}
	result := []string{}
	for value := range rules {
		result = append(result, value)
	}
	sort.Strings(result)
	return result, nil
}

type quarantinePlan struct {
	Nonce             string            `json:"nonce"`
	ExpiresAt         time.Time         `json:"expires_at"`
	Protected         []ProtectedEgress `json:"protected"`
	ManagementSources []string          `json:"management_sources"`
	SSHPorts          []int             `json:"ssh_ports"`
	LeaseSeconds      int64             `json:"lease_seconds"`
}

func nftMatch(left any, op string, right any) any {
	return map[string]any{"match": map[string]any{"left": left, "op": op, "right": right}}
}
func nftMeta(key string) any { return map[string]any{"meta": map[string]any{"key": key}} }
func nftPayload(protocol, field string) any {
	return map[string]any{"payload": map[string]any{"protocol": protocol, "field": field}}
}
func nftNetwork(prefix netip.Prefix) any {
	return map[string]any{"prefix": map[string]any{"addr": prefix.Addr().String(), "len": prefix.Bits()}}
}

// The only nft writer accepts locally constructed typed data, never controller
// commands/expressions. An independent kernel element timeout gates every drop,
// so a dead controller, agent or expiry service cannot leave the isolation on.
func quarantineNFTObjects(plan quarantinePlan, ttl time.Duration) ([]map[string]any, error) {
	if !validManagedNonce(plan.Nonce) || ttl < time.Second || ttl > time.Hour || len(plan.Protected) > 64 || len(plan.ManagementSources) == 0 || len(plan.ManagementSources) > 100 || len(plan.SSHPorts) == 0 || len(plan.SSHPorts) > 16 {
		return nil, errors.New("quarantine protected scope/lease exceeds its safety bounds")
	}
	objects := []map[string]any{{"table": map[string]any{"family": "inet", "name": quarantineTableName, "comment": "Prrthak emergency quarantine owner:" + plan.Nonce}}}
	for _, name := range []string{"input", "output", "forward"} {
		objects = append(objects, map[string]any{"chain": map[string]any{"family": "inet", "table": quarantineTableName, "name": name, "type": "filter", "hook": name, "prio": -301, "policy": "accept"}})
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		kind := "ipv4_addr"
		name := "lease4"
		address := "0.0.0.0"
		if family == "ipv6" {
			kind = "ipv6_addr"
			name = "lease6"
			address = "::"
		}
		seconds := int64(ttl / time.Second)
		objects = append(objects, map[string]any{"set": map[string]any{"family": "inet", "table": quarantineTableName, "name": name, "type": kind, "flags": []string{"interval", "timeout"}, "timeout": seconds, "elem": []any{map[string]any{"elem": map[string]any{"val": map[string]any{"prefix": map[string]any{"addr": address, "len": 0}}, "timeout": seconds}}}}})
	}
	add := func(chain string, expressions ...any) {
		objects = append(objects, map[string]any{"rule": map[string]any{"family": "inet", "table": quarantineTableName, "chain": chain, "expr": expressions}})
	}
	accept := map[string]any{"accept": nil}
	add("input", nftMatch(nftMeta("iifname"), "==", "lo"), accept)
	add("output", nftMatch(nftMeta("oifname"), "==", "lo"), accept)
	addPair := func(prefix netip.Prefix, port int, protocol string, controller bool) {
		ip := "ip6"
		if prefix.Addr().Is4() {
			ip = "ip"
		}
		if controller {
			add("output", nftMatch(nftPayload(ip, "daddr"), "==", nftNetwork(prefix)), nftMatch(nftMeta("l4proto"), "==", protocol), nftMatch(nftPayload(protocol, "dport"), "==", port), accept)
			add("input", nftMatch(nftPayload(ip, "saddr"), "==", nftNetwork(prefix)), nftMatch(nftMeta("l4proto"), "==", protocol), nftMatch(nftPayload(protocol, "sport"), "==", port), accept)
		} else {
			add("input", nftMatch(nftPayload(ip, "saddr"), "==", nftNetwork(prefix)), nftMatch(nftMeta("l4proto"), "==", protocol), nftMatch(nftPayload(protocol, "dport"), "==", port), accept)
			add("output", nftMatch(nftPayload(ip, "daddr"), "==", nftNetwork(prefix)), nftMatch(nftMeta("l4proto"), "==", protocol), nftMatch(nftPayload(protocol, "sport"), "==", port), accept)
		}
	}
	for _, route := range plan.Protected {
		if route.Kind == "dhcp" && ((route.Destination == "0.0.0.0/0" && route.Port == 67) || (route.Destination == "::/0" && route.Port == 547)) && route.Protocol == "udp" {
			continue // Fixed client/server port exceptions are generated below.
		}
		prefix, err := netip.ParsePrefix(route.Destination)
		if err != nil || prefix.Addr().Is4In6() || prefix.Bits() == 0 || route.Port < 1 || route.Port > 65535 || route.Protocol != "tcp" && route.Protocol != "udp" || route.Kind != "controller" && route.Kind != "dns" {
			return nil, errors.New("quarantine accepts only exact locally derived controller and DNS routes")
		}
		addPair(prefix, route.Port, route.Protocol, true)
	}
	for _, source := range plan.ManagementSources {
		prefix, err := netip.ParsePrefix(source)
		if err != nil || prefix.Bits() == 0 || prefix.Addr().Is4In6() {
			return nil, errors.New("quarantine management networks must be restricted")
		}
		for _, port := range plan.SSHPorts {
			if port < 1 || port > 65535 {
				return nil, errors.New("invalid quarantine protected SSH port")
			}
			addPair(prefix, port, "tcp", false)
		}
	}
	// DHCP client/server ports, IPv6 neighbor discovery and path MTU are network
	// control traffic, not an allowance for arbitrary application connections.
	for _, pair := range [][3]string{{"ip", "67", "68"}, {"ip6", "547", "546"}} {
		server, _ := strconv.Atoi(pair[1])
		client, _ := strconv.Atoi(pair[2])
		add("input", nftMatch(nftMeta("nfproto"), "==", map[string]string{"ip": "ipv4", "ip6": "ipv6"}[pair[0]]), nftMatch(nftMeta("l4proto"), "==", "udp"), nftMatch(nftPayload("udp", "sport"), "==", server), nftMatch(nftPayload("udp", "dport"), "==", client), accept)
		add("output", nftMatch(nftMeta("nfproto"), "==", map[string]string{"ip": "ipv4", "ip6": "ipv6"}[pair[0]]), nftMatch(nftMeta("l4proto"), "==", "udp"), nftMatch(nftPayload("udp", "sport"), "==", client), nftMatch(nftPayload("udp", "dport"), "==", server), accept)
	}
	for _, chain := range []string{"input", "output"} {
		add(chain, nftMatch(nftMeta("l4proto"), "==", "icmp"), nftMatch(nftPayload("icmp", "type"), "==", 3), nftMatch(nftPayload("icmp", "code"), "==", 4), accept)
		add(chain, nftMatch(nftMeta("l4proto"), "==", "ipv6-icmp"), nftMatch(nftPayload("icmpv6", "type"), "in", map[string]any{"set": []int{133, 134, 135, 136}}), nftMatch(nftPayload("ip6", "hoplimit"), "==", 255), accept)
		add(chain, nftMatch(nftMeta("l4proto"), "==", "ipv6-icmp"), nftMatch(nftPayload("icmpv6", "type"), "==", 2), accept)
	}
	for _, chain := range []string{"input", "output", "forward"} {
		for _, family := range [][2]string{{"ip", "@lease4"}, {"ip6", "@lease6"}} {
			add(chain, nftMatch(nftPayload(family[0], "daddr"), "in", family[1]), map[string]any{"drop": nil})
		}
	}
	return objects, nil
}

func quarantineNFTBatch(objects []map[string]any, deleteHandle string) ([]byte, error) {
	commands := []any{}
	if deleteHandle != "" {
		handle, ok := counterString(deleteHandle)
		if !ok || handle == "0" {
			return nil, errors.New("quarantine table deletion requires its exact native handle")
		}
		number := json.Number(handle)
		commands = append(commands, map[string]any{"delete": map[string]any{"table": map[string]any{"family": "inet", "handle": number}}})
	}
	for i, object := range objects {
		verb := "add"
		if i == 0 {
			verb = "create"
		}
		commands = append(commands, map[string]any{verb: object})
	}
	return json.Marshal(map[string]any{"nftables": commands})
}

func networkStringSet(values []string) []string {
	seen := map[string]bool{}
	for _, value := range values {
		seen[strings.TrimSpace(value)] = true
	}
	result := []string{}
	for value := range seen {
		if value != "" {
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}
