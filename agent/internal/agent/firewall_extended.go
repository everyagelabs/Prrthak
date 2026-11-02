package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var directNumber = regexp.MustCompile(`^[0-9]{1,5}$`)
var extendedPort = regexp.MustCompile(`^[0-9]{1,5}(?:[-:][0-9]{1,5})?$`)
var forwardPortValue = regexp.MustCompile(`^port=([0-9]{1,5}(?:-[0-9]{1,5})?):proto=(tcp|udp):toport=([0-9]{1,5}):toaddr=$`)

type directInfo struct {
	Args                     []string
	Source, Protocol, Action string
	First, Last              int
}
type forwardPortInfo struct {
	First, Last, ToPort int
	Protocol            string
}

func validZoneTarget(value string) bool {
	return value == "ACCEPT" || value == "DROP" || value == "REJECT" || value == "default"
}
func extendedRange(value string) (int, int, error) {
	if !extendedPort.MatchString(value) {
		return 0, 0, errors.New("numeric port/range required")
	}
	return portRange(strings.ReplaceAll(value, ":", "-"))
}
func parseDirect(value string) (directInfo, error) {
	info := directInfo{}
	if len(value) > 2048 || strings.ContainsAny(value, "'\";`$\\") {
		return info, errors.New("unsupported direct-rule syntax")
	}
	for _, char := range value {
		if char < 32 || char == 127 {
			return info, errors.New("direct rule must be single-line argv")
		}
	}
	fields := strings.Fields(value)
	if len(fields) < 10 || len(fields) > 14 || len(fields)%2 != 0 || (fields[0] != "ipv4" && fields[0] != "ipv6") || fields[1] != "filter" || fields[2] != "INPUT" || !directNumber.MatchString(fields[3]) {
		return info, errors.New("direct rules require an IPv4/IPv6 INPUT filter header")
	}
	priority, err := strconv.Atoi(fields[3])
	if err != nil || priority > 32767 {
		return info, errors.New("direct priority must be 0..32767")
	}
	options := map[string]string{}
	for index := 4; index < len(fields); index += 2 {
		key := fields[index]
		if key != "-s" && key != "-p" && key != "-m" && key != "--dport" && key != "-j" {
			return info, errors.New("unsupported direct-rule option")
		}
		if _, exists := options[key]; exists {
			return info, errors.New("duplicate direct-rule option")
		}
		options[key] = fields[index+1]
	}
	if (options["-p"] != "tcp" && options["-p"] != "udp") || (options["-j"] != "ACCEPT" && options["-j"] != "DROP" && options["-j"] != "REJECT") {
		return info, errors.New("direct rule requires TCP/UDP and a typed action")
	}
	if module, present := options["-m"]; present && module != options["-p"] {
		return info, errors.New("direct module must match transport")
	}
	first, last, err := extendedRange(options["--dport"])
	if err != nil {
		return info, err
	}
	if source, present := options["-s"]; present {
		prefix, err := parsePrefix(source)
		if err != nil || prefix.Addr().Zone() != "" || prefix.Addr().Is4() != (fields[0] == "ipv4") {
			return info, errors.New("direct source must be numeric and match its family")
		}
		info.Source = prefix.Masked().String()
	}
	info.Args = append([]string{}, fields...)
	for index := 4; index < len(info.Args); index += 2 {
		if info.Args[index] == "--dport" {
			info.Args[index+1] = strings.ReplaceAll(info.Args[index+1], "-", ":")
		}
	}
	info.Protocol, info.Action, info.First, info.Last = options["-p"], options["-j"], first, last
	return info, nil
}
func parseForwardPort(value string) (forwardPortInfo, error) {
	info := forwardPortInfo{}
	parts := forwardPortValue.FindStringSubmatch(value)
	if parts == nil {
		return info, errors.New("forward ports support numeric local redirects with empty toaddr only")
	}
	first, last, err := extendedRange(parts[1])
	if err != nil {
		return info, err
	}
	to, _, err := extendedRange(parts[3])
	if err != nil {
		return info, err
	}
	return forwardPortInfo{first, last, to, parts[2]}, nil
}
func extendedKind(kind string) bool {
	return kind == "target" || kind == "direct" || kind == "forward_port"
}
func protectedFirewallSSHPorts(listeners []Listener, c Config) ([]int, error) {
	ports, seen := []int{}, map[int]bool{}
	for _, port := range c.ProtectedSSHPorts {
		if port < 1 || port > 65535 {
			return nil, errors.New("invalid configured protected SSH port")
		}
		if !seen[port] {
			ports = append(ports, port)
			seen[port] = true
		}
	}
	for _, listener := range listeners {
		if protectedSSHListener(listener, c) && !seen[listener.Port] {
			ports = append(ports, listener.Port)
			seen[listener.Port] = true
		}
	}
	if len(ports) == 0 {
		ports = []int{22}
	}
	return ports, nil
}
func directConflict(a, b directInfo) bool {
	if a.Args[0] != b.Args[0] || a.Protocol != b.Protocol || a.Action == b.Action || !rangesIntersect(a.First, a.Last, b.First, b.Last) {
		return false
	}
	pa, _ := strconv.Atoi(a.Args[3])
	pb, _ := strconv.Atoi(b.Args[3])
	if pa != pb {
		return false
	}
	if a.Source == "" || b.Source == "" {
		return true
	}
	sa, _ := parsePrefix(a.Source)
	sb, _ := parsePrefix(b.Source)
	return prefixesOverlap(sa, sb)
}
func conflictingDirectRules(rules []FirewallRule) bool {
	type scoped struct {
		scope string
		info  directInfo
	}
	parsed := []scoped{}
	for _, rule := range rules {
		if rule.Kind == "direct" {
			if info, err := parseDirect(rule.Value); err == nil {
				parsed = append(parsed, scoped{rule.Scope, info})
			}
		}
	}
	for index, first := range parsed {
		for _, second := range parsed[index+1:] {
			if first.scope == second.scope && directConflict(first.info, second.info) {
				return true
			}
		}
	}
	return false
}
func validateDirectContexts(change FirewallChange, snapshot *FirewallSnapshot) error {
	removed, remaining := map[string]bool{}, []FirewallRule{}
	for _, op := range change.Operations {
		if op.Kind == "direct" {
			removed[FirewallFingerprint(op.Scope, op.Zone, op.Kind, op.OldValue)] = true
		}
	}
	for _, rule := range snapshot.Rules {
		if !removed[rule.Fingerprint] {
			remaining = append(remaining, rule)
		}
	}
	for _, op := range change.Operations {
		if op.Kind == "direct" && op.Operation == "replace" {
			remaining = append(remaining, FirewallRule{Scope: op.Scope, Kind: "direct", Value: op.NewValue})
		}
	}
	if conflictingDirectRules(remaining) {
		return errors.New("overlapping conflicting direct rules at equal priority require manual review")
	}
	return nil
}
func validateExtendedOperation(op FirewallOperation) error {
	if op.Kind == "target" {
		if op.Scope != "permanent" || !firewallName.MatchString(op.Zone) || op.Operation != "replace" || !validZoneTarget(op.OldValue) || !validZoneTarget(op.NewValue) {
			return errors.New("zone targets support permanent exact replacement only")
		}
	} else if op.Kind == "direct" {
		if op.Zone != "" {
			return errors.New("direct rules require an empty zone")
		}
		if _, err := parseDirect(op.OldValue); err != nil {
			return err
		}
		if op.Operation == "replace" {
			if _, err := parseDirect(op.NewValue); err != nil {
				return err
			}
		}
	} else if op.Kind == "forward_port" {
		if !firewallName.MatchString(op.Zone) {
			return errors.New("local redirects require a valid zone")
		}
		if _, err := parseForwardPort(op.OldValue); err != nil {
			return err
		}
		if op.Operation == "replace" {
			if _, err := parseForwardPort(op.NewValue); err != nil {
				return err
			}
		}
	}
	return nil
}
func firewallTarget(ctx context.Context, runner CommandRunner, scope, zone string) (string, error) {
	if scope != "permanent" || !firewallName.MatchString(zone) {
		return "", errors.New("target read requires a permanent zone")
	}
	value, err := runner.Run(ctx, "firewall-cmd", "--permanent", "--zone="+zone, "--get-target")
	value = strings.TrimSpace(value)
	if err != nil {
		return "", err
	}
	if !validZoneTarget(value) {
		return "", errors.New("unexpected zone target readback")
	}
	return value, nil
}
func directCommand(ctx context.Context, runner CommandRunner, scope, verb, value string) (string, error) {
	if scope != "runtime" && scope != "permanent" {
		return "", errors.New("invalid direct scope")
	}
	info, err := parseDirect(value)
	if err != nil {
		return "", err
	}
	if verb != "query" && verb != "add" && verb != "remove" {
		return "", errors.New("invalid direct command")
	}
	args := firewallArgs(scope, "--direct", "--"+verb+"-rule")
	return runner.Run(ctx, "firewall-cmd", append(args, info.Args...)...)
}
func (a *Agent) executeFirewallTarget(ctx context.Context, journal *firewallJournal, mutation firewallMutation) error {
	if mutation.Operation != "set" || !validZoneTarget(mutation.PreviousValue) || !validZoneTarget(mutation.Value) || mutation.PreviousValue == mutation.Value {
		return errors.New("invalid exact target transition")
	}
	current, err := firewallTarget(ctx, a.Commands, mutation.Scope, mutation.Zone)
	if err != nil {
		return err
	}
	if current != mutation.PreviousValue {
		return errors.New("zone target changed before replacement")
	}
	a.invalidatePolicyVerificationAccess()
	journal.Mutations = append(journal.Mutations, mutation)
	journal.Status = "applying"
	if err = a.saveFirewallJournal(journal); err != nil {
		return err
	}
	if err = firewallMutate(ctx, a.Commands, mutation); err != nil {
		return err
	}
	journal.Mutations[len(journal.Mutations)-1].Completed = true
	if err = a.saveFirewallJournal(journal); err != nil {
		return err
	}
	current, err = firewallTarget(ctx, a.Commands, mutation.Scope, mutation.Zone)
	if err != nil || current != mutation.Value {
		return errors.New("zone target readback did not match")
	}
	return nil
}
func (a *Agent) rollbackFirewallTarget(ctx context.Context, mutation firewallMutation) error {
	if mutation.Operation != "set" || !validZoneTarget(mutation.PreviousValue) || !validZoneTarget(mutation.Value) {
		return errors.New("invalid target rollback journal")
	}
	current, err := firewallTarget(ctx, a.Commands, mutation.Scope, mutation.Zone)
	if err != nil {
		return err
	}
	if current == mutation.PreviousValue {
		return nil
	}
	if current != mutation.Value {
		return errors.New("target rollback refused a third-party value")
	}
	inverse := mutation
	inverse.Value, inverse.PreviousValue = mutation.PreviousValue, mutation.Value
	if err = firewallMutate(ctx, a.Commands, inverse); err != nil {
		return err
	}
	current, err = firewallTarget(ctx, a.Commands, inverse.Scope, inverse.Zone)
	if err != nil || current != inverse.Value {
		return errors.New("target rollback readback did not match")
	}
	return nil
}

var readFirewallEphemeralRange = func() (int, int, error) {
	file, err := os.Open("/proc/sys/net/ipv4/ip_local_port_range")
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 129))
	parts := strings.Fields(string(data))
	if err != nil || len(data) > 128 || len(parts) != 2 || !directNumber.MatchString(parts[0]) || !directNumber.MatchString(parts[1]) {
		return 0, 0, errors.New("ephemeral return-port range unavailable")
	}
	return extendedRange(parts[0] + "-" + parts[1])
}

func protectedControllerPorts(c Config) ([]int, error) {
	ports := []int{}
	for _, origin := range []string{c.ControllerURL, c.ControlURL, c.DiscoveryURL} {
		if origin == "" {
			continue
		}
		parsed, err := url.Parse(origin)
		if err != nil || parsed.Hostname() == "" || parsed.User != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") {
			return nil, errors.New("controller endpoint port cannot be established safely")
		}
		port := 443
		if parsed.Scheme == "http" {
			port = 80
		}
		if parsed.Port() != "" {
			port, err = strconv.Atoi(parsed.Port())
			if err != nil || port < 1 || port > 65535 {
				return nil, errors.New("invalid controller endpoint port")
			}
		}
		ports = append(ports, port)
	}
	return ports, nil
}

// The shared topology check treats unresolved/unreadable topology as local.
// It is called lazily only for an intersected controller TCP port, at most once
// per configured origin per change. Proven-remote controller ports remain usable
// by ordinary endpoint applications; ephemeral guards protect return traffic.
var firewallControllerIngressTargeted = controllerIngressTargeted

func rangesIntersect(first, last, otherFirst, otherLast int) bool {
	return first <= otherLast && otherFirst <= last
}
func protectExtendedManagement(ctx context.Context, runner CommandRunner, c Config, snapshot *FirewallSnapshot, change FirewallChange, ssh []int) error {
	needed := false
	for _, op := range change.Operations {
		if extendedKind(op.Kind) {
			needed = true
		}
	}
	if !needed {
		return nil
	}
	controller, err := protectedControllerPorts(c)
	if err != nil {
		return err
	}
	origins := []string{}
	for _, origin := range []string{c.ControllerURL, c.ControlURL, c.DiscoveryURL} {
		if origin != "" {
			origins = append(origins, origin)
		}
	}
	locality := map[int]bool{}
	known := map[int]bool{}
	localControllerPort := func(first, last int) bool {
		for index, port := range controller {
			if port < first || port > last {
				continue
			}
			if !known[index] {
				parsed, _ := url.Parse(origins[index])
				parsed.Host = net.JoinHostPort(parsed.Hostname(), strconv.Itoa(port))
				locality[index] = firewallControllerIngressTargeted(parsed.String(), &Policy{Mode: "enforce", Services: []Service{{Port: port, Protocol: "tcp"}}})
				known[index] = true
			}
			if locality[index] {
				return true
			}
		}
		return false
	}
	for _, op := range change.Operations {
		if !extendedKind(op.Kind) {
			continue
		}
		if op.Kind == "target" {
			if op.NewValue != "ACCEPT" {
				if localControllerPort(1, 65535) {
					return errors.New("restricting a local/unknown controller host target requires manual review")
				}
				for _, port := range ssh {
					if !survivingManagementAllow(ctx, runner, snapshot, change, op.Scope, op.Zone, port, c.ManagementSources) {
						return errors.New("restricting a permanent target requires independent surviving SSH allowances")
					}
				}
			}
			continue
		}
		firstEphemeral, lastEphemeral, err := readFirewallEphemeralRange()
		if err != nil {
			return errors.New("local ephemeral return-port range unavailable; typed change refused")
		}
		touches := func(first, last int, protocol string) bool {
			if rangesIntersect(first, last, firstEphemeral, lastEphemeral) {
				return true
			}
			if protocol == "tcp" {
				for _, port := range ssh {
					if first <= port && port <= last {
						return true
					}
				}
				if localControllerPort(first, last) {
					return true
				}
			}
			return false
		}
		if op.Kind == "forward_port" {
			values := []string{op.OldValue}
			if op.Operation == "replace" {
				values = append(values, op.NewValue)
			}
			for _, value := range values {
				info, err := parseForwardPort(value)
				if err != nil {
					return err
				}
				if touches(info.First, info.Last, info.Protocol) || touches(info.ToPort, info.ToPort, info.Protocol) {
					return errors.New("local redirect overlaps SSH, controller or ephemeral return ports")
				}
			}
			continue
		}
		old, err := parseDirect(op.OldValue)
		if err != nil {
			return err
		}
		if old.Action == "ACCEPT" && touches(old.First, old.Last, old.Protocol) {
			return errors.New("removing a protected direct allowance requires manual review")
		}
		if op.Operation == "replace" {
			info, err := parseDirect(op.NewValue)
			if err != nil {
				return err
			}
			if info.Action != "ACCEPT" {
				if touches(info.First, info.Last, info.Protocol) {
					return errors.New("new direct deny overlaps SSH, controller or ephemeral return ports")
				}
				if info.Source != "" {
					for _, source := range c.ManagementSources {
						management, err := parsePrefix(source)
						denied, _ := parsePrefix(info.Source)
						if err != nil || prefixesOverlap(management, denied) {
							return errors.New("new direct deny overlaps management sources")
						}
					}
				}
			}
		}
	}
	return nil
}

func extendedMutationError(out string, err error) error {
	if err != nil {
		return err
	}
	if strings.Contains(out, "ALREADY_ENABLED") || strings.Contains(out, "NOT_ENABLED") || strings.Contains(out, "ALREADY_SET") {
		return fmt.Errorf("firewall changed concurrently; typed mutation ownership is ambiguous")
	}
	return nil
}
