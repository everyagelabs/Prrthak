package agent

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func validDigest(value string) bool {
	b, e := hex.DecodeString(value)
	return e == nil && len(b) == 32 && len(value) == 64
}
func changeIDValid(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}
func findFirewallRule(snapshot *FirewallSnapshot, op FirewallOperation) (FirewallRule, bool) {
	fingerprint := FirewallFingerprint(op.Scope, op.Zone, op.Kind, op.OldValue)
	for _, rule := range snapshot.Rules {
		if rule.Fingerprint == fingerprint {
			return rule, true
		}
	}
	return FirewallRule{}, false
}
func operationKey(op FirewallOperation, value string) string {
	if op.Kind == "direct" {
		if info, err := parseDirect(value); err == nil {
			priority, _ := strconv.Atoi(info.Args[3])
			value = fmt.Sprintf("%s/%d/%s/%s/%d/%d/%s", info.Args[0], priority, info.Source, info.Protocol, info.First, info.Last, info.Action)
		}
	}
	if op.Kind == "forward_port" {
		if info, err := parseForwardPort(value); err == nil {
			value = fmt.Sprintf("%d/%d/%s/%d", info.First, info.Last, info.Protocol, info.ToPort)
		}
	}
	return op.Scope + "\x00" + op.Zone + "\x00" + op.Kind + "\x00" + value
}
func validateFirewallOperations(change FirewallChange, snapshot *FirewallSnapshot) error {
	if len(change.Operations) < 1 || len(change.Operations) > 50 {
		return errors.New("approved change must contain 1..50 operations")
	}
	oldKeys := map[string]bool{}
	newKeys := map[string]bool{}
	for _, op := range change.Operations {
		if (op.Scope != "runtime" && op.Scope != "permanent") || (op.Kind != "direct" && !firewallName.MatchString(op.Zone)) || (op.Kind != "service" && op.Kind != "port" && op.Kind != "rich_rule" && !extendedKind(op.Kind)) || (op.Operation != "replace" && op.Operation != "remove") {
			return errors.New("unsupported firewall operation/scope; bindings, remote routing and policies are view-only")
		}
		if extendedKind(op.Kind) {
			if err := validateExtendedOperation(op); err != nil {
				return err
			}
		}
		if len(op.OldValue) > 2048 || strings.ContainsAny(op.OldValue, "\r\n\x00") {
			return errors.New("invalid old firewall value")
		}
		rule, ok := findFirewallRule(snapshot, op)
		if !ok {
			return errors.New("old firewall rule is no longer present")
		}
		if !rule.Editable {
			return fmt.Errorf("rule is view-only: %s", rule.Reason)
		}
		key := operationKey(op, op.OldValue)
		if oldKeys[key] {
			return errors.New("duplicate operation on the same old rule")
		}
		oldKeys[key] = true
		if op.Operation == "remove" {
			if op.NewValue != "" {
				return errors.New("remove operation cannot have a new value")
			}
			continue
		}
		if op.NewValue == op.OldValue || op.NewValue == "" || len(op.NewValue) > 2048 || strings.ContainsAny(op.NewValue, "\r\n\x00") {
			return errors.New("replacement requires a distinct valid new value")
		}
		switch op.Kind {
		case "service":
			if !firewallName.MatchString(op.NewValue) {
				return errors.New("invalid service name")
			}
		case "port":
			if !validPortValue(op.NewValue) {
				return errors.New("invalid replacement port")
			}
		case "rich_rule":
			info, e := parseRich(op.NewValue)
			if e != nil || !richEditable(info) {
				return errors.New("replacement rich rule is outside the safe editing subset")
			}
		}
		key = operationKey(op, op.NewValue)
		if newKeys[key] {
			return errors.New("duplicate replacement target")
		}
		newKeys[key] = true
	}
	for key := range newKeys {
		if oldKeys[key] {
			return errors.New("interdependent replacements require separate plans")
		}
	}
	return validateDirectContexts(change, snapshot)
}
func restrictiveFirewallChange(change FirewallChange) bool {
	if change.RequiresDoubleConfirmation {
		return true
	}
	for _, op := range change.Operations {
		if extendedKind(op.Kind) {
			return true
		}
		if op.Kind == "service" || op.Kind == "port" {
			return true
		}
		old, e := parseRich(op.OldValue)
		if e != nil || old.Action == "accept" || old.Action == "drop" || old.Action == "reject" {
			return true
		}
		if op.Operation == "replace" {
			newRule, e := parseRich(op.NewValue)
			if e != nil || newRule.Action == "drop" || newRule.Action == "reject" {
				return true
			}
		}
	}
	return false
}
func firewallQuery(ctx context.Context, runner CommandRunner, scope, zone, kind, value string) (bool, error) {
	if kind == "target" {
		current, err := firewallTarget(ctx, runner, scope, zone)
		return current == value, err
	}
	if kind == "direct" {
		if zone != "" {
			return false, errors.New("direct query requires an empty zone")
		}
		out, err := directCommand(ctx, runner, scope, "query", value)
		if strings.TrimSpace(out) == "yes" && err == nil {
			return true, nil
		}
		if strings.TrimSpace(out) == "no" {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return false, errors.New("unexpected direct-rule query response")
	}
	if kind == "forward_port" {
		if (scope != "runtime" && scope != "permanent") || !firewallName.MatchString(zone) {
			return false, errors.New("local redirect query requires a valid scope and zone")
		}
		if _, err := parseForwardPort(value); err != nil {
			return false, err
		}
	}
	query := map[string]string{"service": "--query-service=", "port": "--query-port=", "rich_rule": "--query-rich-rule=", "forward_port": "--query-forward-port="}[kind]
	if query == "" {
		return false, errors.New("unsupported query")
	}
	out, e := runner.Run(ctx, "firewall-cmd", firewallArgs(scope, "--zone="+zone, query+value)...)
	trimmed := strings.TrimSpace(out)
	if trimmed == "yes" && e == nil {
		return true, nil
	}
	if trimmed == "no" {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	return false, errors.New("unexpected firewalld query response")
}
func firewallMutate(ctx context.Context, runner CommandRunner, mutation firewallMutation) error {
	if mutation.Kind == "target" {
		if mutation.Operation != "set" || !validZoneTarget(mutation.Value) || !validZoneTarget(mutation.PreviousValue) || mutation.Value == mutation.PreviousValue {
			return errors.New("invalid target set mutation")
		}
		current, err := firewallTarget(ctx, runner, mutation.Scope, mutation.Zone)
		if err != nil {
			return err
		}
		if current != mutation.PreviousValue {
			return errors.New("zone target changed concurrently; set refused")
		}
		out, err := runner.Run(ctx, "firewall-cmd", "--permanent", "--zone="+mutation.Zone, "--set-target="+mutation.Value)
		return extendedMutationError(out, err)
	}
	if mutation.Kind == "direct" {
		if mutation.Zone != "" || (mutation.Operation != "add" && mutation.Operation != "remove") {
			return errors.New("invalid direct mutation")
		}
		out, err := directCommand(ctx, runner, mutation.Scope, mutation.Operation, mutation.Value)
		return extendedMutationError(out, err)
	}
	if mutation.Kind == "forward_port" {
		if (mutation.Scope != "runtime" && mutation.Scope != "permanent") || !firewallName.MatchString(mutation.Zone) {
			return errors.New("local redirect mutation requires a valid scope and zone")
		}
		if _, err := parseForwardPort(mutation.Value); err != nil {
			return err
		}
	}
	verb := map[string]string{"add": "--add-", "remove": "--remove-"}[mutation.Operation]
	kind := map[string]string{"service": "service=", "port": "port=", "rich_rule": "rich-rule=", "forward_port": "forward-port="}[mutation.Kind]
	if verb == "" || kind == "" {
		return errors.New("unsupported mutation")
	}
	out, e := runner.Run(ctx, "firewall-cmd", firewallArgs(mutation.Scope, "--zone="+mutation.Zone, verb+kind+mutation.Value)...)
	if e != nil {
		return e
	}
	if strings.Contains(out, "ALREADY_ENABLED") || strings.Contains(out, "NOT_ENABLED") {
		return errors.New("firewall changed concurrently; mutation ownership is ambiguous")
	}
	return nil
}
func servicePortValues(ctx context.Context, runner CommandRunner, scope, name string) ([]string, error) {
	out, e := runner.Run(ctx, "firewall-cmd", firewallArgs(scope, "--info-service="+name)...)
	if e != nil {
		return nil, e
	}
	return parseServicePortValues(out)
}
func parseServicePortValues(out string) ([]string, error) {
	ports := []string{}
	foundPorts := false
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "ports":
			foundPorts = true
			for _, p := range strings.Fields(value) {
				if !validPortValue(p) {
					return nil, errors.New("service uses unsupported port definition")
				}
				ports = append(ports, p)
			}
		case "protocols", "source-ports", "destination", "includes":
			if value != "" {
				return nil, errors.New("complex service definition requires manual review")
			}
		}
	}
	if !foundPorts {
		return nil, errors.New("service definition lacks a ports field")
	}
	return ports, nil
}
func portIncludes(value string, port int) bool {
	parts := strings.Split(value, "/")
	if len(parts) != 2 || parts[1] != "tcp" {
		return false
	}
	first, last, e := portRange(parts[0])
	return e == nil && port >= first && port <= last
}
func richTouchesSSH(ctx context.Context, runner CommandRunner, scope string, info richInfo, ssh []int) (bool, error) {
	if info.Protocol != "" {
		return info.Protocol == "tcp", nil
	}
	if info.Port != "" {
		for _, port := range ssh {
			if info.Transport == "tcp" {
				first, last, e := portRange(info.Port)
				if e == nil && port >= first && port <= last {
					return true, nil
				}
			}
		}
		return false, nil
	}
	if info.Service != "" {
		ports, e := servicePortValues(ctx, runner, scope, info.Service)
		if e != nil {
			return false, e
		}
		for _, value := range ports {
			for _, port := range ssh {
				if portIncludes(value, port) {
					return true, nil
				}
			}
		}
		return false, nil
	}
	return true, nil
}
func prefixCovers(allow, source netip.Prefix) bool {
	return allow.Addr().Is4() == source.Addr().Is4() && allow.Bits() <= source.Bits() && allow.Contains(source.Masked().Addr())
}
func prefixesOverlap(a, b netip.Prefix) bool {
	return a.Addr().Is4() == b.Addr().Is4() && (a.Contains(b.Masked().Addr()) || b.Contains(a.Masked().Addr()))
}
func survivingManagementAllow(ctx context.Context, runner CommandRunner, snapshot *FirewallSnapshot, change FirewallChange, scope, zone string, port int, sources []string) bool {
	removed := map[string]bool{}
	for _, op := range change.Operations {
		removed[FirewallFingerprint(op.Scope, op.Zone, op.Kind, op.OldValue)] = true
	}
	need := sources
	if len(need) == 0 {
		need = []string{"0.0.0.0/0", "::/0"}
	}
	for _, source := range need {
		management, e := parsePrefix(source)
		if e != nil {
			return false
		}
		for _, rule := range snapshot.Rules {
			if rule.Scope != scope || rule.Zone != zone || rule.Kind != "rich_rule" || removed[rule.Fingerprint] {
				continue
			}
			info, err := parseRich(rule.Value)
			if err != nil {
				return false
			}
			if info.Action != "drop" && info.Action != "reject" {
				continue
			}
			matches, err := richTouchesSSH(ctx, runner, scope, info, []int{port})
			if err != nil {
				return false
			}
			if !matches {
				continue
			}
			if info.Family == "ipv4" && !management.Addr().Is4() || info.Family == "ipv6" && management.Addr().Is4() {
				continue
			}
			if info.Source == "" {
				return false
			}
			denied, err := netip.ParsePrefix(info.Source)
			if err != nil || prefixesOverlap(denied, management) {
				return false
			}
		}
		covered := false
		for _, rule := range snapshot.Rules {
			if rule.Scope != scope || rule.Zone != zone || removed[rule.Fingerprint] {
				continue
			}
			switch rule.Kind {
			case "port":
				if portIncludes(rule.Value, port) {
					covered = true
				}
			case "service":
				ports, e := servicePortValues(ctx, runner, scope, rule.Value)
				if e == nil {
					for _, value := range ports {
						if portIncludes(value, port) {
							covered = true
						}
					}
				}
			case "rich_rule":
				info, e := parseRich(rule.Value)
				if e != nil || info.Action != "accept" || info.Priority != 0 {
					continue
				}
				matches, e := richTouchesSSH(ctx, runner, scope, info, []int{port})
				if e != nil || !matches {
					continue
				}
				if info.Family == "ipv4" && !management.Addr().Is4() || info.Family == "ipv6" && management.Addr().Is4() {
					continue
				}
				if info.Source == "" {
					covered = true
				} else if allow, e := netip.ParsePrefix(info.Source); e == nil && prefixCovers(allow, management) {
					covered = true
				}
			}
		}
		if !covered {
			return false
		}
	}
	return true
}
func protectManagement(ctx context.Context, runner CommandRunner, c Config, snapshot *FirewallSnapshot, change FirewallChange) error {
	text, e := runner.Run(ctx, "ss", "-H", "-lntup")
	if e != nil {
		return errors.New("SSH management discovery unavailable; refusing firewall changes")
	}
	listeners := ParseSockets(text)
	socketBindings := []SocketBinding{}
	if text, e := runner.Run(ctx, "systemctl", "list-sockets", "--all", "--no-legend", "--no-pager", "--plain"); e == nil {
		socketBindings = ParseSystemdSockets(text)
	}
	listeners = EnrichListeners(listeners, readProcessCgroup, socketBindings)
	ports, e := protectedFirewallSSHPorts(listeners, c)
	if e != nil {
		return e
	}
	if err := protectExtendedManagement(ctx, runner, c, snapshot, change, ports); err != nil {
		return err
	}
	for _, op := range change.Operations {
		touches := false
		switch op.Kind {
		case "port":
			for _, port := range ports {
				if portIncludes(op.OldValue, port) {
					touches = true
				}
			}
		case "service":
			values, e := servicePortValues(ctx, runner, op.Scope, op.OldValue)
			if e != nil {
				return errors.New("service definition cannot be evaluated safely")
			}
			for _, value := range values {
				for _, port := range ports {
					if portIncludes(value, port) {
						touches = true
					}
				}
			}
			if op.Operation == "replace" {
				if _, e = servicePortValues(ctx, runner, op.Scope, op.NewValue); e != nil {
					return errors.New("new service definition unavailable or complex")
				}
			}
		case "rich_rule":
			old, _ := parseRich(op.OldValue)
			if old.Action == "accept" {
				touches, e = richTouchesSSH(ctx, runner, op.Scope, old, ports)
				if e != nil {
					return errors.New("old rich-rule service scope cannot be evaluated")
				}
			}
			if op.Operation == "replace" {
				newRule, _ := parseRich(op.NewValue)
				if newRule.Action == "drop" || newRule.Action == "reject" {
					matching, e := richTouchesSSH(ctx, runner, op.Scope, newRule, ports)
					if e != nil {
						return e
					}
					if matching {
						if newRule.Source == "" || len(c.ManagementSources) == 0 {
							return errors.New("new broad/unknown-source deny could block SSH management")
						}
						denied, _ := netip.ParsePrefix(newRule.Source)
						for _, source := range c.ManagementSources {
							management, e := parsePrefix(source)
							if e != nil || prefixesOverlap(denied, management) {
								return errors.New("new deny overlaps SSH management sources")
							}
						}
					}
				}
			}
		}
		if touches {
			for _, port := range ports {
				if !survivingManagementAllow(ctx, runner, snapshot, change, op.Scope, op.Zone, port, c.ManagementSources) {
					return errors.New("removing an SSH/broad allow requires an independent surviving management allowance")
				}
			}
		}
	}
	return nil
}
func (a *Agent) firewallJournalPath(id string) string {
	return filepath.Join(a.Config.StateDir, "firewall-changes", shaText(id)+".json")
}
func (a *Agent) saveFirewallJournal(journal *firewallJournal) error {
	journal.UpdatedAt = time.Now().UTC()
	return atomicJSON(a.firewallJournalPath(journal.ID), journal)
}
func (a *Agent) recordFirewallResult(result FirewallChangeResult) error {
	found := false
	for i, old := range a.State.FirewallChangeResults {
		if old.ID == result.ID && old.PlanDigest == result.PlanDigest {
			a.State.FirewallChangeResults[i] = result
			found = true
			break
		}
	}
	if !found {
		a.State.FirewallChangeResults = append(a.State.FirewallChangeResults, result)
	}
	if len(a.State.FirewallChangeResults) > 100 {
		a.State.FirewallChangeResults = a.State.FirewallChangeResults[len(a.State.FirewallChangeResults)-100:]
	}
	return a.save()
}
func (a *Agent) rollbackFirewallJournal(ctx context.Context, journal *firewallJournal) error {
	failures := []string{}
	uncertain := false
	for i := len(journal.Mutations) - 1; i >= 0; i-- {
		mutation := journal.Mutations[i]
		if !mutation.Completed {
			uncertain = true
			continue
		}
		if mutation.Kind == "target" {
			if err := a.rollbackFirewallTarget(ctx, mutation); err != nil {
				failures = append(failures, "target rollback failed: "+err.Error())
			}
			continue
		}
		present, e := firewallQuery(ctx, a.Commands, mutation.Scope, mutation.Zone, mutation.Kind, mutation.Value)
		if e != nil {
			failures = append(failures, "rollback read unavailable")
			continue
		}
		inverse := mutation
		if mutation.Operation == "add" {
			if !present {
				continue
			}
			inverse.Operation = "remove"
		} else {
			if present {
				continue
			}
			inverse.Operation = "add"
		}
		if e = firewallMutate(ctx, a.Commands, inverse); e != nil {
			failures = append(failures, "rollback mutation failed")
			continue
		}
		verified, e := firewallQuery(ctx, a.Commands, inverse.Scope, inverse.Zone, inverse.Kind, inverse.Value)
		if e != nil || verified != (inverse.Operation == "add") {
			failures = append(failures, "rollback verification failed")
		}
	}
	if uncertain {
		verified := CollectFirewallSnapshot(ctx, a.Commands, a.ownedFirewallObservationRules())
		if verified.Status != "ok" || verified.Digest != journal.Before.Digest {
			failures = append(failures, "unacknowledged mutation requires manual review; baseline was not verified")
		}
	}
	if len(failures) > 0 {
		journal.Status = "rollback_failed"
		_ = a.saveFirewallJournal(journal)
		return errors.New(strings.Join(failures, "; "))
	}
	journal.Status = "rolled_back"
	return a.saveFirewallJournal(journal)
}
func (a *Agent) executeFirewallMutation(ctx context.Context, journal *firewallJournal, mutation firewallMutation) error {
	if mutation.Kind == "target" {
		return a.executeFirewallTarget(ctx, journal, mutation)
	}
	present, e := firewallQuery(ctx, a.Commands, mutation.Scope, mutation.Zone, mutation.Kind, mutation.Value)
	if e != nil {
		return e
	}
	if mutation.Operation == "add" && present {
		return nil
	}
	if mutation.Operation == "remove" && !present {
		return errors.New("old rule disappeared before removal")
	}
	journal.Mutations = append(journal.Mutations, mutation)
	journal.Status = "applying"
	if e = a.saveFirewallJournal(journal); e != nil {
		return e
	}
	if e = firewallMutate(ctx, a.Commands, mutation); e != nil {
		return e
	}
	journal.Mutations[len(journal.Mutations)-1].Completed = true
	if e = a.saveFirewallJournal(journal); e != nil {
		return e
	}
	verified, e := firewallQuery(ctx, a.Commands, mutation.Scope, mutation.Zone, mutation.Kind, mutation.Value)
	if e != nil || verified != (mutation.Operation == "add") {
		return errors.New("firewall mutation read-back did not match")
	}
	return nil
}
func (a *Agent) applyFirewallChange(ctx context.Context, change FirewallChange) FirewallChangeResult {
	result := FirewallChangeResult{ID: change.ID, PlanDigest: change.PlanDigest, Status: "failed", CompletedAt: time.Now().UTC()}
	fail := func(message string) FirewallChangeResult {
		result.Message = message
		result.CompletedAt = time.Now().UTC()
		return result
	}
	if a.hostDefaultDenyGuarded() {
		return fail("whole-server default deny withholds imported mutations until reviewed fallback removal commits")
	}
	if !changeIDValid(change.ID) || !validDigest(change.PlanDigest) || !validDigest(change.ExpectedSnapshotDigest) {
		return fail("invalid approved-plan identity or snapshot digest")
	}
	if !time.Now().Before(change.ExpiresAt) {
		return fail("approved firewall plan expired")
	}
	if a.Simulate || !a.Config.AllowFirewallChanges {
		result.Status = "preview"
		return fail("approved change is preview-only until allow_firewall_changes is enabled on this endpoint")
	}
	identity := ""
	if a.Client != nil && a.Client.identity != nil {
		if certificate := a.Client.identity.Load(); certificate != nil && certificate.Leaf != nil {
			identity = certificate.Leaf.Subject.CommonName
		}
	}
	if err := validateEndpointApproval(a.Config, change.ApprovalProof, identity, time.Now().UTC(), false, "imported_firewall"); err != nil {
		return fail(err.Error())
	}
	lock, lockError := managedLock(a.Config.StateDir, true)
	if lockError != nil {
		return fail("another enforcement mutation or descendant still owns the mutation lease")
	}
	defer unlockManaged(lock)
	ctx = withManagedLease(ctx, lock)
	if change.ConfirmationCount < 1 {
		return fail("approved firewall change requires confirmation")
	}
	if a.firewallRecoveryError != "" {
		return fail("an interrupted firewall change requires local recovery review")
	}
	if restrictiveFirewallChange(change) && change.ConfirmationCount < 2 {
		return fail("restricting/deny changes require two confirmations")
	}
	for _, previous := range a.State.FirewallChangeResults {
		if previous.ID == change.ID && previous.PlanDigest != change.PlanDigest {
			result.Status = "conflict"
			return fail("plan ID was previously used with a different digest")
		}
	}
	snapshot := CollectFirewallSnapshot(ctx, a.Commands, a.ownedFirewallObservationRules())
	result.SnapshotDigest = snapshot.Digest
	if snapshot.Status != "ok" {
		return fail("fresh firewall inventory is incomplete; change refused")
	}
	if snapshot.Digest != change.ExpectedSnapshotDigest {
		result.Status = "conflict"
		return fail("firewall snapshot changed since approval")
	}
	if e := validateFirewallOperations(change, snapshot); e != nil {
		return fail(e.Error())
	}
	if e := protectManagement(ctx, a.Commands, a.Config, snapshot, change); e != nil {
		return fail(e.Error())
	}
	if e := a.firewallAuthorization(ctx, change); e != nil {
		return fail("fresh firewall authorization failed: " + e.Error())
	}
	journal := &firewallJournal{ID: change.ID, PlanDigest: change.PlanDigest, Status: "prepared", Before: *snapshot, Mutations: []firewallMutation{}}
	if e := a.saveFirewallJournal(journal); e != nil {
		return fail("could not persist pre-change backup; nothing changed")
	}
	for _, op := range change.Operations {
		if e := a.firewallAuthorization(ctx, change); e != nil {
			if rollback := a.rollbackFirewallJournal(ctx, journal); rollback != nil {
				return fail("firewall authorization revoked and rollback needs review")
			}
			return fail("firewall authorization revoked; completed mutations rolled back")
		}
		if op.Kind == "target" {
			if e := a.executeFirewallMutation(ctx, journal, firewallMutation{Scope: op.Scope, Zone: op.Zone, Kind: op.Kind, Value: op.NewValue, PreviousValue: op.OldValue, Operation: "set"}); e != nil {
				if rollback := a.rollbackFirewallJournal(ctx, journal); rollback != nil {
					return fail("target set failed and rollback needs manual review; local backup retained")
				}
				return fail("target set failed; completed mutations rolled back")
			}
			continue
		}
		if op.Operation == "replace" {
			if e := a.executeFirewallMutation(ctx, journal, firewallMutation{Scope: op.Scope, Zone: op.Zone, Kind: op.Kind, Value: op.NewValue, Operation: "add"}); e != nil {
				rollback := a.rollbackFirewallJournal(ctx, journal)
				if rollback != nil {
					return fail("add failed and rollback needs manual review; local backup retained")
				}
				return fail("change failed; completed mutations rolled back")
			}
		}
		if e := a.executeFirewallMutation(ctx, journal, firewallMutation{Scope: op.Scope, Zone: op.Zone, Kind: op.Kind, Value: op.OldValue, Operation: "remove"}); e != nil {
			rollback := a.rollbackFirewallJournal(ctx, journal)
			if rollback != nil {
				return fail("remove failed and rollback needs manual review; local backup retained")
			}
			return fail("change failed; completed mutations rolled back")
		}
	}
	after := CollectFirewallSnapshot(ctx, a.Commands, a.ownedFirewallObservationRules())
	if after.Status != "ok" {
		_ = a.rollbackFirewallJournal(ctx, journal)
		return fail("post-change inventory incomplete; rollback attempted and backup retained")
	}
	stagedTarget := false
	for _, op := range change.Operations {
		if op.Kind != "target" {
			continue
		}
		stagedTarget = true
		expected := op
		expected.OldValue = op.NewValue
		if _, present := findFirewallRule(after, expected); !present {
			if rollback := a.rollbackFirewallJournal(ctx, journal); rollback != nil {
				return fail("post-change target differs from approval and rollback needs review")
			}
			return fail("post-change target differs from approval; completed mutations rolled back")
		}
	}
	if e := a.firewallAuthorization(ctx, change); e != nil {
		if rollback := a.rollbackFirewallJournal(ctx, journal); rollback != nil {
			return fail("final firewall authorization revoked and rollback needs review")
		}
		return fail("final firewall authorization revoked; completed mutations rolled back")
	}
	result.Status = "applied"
	result.Message = "approved exact rule changes applied and read back; no reload or compiled-policy enforcement"
	if stagedTarget {
		result.Message = "approved permanent zone target staged and read back; runtime target unchanged by this plan; no reload"
	}
	result.SnapshotDigest = after.Digest
	result.CompletedAt = time.Now().UTC()
	journal.Status = "applied"
	if e := a.saveFirewallJournal(journal); e != nil {
		result.Status = "failed"
		result.Message = "rules changed but final journal commit failed; manual review required"
		return result
	}
	if a.inventory != nil {
		a.inventory.FirewallSnapshot = after
	}
	return result
}
func (a *Agent) processApprovedChanges(ctx context.Context, changes []FirewallChange) error {
	for _, change := range changes {
		skip := false
		for _, previous := range a.State.FirewallChangeResults {
			if previous.ID == change.ID && previous.PlanDigest == change.PlanDigest && (previous.Status != "preview" || !a.Config.AllowFirewallChanges || a.Simulate) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		// A previously committed journal remains authoritative if a final report/state write was interrupted.
		if data, e := os.ReadFile(a.firewallJournalPath(change.ID)); e == nil {
			var journal firewallJournal
			if json.Unmarshal(data, &journal) == nil && journal.PlanDigest == change.PlanDigest && journal.Status == "applied" {
				if e = a.recordFirewallResult(FirewallChangeResult{ID: change.ID, PlanDigest: change.PlanDigest, Status: "applied", Message: "replayed committed approved-change outcome", CompletedAt: journal.UpdatedAt}); e != nil {
					return e
				}
				continue
			}
		}
		result := a.applyFirewallChange(ctx, change)
		if result.Status != "applied" && a.Config.AllowFirewallChanges && !a.Simulate && a.inventory != nil {
			a.inventory.FirewallSnapshot = retainFirewallSnapshot(a.inventory.FirewallSnapshot, CollectFirewallSnapshot(ctx, a.Commands, a.ownedFirewallObservationRules()))
		}
		if e := a.recordFirewallResult(result); e != nil {
			return e
		}
	}
	return nil
}

func (a *Agent) recoverFirewallChanges(ctx context.Context) error {
	if a.Simulate {
		return nil
	}
	entries, e := os.ReadDir(filepath.Join(a.Config.StateDir, "firewall-changes"))
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	lock, lockError := managedLock(a.Config.StateDir, true)
	if lockError != nil {
		return errors.New("an enforcement descendant is still active; imported recovery is paused")
	}
	defer unlockManaged(lock)
	ctx = withManagedLease(ctx, lock)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, e := os.ReadFile(filepath.Join(a.Config.StateDir, "firewall-changes", entry.Name()))
		if e != nil {
			return e
		}
		var journal firewallJournal
		if json.Unmarshal(data, &journal) != nil || !changeIDValid(journal.ID) || entry.Name() != shaText(journal.ID)+".json" {
			return errors.New("invalid local approved-change journal; manual review required")
		}
		if journal.Status != "applying" && journal.Status != "prepared" && journal.Status != "rollback_failed" && journal.Status != "interrupted" {
			continue
		}
		message := "interrupted approved change; completed exact mutations rolled back"
		uncertain := false
		for _, mutation := range journal.Mutations {
			if !mutation.Completed {
				uncertain = true
			}
		}
		if !a.Config.AllowFirewallChanges {
			message = "interrupted change retained for manual review; changes are disabled"
		} else if e = a.rollbackFirewallJournal(ctx, &journal); e != nil {
			message = "interrupted change rollback failed; inspect local backup before new changes"
		} else {
			uncertain = false // Exact baseline was verified by rollbackFirewallJournal.
		}
		if uncertain {
			message += "; an unacknowledged command may need manual inspection"
		}
		// Uncertainty is durable. A later restart must attempt/verify the same
		// recovery rather than interpreting an old interrupted marker as success.
		if uncertain || !a.Config.AllowFirewallChanges || strings.Contains(message, "rollback failed") {
			journal.Status = "rollback_failed"
		}
		_ = a.saveFirewallJournal(&journal)
		if e = a.recordFirewallResult(FirewallChangeResult{ID: journal.ID, PlanDigest: journal.PlanDigest, Status: "failed", Message: message, CompletedAt: time.Now().UTC()}); e != nil {
			return e
		}
		if uncertain || !a.Config.AllowFirewallChanges || strings.Contains(message, "rollback failed") {
			return errors.New(message)
		}
	}
	return nil
}
