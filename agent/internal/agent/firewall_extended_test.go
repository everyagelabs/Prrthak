package agent

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestExtendedDirectParserPreservesTypedArgvAndNormalizesRanges(t *testing.T) {
	tests := []struct {
		name, value, source, protocol, action string
		first, last                           int
		args                                  []string
	}{
		{"minimal", "ipv4 filter INPUT 0 -p tcp --dport 8080 -j ACCEPT", "", "tcp", "ACCEPT", 8080, 8080,
			[]string{"ipv4", "filter", "INPUT", "0", "-p", "tcp", "--dport", "8080", "-j", "ACCEPT"}},
		{"source-and-module", "ipv4 filter INPUT 32767 -s 192.0.2.19/24 -p tcp -m tcp --dport 8080-8090 -j DROP", "192.0.2.0/24", "tcp", "DROP", 8080, 8090,
			[]string{"ipv4", "filter", "INPUT", "32767", "-s", "192.0.2.19/24", "-p", "tcp", "-m", "tcp", "--dport", "8080:8090", "-j", "DROP"}},
		{"ipv6-reordered-options", "ipv6 filter INPUT 10 --dport 1024:2048 -j REJECT -p udp -s 2001:db8::1/64 -m udp", "2001:db8::/64", "udp", "REJECT", 1024, 2048,
			[]string{"ipv6", "filter", "INPUT", "10", "--dport", "1024:2048", "-j", "REJECT", "-p", "udp", "-s", "2001:db8::1/64", "-m", "udp"}},
		{"module-after-port-and-boundaries", "ipv4 filter INPUT 1 -j DROP --dport 1-65535 -m udp -p udp", "", "udp", "DROP", 1, 65535,
			[]string{"ipv4", "filter", "INPUT", "1", "-j", "DROP", "--dport", "1:65535", "-m", "udp", "-p", "udp"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseDirect(test.value)
			if err != nil {
				t.Fatal(err)
			}
			if got.Source != test.source || got.Protocol != test.protocol || got.Action != test.action || got.First != test.first || got.Last != test.last {
				t.Fatalf("unexpected typed rule: %+v", got)
			}
			if !reflect.DeepEqual(got.Args, test.args) {
				t.Fatalf("argv changed: got %q, want %q", got.Args, test.args)
			}
		})
	}
}

func TestExtendedDirectParserRejectsUnreviewableOrInjectedRules(t *testing.T) {
	base := "ipv4 filter INPUT 0 -p tcp --dport 8080 -j ACCEPT"
	tests := map[string]string{
		"empty":                    "",
		"too-long":                 strings.Repeat(" ", 2049) + base,
		"unsupported-family":       strings.Replace(base, "ipv4", "eb", 1),
		"nat-table":                strings.Replace(base, "filter", "nat", 1),
		"output-chain":             strings.Replace(base, "INPUT", "OUTPUT", 1),
		"custom-chain":             strings.Replace(base, "INPUT", "custom", 1),
		"negative-priority":        strings.Replace(base, "INPUT 0", "INPUT -1", 1),
		"signed-priority":          strings.Replace(base, "INPUT 0", "INPUT +1", 1),
		"priority-overflow":        strings.Replace(base, "INPUT 0", "INPUT 32768", 1),
		"priority-word":            strings.Replace(base, "INPUT 0", "INPUT first", 1),
		"missing-protocol":         "ipv4 filter INPUT 0 --dport 8080 -j ACCEPT",
		"icmp":                     strings.Replace(base, "-p tcp", "-p icmp", 1),
		"duplicate-protocol":       base + " -p tcp",
		"duplicate-source":         base + " -s 192.0.2.0/24 -s 192.0.2.0/24",
		"duplicate-port":           base + " --dport 8080",
		"duplicate-action":         base + " -j ACCEPT",
		"duplicate-module":         base + " -m tcp -m tcp",
		"mismatched-module":        base + " -m udp",
		"state-module":             base + " -m state",
		"wrong-source-family":      base + " -s 2001:db8::/64",
		"wrong-ipv6-source-family": "ipv6 filter INPUT 0 -s 192.0.2.0/24 -p tcp --dport 8080 -j DROP",
		"hostname-source":          base + " -s example.invalid",
		"invalid-prefix":           base + " -s 192.0.2.0/33",
		"negated-source":           base + " ! -s 192.0.2.0/24",
		"interface":                base + " -i eth0",
		"destination":              base + " -d 192.0.2.1/32",
		"source-port":              base + " --sport 1234",
		"return-action":            strings.Replace(base, "ACCEPT", "RETURN", 1),
		"log-action":               strings.Replace(base, "ACCEPT", "LOG", 1),
		"lowercase-action":         strings.Replace(base, "ACCEPT", "accept", 1),
		"named-port":               strings.Replace(base, "8080", "http", 1),
		"zero-port":                strings.Replace(base, "8080", "0", 1),
		"port-overflow":            strings.Replace(base, "8080", "65536", 1),
		"reverse-hyphen":           strings.Replace(base, "8080", "8090-8080", 1),
		"reverse-colon":            strings.Replace(base, "8080", "8090:8080", 1),
		"multiple-range":           strings.Replace(base, "8080", "80:90:100", 1),
		"signed-port":              strings.Replace(base, "8080", "+80", 1),
		"port-list":                strings.Replace(base, "8080", "80,443", 1),
		"trailing-option":          base + " --syn",
		"semicolon":                base + "; id",
		"substitution":             strings.Replace(base, "8080", "$(id)", 1),
		"backticks":                strings.Replace(base, "8080", "`id`", 1),
		"single-quote":             strings.Replace(base, "8080", "'8080'", 1),
		"double-quote":             strings.Replace(base, "8080", "\"8080\"", 1),
		"backslash":                base + "\\",
		"newline":                  base + "\n",
		"carriage-return":          base + "\r",
		"tab":                      strings.Replace(base, " -p", "\t-p", 1),
		"nul":                      base + "\x00",
		"delete-control":           base + "\x7f",
	}
	for name, value := range tests {
		t.Run(name, func(t *testing.T) {
			if got, err := parseDirect(value); err == nil {
				t.Fatalf("unsafe rule accepted: %q -> %+v", value, got)
			}
		})
	}
}

func TestExtendedForwardPortParserRequiresExactLocalRedirect(t *testing.T) {
	valid := []struct {
		value               string
		first, last, toPort int
		protocol            string
	}{
		{"port=8080:proto=tcp:toport=80:toaddr=", 8080, 8080, 80, "tcp"},
		{"port=1000-2000:proto=udp:toport=5353:toaddr=", 1000, 2000, 5353, "udp"},
		{"port=1-65535:proto=tcp:toport=65535:toaddr=", 1, 65535, 65535, "tcp"},
	}
	for _, test := range valid {
		t.Run(test.value, func(t *testing.T) {
			got, err := parseForwardPort(test.value)
			if err != nil || got.First != test.first || got.Last != test.last || got.ToPort != test.toPort || got.Protocol != test.protocol {
				t.Fatalf("unexpected local redirect: %+v, %v", got, err)
			}
		})
	}
	for _, value := range []string{
		"", "port=8080:proto=tcp:toport=80", "port=8080:proto=tcp:toport=80:toaddr=192.0.2.1",
		"port=8080:proto=tcp:toport=80:toaddr=2001:db8::1", "port=8080:proto=tcp:toport=:toaddr=",
		"port=8080:proto=tcp:toport=80-90:toaddr=", "port=8080:proto=tcp:toport=0:toaddr=",
		"port=8080:proto=tcp:toport=65536:toaddr=", "port=0:proto=tcp:toport=80:toaddr=",
		"port=65536:proto=tcp:toport=80:toaddr=", "port=8090-8080:proto=tcp:toport=80:toaddr=",
		"port=8080:8090:proto=tcp:toport=80:toaddr=", "port=http:proto=tcp:toport=80:toaddr=",
		"port=8080:proto=sctp:toport=80:toaddr=", "port=8080:proto=TCP:toport=80:toaddr=",
		"proto=tcp:port=8080:toport=80:toaddr=", "port=8080:proto=tcp:proto=tcp:toport=80:toaddr=",
		"port=8080:proto=tcp:toport=80:toaddr=:family=ipv4", "port=8080:proto=tcp:toport=80:toaddr=;id",
		" port=8080:proto=tcp:toport=80:toaddr=", "port=8080:proto=tcp:toport=80:toaddr=\n",
	} {
		t.Run("reject/"+value, func(t *testing.T) {
			if got, err := parseForwardPort(value); err == nil {
				t.Fatalf("unsafe redirect accepted: %q -> %+v", value, got)
			}
		})
	}
}

func TestExtendedZoneTargetIsAnExactEnum(t *testing.T) {
	for _, value := range []string{"ACCEPT", "DROP", "REJECT", "default"} {
		if !validZoneTarget(value) {
			t.Errorf("valid target rejected: %q", value)
		}
	}
	for _, value := range []string{"", "accept", "DEFAULT", "Default", "ACCEPT ", " DROP", "ACCEPT\n", "ACCEPT;id", "RETURN", "LOG"} {
		if validZoneTarget(value) {
			t.Errorf("unsafe target accepted: %q", value)
		}
	}
}

type extendedCommandCall struct {
	name string
	args []string
}

type extendedArgvRunner struct {
	calls []extendedCommandCall
	out   string
	err   error
}

func (r *extendedArgvRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.calls = append(r.calls, extendedCommandCall{name, append([]string{}, args...)})
	if len(args) > 0 && strings.HasPrefix(args[len(args)-1], "--set-target=") && r.err == nil {
		return "success", nil
	}
	return r.out, r.err
}

func requireExtendedCalls(t *testing.T, runner *extendedArgvRunner, args ...[]string) {
	t.Helper()
	want := make([]extendedCommandCall, 0, len(args))
	for _, value := range args {
		want = append(want, extendedCommandCall{"firewall-cmd", value})
	}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("unexpected command argv: got %#v, want %#v", runner.calls, want)
	}
}

func TestExtendedFirewallQueriesUseTypedArgv(t *testing.T) {
	direct := "ipv4 filter INPUT 7 -p tcp --dport 8080-8082 -j DROP"
	forward := "port=8080:proto=tcp:toport=80:toaddr="
	tests := []struct {
		name, scope, zone, kind, value, out string
		present                             bool
		args                                []string
	}{
		{"target-matches", "permanent", "public", "target", "DROP", "DROP\n", true, []string{"--permanent", "--zone=public", "--get-target"}},
		{"target-differs", "permanent", "public", "target", "DROP", "ACCEPT\n", false, []string{"--permanent", "--zone=public", "--get-target"}},
		{"direct-runtime", "runtime", "", "direct", direct, "yes\n", true, []string{"--direct", "--query-rule", "ipv4", "filter", "INPUT", "7", "-p", "tcp", "--dport", "8080:8082", "-j", "DROP"}},
		{"direct-permanent", "permanent", "", "direct", direct, "no\n", false, []string{"--permanent", "--direct", "--query-rule", "ipv4", "filter", "INPUT", "7", "-p", "tcp", "--dport", "8080:8082", "-j", "DROP"}},
		{"forward-runtime", "runtime", "public", "forward_port", forward, "yes", true, []string{"--zone=public", "--query-forward-port=" + forward}},
		{"forward-permanent", "permanent", "public", "forward_port", forward, "no", false, []string{"--permanent", "--zone=public", "--query-forward-port=" + forward}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := &extendedArgvRunner{out: test.out}
			got, err := firewallQuery(context.Background(), runner, test.scope, test.zone, test.kind, test.value)
			if err != nil || got != test.present {
				t.Fatalf("query returned %v, %v", got, err)
			}
			requireExtendedCalls(t, runner, test.args)
		})
	}
}

func TestExtendedFirewallMutationsUseTypedArgvAndCheckTargetPrecondition(t *testing.T) {
	direct := "ipv6 filter INPUT 0 --dport 8080-8082 -p udp -j REJECT"
	forward := "port=8080-8082:proto=udp:toport=5353:toaddr="
	for _, operation := range []string{"add", "remove"} {
		t.Run("direct/"+operation, func(t *testing.T) {
			runner := &extendedArgvRunner{out: "success"}
			if err := firewallMutate(context.Background(), runner, firewallMutation{Scope: "permanent", Kind: "direct", Value: direct, Operation: operation}); err != nil {
				t.Fatal(err)
			}
			requireExtendedCalls(t, runner, []string{"--permanent", "--direct", "--" + operation + "-rule", "ipv6", "filter", "INPUT", "0", "--dport", "8080:8082", "-p", "udp", "-j", "REJECT"})
		})
		t.Run("forward/"+operation, func(t *testing.T) {
			runner := &extendedArgvRunner{out: "success"}
			if err := firewallMutate(context.Background(), runner, firewallMutation{Scope: "runtime", Zone: "public", Kind: "forward_port", Value: forward, Operation: operation}); err != nil {
				t.Fatal(err)
			}
			requireExtendedCalls(t, runner, []string{"--zone=public", "--" + operation + "-forward-port=" + forward})
		})
	}
	t.Run("target-check-and-set", func(t *testing.T) {
		runner := &extendedArgvRunner{out: "ACCEPT\n"}
		if err := firewallMutate(context.Background(), runner, firewallMutation{Scope: "permanent", Zone: "public", Kind: "target", PreviousValue: "ACCEPT", Value: "DROP", Operation: "set"}); err != nil {
			t.Fatal(err)
		}
		requireExtendedCalls(t, runner, []string{"--permanent", "--zone=public", "--get-target"}, []string{"--permanent", "--zone=public", "--set-target=DROP"})
	})
	t.Run("target-concurrent-change-is-not-overwritten", func(t *testing.T) {
		runner := &extendedArgvRunner{out: "REJECT"}
		if err := firewallMutate(context.Background(), runner, firewallMutation{Scope: "permanent", Zone: "public", Kind: "target", PreviousValue: "ACCEPT", Value: "DROP", Operation: "set"}); err == nil {
			t.Fatal("third-party target was overwritten")
		}
		requireExtendedCalls(t, runner, []string{"--permanent", "--zone=public", "--get-target"})
	})
}

func TestExtendedFirewallMutationFailuresDoNotBecomeSuccess(t *testing.T) {
	for _, failure := range []struct {
		name, output string
		err          error
	}{
		{"command-error", "", errors.New("command failed")},
		{"already-enabled", "ALREADY_ENABLED", nil},
		{"not-enabled", "NOT_ENABLED", nil},
	} {
		t.Run(failure.name, func(t *testing.T) {
			runner := &extendedArgvRunner{out: failure.output, err: failure.err}
			if err := firewallMutate(context.Background(), runner, firewallMutation{Scope: "runtime", Kind: "direct", Value: "ipv4 filter INPUT 0 -p tcp --dport 8080 -j DROP", Operation: "add"}); err == nil {
				t.Fatal("ambiguous or failed mutation reported success")
			}
			if len(runner.calls) != 1 {
				t.Fatalf("unexpected fallback commands: %#v", runner.calls)
			}
		})
	}
}

func TestExtendedFirewallRejectsUnsafeMutationBeforeRunner(t *testing.T) {
	direct := "ipv4 filter INPUT 0 -p tcp --dport 8080 -j DROP"
	for name, mutation := range map[string]firewallMutation{
		"direct-zone":       {Scope: "runtime", Zone: "public", Kind: "direct", Value: direct, Operation: "add"},
		"direct-scope":      {Scope: "unknown", Kind: "direct", Value: direct, Operation: "add"},
		"direct-extra-args": {Scope: "runtime", Kind: "direct", Value: direct + " -i eth0", Operation: "remove"},
		"routed-forward":    {Scope: "runtime", Zone: "public", Kind: "forward_port", Value: "port=8080:proto=tcp:toport=80:toaddr=192.0.2.1", Operation: "add"},
		"runtime-target":    {Scope: "runtime", Zone: "public", Kind: "target", PreviousValue: "ACCEPT", Value: "DROP", Operation: "set"},
		"remove-target":     {Scope: "permanent", Zone: "public", Kind: "target", PreviousValue: "ACCEPT", Value: "DROP", Operation: "remove"},
		"invalid-target":    {Scope: "permanent", Zone: "public", Kind: "target", PreviousValue: "ACCEPT", Value: "DROP;id", Operation: "set"},
		"missing-baseline":  {Scope: "permanent", Zone: "public", Kind: "target", Value: "DROP", Operation: "set"},
		"no-op-target":      {Scope: "permanent", Zone: "public", Kind: "target", PreviousValue: "DROP", Value: "DROP", Operation: "set"},
	} {
		t.Run(name, func(t *testing.T) {
			runner := &extendedArgvRunner{out: "success"}
			if err := firewallMutate(context.Background(), runner, mutation); err == nil {
				t.Fatalf("unsafe mutation accepted: %+v", mutation)
			}
			if len(runner.calls) != 0 {
				t.Fatalf("unsafe mutation reached command runner: %#v", runner.calls)
			}
		})
	}
}

func TestExtendedFirewallQueriesFailClosedOnUnreadableState(t *testing.T) {
	for _, test := range []struct {
		name, scope, zone, kind, value, out string
		err                                 error
	}{
		{"direct-read-error", "runtime", "", "direct", "ipv4 filter INPUT 0 -p tcp --dport 8080 -j DROP", "yes", errors.New("read unavailable")},
		{"direct-unknown-response", "runtime", "", "direct", "ipv4 filter INPUT 0 -p tcp --dport 8080 -j DROP", "success", nil},
		{"target-read-error", "permanent", "public", "target", "DROP", "DROP", errors.New("read unavailable")},
		{"target-unknown-response", "permanent", "public", "target", "DROP", "RETURN", nil},
		{"forward-read-error", "runtime", "public", "forward_port", "port=8080:proto=tcp:toport=80:toaddr=", "yes", errors.New("read unavailable")},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := &extendedArgvRunner{out: test.out, err: test.err}
			if _, err := firewallQuery(context.Background(), runner, test.scope, test.zone, test.kind, test.value); err == nil {
				t.Fatal("unknown or failed read reported success")
			}
			if len(runner.calls) != 1 {
				t.Fatalf("unexpected fallback commands: %#v", runner.calls)
			}
		})
	}
}
