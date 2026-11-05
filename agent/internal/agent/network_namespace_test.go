package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const privateLoopbackAddresses = `[{"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP","LOWER_UP"],"mtu":65536,"qdisc":"noqueue","operstate":"UNKNOWN","linkmode":"DEFAULT","group":"default","txqlen":1000,"link_type":"loopback","address":"00:00:00:00:00:00","broadcast":"00:00:00:00:00:00","addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8,"scope":"host","label":"lo","valid_life_time":4294967295,"preferred_life_time":4294967295},{"family":"inet6","local":"::1","prefixlen":128,"scope":"host","valid_life_time":4294967295,"preferred_life_time":4294967295}]}]`
const privateLoopbackRoutes4 = `[{"type":"local","dst":"127.0.0.0/8","dev":"lo","protocol":"kernel","scope":"host","prefsrc":"127.0.0.1","table":"local","flags":[]},{"type":"local","dst":"127.0.0.1","dev":"lo","protocol":"kernel","scope":"host","prefsrc":"127.0.0.1","table":"local","flags":[]},{"type":"broadcast","dst":"127.255.255.255","dev":"lo","protocol":"kernel","scope":"link","prefsrc":"127.0.0.1","table":"local","flags":[]}]`
const privateLoopbackRoutes6 = `[{"type":"local","dst":"::1","dev":"lo","protocol":"kernel","table":"local","metric":0,"flags":[],"pref":"medium"},{"dst":"::1","dev":"lo","protocol":"kernel","metric":256,"flags":[],"pref":"medium"}]`

func namespaceTestProcess(t *testing.T, root string, pid int, namespace string) {
	t.Helper()
	directory := filepath.Join(root, "proc", strconv.Itoa(pid), "ns")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	// The fake runner never calls setns; the retained regular file lets tests
	// verify fd identity and process races through the same filesystem API.
	if err := os.WriteFile(filepath.Join(directory, namespace), []byte("fake namespace"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(namespace, filepath.Join(directory, "net")); err != nil {
		t.Fatal(err)
	}
	namespaceTestStart(t, root, pid, "1234")
}

func namespaceTestStart(t *testing.T, root string, pid int, start string) {
	t.Helper()
	text := fmt.Sprintf("%d (arbitrary sandbox name) S %s%s\n", pid, strings.Repeat("0 ", 18), start)
	if err := os.WriteFile(filepath.Join(root, "proc", strconv.Itoa(pid), "stat"), []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
}

func namespaceTestRoot(t *testing.T, count int) string {
	t.Helper()
	root := t.TempDir()
	for _, name := range []string{"proc/self/ns", "proc/1/ns", "proc/sys/net/ipv4", "proc/sys/net/ipv6/conf/all"} {
		if err := os.MkdirAll(filepath.Join(root, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"self", "1"} {
		if err := os.Symlink("net:[123]", filepath.Join(root, "proc", name, "ns/net")); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"proc/sys/net/ipv4/ip_forward", "proc/sys/net/ipv6/conf/all/forwarding"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("0\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for i := range count {
		namespaceTestProcess(t, root, i+2, fmt.Sprintf("net:[%d]", 456+i))
	}
	return root
}

type namespaceTestRunner struct {
	t                           *testing.T
	addresses, routes4, routes6 string
	calls                       int
	afterCall                   func(int)
	err                         error
	pinPaths                    []string
	addressesByPin              map[string]string
}

type activationNamespaceTestRunner struct{ private *namespaceTestRunner }

func (r activationNamespaceTestRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if name == "nsenter" {
		return r.private.Run(ctx, name, args...)
	}
	return (activationContextRunner{}).Run(ctx, name, args...)
}

func newNamespaceTestRunner(t *testing.T) *namespaceTestRunner {
	return &namespaceTestRunner{t: t, addresses: privateLoopbackAddresses, routes4: privateLoopbackRoutes4, routes6: privateLoopbackRoutes6}
}

func (r *namespaceTestRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	r.t.Helper()
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > 2*time.Second || ctx.Value(commandOutputLimitKey{}) != 65536 {
		r.t.Fatal("namespace child lost its time/output bound")
	}
	if name != "nsenter" || len(args) < 4 || !strings.HasPrefix(args[0], "--net=/proc/"+strconv.Itoa(os.Getpid())+"/fd/") || args[1] != "--" || args[2] != "ip" {
		r.t.Fatal("namespace was not entered through retained fd by a read-only ip child", name, args)
	}
	r.calls++
	r.pinPaths = append(r.pinPaths, args[0])
	if r.afterCall != nil {
		r.afterCall(r.calls)
	}
	switch strings.Join(args[3:], " ") {
	case "-j address show":
		if value, present := r.addressesByPin[args[0]]; present {
			return value, r.err
		}
		return r.addresses, r.err
	case "-j -4 route show table all":
		return r.routes4, r.err
	case "-j -6 route show table all":
		return r.routes6, r.err
	default:
		r.t.Fatal("namespace inspection attempted an unexpected command", args)
		return "", errors.New("unexpected namespace command")
	}
}

func TestLoopbackOnlyPrivateNetworkNamespacesAreProvenAndBoundToContext(t *testing.T) {
	root := namespaceTestRoot(t, 2)
	runner := newNamespaceTestRunner(t)
	first, err := networkNamespace(context.Background(), runner, root)
	if err != nil || !validDigest(first) || runner.calls != 12 {
		t.Fatal("two independently read and stable loopback namespaces rejected", first, err, runner.calls)
	}
	second, err := networkNamespace(context.Background(), runner, root)
	if err != nil || first != second {
		t.Fatal("same namespace evidence did not produce a stable context", err)
	}
	runner.addresses = `[{"ifindex":1,"ifname":"lo","flags":["LOOPBACK"],"link_type":"loopback","addr_info":[]}]`
	runner.routes4, runner.routes6 = "[]", "[]"
	third, err := networkNamespace(context.Background(), runner, root)
	if err != nil || first == third {
		t.Fatal("safe topology change did not invalidate the reviewed context", err)
	}
}

func TestFirewallActivationBindsTheSafePrivateNamespaceProof(t *testing.T) {
	root, runner := namespaceTestRoot(t, 1), newNamespaceTestRunner(t)
	first, err := activationInactiveContext(context.Background(), activationNamespaceTestRunner{runner}, root, false, nil)
	if err != nil || !validDigest(first) {
		t.Fatal("ordinary host with proven loopback sandbox could not be assessed", err)
	}
	runner.addresses = `[{"ifindex":1,"ifname":"lo","flags":["LOOPBACK"],"link_type":"loopback","addr_info":[]}]`
	runner.routes4, runner.routes6 = "[]", "[]"
	second, err := activationInactiveContext(context.Background(), activationNamespaceTestRunner{runner}, root, false, nil)
	if err != nil || first == second {
		t.Fatal("changed sandbox context did not invalidate the reviewed activation digest", err)
	}
}

func TestPrivateNamespaceProofRejectsRoutedMalformedOrUnboundedTopology(t *testing.T) {
	for name, change := range map[string]func(*namespaceTestRunner){
		"additional interface": func(r *namespaceTestRunner) {
			r.addresses = strings.TrimSuffix(r.addresses, "]") + `,{"ifindex":2,"ifname":"eth0","link_type":"ether","addr_info":[]}]`
		},
		"renamed interface":   func(r *namespaceTestRunner) { r.addresses = strings.ReplaceAll(r.addresses, `"lo"`, `"eth0"`) },
		"nonloopback address": func(r *namespaceTestRunner) { r.addresses = strings.ReplaceAll(r.addresses, "127.0.0.1", "10.0.0.1") },
		"incorrect loopback prefix": func(r *namespaceTestRunner) {
			r.addresses = strings.ReplaceAll(r.addresses, `"prefixlen":8`, `"prefixlen":0`)
		},
		"duplicate JSON key": func(r *namespaceTestRunner) {
			r.addresses = strings.Replace(r.addresses, `"ifindex":1`, `"ifindex":1,"ifindex":1`, 1)
		},
		"unsupported link type metadata": func(r *namespaceTestRunner) {
			r.addresses = strings.Replace(r.addresses, `"ifindex":1`, `"ifindex":1,"linkinfo":{"info_kind":"veth"}`, 1)
		},
		"malformed link flags": func(r *namespaceTestRunner) {
			r.addresses = strings.Replace(r.addresses, `"LOOPBACK"`, `{"LOOPBACK":true}`, 1)
		},
		"malformed address lifetime": func(r *namespaceTestRunner) {
			r.addresses = strings.ReplaceAll(r.addresses, `"valid_life_time":4294967295`, `"valid_life_time":[]`)
		},
		"default route":      func(r *namespaceTestRunner) { r.routes4 = `[{"dst":"default","dev":"lo","protocol":"kernel"}]` },
		"IPv6 default route": func(r *namespaceTestRunner) { r.routes6 = `[{"dst":"::/0","dev":"lo","protocol":"kernel"}]` },
		"gateway route": func(r *namespaceTestRunner) {
			r.routes4 = `[{"dst":"127.0.0.0/8","dev":"lo","protocol":"kernel","gateway":"127.0.0.1"}]`
		},
		"nonloopback route":           func(r *namespaceTestRunner) { r.routes4 = `[{"dst":"10.0.0.0/8","dev":"lo","protocol":"kernel"}]` },
		"nonloopback route interface": func(r *namespaceTestRunner) { r.routes4 = strings.ReplaceAll(r.routes4, `"lo"`, `"eth0"`) },
		"unexpected route table": func(r *namespaceTestRunner) {
			r.routes4 = strings.ReplaceAll(r.routes4, `"table":"local"`, `"table":100`)
		},
		"malformed route metric": func(r *namespaceTestRunner) { r.routes6 = strings.ReplaceAll(r.routes6, `"metric":256`, `"metric":[]`) },
		"invalid route JSON":     func(r *namespaceTestRunner) { r.routes4 = "null" },
		"unavailable nsenter":    func(r *namespaceTestRunner) { r.err = errors.New("permission denied") },
		"oversized output":       func(r *namespaceTestRunner) { r.addresses += strings.Repeat(" ", 65537) },
	} {
		t.Run(name, func(t *testing.T) {
			root, runner := namespaceTestRoot(t, 1), newNamespaceTestRunner(t)
			change(runner)
			if _, err := networkNamespace(context.Background(), runner, root); err == nil {
				t.Fatal("unverified private namespace admitted")
			} else if !strings.Contains(err.Error(), "net:[456] (PID 2)") {
				t.Fatal("actionable namespace/PID reason lost", err)
			}
		})
	}
}

func TestPrivateNamespaceProofRejectsProcessAndTopologyRaces(t *testing.T) {
	for name, change := range map[string]func(*testing.T, string, *namespaceTestRunner){
		"PID reused": func(t *testing.T, root string, r *namespaceTestRunner) {
			r.afterCall = func(n int) {
				if n == 1 {
					namespaceTestStart(t, root, 2, "5678")
				}
			}
		},
		"process exited": func(t *testing.T, root string, r *namespaceTestRunner) {
			r.afterCall = func(n int) {
				if n == 1 {
					_ = os.RemoveAll(filepath.Join(root, "proc/2"))
				}
			}
		},
		"namespace inode replaced": func(t *testing.T, root string, r *namespaceTestRunner) {
			r.afterCall = func(n int) {
				if n == 1 {
					path := filepath.Join(root, "proc/2/ns/net:[456]")
					_ = os.Rename(path, path+"-old")
					_ = os.WriteFile(path, []byte("new inode"), 0600)
				}
			}
		},
		"private membership changed": func(t *testing.T, root string, r *namespaceTestRunner) {
			r.afterCall = func(n int) {
				if n == 6 {
					namespaceTestProcess(t, root, 3, "net:[789]")
				}
			}
		},
		"topology changed": func(t *testing.T, root string, r *namespaceTestRunner) {
			r.afterCall = func(n int) {
				if n == 4 {
					r.routes4 = "[]"
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			root, runner := namespaceTestRoot(t, 1), newNamespaceTestRunner(t)
			change(t, root, runner)
			if _, err := networkNamespace(context.Background(), runner, root); err == nil {
				t.Fatal("raced private namespace proof accepted")
			}
		})
	}
}

func TestPrivateNamespaceInventorySweepsCatchEarlierNamespaceTopologyRace(t *testing.T) {
	root, runner := namespaceTestRoot(t, 2), newNamespaceTestRunner(t)
	runner.addressesByPin = map[string]string{}
	runner.afterCall = func(n int) {
		if n == 4 {
			if runner.pinPaths[0] == runner.pinPaths[3] {
				t.Fatal("namespace pins were closed and reused between inventory entries")
			}
			// Namespace 1 changes during namespace 2's first inspection. Its
			// PID, inode and membership remain unchanged throughout.
			runner.addressesByPin[runner.pinPaths[0]] = strings.Replace(privateLoopbackAddresses, `"LOOPBACK","UP","LOWER_UP"`, `"LOOPBACK","UP"`, 1)
		}
	}
	if _, err := networkNamespace(context.Background(), runner, root); err == nil || !strings.Contains(err.Error(), "topology changed between inventory sweeps") {
		t.Fatal("earlier namespace topology change was missed by whole-inventory sweeps", err)
	}
}

func TestPrivateNamespaceProofRejectsCountContainerAndCancellation(t *testing.T) {
	root, runner := namespaceTestRoot(t, 9), newNamespaceTestRunner(t)
	if _, err := networkNamespace(context.Background(), runner, root); err == nil || runner.calls != 0 {
		t.Fatal("namespace-count bound did not fail before child commands", err)
	}
	root = namespaceTestRoot(t, 1)
	if err := os.WriteFile(filepath.Join(root, ".dockerenv"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := networkNamespace(context.Background(), runner, root); err == nil {
		t.Fatal("containerized agent admitted")
	}
	root = namespaceTestRoot(t, 1)
	ctx, cancel := context.WithCancel(context.Background())
	runner.afterCall = func(int) { cancel() }
	if _, err := networkNamespace(ctx, runner, root); err == nil {
		t.Fatal("canceled namespace inspection admitted")
	}
}
