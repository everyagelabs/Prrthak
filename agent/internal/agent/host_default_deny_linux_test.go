//go:build linux

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Packet injection crosses a veth pair inside one disposable network namespace.
// Neither SYS_ADMIN, nested namespaces, host networking nor host firewall access
// is needed. The peer has no test IP, preventing a local-route/loopback bypass.
const hostDenyPacketProbe = `import socket,struct,random,time,sys
family,source,target,port,kind=sys.argv[1],sys.argv[2],sys.argv[3],int(sys.argv[4]),sys.argv[5]
v6=family=='6'; af=socket.AF_INET6 if v6 else socket.AF_INET
src=socket.inet_pton(af,source); dst=socket.inet_pton(af,target)
def mac(name):return bytes.fromhex(open('/sys/class/net/'+name+'/address').read().strip().replace(':',''))
eth=mac('hd-host')+mac('hd-peer')+struct.pack('!H',0x86dd if v6 else 0x0800)
def checksum(x):
 if len(x)%2:x+=b'\x00'
 n=sum(struct.unpack('!%dH'%(len(x)//2),x));n=(n>>16)+(n&65535);n+=(n>>16);return ~n&65535
proto=(58 if v6 else 1) if kind=='icmp' else (17 if kind=='udp' else 6)
sport=random.randrange(20000,60000); seq=random.randrange(1,2**30)
def send(flags=2,ack=0,payload=b''):
 if proto==6:
  l4=struct.pack('!HHIIHHHH',sport,port,seq+(1 if flags!=2 else 0),ack,0x5000|flags,64000,0,0)+payload
 elif proto==17:l4=struct.pack('!HHHH',sport,port,8+len(payload),0)+payload
 else:l4=struct.pack('!BBHHH',128 if v6 else 8,0,0,sport,1)+payload
 pseudo=src+dst+(struct.pack('!I3xB',len(l4),proto) if v6 else struct.pack('!BBH',0,proto,len(l4)))
 if proto==1:pseudo=b''
 off=16 if proto==6 else (6 if proto==17 else 2);l4=l4[:off]+struct.pack('!H',checksum(pseudo+l4) or 65535)+l4[off+2:]
 if v6:ip=struct.pack('!IHBB16s16s',6<<28,len(l4),proto,64,src,dst)
 else:
  ip=struct.pack('!BBHHHBBH4s4s',69,0,20+len(l4),random.randrange(65536),0,64,proto,0,src,dst);ip=ip[:10]+struct.pack('!H',checksum(ip))+ip[12:]
 s.send(eth+ip+l4)
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));s.bind(('hd-peer',0));s.settimeout(.05)
send(payload=b'prthak-control-probe' if proto!=6 else b'');deadline=time.monotonic()+.8;allowed=False;syn=False
while time.monotonic()<deadline:
 try:raw=s.recv(65535)
 except socket.timeout:continue
 if len(raw)<54:continue
 if v6:
  if raw[12:14]!=b'\x86\xdd' or raw[20]!=proto or raw[22:38]!=dst or raw[38:54]!=src:continue
  off=54
 else:
  if raw[12:14]!=b'\x08\x00' or raw[23]!=proto or raw[26:30]!=dst or raw[30:34]!=src:continue
  off=14+(raw[14]&15)*4
 if len(raw)<off+8:continue
 if kind=='icmp':
  allowed=raw[off]==(129 if v6 else 0) and struct.unpack('!H',raw[off+4:off+6])[0]==sport and b'prthak-control-probe' in raw[off+8:]
  if allowed:break
  continue
 a,b=struct.unpack('!HH',raw[off:off+4])
 if a!=port or b!=sport:continue
 if proto==17:allowed=b'prthak-control-probe' in raw[off+8:];break
 if len(raw)<off+20:continue
 flags=raw[off+13];serverseq=struct.unpack('!I',raw[off+4:off+8])[0]
 if flags&18==18:
  syn=True
  if kind!='ssh':allowed=True;send(4,serverseq+1);break
  send(16,serverseq+1)
 elif kind=='ssh' and syn:
  offset=(raw[off+12]>>4)*4
  if raw[off+offset:].startswith(b'SSH-2.0-'):allowed=True;send(4,serverseq+1);break
print('ALLOW' if allowed else 'DENY')
`

func TestRealHostDefaultDenyPrivateLinuxPackets(t *testing.T) {
	if os.Getenv("PRTHAK_HOST_DEFAULT_DENY_LINUX_SMOKE") != "1" {
		t.Skip("explicit disposable NET_ADMIN/NET_RAW private-network container only")
	}
	if _, err := os.Stat("/run/prthak-private-netns"); err != nil {
		t.Fatal("missing private namespace fixture marker")
	}
	ctx := context.Background()
	runner := ExecRunner{}
	command := func(name string, args ...string) {
		t.Helper()
		if out, err := runner.Run(ctx, name, args...); err != nil {
			t.Fatalf("%s %v: %s %v", name, args, out, err)
		}
	}
	command("ip", "link", "add", "hd-host", "type", "veth", "peer", "name", "hd-peer")
	defer runner.Run(ctx, "ip", "link", "delete", "hd-host")
	for _, device := range []string{"hd-host", "hd-peer"} {
		command("ip", "link", "set", device, "up")
	}
	command("ip", "addr", "add", "10.253.0.1/24", "dev", "hd-host")
	v6 := os.Getenv("PRTHAK_HOST_DEFAULT_DENY_IPV6_DISABLED") != "1"
	if v6 {
		command("ip", "-6", "addr", "add", "fd00:253::1/64", "dev", "hd-host", "nodad")
	}
	peerMac, err := os.ReadFile("/sys/class/net/hd-peer/address")
	if err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"2", "3", "4"} {
		command("ip", "neigh", "replace", "10.253.0."+suffix, "lladdr", strings.TrimSpace(string(peerMac)), "dev", "hd-host", "nud", "permanent")
		if v6 {
			command("ip", "-6", "neigh", "replace", "fd00:253::"+suffix, "lladdr", strings.TrimSpace(string(peerMac)), "dev", "hd-host", "nud", "permanent")
		}
	}
	command("firewall-cmd", "--zone=public", "--add-interface=hd-host")
	for _, port := range []int{2022, 18443, 18444} {
		for _, family := range []string{"tcp4", "tcp6"} {
			if family == "tcp6" && !v6 {
				continue
			}
			host := "0.0.0.0"
			if family == "tcp6" {
				host = "::"
			}
			listener, err := net.Listen(family, net.JoinHostPort(host, fmt.Sprint(port)))
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			go func(ssh bool) {
				for {
					c, e := listener.Accept()
					if e != nil {
						return
					}
					if ssh {
						c.Write([]byte("SSH-2.0-PrthakPrivateTest\r\n"))
					}
					c.Close()
				}
			}(port == 2022)
		}
		for _, scope := range []string{"runtime", "permanent"} {
			command("firewall-cmd", firewallArgs(scope, "--zone=public", fmt.Sprintf("--add-port=%d/tcp", port))...)
		}
	}
	for _, family := range []string{"udp4", "udp6"} {
		if family == "udp6" && !v6 {
			continue
		}
		port, host := 68, "0.0.0.0"
		if family == "udp6" {
			port, host = 546, "::"
		}
		listener, err := net.ListenPacket(family, net.JoinHostPort(host, fmt.Sprint(port)))
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		go func() {
			b := make([]byte, 512)
			for {
				n, addr, e := listener.ReadFrom(b)
				if e != nil {
					return
				}
				listener.WriteTo(b[:n], addr)
			}
		}()
	}
	probe := func(suffix string, port int, kind string, allowed bool) error {
		for _, family := range []string{"4", "6"} {
			if family == "6" && !v6 {
				continue
			}
			source, target := "10.253.0."+suffix, "10.253.0.1"
			if family == "6" {
				source, target = "fd00:253::"+suffix, "fd00:253::1"
			}
			out, err := exec.CommandContext(ctx, "python3", "-c", hostDenyPacketProbe, family, source, target, fmt.Sprint(port), kind).CombinedOutput()
			if err != nil || (strings.TrimSpace(string(out)) == "ALLOW") != allowed {
				return fmt.Errorf("IPv%s source%s port%d %s expectedallow=%v got=%s err=%v", family, suffix, port, kind, allowed, out, err)
			}
		}
		return nil
	}
	if err := probe("4", 18444, "tcp", true); err != nil {
		t.Fatal("baseline legacy open port:", err)
	}
	a := &Agent{Config: Config{StateDir: t.TempDir(), Enforce: true, AllowHostDefaultDeny: true, Zone: "public", ControllerURL: "https://192.0.2.200:8787", ManagementSources: []string{"10.253.0.3/32", "fd00:253::3/128"}, ProtectedSSHPorts: []int{2022}}, Commands: runner, State: State{Coverage: map[string]*Coverage{}}}
	fixturePolicyTrust(t, a)
	a.armManaged = func(context.Context, string, *managedJournal) error { return nil } // Private adapter fixture; watchdog tests cover the production timer separately.
	protection, err := a.managedProtection(ctx)
	if err != nil || !protection.HostDefaultDenyReady {
		t.Fatalf("native context not ready: %+v %v", protection, err)
	}
	forwardDigest := func() string {
		raw, e := runner.Run(ctx, "nft", "-j", "list", "table", "inet", "firewalld")
		if e != nil {
			t.Fatal(e)
		}
		var d struct {
			Objects []map[string]json.RawMessage `json:"nftables"`
		}
		if json.Unmarshal([]byte(raw), &d) != nil {
			t.Fatal("nft forwarding inventory")
		}
		rules := []json.RawMessage{}
		for _, o := range d.Objects {
			var r map[string]json.RawMessage
			if json.Unmarshal(o["rule"], &r) != nil {
				continue
			}
			var chain string
			json.Unmarshal(r["chain"], &chain)
			if strings.HasPrefix(chain, "filter_FWD_") || strings.HasPrefix(chain, "filter_FORWARD") {
				delete(r, "handle")
				delete(r, "index")
				b, _ := json.Marshal(r)
				rules = append(rules, b)
			}
		}
		b, _ := json.Marshal(rules)
		return shaText(string(b))
	}
	forwardBefore := forwardDigest()
	for version, suffix := range []string{"2", "4"} {
		policy := hostDenyPolicy(a, protection, version+1, true, "10.253.0."+suffix+"/32", "fd00:253::"+suffix+"/128")
		policy.Services[0].Port = 18443
		policy.Digest, _ = compiledPolicyDigest(policy)
		policy.Enforcement.ApprovedDigest = policy.Digest
		policy.Enforcement.BindingDigest = enforcementBinding(policy, protection.Digest)
		checks := 0
		a.checkManagedHealth = func(context.Context, *Policy, Protection, string) error {
			checks++
			if err := probe("3", 2022, "ssh", true); err != nil {
				return err
			}
			if checks > 1 {
				if err := probe(suffix, 18443, "tcp", true); err != nil {
					return err
				}
				denied := "4"
				if suffix == "4" {
					denied = "2"
				}
				if err := probe(denied, 18443, "tcp", false); err != nil {
					return err
				}
				if err := probe("2", 18444, "tcp", false); err != nil {
					return err
				}
				if err := probe("2", 2022, "tcp", false); err != nil {
					return err
				}
			}
			return nil
		}
		if err := a.applyManaged(ctx, policy, protection); err != nil {
			t.Fatal(err)
		}
		fresh, _ := a.managedProtection(ctx)
		if fresh.Digest != protection.Digest || !fresh.HostDefaultDenyReady {
			t.Fatalf("native own-generation context changed: %+v", fresh)
		}
	}
	for _, family := range []string{"4", "6"} {
		if family == "6" && !v6 {
			continue
		}
		source, target, port := "10.253.0.4", "10.253.0.1", 68
		if family == "6" {
			source, target, port = "fd00:253::4", "fd00:253::1", 546
		}
		out, err := exec.CommandContext(ctx, "python3", "-c", hostDenyPacketProbe, family, source, target, fmt.Sprint(port), "udp").CombinedOutput()
		if err != nil || strings.TrimSpace(string(out)) != "ALLOW" {
			t.Fatalf("DHCP client exception IPv%s failed: %s %v", family, out, err)
		}
	}
	if err := probe("4", 0, "icmp", true); err != nil {
		t.Fatal("essential ICMP control:", err)
	}
	if forwardDigest() != forwardBefore {
		t.Fatal("host-only policy changed forwarding chains")
	}
	previous := a.State.ManagedBundle
	failed := hostDenyPolicy(a, protection, 3, true, "10.253.0.2/32", "fd00:253::2/128")
	failed.Services[0].Port = 18443
	failed.Digest, _ = compiledPolicyDigest(failed)
	failed.Enforcement.ApprovedDigest = failed.Digest
	failed.Enforcement.BindingDigest = enforcementBinding(failed, protection.Digest)
	calls := 0
	a.checkManagedHealth = func(context.Context, *Policy, Protection, string) error {
		calls++
		if calls == 2 {
			return errors.New("private injected staged health failure")
		}
		return probe("3", 2022, "ssh", true)
	}
	if err := a.applyManaged(ctx, failed, protection); err == nil {
		t.Fatal("health failure did not roll back")
	}
	if a.State.ManagedBundle.Generation != previous.Generation || !a.State.ManagedBundle.HostDefaultDeny {
		t.Fatal("native rollback did not restore previous owner")
	}
	if err := probe("4", 18443, "tcp", true); err != nil {
		t.Fatal("native rollback lost approved source:", err)
	}
	if err := probe("2", 18443, "tcp", false); err != nil {
		t.Fatal("native rollback kept failed source:", err)
	}
	remove := hostDenyPolicy(a, protection, 4, false, "10.253.0.4/32", "fd00:253::4/128")
	remove.Services[0].Port = 18443
	remove.Digest, _ = compiledPolicyDigest(remove)
	remove.Enforcement.ApprovedDigest = remove.Digest
	remove.Enforcement.BindingDigest = enforcementBinding(remove, protection.Digest)
	a.checkManagedHealth = func(context.Context, *Policy, Protection, string) error { return probe("3", 2022, "ssh", true) }
	if err := a.applyManaged(ctx, remove, protection); err != nil {
		t.Fatal("native global-only cleanup:", err)
	}
	if err := probe("2", 18444, "tcp", true); err != nil {
		t.Fatal("native global fallback was not removed:", err)
	}
	if a.State.ManagedBundle.HostDefaultDeny || len(a.State.ManagedBundle.Rules) != len(previous.Rules)-2 || forwardDigest() != forwardBefore {
		t.Fatal("native cleanup lost retained grants or altered forwarding")
	}
	if c, err := net.Dial("tcp4", "127.0.0.1:18444"); err != nil {
		t.Fatal("loopback broken:", err)
	} else {
		c.Close()
	}
	t.Logf("PASS private real-kernel host INPUT source deny, legacy-open override, protected SSH, staged replacement, DHCP/ICMP/loopback, exact rollback/global-only cleanup and unchanged forwarding; IPv6 enabled=%v", v6)
}
