//go:build linux

package agent

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
)

const captureQueueLimit = 8192
const captureSeenLimit = 32768

type captureSocket struct {
	fd    int
	epoch string
	stop  chan struct{}
	done  chan struct{}
}
type netfilterCapture struct {
	mu                  sync.Mutex
	scopes              []capturePortScope
	local               map[netip.Addr]bool
	queue               []capturedFlow
	ct                  *captureSocket
	log                 *captureSocket
	ctStatus, logStatus CaptureBackendReport
	gaps                map[string]bool
	prefixes            map[string]bool
	group               uint16
	boot                string
	lost                map[string]int
	unknownLoss         map[string]bool
	deadlines           map[string]time.Time
}

func newNativeCapture() nativeCapture {
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	m := &netfilterCapture{gaps: map[string]bool{}, prefixes: map[string]bool{}, deadlines: map[string]time.Time{}, lost: map[string]int{}, unknownLoss: map[string]bool{}, boot: strings.TrimSpace(string(boot))}
	if err != nil || len(m.boot) != 36 {
		m.boot = "unknown-" + batchID()
		m.gaps["Conntrack boot identity unavailable; cross-restart deduplication is uncertain."] = true
	}
	return m
}
func captureSocketOpen(groups uint32) (*captureSocket, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_NETFILTER)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*captureSocket, error) { _ = syscall.Close(fd); return nil, err }
	if err = syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Groups: groups}); err != nil {
		return fail(err)
	}
	if err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4*1024*1024); err != nil {
		return fail(err)
	}
	if err = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Usec: 200000}); err != nil {
		return fail(err)
	}
	return &captureSocket{fd: fd, epoch: batchID(), stop: make(chan struct{}), done: make(chan struct{})}, nil
}
func (socket *captureSocket) close() { close(socket.stop); <-socket.done; _ = syscall.Close(socket.fd) }
func (m *netfilterCapture) refuseScope(err error) error {
	_ = m.Close()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ctStatus = CaptureBackendReport{Backend: "conntrack", Status: "error", Error: err.Error()}
	m.logStatus = CaptureBackendReport{Backend: "nflog", Status: "error", Error: err.Error()}
	if len(m.gaps) < 16 {
		m.gaps["Native scope replacement failed; previous capture readers were closed."] = true
	}
	return fmt.Errorf("%w: %v", errCaptureScope, err)
}
func (m *netfilterCapture) Configure(scopes []capturePortScope) error {
	if len(scopes) > 2048 {
		return m.refuseScope(errors.New("native capture scope exceeds bound"))
	}
	locals := map[netip.Addr]bool{}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return m.refuseScope(err)
	}
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err == nil {
			locals[prefix.Addr().Unmap()] = true
		}
	}
	accepted := false
	for _, scope := range scopes {
		if scope.Kind == captureAccepted {
			accepted = true
		}
	}
	m.mu.Lock()
	retained := map[string]time.Time{}
	for index := range scopes {
		key := canonicalCaptureScope([]capturePortScope{scopes[index]})
		deadline := time.Now().Add(scopes[index].ExpiresAt.Sub(time.Now().UTC()))
		if old, ok := m.deadlines[key]; ok && old.Before(deadline) {
			deadline = old
		}
		scopes[index].Deadline = deadline
		retained[key] = deadline
	}
	m.deadlines = retained
	m.scopes = append([]capturePortScope{}, scopes...)
	m.local = locals
	current := m.ct
	if m.ctStatus.Backend == "" {
		m.ctStatus = CaptureBackendReport{Backend: "conntrack", Status: "off"}
		m.logStatus = CaptureBackendReport{Backend: "nflog", Status: "off"}
	}
	m.mu.Unlock()
	if !accepted && current != nil {
		current.close()
		m.mu.Lock()
		m.ct = nil
		m.ctStatus.Status = "off"
		m.mu.Unlock()
	}
	if accepted && current == nil {
		socket, err := captureSocketOpen(1 | 2 | 4) // NEW, UPDATE, DESTROY; no mutable sysctl.
		if err != nil {
			m.mu.Lock()
			m.ctStatus = CaptureBackendReport{Backend: "conntrack", Status: "unsupported", Error: "conntrack event subscription unavailable: " + err.Error()}
			m.gaps["Conntrack is unavailable; no implicit kernel-journal fallback."] = true
			m.mu.Unlock()
			return err
		}
		m.mu.Lock()
		m.ct = socket
		m.ctStatus = CaptureBackendReport{Backend: "conntrack", Status: "error", IPv4: true, IPv6: captureIPv6Enabled(), Error: "waiting for verified initial conntrack baseline"}
		m.gaps["Conntrack startup/dump races, untracked flows and event loss cannot establish a complete connection ledger."] = true
		m.mu.Unlock()
		go m.readConntrack(socket)
	}
	return nil
}
func captureIPv6Enabled() bool {
	raw, err := os.ReadFile("/proc/sys/net/ipv6/conf/all/disable_ipv6")
	return err == nil && strings.TrimSpace(string(raw)) == "0"
}
func (m *netfilterCapture) addGap(message string, unknown bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.gaps) < 16 {
		m.gaps[message] = true
	}
	if unknown {
		backend := "conntrack"
		if strings.HasPrefix(message, "NFLOG") {
			backend = "nflog"
		}
		m.unknownLoss[backend] = true
	}
}
func (m *netfilterCapture) publish(flow capturedFlow) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.local[netip.MustParseAddr(flow.DestinationIP).Unmap()] {
		return
	}
	selected := false
	for _, scope := range m.scopes {
		if scope.Kind == flow.CaptureKind && scope.Port.Port == flow.Port && scope.Port.Protocol == flow.Protocol && captureScopeLive(scope, flow.FirstSeen) {
			selected = true
			break
		}
	}
	if !selected {
		return
	}
	if len(m.queue) >= captureQueueLimit {
		m.lost[flow.CaptureBackend]++
		m.gaps["Native capture queue reached its bound; exact dropped-event count is reported."] = true
		return
	}
	m.queue = append(m.queue, flow)
}
func (m *netfilterCapture) eligible(record conntrackRecord, now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.local[record.reply.source.Unmap()] {
		return false
	}
	protocol := "tcp"
	if record.original.protocol == 17 {
		protocol = "udp"
	}
	for _, scope := range m.scopes {
		if scope.Kind == captureAccepted && scope.Port.Port == int(record.reply.sourcePort) && scope.Port.Protocol == protocol && captureScopeLive(scope, now) {
			return true
		}
	}
	return false
}
func captureNetlinkPacket(kind, flags uint16, seq uint32, family byte, attributes []byte) []byte {
	raw := make([]byte, 20+len(attributes))
	binary.NativeEndian.PutUint32(raw, uint32(len(raw)))
	binary.NativeEndian.PutUint16(raw[4:], kind)
	binary.NativeEndian.PutUint16(raw[6:], flags)
	binary.NativeEndian.PutUint32(raw[8:], seq)
	raw[16] = family
	copy(raw[20:], attributes)
	return raw
}
func captureSend(fd int, raw []byte) error {
	return syscall.Sendto(fd, raw, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK})
}
func captureReceive(socket *captureSocket, buffer []byte) ([]byte, error) {
	count, _, flags, peer, err := syscall.Recvmsg(socket.fd, buffer, nil, 0)
	if err != nil {
		return nil, err
	}
	address, ok := peer.(*syscall.SockaddrNetlink)
	if !ok || address.Pid != 0 {
		return nil, errors.New("netfilter message did not originate from kernel")
	}
	if flags&syscall.MSG_TRUNC != 0 {
		return nil, errors.New("netfilter datagram truncated")
	}
	return buffer[:count], nil
}
func (m *netfilterCapture) readConntrack(socket *captureSocket) {
	defer close(socket.done)
	dedup := conntrackDedup{limit: captureSeenLimit}
	seq := uint32(1)
	dumpSeq := seq
	baseline := true
	sendDump := func() {
		if err := captureSend(socket.fd, captureNetlinkPacket(0x101, 1|0x300, seq, 0, nil)); err != nil {
			m.addGap("Conntrack dump failed: "+err.Error(), true)
		}
	}
	sendDump()
	nextDump := time.Now().Add(time.Minute)
	buffer := make([]byte, maxCaptureDatagram)
	for {
		select {
		case <-socket.stop:
			return
		default:
		}
		if time.Now().After(nextDump) {
			seq++
			dumpSeq = seq
			sendDump()
			nextDump = time.Now().Add(time.Minute)
		}
		raw, err := captureReceive(socket, buffer)
		if err == syscall.EAGAIN || err == syscall.EINTR {
			continue
		}
		if err != nil {
			m.addGap("Conntrack event stream gap: "+err.Error(), true)
			continue
		}
		messages, err := syscall.ParseNetlinkMessage(raw)
		if err != nil {
			m.addGap("Malformed conntrack netlink datagram; loss is unknown.", true)
			continue
		}
		for _, message := range messages {
			if message.Header.Type == syscall.NLMSG_ERROR {
				if len(message.Data) < 4 || int32(binary.NativeEndian.Uint32(message.Data)) != 0 {
					m.addGap("Conntrack kernel rejected the read-only dump; resynchronization is incomplete.", true)
					if baseline {
						nextDump = time.Now().Add(5 * time.Second)
					}
					m.mu.Lock()
					m.ctStatus.Status = "error"
					m.ctStatus.Error = "conntrack snapshot was rejected; coverage is incomplete"
					m.mu.Unlock()
				}
				continue
			}
			if message.Header.Type == syscall.NLMSG_OVERRUN {
				m.addGap("Conntrack netlink overrun; loss is unknown.", true)
				continue
			}
			if message.Header.Type == syscall.NLMSG_DONE {
				if message.Header.Flags&0x10 != 0 {
					m.addGap("Conntrack dump interrupted by concurrent table changes.", true)
				} else if message.Header.Seq == dumpSeq {
					baseline = false
					m.mu.Lock()
					m.ctStatus.Status = "active"
					m.ctStatus.Error = ""
					m.mu.Unlock()
				}
				continue
			}
			if message.Header.Type != 0x100 && message.Header.Type != 0x102 {
				continue
			}
			record, err := decodeConntrackRecord(message.Data, message.Header.Type == 0x102)
			if err != nil {
				if strings.Contains(err.Error(), "identity") {
					m.addGap("Conntrack identity metadata unavailable; entries are skipped rather than fabricated.", true)
				}
				continue
			}
			now := time.Now().UTC()
			if !m.eligible(record, now) {
				continue
			}
			count, limited := dedup.observe(record, baseline, now)
			if limited {
				m.addGap("Conntrack identity bound reached; new connections are skipped rather than double-counted.", true)
			}
			if !count {
				continue
			}
			protocol := "tcp"
			if record.original.protocol == 17 {
				protocol = "udp"
			}
			// Reply's source is the local post-DNAT address/port; original source
			// remains the peer visible to this network namespace. Outbound flows
			// fail the local-address check in publish.
			local := record.reply.source.Unmap()
			source := record.original.source.Unmap()
			if record.started == 0 {
				m.addGap("Conntrack start timestamps are unavailable; kernel ID reuse/deduplication cannot establish an exact ledger.", false)
			}
			id := conntrackFlowID(m.boot, record)
			m.publish(capturedFlow{Flow: Flow{EventID: id, CaptureKind: captureAccepted, CaptureBackend: "conntrack", CountUnit: "connections", AddressFamily: captureFamily(source), SourceIP: source.String(), Port: int(record.reply.sourcePort), Protocol: protocol, Verdict: "allowed", Count: 1, FirstSeen: now, LastSeen: now}, DestinationIP: local.String()})
		}
	}
}
func (m *netfilterCapture) Drain() ([]capturedFlow, TrafficCaptureCoverage) {
	m.mu.Lock()
	defer m.mu.Unlock()
	flows := m.queue
	m.queue = nil
	ct, log := m.ctStatus, m.logStatus
	if !m.unknownLoss["conntrack"] {
		lost := m.lost["conntrack"]
		ct.LostEvents = &lost
	}
	if !m.unknownLoss["nflog"] {
		lost := m.lost["nflog"]
		log.LostEvents = &lost
	}
	coverage := TrafficCaptureCoverage{Backends: []CaptureBackendReport{ct, log}}
	for gap := range m.gaps {
		coverage.Gaps = append(coverage.Gaps, gap)
	}
	return flows, coverage
}
func (m *netfilterCapture) Close() error {
	m.mu.Lock()
	ct, log := m.ct, m.log
	m.ct = nil
	m.log = nil
	m.scopes = nil
	m.mu.Unlock()
	if ct != nil {
		ct.close()
	}
	if log != nil {
		log.close()
	}
	return nil
}

// The group is stable per protected state root and exclusively bound. Failure
// never steals another application's group or changes a global logging target.
func captureNLA(kind uint16, value []byte) []byte {
	raw := make([]byte, (len(value)+7)&^3)
	binary.NativeEndian.PutUint16(raw, uint16(4+len(value)))
	binary.NativeEndian.PutUint16(raw[2:], kind)
	copy(raw[4:], value)
	return raw
}
func (m *netfilterCapture) SetDeniedPrefixes(group uint16, prefixes []string) error {
	m.mu.Lock()
	m.group = group
	m.prefixes = map[string]bool{}
	for _, p := range prefixes {
		m.prefixes[p] = true
	}
	current := m.log
	m.mu.Unlock()
	if len(prefixes) == 0 {
		if current != nil {
			current.close()
			m.mu.Lock()
			m.log = nil
			m.logStatus.Status = "off"
			m.mu.Unlock()
		}
		return nil
	}
	if current != nil {
		m.mu.Lock()
		m.logStatus = CaptureBackendReport{Backend: "nflog", Status: "active", IPv4: true, IPv6: captureIPv6Enabled()}
		m.mu.Unlock()
		return nil
	}
	socket, err := captureSocketOpen(0)
	if err != nil {
		return err
	}
	// NFULNL_CFG_CMD_BIND, packet copy128, per-group sequence. Never PF_UNBIND.
	mode := make([]byte, 6)
	binary.BigEndian.PutUint32(mode, 128)
	mode[4] = 2
	flags := make([]byte, 2)
	binary.BigEndian.PutUint16(flags, 1)
	attrs := append(captureNLA(1, []byte{1}), captureNLA(2, mode)...)
	attrs = append(attrs, captureNLA(6, flags)...)
	packet := captureNetlinkPacket(0x401, 1|4, 1, 0, attrs)
	binary.BigEndian.PutUint16(packet[18:], group)
	if err = captureSend(socket.fd, packet); err != nil {
		_ = syscall.Close(socket.fd)
		return err
	}
	buffer := make([]byte, maxCaptureDatagram)
	reply, err := captureReceive(socket, buffer)
	if err == nil {
		var messages []syscall.NetlinkMessage
		messages, err = syscall.ParseNetlinkMessage(reply)
		if err == nil && (len(messages) != 1 || messages[0].Header.Type != syscall.NLMSG_ERROR || len(messages[0].Data) < 4 || int32(binary.NativeEndian.Uint32(messages[0].Data)) != 0) {
			err = errors.New("NFLOG exclusive group/configuration rejected")
		}
	}
	if err != nil {
		_ = syscall.Close(socket.fd)
		m.mu.Lock()
		m.logStatus = CaptureBackendReport{Backend: "nflog", Status: "unsupported", Error: err.Error()}
		m.mu.Unlock()
		return err
	}
	m.mu.Lock()
	m.log = socket
	m.logStatus = CaptureBackendReport{Backend: "nflog", Status: "active", IPv4: true, IPv6: captureIPv6Enabled()}
	m.unknownLoss["nflog"] = true // The native rule limiter does not expose suppressed-packet counts.
	m.gaps["NFLOG deny rules are rate limited; rate-limit omissions have unknown count."] = true
	m.mu.Unlock()
	go m.readNFLog(socket)
	return nil
}
func (m *netfilterCapture) SetDeniedFailure(message string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logStatus = CaptureBackendReport{Backend: "nflog", Status: "unsupported", Error: message}
	if len(m.gaps) < 16 {
		m.gaps["NFLOG: "+message] = true
	}
}
func (m *netfilterCapture) readNFLog(socket *captureSocket) {
	defer close(socket.done)
	buffer := make([]byte, maxCaptureDatagram)
	var last uint32
	hasLast := false
	var wraps uint64
	for {
		select {
		case <-socket.stop:
			return
		default:
		}
		raw, err := captureReceive(socket, buffer)
		if err == syscall.EAGAIN || err == syscall.EINTR {
			continue
		}
		if err != nil {
			m.addGap("NFLOG socket gap: "+err.Error(), true)
			continue
		}
		messages, err := syscall.ParseNetlinkMessage(raw)
		if err != nil {
			m.addGap("Malformed NFLOG datagram.", true)
			continue
		}
		for _, message := range messages {
			if message.Header.Type != 0x400 {
				continue
			}
			record, err := decodeNFLogRecord(message.Data)
			if err != nil {
				m.addGap("NFLOG packet metadata is truncated or unsupported: "+err.Error(), true)
				continue
			}
			m.mu.Lock()
			valid := m.prefixes[record.prefix]
			m.mu.Unlock()
			if !valid {
				continue
			}
			if record.hasSequence {
				if hasLast && record.sequence <= last {
					if record.sequence < last && last-record.sequence > 1<<31 {
						wraps++
					} else {
						if record.sequence != last {
							m.addGap("NFLOG out-of-order sequence skipped to preserve event identity.", true)
						}
						continue
					}
				}
				if hasLast && record.sequence != last+1 {
					m.addGap("NFLOG per-group sequence gap; packet loss is unknown.", true)
				}
				last = record.sequence
				hasLast = true
			} else {
				m.addGap("NFLOG sequence metadata is unavailable; loss detection is incomplete.", true)
			}
			now := time.Now().UTC()
			protocol := "tcp"
			if !record.observedAt.IsZero() {
				if record.observedAt.After(now.Add(time.Minute)) {
					m.addGap("NFLOG future timestamp rejected.", true)
					continue
				}
				now = record.observedAt
			} else {
				m.addGap("NFLOG kernel timestamps unavailable; capture-time precision is limited.", true)
			}
			if record.protocol == 17 {
				protocol = "udp"
			}
			m.mu.Lock()
			group := m.group
			m.mu.Unlock()
			id := shaText(fmt.Sprintf("prthak-nflog-v1\x00%s\x00%d\x00%d\x00%d\x00%s", socket.epoch, group, wraps, record.sequence, record.prefix))
			if !record.hasSequence {
				id = shaText(id + "/" + batchID())
			}
			m.publish(capturedFlow{Flow: Flow{EventID: id, CaptureKind: captureDenied, CaptureBackend: "nflog", CountUnit: "packets", AddressFamily: captureFamily(record.source), SourceIP: record.source.String(), Port: int(record.port), Protocol: protocol, Verdict: "denied", Count: 1, FirstSeen: now, LastSeen: now}, DestinationIP: record.destination.String()})
		}
	}
}
