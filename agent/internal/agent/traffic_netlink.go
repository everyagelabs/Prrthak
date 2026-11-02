package agent

// Bounded decoders for the Linux UAPI. Packet payload bytes never leave this
// decoder; only the scoped source/local port metadata enters an event batch.
import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

const maxCaptureDatagram = 256 * 1024

type captureAttribute struct {
	kind  uint16
	value []byte
}

func captureAttributes(raw []byte) (map[uint16][]byte, error) {
	result := map[uint16][]byte{}
	for count := 0; len(raw) > 0; count++ {
		if count >= 256 || len(raw) < 4 {
			return nil, errors.New("malformed/bounded netfilter attributes")
		}
		length := int(binary.NativeEndian.Uint16(raw))
		kind := binary.NativeEndian.Uint16(raw[2:]) & 0x3fff
		if length < 4 || length > len(raw) {
			return nil, errors.New("invalid netfilter attribute length")
		}
		if _, present := result[kind]; present {
			return nil, errors.New("duplicate netfilter attribute")
		}
		result[kind] = raw[4:length]
		aligned := (length + 3) &^ 3
		if aligned > len(raw) {
			if length == len(raw) {
				break
			}
			return nil, errors.New("truncated netfilter alignment")
		}
		raw = raw[aligned:]
	}
	return result, nil
}

type conntrackTuple struct {
	source, destination         netip.Addr
	sourcePort, destinationPort uint16
	protocol                    byte
}
type conntrackRecord struct {
	original, reply conntrackTuple
	status, id      uint32
	zone            uint16
	tcpState        byte
	deleted         bool
	started         uint64
}

func decodeConntrackTuple(raw []byte, family byte) (conntrackTuple, error) {
	var result conntrackTuple
	attrs, err := captureAttributes(raw)
	if err != nil {
		return result, err
	}
	ips, err := captureAttributes(attrs[1])
	if err != nil {
		return result, err
	}
	proto, err := captureAttributes(attrs[2])
	if err != nil {
		return result, err
	}
	if family == 2 {
		if len(ips[1]) != 4 || len(ips[2]) != 4 {
			return result, errors.New("invalid IPv4 conntrack tuple")
		}
		result.source = netip.AddrFrom4([4]byte(ips[1]))
		result.destination = netip.AddrFrom4([4]byte(ips[2]))
	} else if family == 10 {
		if len(ips[3]) != 16 || len(ips[4]) != 16 {
			return result, errors.New("invalid IPv6 conntrack tuple")
		}
		result.source = netip.AddrFrom16([16]byte(ips[3]))
		result.destination = netip.AddrFrom16([16]byte(ips[4]))
	} else {
		return result, errors.New("unsupported conntrack family")
	}
	if len(proto[1]) != 1 || len(proto[2]) != 2 || len(proto[3]) != 2 {
		return result, errors.New("non TCP/UDP conntrack tuple")
	}
	result.protocol = proto[1][0]
	if result.protocol != 6 && result.protocol != 17 {
		return result, errors.New("non TCP/UDP conntrack protocol")
	}
	result.sourcePort = binary.BigEndian.Uint16(proto[2])
	result.destinationPort = binary.BigEndian.Uint16(proto[3])
	if result.source.Is4In6() || result.destination.Is4In6() {
		return result, errors.New("mapped addresses do not match conntrack family")
	}
	return result, nil
}
func decodeConntrackRecord(raw []byte, deleted bool) (conntrackRecord, error) {
	var result conntrackRecord
	result.deleted = deleted
	if len(raw) < 4 || raw[1] != 0 {
		return result, errors.New("invalid conntrack generic header")
	}
	attrs, err := captureAttributes(raw[4:])
	if err != nil {
		return result, err
	}
	result.original, err = decodeConntrackTuple(attrs[1], raw[0])
	if err != nil {
		return result, err
	}
	result.reply, err = decodeConntrackTuple(attrs[2], raw[0])
	if err != nil {
		return result, err
	}
	if result.original.protocol != result.reply.protocol || len(attrs[3]) != 4 || len(attrs[12]) != 4 {
		return result, errors.New("incomplete conntrack identity/status")
	}
	result.status = binary.BigEndian.Uint32(attrs[3])
	result.id = binary.BigEndian.Uint32(attrs[12])
	if timestamp, ok := attrs[20]; ok {
		values, err := captureAttributes(timestamp)
		if err != nil {
			return result, err
		}
		if start, ok := values[1]; ok {
			if len(start) != 8 {
				return result, errors.New("invalid conntrack start timestamp")
			}
			result.started = binary.BigEndian.Uint64(start)
		}
	}
	if zone, present := attrs[18]; present {
		if len(zone) != 2 {
			return result, errors.New("invalid conntrack zone")
		}
		result.zone = binary.BigEndian.Uint16(zone)
	}
	if result.original.protocol == 6 {
		info, err := captureAttributes(attrs[4])
		if err != nil {
			return result, err
		}
		tcp, err := captureAttributes(info[1])
		if err != nil || len(tcp[1]) != 1 {
			return result, errors.New("missing conntrack TCP state")
		}
		result.tcpState = tcp[1][0]
	}
	return result, nil
}
func (record conntrackRecord) identity() string {
	return fmt.Sprintf("%d/%d/%s/%d/%s/%d/%d/%d", record.zone, record.id, record.original.source, record.original.sourcePort, record.original.destination, record.original.destinationPort, record.original.protocol, record.started)
}
func (record conntrackRecord) accepted() bool {
	// IPS_CONFIRMED is set at local INPUT's final confirm hook, after filtering.
	// TCP additionally requires ESTABLISHED and observed reply direction; loose
	// pickup of a one-way ACK is not treated as an established connection.
	return record.status&8 != 0 && (record.original.protocol == 17 || record.tcpState == 3 && record.status&2 != 0)
}
func conntrackFlowID(boot string, record conntrackRecord) string {
	return shaText("prthak-conntrack-v1\x00" + boot + "\x00" + record.identity())
}

type conntrackDedup struct {
	entries map[string]time.Time
	limit   int
}

type conntrackLifecycle struct {
	identityStart, knownStart uint64
	acceptedBirth             bool
	lastLookup                time.Time
}
type conntrackLifecycles struct {
	entries map[string]conntrackLifecycle
	limit   int
}

func conntrackBaseIdentity(record conntrackRecord) string {
	record.started = 0
	return record.identity()
}

// Multicast NEW/UPDATE omits birth timestamps while GET/dump includes them.
// Preserve the identity chosen on first sight, keep authoritative birth private,
// and never recount the same object merely because later metadata is richer.
func (cache *conntrackLifecycles) normalize(record conntrackRecord) (conntrackRecord, uint64, bool) {
	if cache.entries == nil {
		cache.entries = map[string]conntrackLifecycle{}
	}
	key := conntrackBaseIdentity(record)
	entry, exists := cache.entries[key]
	if !exists {
		if len(cache.entries) >= cache.limit {
			return record, 0, false
		}
		entry.identityStart, entry.knownStart = record.started, record.started
		entry.acceptedBirth = record.started > 0 && record.accepted()
	} else if record.started > 0 {
		if entry.knownStart > 0 && record.started < entry.knownStart {
			return record, 0, false // Old lifecycle update after kernel ID reuse.
		}
		if entry.knownStart > 0 && record.started > entry.knownStart {
			entry.identityStart = record.started
			entry.acceptedBirth = false
		}
		entry.knownStart = record.started
		entry.acceptedBirth = entry.acceptedBirth || record.accepted()
	}
	cache.entries[key] = entry
	record.started = entry.identityStart
	return record, entry.knownStart, true
}

func (d *conntrackDedup) observe(record conntrackRecord, baseline bool, now time.Time) (bool, bool) {
	if d.entries == nil {
		d.entries = map[string]time.Time{}
	}
	key := record.identity()
	if _, present := d.entries[key]; present {
		d.entries[key] = now
		return false, false
	}
	if len(d.entries) >= d.limit {
		// A quiet connection can remain alive indefinitely. Never evict it by
		// age and fabricate a later UPDATE/dump as a new connection. Retain
		// bounded tombstones too, so out-of-order notifications cannot replay.
		return false, true
	}
	if baseline || record.deleted {
		d.entries[key] = now
		return false, false
	}
	if !record.accepted() {
		return false, false
	}
	d.entries[key] = now
	return true, false
}

type nflogRecord struct {
	source, destination netip.Addr
	port                uint16
	protocol            byte
	prefix              string
	sequence            uint32
	hasSequence         bool
	ingress             uint32
	observedAt          time.Time
}

func decodeNFLogRecord(raw []byte) (nflogRecord, error) {
	var result nflogRecord
	if len(raw) < 4 || raw[1] != 0 {
		return result, errors.New("invalid NFLOG generic header")
	}
	attrs, err := captureAttributes(raw[4:])
	if err != nil {
		return result, err
	}
	// LOCAL_IN only: PREROUTING cannot establish local delivery or a verdict.
	if len(attrs[1]) != 4 || attrs[1][2] != 1 || len(attrs[4]) != 4 {
		return result, errors.New("NFLOG is not verified local ingress")
	}
	result.ingress = binary.BigEndian.Uint32(attrs[4])
	if result.ingress == 0 {
		return result, errors.New("NFLOG has no ingress interface")
	}
	if timestamp, present := attrs[3]; present {
		if len(timestamp) != 16 {
			return result, errors.New("NFLOG invalid timestamp")
		}
		seconds, micros := binary.BigEndian.Uint64(timestamp), binary.BigEndian.Uint64(timestamp[8:])
		if seconds > 1<<40 || micros >= 1000000 {
			return result, errors.New("NFLOG invalid timestamp range")
		}
		result.observedAt = time.Unix(int64(seconds), int64(micros)*1000).UTC()
	}
	if out, present := attrs[5]; present && (len(out) != 4 || binary.BigEndian.Uint32(out) != 0) {
		return result, errors.New("NFLOG forwarded/output packet")
	}
	prefix := attrs[10]
	if len(prefix) < 2 || len(prefix) > 128 || prefix[len(prefix)-1] != 0 {
		return result, errors.New("NFLOG prefix missing/bounded")
	}
	result.prefix = string(prefix[:len(prefix)-1])
	if seq, present := attrs[12]; present {
		if len(seq) != 4 {
			return result, errors.New("invalid NFLOG sequence")
		}
		result.sequence = binary.BigEndian.Uint32(seq)
		result.hasSequence = true
	}
	packet := attrs[9]
	if len(packet) < 1 {
		return result, errors.New("NFLOG missing bounded network header")
	}
	var offset int
	if packet[0]>>4 == 4 {
		if raw[0] != 2 || len(packet) < 20 {
			return result, errors.New("NFLOG IPv4 family mismatch")
		}
		offset = int(packet[0]&15) * 4
		if offset < 20 || offset > 60 || len(packet) < offset+4 || binary.BigEndian.Uint16(packet[6:])&0x1fff != 0 {
			return result, errors.New("NFLOG IPv4 fragmented/truncated transport")
		}
		result.protocol = packet[9]
		result.source = netip.AddrFrom4([4]byte(packet[12:16]))
		result.destination = netip.AddrFrom4([4]byte(packet[16:20]))
	} else if packet[0]>>4 == 6 {
		if raw[0] != 10 || len(packet) < 44 {
			return result, errors.New("NFLOG IPv6 family mismatch")
		}
		result.source = netip.AddrFrom16([16]byte(packet[8:24]))
		result.destination = netip.AddrFrom16([16]byte(packet[24:40]))
		result.protocol = packet[6]
		offset = 40
		for steps := 0; result.protocol != 6 && result.protocol != 17; steps++ {
			if steps >= 8 || offset+2 > len(packet) {
				return result, errors.New("NFLOG IPv6 extension bound")
			}
			size := 0
			switch result.protocol {
			case 0, 43, 60:
				size = (int(packet[offset+1]) + 1) * 8
			case 51:
				size = (int(packet[offset+1]) + 2) * 4
			case 44:
				if offset+8 > len(packet) || binary.BigEndian.Uint16(packet[offset+2:])&0xfff8 != 0 {
					return result, errors.New("NFLOG noninitial IPv6 fragment")
				}
				size = 8
			default:
				return result, errors.New("NFLOG unsupported IPv6 extension")
			}
			if size < 8 || offset+size > len(packet) {
				return result, errors.New("NFLOG truncated IPv6 extension")
			}
			result.protocol = packet[offset]
			offset += size
		}
	} else {
		return result, errors.New("NFLOG unknown network family")
	}
	if result.source.Is4In6() || result.destination.Is4In6() || offset+4 > len(packet) || (result.protocol != 6 && result.protocol != 17) {
		return result, errors.New("NFLOG invalid TCP/UDP header")
	}
	result.port = binary.BigEndian.Uint16(packet[offset+2:])
	if result.port == 0 {
		return result, errors.New("NFLOG invalid destination port")
	}
	return result, nil
}
