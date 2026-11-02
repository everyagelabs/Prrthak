//go:build linux

package agent

import (
	"encoding/binary"
	"errors"
	"syscall"
)

func captureConntrackTuple(tuple conntrackTuple) []byte {
	source, destination := uint16(1), uint16(2)
	if tuple.source.Is6() {
		source, destination = 3, 4
	}
	ips := append(captureNLA(source, tuple.source.AsSlice()), captureNLA(destination, tuple.destination.AsSlice())...)
	ports := make([]byte, 2)
	binary.BigEndian.PutUint16(ports, tuple.sourcePort)
	protocol := append(captureNLA(1, []byte{tuple.protocol}), captureNLA(2, ports)...)
	ports = make([]byte, 2)
	binary.BigEndian.PutUint16(ports, tuple.destinationPort)
	protocol = append(protocol, captureNLA(3, ports)...)
	return append(captureNLA(0x8001, ips), captureNLA(0x8002, protocol)...)
}

func captureBirthRequest(record conntrackRecord, sequence uint32) []byte {
	attributes := captureNLA(0x8001, captureConntrackTuple(record.original))
	zone, id := make([]byte, 2), make([]byte, 4)
	binary.BigEndian.PutUint16(zone, record.zone)
	binary.BigEndian.PutUint32(id, record.id)
	attributes = append(attributes, captureNLA(18, zone)...)
	attributes = append(attributes, captureNLA(12, id)...)
	family := byte(syscall.AF_INET)
	if record.original.source.Is6() {
		family = syscall.AF_INET6
	}
	// IPCTNL_MSG_CT_GET + REQUEST only. Never DELETE, update, dump-and-zero,
	// controller traffic, sysctl writes or a mutable conntrack operation.
	return captureNetlinkPacket(0x101, 1, sequence, family, attributes)
}

func captureBirthReply(raw []byte, sequence uint32, candidate conntrackRecord) (conntrackRecord, error) {
	messages, err := syscall.ParseNetlinkMessage(raw)
	if err != nil || len(messages) != 1 || messages[0].Header.Seq != sequence || messages[0].Header.Type != 0x100 {
		return conntrackRecord{}, errors.New("exact conntrack birth lookup returned no matching object")
	}
	result, err := decodeConntrackRecord(messages[0].Data, false)
	// GET currently selects by tuple/zone; some kernels ignore CTA_ID. Bind the
	// returned ID and both NAT tuples ourselves before trusting its timestamp.
	// Kernel IDs are almost unique, not a cryptographic lifecycle identity. The
	// exact GET must itself prove the accepted state as well as post-arm birth;
	// a closing/new-unestablished object cannot borrow an old event's verdict.
	if err != nil || !candidate.accepted() || !result.accepted() || result.id != candidate.id || result.zone != candidate.zone || result.original != candidate.original || result.reply != candidate.reply || result.started == 0 || result.started > uint64(1<<63-1) {
		return conntrackRecord{}, errors.New("conntrack birth metadata did not match the exact accepted kernel object")
	}
	// Both observations now prove accepted state; copy only authoritative birth.
	candidate.started = result.started
	return candidate, nil
}

func captureLookupBirth(socket *captureSocket, candidate conntrackRecord, sequence uint32) (conntrackRecord, error) {
	if err := captureSend(socket.fd, captureBirthRequest(candidate, sequence)); err != nil {
		return conntrackRecord{}, err
	}
	buffer := make([]byte, maxCaptureDatagram)
	raw, err := captureReceive(socket, buffer)
	if err != nil {
		return conntrackRecord{}, err
	}
	return captureBirthReply(raw, sequence, candidate)
}
