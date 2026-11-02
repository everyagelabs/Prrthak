//go:build linux

package agent

import (
	"encoding/binary"
	"syscall"
	"testing"
)

func captureBirthTestData(v6 bool, protocol byte, started uint64) []byte {
	return captureBirthTestStateData(v6, protocol, 3, started)
}

func captureBirthTestStateData(v6 bool, protocol, state byte, started uint64) []byte {
	data := captureTestConntrack(v6, protocol, state, 10)
	if started > 0 {
		stamp := make([]byte, 8)
		binary.BigEndian.PutUint64(stamp, started)
		data = append(data, captureTestNLA(20, captureTestNLA(1, stamp))...)
	}
	return data
}

func TestTrafficBirthLookupRequestIsExactReadOnlyAcrossFamiliesAndProtocols(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		for _, protocol := range []byte{6, 17} {
			candidate, err := decodeConntrackRecord(captureBirthTestData(v6, protocol, 0), false)
			if err != nil {
				t.Fatal(err)
			}
			messages, err := syscall.ParseNetlinkMessage(captureBirthRequest(candidate, 27))
			if err != nil || len(messages) != 1 || messages[0].Header.Type != 0x101 || messages[0].Header.Flags != 1 || messages[0].Header.Seq != 27 {
				t.Fatal("birth lookup is not a single read-only GET", err)
			}
			attributes, err := captureAttributes(messages[0].Data[4:])
			if err != nil || len(attributes) != 3 || len(attributes[12]) != 4 || binary.BigEndian.Uint32(attributes[12]) != candidate.id || len(attributes[18]) != 2 || binary.BigEndian.Uint16(attributes[18]) != candidate.zone {
				t.Fatal("GET lost exact ID/zone fencing", err)
			}
			tuple, err := decodeConntrackTuple(attributes[1], messages[0].Data[0])
			if err != nil || tuple != candidate.original {
				t.Fatal("GET changed the candidate tuple", err)
			}
		}
	}
}

func TestTrafficBirthLookupAcceptsOnlyMatchingAuthoritativeKernelObject(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		candidate, _ := decodeConntrackRecord(captureBirthTestData(v6, 6, 0), false)
		data := captureBirthTestData(v6, 6, 1800000000000000000)
		reply := captureNetlinkPacket(0x100, 0, 7, data[0], data[4:])
		result, err := captureBirthReply(reply, 7, candidate)
		if err != nil || result.started != 1800000000000000000 {
			t.Fatal("authoritative kernel GET rejected", err)
		}
		closing := captureBirthTestStateData(v6, 6, 7, 1800000000000000000)
		closed, err := captureBirthReply(captureNetlinkPacket(0x100, 0, 7, closing[0], closing[4:]), 7, candidate)
		if err == nil || closed.started != 0 {
			t.Fatal("closing/unestablished lifecycle borrowed a prior accepted verdict", err)
		}
		for _, kind := range []string{"id", "zone", "original", "reply", "unaccepted", "sequence", "no-birth", "future-overflow", "reused-unestablished-birth"} {
			changed, raw, sequence := candidate, reply, uint32(7)
			switch kind {
			case "id":
				changed.id++
			case "zone":
				changed.zone++
			case "original":
				changed.original.sourcePort++
			case "reply":
				changed.reply.sourcePort++
			case "unaccepted":
				changed.status = 0
			case "sequence":
				sequence++
			case "no-birth":
				body := captureBirthTestData(v6, 6, 0)
				raw = captureNetlinkPacket(0x100, 0, 7, body[0], body[4:])
			case "future-overflow":
				body := captureBirthTestData(v6, 6, ^uint64(0))
				raw = captureNetlinkPacket(0x100, 0, 7, body[0], body[4:])
			case "reused-unestablished-birth":
				body := captureBirthTestStateData(v6, 6, 1, 1800000000000000001)
				raw = captureNetlinkPacket(0x100, 0, 7, body[0], body[4:])
			}
			if _, err := captureBirthReply(raw, sequence, changed); err == nil {
				t.Fatal("raced/unbound metadata accepted", kind)
			}
		}
		for cut := 0; cut < len(reply); cut++ {
			if _, err := captureBirthReply(reply[:cut], 7, candidate); err == nil {
				t.Fatal("truncated GET metadata accepted", cut)
			}
		}
	}
}
