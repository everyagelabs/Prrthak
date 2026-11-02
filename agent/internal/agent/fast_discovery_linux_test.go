//go:build linux

package agent

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"
)

func testDiagPayload(family, protocol byte, port uint16) []byte {
	raw := make([]byte, 72)
	raw[0], raw[1] = family, 10
	if protocol == 17 {
		raw[1] = 7
	}
	binary.BigEndian.PutUint16(raw[4:], port)
	if family == syscall.AF_INET {
		copy(raw[8:], net.ParseIP("127.0.0.1").To4())
	} else {
		copy(raw[8:], net.ParseIP("::1").To16())
	}
	binary.NativeEndian.PutUint32(raw[40:], 2)
	binary.NativeEndian.PutUint32(raw[68:], 123)
	return raw
}

func testDiagMessage(kind uint16, flags uint16, sequence, pid uint32, body []byte) []byte {
	raw := make([]byte, (16+len(body)+3)&^3)
	binary.NativeEndian.PutUint32(raw, uint32(16+len(body)))
	binary.NativeEndian.PutUint16(raw[4:], kind)
	binary.NativeEndian.PutUint16(raw[6:], flags)
	binary.NativeEndian.PutUint32(raw[8:], sequence)
	binary.NativeEndian.PutUint32(raw[12:], pid)
	copy(raw[16:], body)
	return raw
}

func TestNativeListenerRequestsAndIPv4IPv6ReplyDecoding(t *testing.T) {
	for _, family := range []byte{syscall.AF_INET, syscall.AF_INET6} {
		for _, protocol := range []byte{6, 17} {
			request := diagRequest(family, protocol, 42, 123)
			state := uint32(1 << 10)
			if protocol == 17 {
				state = 1 << 7
			}
			if len(request) != 72 || request[16] != family || request[17] != protocol || binary.NativeEndian.Uint32(request[20:]) != state || binary.NativeEndian.Uint32(request[8:]) != 42 || binary.NativeEndian.Uint32(request[12:]) != 123 {
				t.Fatal("incorrect native listener dump request")
			}
			reply, err := decodeListenerDiag(testDiagPayload(family, protocol, 2022), family, protocol)
			if err != nil || reply.port != 2022 || reply.inode != 123 || reply.ifindex != 2 || !reply.address.IsLoopback() {
				t.Fatalf("invalid listener decode: %+v %v", reply, err)
			}
		}
	}
}

func TestNativeListenerDatagramsRejectIncompleteInterruptedAndWrongSequence(t *testing.T) {
	good := testDiagMessage(sockDiagByFamily, syscall.NLM_F_MULTI, 42, 123, testDiagPayload(syscall.AF_INET, 6, 2022))
	done := testDiagMessage(syscall.NLMSG_DONE, syscall.NLM_F_MULTI, 42, 123, make([]byte, 4))
	for name, raw := range map[string][]byte{
		"truncated header": good[:10],
		"truncated record": good[:len(good)-4],
		"partial tail":     append(append([]byte{}, good...), 1, 2, 3, 4),
		"interrupted":      testDiagMessage(sockDiagByFamily, 0x10, 42, 123, testDiagPayload(syscall.AF_INET, 6, 2022)),
		"wrong sequence":   testDiagMessage(sockDiagByFamily, 0, 43, 123, testDiagPayload(syscall.AF_INET, 6, 2022)),
		"wrong port ID":    testDiagMessage(sockDiagByFamily, 0, 42, 124, testDiagPayload(syscall.AF_INET, 6, 2022)),
		"data after done":  append(append([]byte{}, done...), good...),
		"wrong family":     testDiagMessage(sockDiagByFamily, 0, 42, 123, testDiagPayload(syscall.AF_INET6, 6, 2022)),
		"short record":     testDiagMessage(sockDiagByFamily, 0, 42, 123, []byte{syscall.AF_INET}),
		"short error":      testDiagMessage(syscall.NLMSG_ERROR, 0, 42, 123, []byte{0}),
		"positive error":   testDiagMessage(syscall.NLMSG_ERROR, 0, 42, 123, []byte{1, 0, 0, 0}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := decodeListenerDatagram(raw, 42, 123, syscall.AF_INET, 6, func() bool { return false }); err == nil {
				t.Fatal("unsafe partial listener dump accepted")
			}
		})
	}
	rows, completed, err := decodeListenerDatagram(append(good, done...), 42, 123, syscall.AF_INET, 6, func() bool { return false })
	if err != nil || !completed || len(rows) != 1 || rows[0].port != 2022 {
		t.Fatalf("complete native dump rejected: %+v %v %v", rows, completed, err)
	}
}

func TestNativeListenerIPv6DisabledDoesNotSuppressIPv4(t *testing.T) {
	errorBody := make([]byte, 4)
	missingFamily := int32(-int32(syscall.EAFNOSUPPORT))
	binary.NativeEndian.PutUint32(errorBody, uint32(missingFamily))
	raw := testDiagMessage(syscall.NLMSG_ERROR, 0, 42, 123, errorBody)
	if rows, done, err := decodeListenerDatagram(raw, 42, 123, syscall.AF_INET6, 6, func() bool { return true }); err != nil || !done || len(rows) != 0 {
		t.Fatal("a confirmed unavailable IPv6 family disabled IPv4 coverage")
	}
	if _, _, err := decodeListenerDatagram(raw, 42, 123, syscall.AF_INET6, 6, func() bool { return false }); !errors.Is(err, errFastDiscoveryUnsupported) {
		t.Fatal("an unexplained IPv6 coverage failure was silently ignored")
	}
	if _, _, err := decodeListenerDatagram(raw, 42, 123, syscall.AF_INET, 6, func() bool { return true }); !errors.Is(err, errFastDiscoveryUnsupported) {
		t.Fatal("an IPv4 coverage failure was silently ignored")
	}
}

func TestNativeListenerSnapshotObservesRealTCPAndUDPStartStop(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := nativeListenerSnapshot(ctx); err != nil {
		if errors.Is(err, errFastDiscoveryUnsupported) {
			t.Skipf("this Linux kernel does not expose inet_diag: %v", err)
		}
		t.Fatal(err)
	}
	for _, network := range []string{"tcp4", "udp4", "tcp6", "udp6"} {
		t.Run(network, func(t *testing.T) {
			address := "127.0.0.1:0"
			if strings.HasSuffix(network, "6") {
				address = "[::1]:0"
			}
			var closeSocket func() error
			var local net.Addr
			if strings.HasPrefix(network, "tcp") {
				socket, err := net.Listen(network, address)
				if err != nil {
					if strings.HasSuffix(network, "6") && listenerIPv6Unavailable() {
						t.Skip("IPv6 family is disabled")
					}
					t.Fatal(err)
				}
				closeSocket, local = socket.Close, socket.Addr()
			} else {
				socket, err := net.ListenPacket(network, address)
				if err != nil {
					if strings.HasSuffix(network, "6") && listenerIPv6Unavailable() {
						t.Skip("IPv6 family is disabled")
					}
					t.Fatal(err)
				}
				closeSocket, local = socket.Close, socket.LocalAddr()
			}
			defer closeSocket()
			host, port, _ := net.SplitHostPort(local.String())
			key := network[:3] + "/" + port + "/" + host
			before, err := nativeListenerSnapshot(ctx)
			if err != nil || !before.bindings[key] {
				t.Fatalf("new %s listener not discovered: %s %v", network, key, err)
			}
			if err := closeSocket(); err != nil {
				t.Fatal(err)
			}
			after, err := nativeListenerSnapshot(ctx)
			if err != nil || after.bindings[key] || after.fingerprint == before.fingerprint {
				t.Fatalf("stopped %s listener remained discovered: %s %v", network, key, err)
			}
		})
	}
}

func TestNativeListenerSnapshotCancellationIsBounded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	if _, err := nativeListenerSnapshot(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled native scan did not stop: %v", err)
	}
	if time.Since(started) > 250*time.Millisecond {
		t.Fatal("native cancellation exceeded the receive timeout bound")
	}
}

func BenchmarkNativeListenerSnapshot(b *testing.B) {
	b.ReportAllocs()
	for index := 0; index < b.N; index++ {
		if _, err := nativeListenerSnapshot(context.Background()); err != nil {
			b.Fatal(err)
		}
	}
}
