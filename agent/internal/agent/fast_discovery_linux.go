//go:build linux

package agent

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"syscall"
	"time"
)

const sockDiagByFamily = 20
const maxListenerSnapshotBytes = 4 * 1024 * 1024

type listenerDiag struct {
	family, protocol byte
	port             uint16
	address          netip.Addr
	ifindex, inode   uint32
}

func decodeListenerDiag(raw []byte, family, protocol byte) (listenerDiag, error) {
	result := listenerDiag{family: family, protocol: protocol}
	state := byte(10) // TCP_LISTEN; UDP's unconnected bound sockets use TCP_CLOSE.
	if protocol == 17 {
		state = 7
	}
	if len(raw) < 72 || raw[0] != family || raw[1] != state || binary.BigEndian.Uint16(raw[6:8]) != 0 {
		return result, errors.New("native listener reply has an unexpected family/state/peer")
	}
	result.port = binary.BigEndian.Uint16(raw[4:6])
	if family == syscall.AF_INET {
		result.address = netip.AddrFrom4([4]byte(raw[8:12]))
	} else if family == syscall.AF_INET6 {
		result.address = netip.AddrFrom16([16]byte(raw[8:24]))
	} else {
		return result, errors.New("native listener reply has an unsupported family")
	}
	result.ifindex = binary.NativeEndian.Uint32(raw[40:44])
	result.inode = binary.NativeEndian.Uint32(raw[68:72])
	return result, nil
}

func diagRequest(family, protocol byte, sequence, pid uint32) []byte {
	raw := make([]byte, 16+56)
	binary.NativeEndian.PutUint32(raw, uint32(len(raw)))
	binary.NativeEndian.PutUint16(raw[4:], sockDiagByFamily)
	binary.NativeEndian.PutUint16(raw[6:], syscall.NLM_F_REQUEST|syscall.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(raw[8:], sequence)
	binary.NativeEndian.PutUint32(raw[12:], pid)
	raw[16], raw[17] = family, protocol
	state := uint32(1 << 10)
	if protocol == 17 {
		state = 1 << 7
	}
	binary.NativeEndian.PutUint32(raw[20:], state)
	for index := 64; index < 72; index++ {
		raw[index] = 0xff // INET_DIAG_NOCOOKIE
	}
	return raw
}

func unsupportedListenerDiag(err error) bool {
	return errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EPROTONOSUPPORT) || errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES)
}

func listenerIPv6Unavailable() bool {
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err == nil {
		_ = syscall.Close(fd)
		return false
	}
	return errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EPROTONOSUPPORT)
}

// decodeListenerDatagram rejects partial or cross-request dumps before any
// observation can become authoritative. Kernel sender/truncation and aggregate
// byte/record limits are checked by the socket reader.
func decodeListenerDatagram(raw []byte, sequence, pid uint32, family, protocol byte, ipv6Unavailable func() bool) ([]listenerDiag, bool, error) {
	messages, err := syscall.ParseNetlinkMessage(raw)
	if err != nil || len(messages) == 0 {
		return nil, false, errors.New("malformed native listener datagram")
	}
	consumed := 0
	for _, message := range messages {
		consumed += (int(message.Header.Len) + 3) &^ 3
	}
	if consumed != len(raw) {
		return nil, false, errors.New("trailing incomplete native listener message")
	}
	records := []listenerDiag{}
	done := false
	for _, message := range messages {
		if done {
			return nil, false, errors.New("native listener dump contains data after its terminal reply")
		}
		if message.Header.Seq != sequence || message.Header.Pid != pid || message.Header.Flags&0x10 != 0 {
			return nil, false, errors.New("native listener dump sequence changed or dump was interrupted")
		}
		switch message.Header.Type {
		case syscall.NLMSG_DONE:
			if len(message.Data) > 0 && (len(message.Data) < 4 || int32(binary.NativeEndian.Uint32(message.Data)) != 0) {
				return nil, false, errors.New("native listener dump did not complete successfully")
			}
			done = true
		case syscall.NLMSG_ERROR:
			if len(message.Data) < 4 {
				return nil, false, errors.New("short native listener error")
			}
			errno := int32(binary.NativeEndian.Uint32(message.Data))
			if errno == 0 {
				continue
			}
			if errno > 0 {
				return nil, false, errors.New("invalid native listener error number")
			}
			failure := syscall.Errno(-errno)
			if family == syscall.AF_INET6 && unsupportedListenerDiag(failure) && ipv6Unavailable() {
				done = true
				continue
			}
			if unsupportedListenerDiag(failure) {
				return nil, false, fmt.Errorf("%w: %v", errFastDiscoveryUnsupported, failure)
			}
			return nil, false, failure
		case sockDiagByFamily:
			record, err := decodeListenerDiag(message.Data, family, protocol)
			if err != nil {
				return nil, false, err
			}
			records = append(records, record)
		default:
			return nil, false, errors.New("unexpected native listener reply type")
		}
	}
	return records, done, nil
}

func nativeListenerSnapshot(ctx context.Context) (listenerSnapshot, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_INET_DIAG)
	if err != nil {
		return listenerSnapshot{}, fmt.Errorf("%w: %v", errFastDiscoveryUnsupported, err)
	}
	defer syscall.Close(fd)
	if err = syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return listenerSnapshot{}, fmt.Errorf("%w: %v", errFastDiscoveryUnsupported, err)
	}
	if err = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Usec: 100000}); err != nil {
		return listenerSnapshot{}, err
	}
	address, err := syscall.Getsockname(fd)
	if err != nil {
		return listenerSnapshot{}, err
	}
	pid := address.(*syscall.SockaddrNetlink).Pid
	deadline := time.Now().Add(time.Second)
	if until, ok := ctx.Deadline(); ok && until.Before(deadline) {
		deadline = until
	}
	buffer := make([]byte, 64*1024)
	records := []string{}
	ports := map[string]bool{}
	bindings := map[string]bool{}
	bytesRead := 0
	sequence := uint32(0)
	for _, family := range []byte{syscall.AF_INET, syscall.AF_INET6} {
		for _, protocol := range []byte{6, 17} {
			sequence++
			if err = syscall.Sendto(fd, diagRequest(family, protocol, sequence, pid), 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
				return listenerSnapshot{}, err
			}
			done := false
			for !done {
				if err = ctx.Err(); err != nil {
					return listenerSnapshot{}, err
				}
				if !time.Now().Before(deadline) {
					return listenerSnapshot{}, errors.New("native listener snapshot exceeded its one-second deadline")
				}
				n, _, flags, peer, receiveErr := syscall.Recvmsg(fd, buffer, nil, 0)
				if errors.Is(receiveErr, syscall.EAGAIN) || errors.Is(receiveErr, syscall.EINTR) {
					continue
				}
				if receiveErr != nil {
					return listenerSnapshot{}, receiveErr
				}
				kernel, ok := peer.(*syscall.SockaddrNetlink)
				if !ok || kernel.Pid != 0 || flags&syscall.MSG_TRUNC != 0 || n == 0 {
					return listenerSnapshot{}, errors.New("native listener reply was truncated or not from the kernel")
				}
				bytesRead += n
				if bytesRead > maxListenerSnapshotBytes {
					return listenerSnapshot{}, errors.New("native listener snapshot exceeded its byte limit")
				}
				batch, completed, parseErr := decodeListenerDatagram(buffer[:n], sequence, pid, family, protocol, listenerIPv6Unavailable)
				if parseErr != nil {
					return listenerSnapshot{}, parseErr
				}
				done = completed
				for _, record := range batch {
					if record.port == 0 {
						continue // An unbound socket is not a listening service.
					}
					if len(records) >= maxFastListenerRecords {
						return listenerSnapshot{}, errors.New("native listener snapshot exceeds its record limit")
					}
					records = append(records, fmt.Sprintf("%d/%d/%s/%d/%d", protocol, record.port, record.address, record.ifindex, record.inode))
					label := "tcp"
					if protocol == 17 {
						label = "udp"
					}
					ports[fmt.Sprintf("%s/%d", label, record.port)] = true
					bindings[listenerBindingKey(label, int(record.port), record.address.String())] = true
				}
			}
		}
	}
	result, err := newListenerSnapshot(records, ports)
	result.bindings = bindings
	return result, err
}
