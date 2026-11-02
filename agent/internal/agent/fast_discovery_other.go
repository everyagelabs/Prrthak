//go:build !linux

package agent

import "context"

func nativeListenerSnapshot(context.Context) (listenerSnapshot, error) {
	return listenerSnapshot{}, errFastDiscoveryUnsupported
}
