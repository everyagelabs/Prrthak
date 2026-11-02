//go:build !linux

package agent

import "errors"

type unsupportedTrafficCapture struct{}

func newNativeCapture() nativeCapture { return unsupportedTrafficCapture{} }
func (unsupportedTrafficCapture) Configure([]capturePortScope) error {
	return errors.New("typed netfilter capture requires Linux")
}
func (unsupportedTrafficCapture) Drain() ([]capturedFlow, TrafficCaptureCoverage) {
	return nil, TrafficCaptureCoverage{Backends: []CaptureBackendReport{{Backend: "conntrack", Status: "unsupported", Error: "Linux netfilter required"}, {Backend: "nflog", Status: "unsupported", Error: "Linux netfilter required"}}, Gaps: []string{"No implicit journal fallback for typed capture."}}
}
func (unsupportedTrafficCapture) Close() error { return nil }
