//go:build !linux

package agent

func checkCommandFence(string, bool) error { return nil }
