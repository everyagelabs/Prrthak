//go:build !linux

package agent

import (
	"context"
	"errors"
)

func sourceBankGlobalConfigDigest(context.Context, CommandRunner) (string, error) {
	return "", errors.New("native Linux daemon configuration metadata is required for source-bank activation")
}
