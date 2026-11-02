package agent

import (
	"context"
	"errors"
)

var errUncertainCommand = errors.New("uncertain enforcement command: full process-tree drain is unproven; compensation and further writes are blocked until safe repair after verified unit drain or a new boot")

const commandFenceFilename = "command-uncertain.json"

func checkManagedCommandFence(ctx context.Context) error {
	if lease := managedLeaseFromContext(ctx); lease != nil {
		return checkCommandFence(lease.Name(), false)
	}
	return nil
}
