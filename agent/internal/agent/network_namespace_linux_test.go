//go:build linux

package agent

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestNamespacePinnedParentDescriptorSurvivesExecRunnerSupervisor(t *testing.T) {
	file, err := os.OpenFile(filepath.Join(t.TempDir(), "retained-namespace-fixture"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	const expected = "pinned-parent-namespace-descriptor\n"
	if _, err := file.WriteString(expected); err != nil {
		t.Fatal(err)
	}
	path := "/proc/" + strconv.Itoa(os.Getpid()) + "/fd/" + strconv.FormatUint(uint64(file.Fd()), 10)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ctx = context.WithValue(ctx, commandOutputLimitKey{}, 65536)
	output, err := (ExecRunner{}).Run(ctx, "cat", path)
	if err != nil || output != expected {
		t.Fatal("supervised child could not open the retained parent descriptor", output, err)
	}
}
