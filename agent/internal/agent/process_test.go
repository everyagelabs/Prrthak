package agent

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestExecRunnerPreservesCommandOutputAndExit(t *testing.T) {
	out, err := (ExecRunner{}).Run(context.Background(), "/bin/sh", "-c", "printf stdout; printf stderr >&2; exit 7")
	if err == nil || !strings.Contains(out, "stdout") || !strings.Contains(out, "stderr") {
		t.Fatalf("output=%q error=%v", out, err)
	}
	out, err = (ExecRunner{}).Run(context.Background(), "/bin/sh", "-c", "printf success")
	if err != nil || out != "success" {
		t.Fatalf("output=%q error=%v", out, err)
	}
}

func TestExecRunnerOwnedContextTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err := (ExecRunner{}).Run(ctx, "/bin/sh", "-c", "sleep 30"); err == nil {
		t.Fatal("command ignored context timeout")
	}
	if time.Since(started) > 3*time.Second {
		t.Fatal("owned command did not drain promptly after timeout")
	}
}
