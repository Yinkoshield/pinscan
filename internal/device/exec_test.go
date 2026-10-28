package device

import (
	"context"
	"testing"
)

func TestExecRootRejectsSingleQuote(t *testing.T) {
	t.Parallel()

	if _, err := NewExec().Root(context.Background(), "echo 'x'"); err == nil {
		t.Error("Root with a single quote = nil error, want an error")
	}
}

func TestExecReportsMissingBinary(t *testing.T) {
	t.Parallel()

	e := &Exec{path: "pinscan-no-such-adb-binary"}
	ctx := context.Background()
	calls := map[string]func() (string, error){
		"Shell": func() (string, error) { return e.Shell(ctx, "true") },
		"Root":  func() (string, error) { return e.Root(ctx, "true") },
		"State": func() (string, error) { return e.State(ctx) },
	}
	for name, call := range calls {
		if _, err := call(); err == nil {
			t.Errorf("%s with a missing adb binary = nil error, want an error", name)
		}
	}
}
