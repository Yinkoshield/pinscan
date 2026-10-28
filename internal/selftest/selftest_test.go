package selftest_test

import (
	"context"
	"testing"

	"github.com/yinkoshield/pinscan/internal/selftest"
)

// TestSelftestProvesEveryPosture is the executable proof that the real
// certmint → proxy → classify path separates no-pinning, metadata validation,
// name validation and SPKI pinning. It is a required CI check.
func TestSelftestProvesEveryPosture(t *testing.T) {
	t.Parallel()

	cases, err := selftest.Run(context.Background())
	if err != nil {
		t.Fatalf("selftest harness error: %v", err)
	}
	if len(cases) == 0 {
		t.Fatal("selftest produced no cases")
	}
	for _, c := range cases {
		if !c.Pass {
			t.Errorf("posture %q: got verdict %q, want %q", c.Posture, c.Got, c.Want)
		}
	}
}
