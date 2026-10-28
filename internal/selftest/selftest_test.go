package selftest_test

import (
	"context"
	"testing"

	"github.com/yinkoshield/pinscan/internal/proxy"
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
	var sawPassthrough bool
	for _, c := range cases {
		if !c.Pass {
			t.Errorf("posture %q: got verdict %q (reason %q), want %q", c.Posture, c.Got, c.Reason, c.Want)
		}
		if c.Posture == "passthrough" {
			sawPassthrough = true
			// The honesty rule end to end: a key-pinning client whose host is
			// relayed must read inconclusive because of the relay, not spki.
			if c.Got != "inconclusive" || c.Reason != proxy.ReasonPassthrough {
				t.Errorf("passthrough posture = %q/%q, want inconclusive/%s", c.Got, c.Reason, proxy.ReasonPassthrough)
			}
		}
	}
	if !sawPassthrough {
		t.Error("selftest has no passthrough posture")
	}
}
