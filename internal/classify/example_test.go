package classify_test

import (
	"fmt"

	"github.com/yinkoshield/pinscan/internal/classify"
)

// A host that genuinely rejects every forged certificate — including the
// cloned-issuer chain — is pinning its key.
func ExampleClassify() {
	r := classify.Classify(classify.HostObservation{
		Host:    "api.example.com",
		Generic: classify.Rejected,
		Cloned:  classify.Rejected,
		Issuer:  classify.Rejected,
	})
	fmt.Println(r.Verdict)
	// Output: spki
}

// Accepting the generic forged leaf means no pinning: an injected CA intercepts
// the host.
func ExampleClassify_open() {
	r := classify.Classify(classify.HostObservation{
		Host:    "cdn.example.com",
		Generic: classify.Accepted,
	})
	fmt.Println(r.Verdict, "interceptable:", r.Verdict.Defeatable())
	// Output: open interceptable: true
}

// An ambiguous signal (a timeout, a reset, no request) is never read as pinning.
func ExampleClassify_inconclusive() {
	r := classify.Classify(classify.HostObservation{
		Host:    "slow.example.com",
		Generic: classify.Ambiguous,
	})
	fmt.Println(r.Verdict)
	// Output: inconclusive
}

func ExampleVerdict_Explain() {
	fmt.Println(classify.SPKI.Explain())
	// Output: Genuine public-key (SPKI) pinning: the app rejected the forged leaves and the cloned issuer alike, so it pins the key, not metadata — a trusted-CA attacker does not intercept it.
}
