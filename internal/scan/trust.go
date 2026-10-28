package scan

import "github.com/yinkoshield/pinscan/internal/classify"

// TrustStatus records whether the research CA was verified to be trusted by
// the client under test. It matters because a client that does not trust the
// CA at all rejects every forged chain with a certificate alert, which is
// exactly what a key-pinned client does: without verified trust, a broken test
// setup is indistinguishable from protection.
type TrustStatus int

const (
	// TrustUnverified means pinscan could not confirm the CA is trusted.
	// Hardened verdicts are withheld (see [ApplyTrust]).
	TrustUnverified TrustStatus = iota
	// TrustVerified means pinscan observed the CA in the trust store the
	// client actually reads (on Android, from inside the app's or zygote's
	// mount namespace), or the client was built to trust it (selftest).
	TrustVerified
	// TrustAsserted means the operator was instructed to install the CA and
	// pinscan has no way to check (manual driver). Hardened verdicts stand but
	// are flagged as resting on that assertion.
	TrustAsserted
)

// String returns the status as it appears in reports.
func (s TrustStatus) String() string {
	switch s {
	case TrustVerified:
		return "verified"
	case TrustAsserted:
		return "operator-asserted"
	case TrustUnverified:
		return "unverified"
	default:
		return "unverified"
	}
}

// TrustReporter is implemented by targets that know whether the research CA
// is trusted by the client they drive.
type TrustReporter interface {
	TrustStatus() TrustStatus
}

// TrustOf returns the trust status a target reports, or [TrustUnverified] for
// a target that cannot say.
func TrustOf(t Target) TrustStatus {
	if r, ok := t.(TrustReporter); ok {
		return r.TrustStatus()
	}
	return TrustUnverified
}

// caveatUnverified explains a withheld verdict.
const caveatUnverified = "research CA trust unverified: a certificate rejection cannot be told apart from a client that simply does not trust the test CA, so the hardened verdict is withheld"

// caveatAsserted flags a hardened verdict that rests on the operator's setup.
const caveatAsserted = "research CA trust asserted by the operator, not verified by pinscan: this verdict is only as good as that setup"

// ApplyTrust applies the "never secure from silence" rule to CA trust. With
// [TrustUnverified], every hardened verdict (spki, key-pinned) becomes
// inconclusive, its confidence recomputed, and the per-wave evidence kept so
// the reader can see the rejections that were observed. With [TrustAsserted],
// verdicts stand and hardened hosts carry a caveat. With [TrustVerified],
// results are returned unchanged. The input slice is not modified.
func ApplyTrust(results []HostResult, status TrustStatus) []HostResult {
	out := make([]HostResult, len(results))
	copy(out, results)
	for i := range out {
		if out[i].Verdict.Defeatable() || out[i].Verdict == classify.Inconclusive {
			continue
		}
		switch status {
		case TrustUnverified:
			out[i].Verdict = classify.Inconclusive
			out[i].Confidence = ConfidenceOf(classify.Inconclusive, out[i].Waves)
			out[i].Caveat = caveatUnverified
		case TrustAsserted:
			out[i].Caveat = caveatAsserted
		case TrustVerified:
		}
	}
	return out
}
