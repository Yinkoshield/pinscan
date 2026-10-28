package scan

import (
	"fmt"

	"github.com/yinkoshield/pinscan/internal/classify"
	"github.com/yinkoshield/pinscan/internal/proxy"
)

// Confidence grades how well-evidenced a verdict is. It is a separate axis from
// the verdict itself: a correct verdict can still rest on thin evidence, and a
// CI gate may require a minimum.
type Confidence string

// Confidence levels, weakest first.
const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

// rank orders the levels for comparison.
func (c Confidence) rank() int {
	switch c {
	case ConfidenceHigh:
		return 2
	case ConfidenceMedium:
		return 1
	case ConfidenceLow:
		return 0
	default:
		return 0
	}
}

// Below reports whether c is a weaker level than other.
func (c Confidence) Below(other Confidence) bool { return c.rank() < other.rank() }

// ParseConfidence maps a level name to a Confidence.
func ParseConfidence(s string) (Confidence, error) {
	switch Confidence(s) {
	case ConfidenceLow, ConfidenceMedium, ConfidenceHigh:
		return Confidence(s), nil
	default:
		return "", fmt.Errorf("invalid confidence %q (want low, medium or high)", s)
	}
}

// ConfidenceOf grades the evidence behind a verdict, conservatively:
//
//   - The deciding wave's attempt count sets the base: two or more consistent
//     attempts is high, a single observation is medium.
//   - key-pinned is a candidate (the cloned-issuer wave did not conclusively
//     run), so it is capped at medium however many attempts backed it.
//   - any conflicting wave (attempts both accepted and genuinely rejected) drops
//     the whole host to low.
//   - inconclusive carries no confident verdict, so it is low.
func ConfidenceOf(verdict classify.Verdict, waves map[string]WaveObservation) Confidence {
	if verdict == classify.Inconclusive {
		return ConfidenceLow
	}
	if anyConflict(waves) {
		return ConfidenceLow
	}
	deciding, ok := decidingWave(verdict, waves)
	if !ok {
		return ConfidenceLow
	}
	conf := ConfidenceMedium
	if deciding.Attempts >= 2 {
		conf = ConfidenceHigh
	}
	if verdict == classify.KeyPinned && conf == ConfidenceHigh {
		conf = ConfidenceMedium
	}
	return conf
}

// decidingWave returns the observation that determined the verdict.
func decidingWave(verdict classify.Verdict, waves map[string]WaveObservation) (WaveObservation, bool) {
	switch verdict {
	case classify.Open:
		return withOutcome(waves, proxy.Generic.String(), classify.Accepted)
	case classify.Metadata:
		return withOutcome(waves, proxy.Cloned.String(), classify.Accepted)
	case classify.NameValidation:
		return withOutcome(waves, proxy.Issuer.String(), classify.Accepted)
	case classify.SPKI:
		return withOutcome(waves, proxy.Issuer.String(), classify.Rejected)
	case classify.KeyPinned:
		if o, ok := withOutcome(waves, proxy.Generic.String(), classify.Rejected); ok {
			return o, true
		}
		return withOutcome(waves, proxy.Cloned.String(), classify.Rejected)
	case classify.Inconclusive:
		return WaveObservation{}, false
	default:
		return WaveObservation{}, false
	}
}

// withOutcome returns the named wave's observation if it has the given outcome.
func withOutcome(waves map[string]WaveObservation, name string, want classify.WaveOutcome) (WaveObservation, bool) {
	if o, ok := waves[name]; ok && o.Outcome == want {
		return o, true
	}
	return WaveObservation{}, false
}

// anyConflict reports whether any wave saw contradictory decisive outcomes.
func anyConflict(waves map[string]WaveObservation) bool {
	for _, o := range waves {
		if o.Conflict {
			return true
		}
	}
	return false
}
