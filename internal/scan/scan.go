// Package scan orchestrates a pinning scan: it runs the waves in order, decides
// when the cloned-issuer wave is worth running, and classifies each host.
//
// The side effects (the proxy, the device, timing) live behind a [WaveFunc], so
// the sequencing logic here is pure and testable without a device.
package scan

import (
	"context"
	"fmt"
	"sort"

	"github.com/yinkoshield/pinscan/internal/classify"
	"github.com/yinkoshield/pinscan/internal/proxy"
)

// WaveObservation is a host's outcome in one wave, with the reason behind it
// (a TLS alert name, a transport failure, "handshake_ok_no_request", …), how
// many connection attempts backed it, and whether attempts conflicted.
type WaveObservation struct {
	Outcome  classify.WaveOutcome
	Reason   string
	Attempts int
	Conflict bool
}

// WaveFunc runs a single wave and returns each contacted host's observation.
type WaveFunc func(ctx context.Context, wave proxy.Wave) (map[string]WaveObservation, error)

// HostResult is a host's verdict together with the per-wave evidence behind it
// and how well-evidenced that verdict is, so the classification is auditable
// rather than a bare label.
type HostResult struct {
	Host       string
	Verdict    classify.Verdict
	Confidence Confidence
	// Waves holds the observation for each wave that saw the host, keyed by the
	// wave name ("generic", "cloned", "issuer").
	Waves map[string]WaveObservation
}

// Interceptable reports whether the verdict is defeatable by a trusted-CA
// attacker.
func (r HostResult) Interceptable() bool { return r.Verdict.Defeatable() }

// Run executes wave A (generic) and wave B (cloned-metadata), then wave C
// (cloned-issuer) only if some host genuinely rejected both, and classifies
// every host seen across the waves.
func Run(ctx context.Context, wave WaveFunc) ([]HostResult, error) {
	generic, err := wave(ctx, proxy.Generic)
	if err != nil {
		return nil, fmt.Errorf("scan: wave A: %w", err)
	}
	cloned, err := wave(ctx, proxy.Cloned)
	if err != nil {
		return nil, fmt.Errorf("scan: wave B: %w", err)
	}

	var issuer map[string]WaveObservation
	if anyKeyPinned(generic, cloned) {
		issuer, err = wave(ctx, proxy.Issuer)
		if err != nil {
			return nil, fmt.Errorf("scan: wave C: %w", err)
		}
	}

	return classifyAll(generic, cloned, issuer), nil
}

// anyKeyPinned reports whether a host genuinely rejected both the generic and
// the cloned leaf, which makes it a candidate the cloned-issuer wave can refine.
func anyKeyPinned(generic, cloned map[string]WaveObservation) bool {
	for host := range generic {
		if generic[host].Outcome == classify.Rejected && cloned[host].Outcome == classify.Rejected {
			return true
		}
	}
	return false
}

// classifyAll classifies every host seen in any wave, attaching the per-wave
// evidence. A nil wave map yields NotObserved for its outcomes.
func classifyAll(generic, cloned, issuer map[string]WaveObservation) []HostResult {
	hosts := sortedHosts(generic, cloned, issuer)
	results := make([]HostResult, 0, len(hosts))
	for _, host := range hosts {
		verdict := classify.Classify(classify.HostObservation{
			Host:    host,
			Generic: generic[host].Outcome,
			Cloned:  cloned[host].Outcome,
			Issuer:  issuer[host].Outcome,
		}).Verdict
		waves := wavesFor(host, generic, cloned, issuer)
		results = append(results, HostResult{
			Host:       host,
			Verdict:    verdict,
			Confidence: ConfidenceOf(verdict, waves),
			Waves:      waves,
		})
	}
	return results
}

// wavesFor collects the observations that actually saw host, keyed by wave name.
func wavesFor(host string, generic, cloned, issuer map[string]WaveObservation) map[string]WaveObservation {
	waves := make(map[string]WaveObservation, 3)
	for name, wave := range map[string]map[string]WaveObservation{
		proxy.Generic.String(): generic,
		proxy.Cloned.String():  cloned,
		proxy.Issuer.String():  issuer,
	} {
		if obs, ok := wave[host]; ok {
			waves[name] = obs
		}
	}
	return waves
}

// sortedHosts returns the union of hosts across the waves, sorted.
func sortedHosts(waves ...map[string]WaveObservation) []string {
	seen := make(map[string]struct{})
	for _, wave := range waves {
		for host := range wave {
			seen[host] = struct{}{}
		}
	}
	hosts := make([]string, 0, len(seen))
	for host := range seen {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	return hosts
}
