package scan

import "github.com/yinkoshield/pinscan/internal/classify"

// Summary is an aggregate count over a scan's host results, for the CLI tally,
// the report, and CI gates.
//
// Passthrough hosts are inconclusive, so they count in Inconclusive (and in
// ByVerdict) as well as in Passthrough: a consumer gating on Inconclusive sees
// every untested host. The tally line prints disjoint buckets that sum to
// Hosts: Interceptable, [Summary.NotVerified], Passthrough,
// [Summary.Undetermined] and [Summary.Hardened].
type Summary struct {
	Hosts         int `json:"hosts_total"`
	Interceptable int `json:"interceptable"`
	Inconclusive  int `json:"inconclusive"`
	// Passthrough counts the hosts relayed to their real server, not tested
	// (schema 1.2.0, additive).
	Passthrough int            `json:"passthrough"`
	ByVerdict   map[string]int `json:"by_verdict"`
}

// NotVerified is the inconclusive hosts other than passthrough ones: the hosts
// the scan tried to test and got no usable signal from.
func (s Summary) NotVerified() int { return s.Inconclusive - s.Passthrough }

// Hardened is the hosts shown to resist a trusted-CA attacker: spki only. It is
// a direct count, not a remainder, so a verdict that belongs in no bucket can
// never be absorbed into this one. A key-pinned host is a candidate, not a
// result (see [Summary.Undetermined]), and is not counted here.
func (s Summary) Hardened() int { return s.ByVerdict[classify.SPKI.String()] }

// Undetermined is the key-pinned hosts: they rejected a forged leaf with a
// certificate alert, but the cloned-issuer wave returned no usable signal, or
// never ran, so the scan did not separate a key-level check from name
// validation. Such a host is not shown interceptable and not shown hardened;
// it is reported as "not established" rather than as either.
func (s Summary) Undetermined() int { return s.ByVerdict[classify.KeyPinned.String()] }

// Summarize counts the host results by verdict. ByVerdict always carries an
// entry for every verdict (zero when none), so a consumer can rely on the keys.
func Summarize(results []HostResult) Summary {
	byVerdict := map[string]int{
		classify.Open.String():           0,
		classify.Metadata.String():       0,
		classify.NameValidation.String(): 0,
		classify.KeyPinned.String():      0,
		classify.SPKI.String():           0,
		classify.Inconclusive.String():   0,
	}
	s := Summary{Hosts: len(results), ByVerdict: byVerdict}
	for _, r := range results {
		byVerdict[r.Verdict.String()]++
		if r.Verdict.Defeatable() {
			s.Interceptable++
		}
		if r.Verdict == classify.Inconclusive {
			s.Inconclusive++
		}
		if r.Passthrough() {
			s.Passthrough++
		}
	}
	return s
}
