// Package baseline compares two pinscan reports to catch posture regressions in
// CI — the day a release stops pinning a host, in the PR that caused it.
//
// The guiding rule matches the rest of pinscan: never let silence read as safe.
// A host that weakens (e.g. spki → open) or a newly-appeared interceptable host
// is a regression; a host that goes from a decided verdict to inconclusive is
// NOT a silent pass and NOT a regression — it is flagged for review, because it
// almost always means the app made no request that run.
package baseline

import (
	"sort"

	"github.com/yinkoshield/pinscan/internal/report"
)

// strength ranks the decided verdicts from weakest to strongest. Inconclusive
// and any unknown verdict are deliberately absent: they are not comparable.
var strength = map[string]int{
	"open":            0,
	"metadata":        1,
	"name-validation": 2,
	"key-pinned":      3,
	"spki":            4,
}

// Change is one host's verdict transition between baseline and current.
type Change struct {
	Host string
	From string
	To   string
}

// Result groups the host-by-host differences between two reports.
type Result struct {
	Regressions  []Change // Weakened pinning, or a newly-interceptable host.
	Improvements []Change // Strengthened pinning, or inconclusive now decided.
	NeedsReview  []Change // A decided host that went inconclusive — not a pass.
	Added        []Change // New hosts that are not interceptable.
	Removed      []Change // Hosts in the baseline not seen this run.
}

// HasRegression reports whether any change weakened the posture.
func (r Result) HasRegression() bool { return len(r.Regressions) > 0 }

// Diff compares a baseline report (old) with a current one, classifying each
// host's change. Hosts are keyed by name; verdicts are compared by the strength
// lattice, with inconclusive handled explicitly.
func Diff(old, current report.Report) Result {
	oldV := verdicts(old)
	curV := verdicts(current)
	var res Result

	for _, host := range sortedKeys(curV) {
		to := curV[host]
		from, existed := oldV[host]
		switch {
		case !existed:
			classifyNew(&res, host, to)
		case from == to:
			// Unchanged.
		default:
			classifyChange(&res, Change{Host: host, From: from, To: to})
		}
	}
	for _, host := range sortedKeys(oldV) {
		if _, ok := curV[host]; !ok {
			res.Removed = append(res.Removed, Change{Host: host, From: oldV[host]})
		}
	}
	return res
}

// classifyNew files a host that appears only in the current report.
func classifyNew(res *Result, host, verdict string) {
	ch := Change{Host: host, To: verdict}
	if interceptable(verdict) {
		res.Regressions = append(res.Regressions, ch)
		return
	}
	res.Added = append(res.Added, ch)
}

// classifyChange files a host whose verdict changed between the reports.
func classifyChange(res *Result, ch Change) {
	fromS, fromOK := strength[ch.From]
	toS, toOK := strength[ch.To]
	switch {
	case fromOK && !toOK:
		// A decided verdict became inconclusive/unknown: suspicious, not a pass.
		res.NeedsReview = append(res.NeedsReview, ch)
	case !fromOK && toOK:
		// Was inconclusive, now decided. A decided-but-interceptable verdict is
		// a regression, not coverage: the host is demonstrably interceptable now
		// and silence before it must not read as safe (same rule as classifyNew).
		if interceptable(ch.To) {
			res.Regressions = append(res.Regressions, ch)
		} else {
			res.Improvements = append(res.Improvements, ch)
		}
	case fromOK && toOK && toS < fromS:
		res.Regressions = append(res.Regressions, ch)
	case fromOK && toOK && toS > fromS:
		res.Improvements = append(res.Improvements, ch)
	default:
		// Both inconclusive/unknown, or equal strength with different labels.
		res.NeedsReview = append(res.NeedsReview, ch)
	}
}

// interceptable reports whether a verdict is defeatable by a trusted-CA attacker.
func interceptable(verdict string) bool {
	s, ok := strength[verdict]
	return ok && s <= strength["name-validation"]
}

// verdicts maps each host to its verdict string.
func verdicts(r report.Report) map[string]string {
	out := make(map[string]string, len(r.Hosts))
	for _, h := range r.Hosts {
		out[h.Host] = h.Verdict
	}
	return out
}

// sortedKeys returns the map keys in sorted order for deterministic output.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
