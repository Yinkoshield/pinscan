package scan

import "github.com/yinkoshield/pinscan/internal/classify"

// Summary is an aggregate count over a scan's host results, for the CLI tally,
// the report, and CI gates.
type Summary struct {
	Hosts         int            `json:"hosts_total"`
	Interceptable int            `json:"interceptable"`
	Inconclusive  int            `json:"inconclusive"`
	ByVerdict     map[string]int `json:"by_verdict"`
}

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
	}
	return s
}
