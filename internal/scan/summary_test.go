package scan_test

import (
	"testing"

	"github.com/yinkoshield/pinscan/internal/classify"
	"github.com/yinkoshield/pinscan/internal/proxy"
	"github.com/yinkoshield/pinscan/internal/scan"
)

func TestSummarize(t *testing.T) {
	t.Parallel()

	results := []scan.HostResult{
		{Host: "a", Verdict: classify.Open},
		{Host: "b", Verdict: classify.Metadata},
		{Host: "c", Verdict: classify.SPKI},
		{Host: "d", Verdict: classify.Inconclusive},
		{Host: "e", Verdict: classify.KeyPinned},
	}
	s := scan.Summarize(results)

	if s.Hosts != 5 {
		t.Errorf("Hosts = %d, want 5", s.Hosts)
	}
	if s.Interceptable != 2 { // open + metadata are defeatable.
		t.Errorf("Interceptable = %d, want 2", s.Interceptable)
	}
	if s.Inconclusive != 1 {
		t.Errorf("Inconclusive = %d, want 1", s.Inconclusive)
	}
	for verdict, want := range map[string]int{
		"open": 1, "metadata": 1, "spki": 1, "inconclusive": 1, "key-pinned": 1, "name-validation": 0,
	} {
		if got := s.ByVerdict[verdict]; got != want {
			t.Errorf("ByVerdict[%q] = %d, want %d", verdict, got, want)
		}
	}
	// A key-pinned host is not hardened: wave C did not separate a key check
	// from name validation, so the host may still be interceptable.
	if s.Hardened() != 1 {
		t.Errorf("Hardened = %d, want 1 (spki only; key-pinned is not hardened)", s.Hardened())
	}
	if s.Undetermined() != 1 {
		t.Errorf("Undetermined = %d, want 1 (the key-pinned host)", s.Undetermined())
	}
}

// TestKeyPinnedIsNotCountedHardened pins the rule on its own: a scan whose only
// non-interceptable host is key-pinned has zero hardened hosts.
func TestKeyPinnedIsNotCountedHardened(t *testing.T) {
	t.Parallel()

	s := scan.Summarize([]scan.HostResult{
		{Host: "candidate", Verdict: classify.KeyPinned},
		{Host: "weak", Verdict: classify.NameValidation},
	})
	if s.Hardened() != 0 {
		t.Errorf("Hardened = %d, want 0: key-pinned must not count as hardened", s.Hardened())
	}
	if s.Undetermined() != 1 || s.Interceptable != 1 {
		t.Errorf("Undetermined = %d, Interceptable = %d, want 1 and 1", s.Undetermined(), s.Interceptable)
	}
}

// TestTallyBucketsAreDisjointAndSumToHosts makes a future verdict impossible to
// misfile silently: every host lands in exactly one tally bucket.
func TestTallyBucketsAreDisjointAndSumToHosts(t *testing.T) {
	t.Parallel()

	var results []scan.HostResult
	for v := classify.Inconclusive; v <= classify.SPKI; v++ {
		results = append(results, scan.HostResult{Host: v.String(), Verdict: v})
	}
	results = append(results, scan.HostResult{Host: "relayed", Verdict: classify.Inconclusive, Waves: map[string]scan.WaveObservation{
		"generic": {Outcome: classify.Ambiguous, Reason: proxy.ReasonPassthrough},
	}})
	s := scan.Summarize(results)

	buckets := map[string]int{
		"interceptable": s.Interceptable,
		"not verified":  s.NotVerified(),
		"passthrough":   s.Passthrough,
		"undetermined":  s.Undetermined(),
		"hardened":      s.Hardened(),
	}
	sum := 0
	for name, n := range buckets {
		if n < 0 {
			t.Errorf("bucket %s = %d, want >= 0", name, n)
		}
		sum += n
	}
	if sum != s.Hosts {
		t.Errorf("buckets %v sum to %d, want %d hosts", buckets, sum, s.Hosts)
	}
	want := map[string]int{"interceptable": 3, "not verified": 1, "passthrough": 1, "undetermined": 1, "hardened": 1}
	for name, n := range want {
		if buckets[name] != n {
			t.Errorf("bucket %s = %d, want %d", name, buckets[name], n)
		}
	}
}

func TestSummarizeCountsPassthroughSeparatelyAndAsInconclusive(t *testing.T) {
	t.Parallel()

	results := []scan.HostResult{
		{Host: "open", Verdict: classify.Open},
		{Host: "quiet", Verdict: classify.Inconclusive, Waves: map[string]scan.WaveObservation{
			"generic": {Outcome: classify.Ambiguous, Reason: "handshake_ok_no_request"},
		}},
		{Host: "login", Verdict: classify.Inconclusive, Waves: map[string]scan.WaveObservation{
			"generic": {Outcome: classify.Ambiguous, Reason: proxy.ReasonPassthrough},
			"cloned":  {Outcome: classify.Ambiguous, Reason: proxy.ReasonPassthrough},
		}},
		{Host: "down", Verdict: classify.Inconclusive, Waves: map[string]scan.WaveObservation{
			"generic": {Outcome: classify.Ambiguous, Reason: proxy.ReasonPassthroughDialFailed},
		}},
		{Host: "pinned", Verdict: classify.SPKI},
	}
	s := scan.Summarize(results)

	if s.Passthrough != 2 {
		t.Errorf("Passthrough = %d, want 2 (relayed and dial-failed both count)", s.Passthrough)
	}
	// Passthrough hosts are inconclusive and stay counted as such: a consumer
	// gating on the inconclusive count must see every untested host.
	if s.Inconclusive != 3 {
		t.Errorf("Inconclusive = %d, want 3 (passthrough hosts included)", s.Inconclusive)
	}
	if s.ByVerdict["inconclusive"] != 3 {
		t.Errorf("ByVerdict[inconclusive] = %d, want 3", s.ByVerdict["inconclusive"])
	}
	// The tally buckets are disjoint and sum to the total.
	if s.NotVerified() != 1 || s.Hardened() != 1 {
		t.Errorf("NotVerified = %d, Hardened = %d, want 1 and 1", s.NotVerified(), s.Hardened())
	}
	if s.Interceptable+s.NotVerified()+s.Passthrough+s.Undetermined()+s.Hardened() != s.Hosts {
		t.Errorf("tally buckets do not sum to %d hosts: %+v", s.Hosts, s)
	}
}

func TestSummarizeEmpty(t *testing.T) {
	t.Parallel()

	s := scan.Summarize(nil)
	if s.Hosts != 0 || s.Interceptable != 0 || s.Inconclusive != 0 {
		t.Errorf("empty summary = %+v, want zeroes", s)
	}
	if s.ByVerdict == nil {
		t.Error("ByVerdict is nil, want an initialized map")
	}
}
