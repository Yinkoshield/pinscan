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
	if s.Interceptable+s.NotVerified()+s.Passthrough+s.Hardened() != s.Hosts {
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
