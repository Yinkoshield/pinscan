package scan_test

import (
	"testing"

	"github.com/yinkoshield/pinscan/internal/classify"
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
