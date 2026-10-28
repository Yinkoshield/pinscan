package scan_test

import (
	"testing"

	"github.com/yinkoshield/pinscan/internal/classify"
	"github.com/yinkoshield/pinscan/internal/scan"
)

func obsN(outcome classify.WaveOutcome, attempts int) scan.WaveObservation {
	return scan.WaveObservation{Outcome: outcome, Attempts: attempts}
}

func TestConfidenceOf(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		verdict classify.Verdict
		waves   map[string]scan.WaveObservation
		want    scan.Confidence
	}{
		{
			"open on many requests is high",
			classify.Open,
			map[string]scan.WaveObservation{"generic": obsN(classify.Accepted, 5)},
			scan.ConfidenceHigh,
		},
		{
			"open on a single request is medium",
			classify.Open,
			map[string]scan.WaveObservation{"generic": obsN(classify.Accepted, 1)},
			scan.ConfidenceMedium,
		},
		{
			"spki rejected consistently is high",
			classify.SPKI,
			map[string]scan.WaveObservation{
				"generic": obsN(classify.Rejected, 3),
				"cloned":  obsN(classify.Rejected, 3),
				"issuer":  obsN(classify.Rejected, 3),
			},
			scan.ConfidenceHigh,
		},
		{
			"spki rejected once is medium",
			classify.SPKI,
			map[string]scan.WaveObservation{"issuer": obsN(classify.Rejected, 1)},
			scan.ConfidenceMedium,
		},
		{
			"key-pinned is capped at medium even with many attempts",
			classify.KeyPinned,
			map[string]scan.WaveObservation{"generic": obsN(classify.Rejected, 9)},
			scan.ConfidenceMedium,
		},
		{
			"inconclusive is low",
			classify.Inconclusive,
			map[string]scan.WaveObservation{"cloned": obsN(classify.Ambiguous, 4)},
			scan.ConfidenceLow,
		},
		{
			"a conflict drops confidence to low",
			classify.Open,
			map[string]scan.WaveObservation{
				"generic": {Outcome: classify.Accepted, Attempts: 5, Conflict: true},
			},
			scan.ConfidenceLow,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := scan.ConfidenceOf(tt.verdict, tt.waves); got != tt.want {
				t.Errorf("ConfidenceOf(%s) = %q, want %q", tt.verdict, got, tt.want)
			}
		})
	}
}

func TestConfidenceBelow(t *testing.T) {
	t.Parallel()

	if !scan.ConfidenceLow.Below(scan.ConfidenceHigh) {
		t.Error("low should be below high")
	}
	if scan.ConfidenceHigh.Below(scan.ConfidenceMedium) {
		t.Error("high should not be below medium")
	}
	if scan.ConfidenceMedium.Below(scan.ConfidenceMedium) {
		t.Error("medium should not be below medium (equal)")
	}
}

func TestParseConfidence(t *testing.T) {
	t.Parallel()

	for in, want := range map[string]scan.Confidence{
		"low": scan.ConfidenceLow, "medium": scan.ConfidenceMedium, "high": scan.ConfidenceHigh,
	} {
		got, err := scan.ParseConfidence(in)
		if err != nil || got != want {
			t.Errorf("ParseConfidence(%q) = (%q, %v), want %q", in, got, err, want)
		}
	}
	if _, err := scan.ParseConfidence("bogus"); err == nil {
		t.Error("ParseConfidence(bogus) = nil error, want an error")
	}
}
