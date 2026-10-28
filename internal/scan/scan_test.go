package scan_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/yinkoshield/pinscan/internal/classify"
	"github.com/yinkoshield/pinscan/internal/proxy"
	"github.com/yinkoshield/pinscan/internal/scan"
)

// obsMap turns a plain outcome map into the observation map a WaveFunc returns,
// supplying a synthetic reason so tests stay terse.
func obsMap(outcomes map[string]classify.WaveOutcome) map[string]scan.WaveObservation {
	out := make(map[string]scan.WaveObservation, len(outcomes))
	for host, o := range outcomes {
		out[host] = scan.WaveObservation{Outcome: o, Reason: "test"}
	}
	return out
}

func fakeWaves(byWave map[proxy.Wave]map[string]classify.WaveOutcome, ran *[]proxy.Wave, errs map[proxy.Wave]error) scan.WaveFunc {
	return func(_ context.Context, w proxy.Wave) (map[string]scan.WaveObservation, error) {
		*ran = append(*ran, w)
		if err := errs[w]; err != nil {
			return nil, err
		}
		return obsMap(byWave[w]), nil
	}
}

func TestRunClassifiesAcrossWaves(t *testing.T) {
	t.Parallel()

	byWave := map[proxy.Wave]map[string]classify.WaveOutcome{
		proxy.Generic: {"open.example.com": classify.Accepted, "pin.example.com": classify.Rejected},
		proxy.Cloned:  {"open.example.com": classify.Accepted, "pin.example.com": classify.Rejected},
		proxy.Issuer:  {"pin.example.com": classify.Rejected},
	}
	var ran []proxy.Wave

	results, err := scan.Run(context.Background(), fakeWaves(byWave, &ran, nil))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	want := map[string]classify.Verdict{
		"open.example.com": classify.Open,
		"pin.example.com":  classify.SPKI,
	}
	if len(results) != len(want) {
		t.Fatalf("got %d results, want %d: %+v", len(results), len(want), results)
	}
	for _, r := range results {
		if r.Verdict != want[r.Host] {
			t.Errorf("%s verdict = %s, want %s", r.Host, r.Verdict, want[r.Host])
		}
	}
	if !slices.Equal(ran, []proxy.Wave{proxy.Generic, proxy.Cloned, proxy.Issuer}) {
		t.Errorf("waves run = %v, want A, B, C (a host was key-pinned)", ran)
	}
}

func TestRunSkipsWaveCWhenNothingKeyPinned(t *testing.T) {
	t.Parallel()

	byWave := map[proxy.Wave]map[string]classify.WaveOutcome{
		proxy.Generic: {"open.example.com": classify.Accepted},
		proxy.Cloned:  {"open.example.com": classify.Accepted},
	}
	var ran []proxy.Wave

	if _, err := scan.Run(context.Background(), fakeWaves(byWave, &ran, nil)); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !slices.Equal(ran, []proxy.Wave{proxy.Generic, proxy.Cloned}) {
		t.Errorf("waves run = %v, want A, B only (nothing key-pinned)", ran)
	}
}

func TestRunPropagatesWaveErrors(t *testing.T) {
	t.Parallel()

	// Generic/Cloned reject the host so wave C is reached, letting us fail any wave.
	byWave := map[proxy.Wave]map[string]classify.WaveOutcome{
		proxy.Generic: {"pin.example.com": classify.Rejected},
		proxy.Cloned:  {"pin.example.com": classify.Rejected},
		proxy.Issuer:  {"pin.example.com": classify.Rejected},
	}
	for _, wave := range []proxy.Wave{proxy.Generic, proxy.Cloned, proxy.Issuer} {
		wave := wave
		t.Run(wave.String(), func(t *testing.T) {
			t.Parallel()

			var ran []proxy.Wave
			errs := map[proxy.Wave]error{wave: errors.New("boom")}
			if _, err := scan.Run(context.Background(), fakeWaves(byWave, &ran, errs)); err == nil {
				t.Errorf("Run with wave %s failing = nil error, want an error", wave)
			}
		})
	}
}
