package classify_test

import (
	"testing"

	"github.com/yinkoshield/pinscan/internal/classify"
)

// TestClassify is the executable specification of the pinning methodology.
// Every precedence rule and every "not observed" edge case has a row.
func TestClassify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		obs     classify.HostObservation
		want    classify.Verdict
		wantDef bool // expected Defeatable() for the resulting verdict
	}{
		{
			name: "no signal in any wave is inconclusive",
			obs:  obs(classify.NotObserved, classify.NotObserved, classify.NotObserved),
			want: classify.Inconclusive, wantDef: false,
		},
		{
			name: "accepting the generic leaf means no pinning",
			obs:  obs(classify.Accepted, classify.NotObserved, classify.NotObserved),
			want: classify.Open, wantDef: true,
		},
		{
			name: "generic acceptance overrides later rejections",
			obs:  obs(classify.Accepted, classify.Rejected, classify.Rejected),
			want: classify.Open, wantDef: true,
		},
		{
			name: "reject generic, accept cloned metadata is metadata validation",
			obs:  obs(classify.Rejected, classify.Accepted, classify.NotObserved),
			want: classify.Metadata, wantDef: true,
		},
		{
			name: "accept cloned metadata without a generic baseline is still metadata",
			obs:  obs(classify.NotObserved, classify.Accepted, classify.NotObserved),
			want: classify.Metadata, wantDef: true,
		},
		{
			name: "reject leaves, accept cloned issuer is name validation",
			obs:  obs(classify.Rejected, classify.Rejected, classify.Accepted),
			want: classify.NameValidation, wantDef: true,
		},
		{
			name: "accept cloned issuer even if cloned leaf was not observed",
			obs:  obs(classify.Rejected, classify.NotObserved, classify.Accepted),
			want: classify.NameValidation, wantDef: true,
		},
		{
			name: "reject every forged cert and the cloned issuer is genuine SPKI",
			obs:  obs(classify.Rejected, classify.Rejected, classify.Rejected),
			want: classify.SPKI, wantDef: false,
		},
		{
			name: "reject leaves but Wave C not run is key-pinned candidate",
			obs:  obs(classify.Rejected, classify.Rejected, classify.NotObserved),
			want: classify.KeyPinned, wantDef: false,
		},
		{
			name: "reject generic only is key-pinned candidate",
			obs:  obs(classify.Rejected, classify.NotObserved, classify.NotObserved),
			want: classify.KeyPinned, wantDef: false,
		},
		{
			name: "reject cloned only is key-pinned candidate",
			obs:  obs(classify.NotObserved, classify.Rejected, classify.NotObserved),
			want: classify.KeyPinned, wantDef: false,
		},
		{
			name: "rejecting the cloned issuer is the strongest signal, SPKI",
			obs:  obs(classify.NotObserved, classify.NotObserved, classify.Rejected),
			want: classify.SPKI, wantDef: false,
		},
		{
			name: "ambiguous signals in every wave are inconclusive, never pinned",
			obs:  obs(classify.Ambiguous, classify.Ambiguous, classify.Ambiguous),
			want: classify.Inconclusive, wantDef: false,
		},
		{
			name: "an ambiguous cloned-issuer must not be read as SPKI",
			obs:  obs(classify.Rejected, classify.Rejected, classify.Ambiguous),
			want: classify.KeyPinned, wantDef: false,
		},
		{
			name: "a genuinely rejected leaf with everything else ambiguous is key-pinned",
			obs:  obs(classify.Rejected, classify.Ambiguous, classify.Ambiguous),
			want: classify.KeyPinned, wantDef: false,
		},
		{
			name: "ambiguous everywhere but a genuine issuer rejection is still SPKI",
			obs:  obs(classify.Ambiguous, classify.Ambiguous, classify.Rejected),
			want: classify.SPKI, wantDef: false,
		},
		{
			name: "acceptance still wins over an ambiguous later wave",
			obs:  obs(classify.Accepted, classify.Ambiguous, classify.Ambiguous),
			want: classify.Open, wantDef: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := classify.Classify(tt.obs)
			if got.Verdict != tt.want {
				t.Errorf("Classify(%+v).Verdict = %s, want %s", tt.obs, got.Verdict, tt.want)
			}
			if got.Verdict.Defeatable() != tt.wantDef {
				t.Errorf("%s.Defeatable() = %t, want %t", got.Verdict, got.Verdict.Defeatable(), tt.wantDef)
			}
		})
	}
}

func TestClassifyPreservesHost(t *testing.T) {
	t.Parallel()

	const host = "secure.example.com"
	got := classify.Classify(classify.HostObservation{Host: host})
	if got.Host != host {
		t.Errorf("Classify kept Host = %q, want %q", got.Host, host)
	}
}

func TestWaveOutcomeString(t *testing.T) {
	t.Parallel()

	cases := map[classify.WaveOutcome]string{
		classify.NotObserved:    "not-observed",
		classify.Accepted:       "accepted",
		classify.Rejected:       "rejected",
		classify.WaveOutcome(9): "invalid",
	}
	for o, want := range cases {
		if got := o.String(); got != want {
			t.Errorf("WaveOutcome(%d).String() = %q, want %q", o, got, want)
		}
	}
}

func TestVerdictString(t *testing.T) {
	t.Parallel()

	cases := map[classify.Verdict]string{
		classify.Inconclusive:   "inconclusive",
		classify.Open:           "open",
		classify.Metadata:       "metadata",
		classify.NameValidation: "name-validation",
		classify.KeyPinned:      "key-pinned",
		classify.SPKI:           "spki",
		classify.Verdict(9):     "invalid",
	}
	for v, want := range cases {
		if got := v.String(); got != want {
			t.Errorf("Verdict(%d).String() = %q, want %q", v, got, want)
		}
	}
}

func TestWaveOutcomeStringAmbiguous(t *testing.T) {
	t.Parallel()

	cases := map[classify.WaveOutcome]string{
		classify.NotObserved:    "not-observed",
		classify.Accepted:       "accepted",
		classify.Rejected:       "rejected",
		classify.Ambiguous:      "ambiguous",
		classify.WaveOutcome(9): "invalid",
	}
	for o, want := range cases {
		if got := o.String(); got != want {
			t.Errorf("WaveOutcome(%d).String() = %q, want %q", o, got, want)
		}
	}
}

func TestVerdictDefeatable(t *testing.T) {
	t.Parallel()

	defeatable := map[classify.Verdict]bool{
		classify.Open:           true,
		classify.Metadata:       true,
		classify.NameValidation: true,
		classify.KeyPinned:      false,
		classify.SPKI:           false,
		classify.Inconclusive:   false,
		classify.Verdict(99):    false, // out-of-range verdicts are never defeatable.
	}
	for v, want := range defeatable {
		if got := v.Defeatable(); got != want {
			t.Errorf("%s.Defeatable() = %t, want %t", v, got, want)
		}
	}
}

func TestVerdictExplain(t *testing.T) {
	t.Parallel()

	// Every verdict must have a non-empty, distinct plain-language mechanism
	// explanation — this is what tells an operator "per-key vs metadata".
	verdicts := []classify.Verdict{
		classify.Inconclusive, classify.Open, classify.Metadata,
		classify.NameValidation, classify.KeyPinned, classify.SPKI,
	}
	seen := map[string]bool{}
	for _, v := range verdicts {
		got := v.Explain()
		if got == "" {
			t.Errorf("%s.Explain() is empty", v)
		}
		if seen[got] {
			t.Errorf("%s.Explain() duplicates another verdict's explanation: %q", v, got)
		}
		seen[got] = true
	}
	if got := classify.Verdict(42).Explain(); got == "" {
		t.Error("out-of-range Verdict.Explain() is empty, want a safe fallback")
	}
}

func TestVerdictStrengthAndAtLeast(t *testing.T) {
	t.Parallel()

	// Strength is strictly increasing in hardening; inconclusive is weakest.
	order := []classify.Verdict{
		classify.Inconclusive, classify.Open, classify.Metadata,
		classify.NameValidation, classify.KeyPinned, classify.SPKI,
	}
	for i := 1; i < len(order); i++ {
		if order[i].Strength() <= order[i-1].Strength() {
			t.Errorf("%s should be stronger than %s", order[i], order[i-1])
		}
	}
	if !classify.SPKI.AtLeast(classify.KeyPinned) {
		t.Error("spki should be at least key-pinned")
	}
	if classify.Open.AtLeast(classify.SPKI) {
		t.Error("open should not be at least spki")
	}
	if classify.Inconclusive.AtLeast(classify.Open) {
		t.Error("inconclusive should not satisfy an expectation of open")
	}
}

func TestParseVerdict(t *testing.T) {
	t.Parallel()

	for _, v := range []classify.Verdict{
		classify.Inconclusive, classify.Open, classify.Metadata,
		classify.NameValidation, classify.KeyPinned, classify.SPKI,
	} {
		got, ok := classify.ParseVerdict(v.String())
		if !ok || got != v {
			t.Errorf("ParseVerdict(%q) = (%s, %v), want %s", v.String(), got, ok, v)
		}
	}
	if _, ok := classify.ParseVerdict("bogus"); ok {
		t.Error("ParseVerdict(bogus) ok=true, want false")
	}
}

// obs is a terse constructor for the three wave outcomes, in A/B/C order.
func obs(generic, cloned, issuer classify.WaveOutcome) classify.HostObservation {
	return classify.HostObservation{
		Host:    "host.example.com",
		Generic: generic,
		Cloned:  cloned,
		Issuer:  issuer,
	}
}
