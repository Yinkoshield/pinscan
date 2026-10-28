package scan_test

import (
	"testing"

	"github.com/yinkoshield/pinscan/internal/classify"
	"github.com/yinkoshield/pinscan/internal/scan"
)

func rejectedEverywhere() map[string]scan.WaveObservation {
	return map[string]scan.WaveObservation{
		"generic": {Outcome: classify.Rejected, Reason: "tls_alert_unknown_ca", Attempts: 2},
		"cloned":  {Outcome: classify.Rejected, Reason: "tls_alert_unknown_ca", Attempts: 2},
		"issuer":  {Outcome: classify.Rejected, Reason: "tls_alert_unknown_ca", Attempts: 2},
	}
}

func TestApplyTrustWithholdsHardenedVerdictsWhenUnverified(t *testing.T) {
	t.Parallel()

	// This is the failure the rule exists for: a client that does not trust
	// the research CA rejects every forged chain with unknown_ca, which reads
	// exactly like SPKI pinning. Unverified trust must not let that stand.
	in := []scan.HostResult{
		{Host: "spki.example", Verdict: classify.SPKI, Confidence: scan.ConfidenceHigh, Waves: rejectedEverywhere()},
		{Host: "kp.example", Verdict: classify.KeyPinned, Confidence: scan.ConfidenceMedium, Waves: rejectedEverywhere()},
		{Host: "open.example", Verdict: classify.Open, Confidence: scan.ConfidenceHigh},
		{Host: "meta.example", Verdict: classify.Metadata, Confidence: scan.ConfidenceHigh},
		{Host: "inc.example", Verdict: classify.Inconclusive, Confidence: scan.ConfidenceLow},
	}
	out := scan.ApplyTrust(in, scan.TrustUnverified)

	want := map[string]classify.Verdict{
		"spki.example": classify.Inconclusive,
		"kp.example":   classify.Inconclusive,
		"open.example": classify.Open,
		"meta.example": classify.Metadata,
		"inc.example":  classify.Inconclusive,
	}
	for _, r := range out {
		if r.Verdict != want[r.Host] {
			t.Errorf("%s: verdict = %s, want %s", r.Host, r.Verdict, want[r.Host])
		}
	}
	assertWithheld(t, out, "spki.example", "kp.example")
	assertNoCaveat(t, out, "open.example", "meta.example", "inc.example")

	// The input is left alone.
	if in[0].Verdict != classify.SPKI {
		t.Error("ApplyTrust modified its input slice")
	}
	sum := scan.Summarize(out)
	if sum.Inconclusive != 3 || sum.Interceptable != 2 {
		t.Errorf("summary after withholding = %+v, want 3 inconclusive and 2 interceptable", sum)
	}
}

// assertWithheld checks that each host's hardened verdict was withheld with low
// confidence, a caveat, and its per-wave evidence intact.
func assertWithheld(t *testing.T, results []scan.HostResult, hosts ...string) {
	t.Helper()
	for _, host := range hosts {
		r := byHost(t, results, host)
		if r.Confidence != scan.ConfidenceLow {
			t.Errorf("%s: withheld verdict keeps confidence %q, want low", host, r.Confidence)
		}
		if r.Caveat == "" {
			t.Errorf("%s: withheld verdict carries no caveat", host)
		}
		if len(r.Waves) != 3 {
			t.Errorf("%s: per-wave evidence was dropped (%d waves)", host, len(r.Waves))
		}
	}
}

// assertNoCaveat checks that none of the hosts was touched by the trust rule.
func assertNoCaveat(t *testing.T, results []scan.HostResult, hosts ...string) {
	t.Helper()
	for _, host := range hosts {
		if r := byHost(t, results, host); r.Caveat != "" {
			t.Errorf("%s: unexpected caveat %q", host, r.Caveat)
		}
	}
}

func TestApplyTrustVerifiedLeavesResultsUnchanged(t *testing.T) {
	t.Parallel()

	in := []scan.HostResult{
		{Host: "spki.example", Verdict: classify.SPKI, Confidence: scan.ConfidenceHigh, Waves: rejectedEverywhere()},
		{Host: "open.example", Verdict: classify.Open, Confidence: scan.ConfidenceHigh},
	}
	for i, r := range scan.ApplyTrust(in, scan.TrustVerified) {
		if r.Verdict != in[i].Verdict || r.Confidence != in[i].Confidence || r.Caveat != "" {
			t.Errorf("verified trust changed %s: %+v", r.Host, r)
		}
	}
}

func TestApplyTrustAssertedKeepsVerdictWithCaveat(t *testing.T) {
	t.Parallel()

	in := []scan.HostResult{
		{Host: "spki.example", Verdict: classify.SPKI, Confidence: scan.ConfidenceHigh, Waves: rejectedEverywhere()},
		{Host: "open.example", Verdict: classify.Open, Confidence: scan.ConfidenceHigh},
	}
	out := scan.ApplyTrust(in, scan.TrustAsserted)
	if r := byHost(t, out, "spki.example"); r.Verdict != classify.SPKI || r.Caveat == "" {
		t.Errorf("asserted trust: spki host = %+v, want verdict kept and a caveat", r)
	}
	if r := byHost(t, out, "open.example"); r.Caveat != "" {
		t.Errorf("asserted trust: interceptable host should carry no caveat, got %q", r.Caveat)
	}
}

func TestTrustStatusString(t *testing.T) {
	t.Parallel()

	cases := map[scan.TrustStatus]string{
		scan.TrustUnverified: "unverified",
		scan.TrustVerified:   "verified",
		scan.TrustAsserted:   "operator-asserted",
		scan.TrustStatus(42): "unverified",
	}
	for s, want := range cases {
		if got := s.String(); got != want {
			t.Errorf("TrustStatus(%d).String() = %q, want %q", int(s), got, want)
		}
	}
}

type plainTarget struct{ scan.Target }

type reportingTarget struct {
	scan.Target
	status scan.TrustStatus
}

func (r reportingTarget) TrustStatus() scan.TrustStatus { return r.status }

func TestTrustOfDefaultsToUnverified(t *testing.T) {
	t.Parallel()

	if got := scan.TrustOf(plainTarget{}); got != scan.TrustUnverified {
		t.Errorf("TrustOf(non-reporting target) = %s, want unverified", got)
	}
	if got := scan.TrustOf(reportingTarget{status: scan.TrustVerified}); got != scan.TrustVerified {
		t.Errorf("TrustOf(reporting target) = %s, want verified", got)
	}
}

func byHost(t *testing.T, results []scan.HostResult, host string) scan.HostResult {
	t.Helper()
	for _, r := range results {
		if r.Host == host {
			return r
		}
	}
	t.Fatalf("host %s missing from results", host)
	return scan.HostResult{}
}
