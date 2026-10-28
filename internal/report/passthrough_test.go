package report_test

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/yinkoshield/pinscan/internal/classify"
	"github.com/yinkoshield/pinscan/internal/proxy"
	"github.com/yinkoshield/pinscan/internal/report"
	"github.com/yinkoshield/pinscan/internal/scan"
)

const relayedHost = "login.example.com"

// passthroughInputs is a scan with one open host, one hardened host, one
// ordinary inconclusive host and one passthrough host, as the scan package
// would classify them.
func passthroughInputs() (report.Meta, []scan.HostResult) {
	results := []scan.HostResult{
		{Host: "secure.example.com", Verdict: classify.Open, Confidence: scan.ConfidenceHigh, Waves: map[string]scan.WaveObservation{
			"generic": {Outcome: classify.Accepted, Reason: "request_observed", Attempts: 2},
		}},
		{Host: "pinned.example.com", Verdict: classify.SPKI, Confidence: scan.ConfidenceMedium, Waves: map[string]scan.WaveObservation{
			"generic": {Outcome: classify.Rejected, Reason: "tls_alert_bad_certificate", Attempts: 1},
			"cloned":  {Outcome: classify.Rejected, Reason: "tls_alert_bad_certificate", Attempts: 1},
			"issuer":  {Outcome: classify.Rejected, Reason: "tls_alert_bad_certificate", Attempts: 1},
		}},
		{Host: "quiet.example.com", Verdict: classify.Inconclusive, Confidence: scan.ConfidenceLow, Waves: map[string]scan.WaveObservation{
			"generic": {Outcome: classify.Ambiguous, Reason: "handshake_ok_no_request", Attempts: 1},
		}},
		{Host: relayedHost, Verdict: classify.Inconclusive, Confidence: scan.ConfidenceLow, Caveat: scan.CaveatPassthrough, Waves: map[string]scan.WaveObservation{
			"generic": {Outcome: classify.Ambiguous, Reason: proxy.ReasonPassthrough, Attempts: 3},
			"cloned":  {Outcome: classify.Ambiguous, Reason: proxy.ReasonPassthrough, Attempts: 3},
			"issuer":  {Outcome: classify.Ambiguous, Reason: proxy.ReasonPassthrough, Attempts: 3},
		}},
	}
	return sampleMeta(), results
}

func TestBuildMarksPassthroughHost(t *testing.T) {
	t.Parallel()

	meta, results := passthroughInputs()
	rep := report.Build(meta, results, nil)

	if rep.Summary.Passthrough != 1 || rep.Summary.Inconclusive != 2 {
		t.Errorf("summary = %+v, want 1 passthrough counted among 2 inconclusive", rep.Summary)
	}
	var found bool
	for _, h := range rep.Hosts {
		if h.Host != relayedHost {
			if h.Passthrough || h.Caveat != "" {
				t.Errorf("%s carries passthrough=%v caveat=%q, want neither", h.Host, h.Passthrough, h.Caveat)
			}
			continue
		}
		found = true
		if !h.Passthrough || h.Verdict != "inconclusive" || h.Caveat != scan.CaveatPassthrough {
			t.Errorf("passthrough host report = %+v", h)
		}
	}
	if !found {
		t.Fatal("passthrough host missing from the report")
	}
}

func TestJSONCarriesPassthroughFieldsOnlyWhereSet(t *testing.T) {
	t.Parallel()

	meta, results := passthroughInputs()
	rep := report.Build(meta, results, nil)

	var buf bytes.Buffer
	if err := report.JSON(&buf, rep); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var raw struct {
		Summary map[string]any   `json:"summary"`
		Hosts   []map[string]any `json:"hosts"`
	}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got, ok := raw.Summary["passthrough"]; !ok || got != float64(1) {
		t.Errorf("summary.passthrough = %v (present %v), want 1", got, ok)
	}
	for _, h := range raw.Hosts {
		_, hasFlag := h["passthrough"]
		if (h["host"] == relayedHost) != hasFlag {
			t.Errorf("host %v: passthrough field present = %v", h["host"], hasFlag)
		}
	}
}

func TestMarkdownAndHTMLShowPassthroughCaveat(t *testing.T) {
	t.Parallel()

	meta, results := passthroughInputs()
	rep := report.Build(meta, results, nil)

	var md, html bytes.Buffer
	if err := report.Markdown(&md, rep); err != nil {
		t.Fatalf("Markdown: %v", err)
	}
	if err := report.HTML(&html, rep); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	for name, out := range map[string]string{"markdown": md.String(), "html": html.String()} {
		for _, want := range []string{
			scan.CaveatPassthrough,
			"1 passthrough (not tested)",
			// Passthrough hosts are not double-counted in the tally's inconclusive bucket.
			"1 inconclusive (not verified)",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("%s missing %q:\n%s", name, want, out)
			}
		}
	}
}

func TestMarkdownOmitsPassthroughTallyWhenNone(t *testing.T) {
	t.Parallel()

	meta, results, rec := sampleInputs(t)
	var md bytes.Buffer
	if err := report.Markdown(&md, report.Build(meta, results, rec)); err != nil {
		t.Fatalf("Markdown: %v", err)
	}
	if strings.Contains(md.String(), "passthrough") {
		t.Errorf("markdown mentions passthrough with none in the scan:\n%s", md.String())
	}
}

func TestSARIFEmitsNoResultForPassthroughHost(t *testing.T) {
	t.Parallel()

	meta, results := passthroughInputs()
	var buf bytes.Buffer
	if err := report.SARIF(&buf, report.Build(meta, results, nil)); err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	var log struct {
		Runs []struct {
			Results []struct {
				Message struct{ Text string } `json:"message"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}
	if len(log.Runs) != 1 || len(log.Runs[0].Results) != 3 {
		t.Fatalf("want 3 results (the passthrough host has none), got %+v", log.Runs)
	}
	for _, r := range log.Runs[0].Results {
		if strings.HasPrefix(r.Message.Text, relayedHost+":") {
			t.Errorf("SARIF carries a result for the passthrough host: %q", r.Message.Text)
		}
	}
}

func TestJUnitSkipsPassthroughHostWithReason(t *testing.T) {
	t.Parallel()

	meta, results := passthroughInputs()
	var buf bytes.Buffer
	if err := report.JUnit(&buf, report.Build(meta, results, nil)); err != nil {
		t.Fatalf("JUnit: %v", err)
	}
	var suites struct {
		Tests  int `xml:"tests,attr"`
		Suites []struct {
			Skipped int `xml:"skipped,attr"`
			Cases   []struct {
				Name    string `xml:"name,attr"`
				Skipped *struct {
					Message string `xml:"message,attr"`
				} `xml:"skipped"`
				Failure *struct{} `xml:"failure"`
			} `xml:"testcase"`
		} `xml:"testsuite"`
	}
	if err := xml.Unmarshal(buf.Bytes(), &suites); err != nil {
		t.Fatalf("JUnit is not valid XML: %v\n%s", err, buf.String())
	}
	if suites.Tests != 4 || suites.Suites[0].Skipped != 2 {
		t.Errorf("tests=%d skipped=%d, want 4 and 2 (quiet + passthrough)", suites.Tests, suites.Suites[0].Skipped)
	}
	var seen bool
	for _, c := range suites.Suites[0].Cases {
		if c.Name != relayedHost {
			continue
		}
		seen = true
		if c.Failure != nil {
			t.Error("passthrough host is a JUnit failure; it was not tested")
		}
		if c.Skipped == nil || c.Skipped.Message != scan.CaveatPassthrough {
			t.Errorf("passthrough skip = %+v, want message %q", c.Skipped, scan.CaveatPassthrough)
		}
	}
	if !seen {
		t.Error("passthrough host missing from the JUnit cases")
	}
}
