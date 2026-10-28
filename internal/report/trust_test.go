package report_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/yinkoshield/pinscan/internal/report"
)

func TestReportCarriesCATrust(t *testing.T) {
	t.Parallel()

	meta, results, rec := sampleInputs(t)
	meta.CATrust = "unverified"
	rep := report.Build(meta, results, rec)
	if rep.Scan.CATrust != "unverified" {
		t.Errorf("Scan.CATrust = %q, want unverified", rep.Scan.CATrust)
	}

	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"ca_trust":"unverified"`) {
		t.Errorf("JSON lacks ca_trust: %s", raw)
	}

	var md bytes.Buffer
	if err := report.Markdown(&md, rep); err != nil {
		t.Fatalf("Markdown: %v", err)
	}
	if !strings.Contains(md.String(), "research CA trust **unverified**") {
		t.Errorf("markdown header does not state CA trust: %s", md.String())
	}
	var html bytes.Buffer
	if err := report.HTML(&html, rep); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	if !strings.Contains(html.String(), "research CA trust unverified") {
		t.Errorf("HTML header does not state CA trust")
	}
}

func TestReportOmitsCATrustWhenUnset(t *testing.T) {
	t.Parallel()

	// Older producers and the canonical baseline fixtures in the tests set no
	// trust status; the field must then be absent, not an empty string.
	meta, results, rec := sampleInputs(t)
	raw, err := json.Marshal(report.Build(meta, results, rec))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "ca_trust") {
		t.Errorf("ca_trust present although unset: %s", raw)
	}
}
