package report_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/yinkoshield/pinscan/internal/capture"
	"github.com/yinkoshield/pinscan/internal/classify"
	"github.com/yinkoshield/pinscan/internal/report"
	"github.com/yinkoshield/pinscan/internal/scan"
)

const samplePackage = "com.example.app"

func sampleMeta() report.Meta {
	return report.Meta{
		ToolVersion: "1.2.3",
		Package:     samplePackage,
		Mode:        "scoped",
		Window:      30 * time.Second,
		CASHA256:    "deadbeef",
		StartedAt:   time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC),
		Duration:    42 * time.Second,
	}
}

func sampleInputs(t *testing.T) (report.Meta, []scan.HostResult, *capture.Recorder) {
	t.Helper()
	results := []scan.HostResult{
		{Host: "secure.example.com", Verdict: classify.Open, Confidence: scan.ConfidenceHigh, Waves: map[string]scan.WaveObservation{
			"generic": {Outcome: classify.Accepted, Reason: "request_observed", Attempts: 4},
		}},
		{Host: "pinned.example.com", Verdict: classify.SPKI, Confidence: scan.ConfidenceMedium, Waves: map[string]scan.WaveObservation{
			"generic": {Outcome: classify.Rejected, Reason: "tls_alert_bad_certificate", Attempts: 1},
			"cloned":  {Outcome: classify.Rejected, Reason: "tls_alert_bad_certificate", Attempts: 1},
			"issuer":  {Outcome: classify.Rejected, Reason: "tls_alert_bad_certificate", Attempts: 1},
		}},
	}
	rec := capture.NewRecorder()
	rec.Add(capture.Exchange{
		Host: "secure.example.com", Method: "GET", URL: "/unleash/api/frontend",
		Status: 200, RespHeaders: http.Header{"Content-Type": {"application/json"}},
		RespBody: []byte(`{"toggles":["pkg.a"]}`),
	})
	return sampleMeta(), results, rec
}

func TestSchemaIsValidJSON(t *testing.T) {
	t.Parallel()

	var doc map[string]any
	if err := json.Unmarshal(report.Schema(), &doc); err != nil {
		t.Fatalf("embedded schema is not valid JSON: %v", err)
	}
	if doc["$schema"] == nil || doc["properties"] == nil {
		t.Errorf("schema missing $schema/properties: %v", doc)
	}
}

func TestBuildPopulatesContract(t *testing.T) {
	t.Parallel()

	meta, results, rec := sampleInputs(t)
	rep := report.Build(meta, results, rec)

	if rep.SchemaVersion != report.SchemaVersion {
		t.Errorf("SchemaVersion = %q, want %q", rep.SchemaVersion, report.SchemaVersion)
	}
	if rep.Scan.Package != samplePackage {
		t.Errorf("Scan.Package = %q", rep.Scan.Package)
	}
	if rep.Scan.WindowSeconds != 30 {
		t.Errorf("Scan.WindowSeconds = %d, want 30", rep.Scan.WindowSeconds)
	}
	if rep.Summary.Hosts != 2 || rep.Summary.Interceptable != 1 {
		t.Errorf("Summary = %+v, want 2 hosts / 1 interceptable", rep.Summary)
	}
	wantWaves := []string{"generic", "cloned", "issuer"}
	if strings.Join(rep.Scan.WavesRun, ",") != strings.Join(wantWaves, ",") {
		t.Errorf("WavesRun = %v, want %v", rep.Scan.WavesRun, wantWaves)
	}
	if rep.Run == nil || rep.Run.StartedAt == "" {
		t.Error("Run block missing in non-canonical report")
	}
}

func TestBuildCanonicalOmitsRun(t *testing.T) {
	t.Parallel()

	meta, results, rec := sampleInputs(t)
	meta.Canonical = true
	rep := report.Build(meta, results, rec)
	if rep.Run != nil {
		t.Errorf("canonical report carries a run block: %+v", rep.Run)
	}
}

func TestBuildCanonicalIsDeterministic(t *testing.T) {
	t.Parallel()

	meta, results, rec := sampleInputs(t)
	meta.Canonical = true

	render := func(startedAt time.Time, dur time.Duration) string {
		m := meta
		m.StartedAt = startedAt
		m.Duration = dur
		var buf bytes.Buffer
		if err := report.JSON(&buf, report.Build(m, results, rec)); err != nil {
			t.Fatalf("JSON: %v", err)
		}
		return buf.String()
	}
	// Two scans with the same posture but different timing must be byte-identical.
	a := render(time.Unix(1000, 0), 10*time.Second)
	b := render(time.Unix(9999, 0), 99*time.Second)
	if a != b {
		t.Errorf("canonical output is not deterministic:\n--- a ---\n%s\n--- b ---\n%s", a, b)
	}
}

func TestBuildBinaryBodyNoted(t *testing.T) {
	t.Parallel()

	rec := capture.NewRecorder()
	rec.Add(capture.Exchange{
		Host: "h.example.com", Method: "GET", URL: "/x", Status: 200,
		RespBody: []byte{0xff, 0xfe, 0x00, 0x01},
	})
	rep := report.Build(sampleMeta(),
		[]scan.HostResult{{Host: "h.example.com", Verdict: classify.Open}}, rec)

	body := rep.Hosts[0].Exchanges[0].RespBody
	if !strings.Contains(body, "binary") {
		t.Errorf("non-UTF-8 body = %q, want a 'binary' note", body)
	}
}

func TestRenderJSONRoundTrips(t *testing.T) {
	t.Parallel()

	meta, results, rec := sampleInputs(t)
	rep := report.Build(meta, results, rec)

	var buf bytes.Buffer
	if err := report.JSON(&buf, rep); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var back report.Report
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatalf("round-trip unmarshal: %v\n%s", err, buf.String())
	}
	if back.Scan.Package != samplePackage || len(back.Hosts) != 2 {
		t.Errorf("round-trip lost data: %+v", back)
	}
	if back.SchemaVersion != report.SchemaVersion {
		t.Errorf("round-trip schema_version = %q", back.SchemaVersion)
	}
}

func TestRenderMarkdownHasHostsAndBodies(t *testing.T) {
	t.Parallel()

	meta, results, rec := sampleInputs(t)
	rep := report.Build(meta, results, rec)

	var buf bytes.Buffer
	if err := report.Markdown(&buf, rep); err != nil {
		t.Fatalf("Markdown: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		samplePackage, "secure.example.com", "open", "spki",
		"/unleash/api/frontend", `{"toggles":["pkg.a"]}`,
		"No pinning",                // Open's mechanism explanation.
		"public-key (SPKI) pinning", // SPKI's mechanism explanation.
		"high", "medium",            // Confidence column.
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
}

func TestRenderHTMLEscapesBodies(t *testing.T) {
	t.Parallel()

	rec := capture.NewRecorder()
	rec.Add(capture.Exchange{
		Host: "h.example.com", Method: "GET", URL: "/x", Status: 200,
		RespBody: []byte(`<script>alert('xss')</script>`),
	})
	rep := report.Build(sampleMeta(),
		[]scan.HostResult{{Host: "h.example.com", Verdict: classify.Open}}, rec)

	var buf bytes.Buffer
	if err := report.HTML(&buf, rep); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "<script>alert") {
		t.Error("HTML did not escape a response body — XSS risk in the artifact")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Errorf("expected escaped body in HTML output")
	}
	if !strings.Contains(out, "h.example.com") {
		t.Error("HTML missing the host")
	}
}
