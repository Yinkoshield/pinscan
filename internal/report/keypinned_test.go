package report_test

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/yinkoshield/pinscan/internal/classify"
	"github.com/yinkoshield/pinscan/internal/report"
	"github.com/yinkoshield/pinscan/internal/scan"
)

const candidateHost = "candidate.example.com"

// keyPinnedInputs is a scan with one interceptable host, one hardened host, one
// key-pinned candidate (wave C ran and returned no usable signal) and one
// inconclusive host. The candidate and the inconclusive host must read "not
// established" everywhere a human looks, never "no".
func keyPinnedInputs() (report.Meta, []scan.HostResult) {
	results := []scan.HostResult{
		{Host: "secure.example.com", Verdict: classify.Open, Confidence: scan.ConfidenceHigh, Waves: map[string]scan.WaveObservation{
			"generic": {Outcome: classify.Accepted, Reason: "request_observed", Attempts: 2},
		}},
		{Host: "pinned.example.com", Verdict: classify.SPKI, Confidence: scan.ConfidenceHigh, Waves: map[string]scan.WaveObservation{
			"generic": {Outcome: classify.Rejected, Reason: "tls_alert_bad_certificate", Attempts: 2},
			"cloned":  {Outcome: classify.Rejected, Reason: "tls_alert_bad_certificate", Attempts: 2},
			"issuer":  {Outcome: classify.Rejected, Reason: "tls_alert_bad_certificate", Attempts: 2},
		}},
		{Host: candidateHost, Verdict: classify.KeyPinned, Confidence: scan.ConfidenceMedium, Waves: map[string]scan.WaveObservation{
			"generic": {Outcome: classify.Rejected, Reason: "tls_alert_bad_certificate", Attempts: 2},
			"cloned":  {Outcome: classify.Rejected, Reason: "tls_alert_bad_certificate", Attempts: 2},
			"issuer":  {Outcome: classify.Ambiguous, Reason: "timeout", Attempts: 2},
		}},
		{Host: "quiet.example.com", Verdict: classify.Inconclusive, Confidence: scan.ConfidenceLow, Waves: map[string]scan.WaveObservation{
			"generic": {Outcome: classify.Ambiguous, Reason: "handshake_ok_no_request", Attempts: 1},
		}},
	}
	return sampleMeta(), results
}

func TestBuildReportsThreeValuedInterceptability(t *testing.T) {
	t.Parallel()

	meta, results := keyPinnedInputs()
	rep := report.Build(meta, results, nil)

	want := map[string]string{
		"secure.example.com": report.InterceptabilityYes,
		"pinned.example.com": report.InterceptabilityNo,
		candidateHost:        report.InterceptabilityNotEstablished,
		"quiet.example.com":  report.InterceptabilityNotEstablished,
	}
	for _, h := range rep.Hosts {
		if h.Interceptability != want[h.Host] {
			t.Errorf("%s interceptability = %q, want %q", h.Host, h.Interceptability, want[h.Host])
		}
		// The deprecated boolean keeps its old meaning: true only when shown defeatable.
		if h.Interceptable != (h.Interceptability == report.InterceptabilityYes) {
			t.Errorf("%s interceptable=%v disagrees with interceptability %q", h.Host, h.Interceptable, h.Interceptability)
		}
	}
	// A key-pinned host is undetermined, not hardened.
	if rep.Summary.Hardened() != 1 || rep.Summary.Undetermined() != 1 {
		t.Errorf("summary hardened=%d undetermined=%d, want 1 and 1: %+v", rep.Summary.Hardened(), rep.Summary.Undetermined(), rep.Summary)
	}
}

func TestJSONCarriesInterceptabilityAndDeprecatedBool(t *testing.T) {
	t.Parallel()

	meta, results := keyPinnedInputs()
	var buf bytes.Buffer
	if err := report.JSON(&buf, report.Build(meta, results, nil)); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var raw struct {
		SchemaVersion string           `json:"schema_version"`
		Hosts         []map[string]any `json:"hosts"`
	}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if raw.SchemaVersion != "1.3.0" {
		t.Errorf("schema_version = %q, want 1.3.0 (interceptability is additive)", raw.SchemaVersion)
	}
	for _, h := range raw.Hosts {
		if _, ok := h["interceptable"]; !ok {
			t.Errorf("host %v: deprecated interceptable boolean missing; it is kept for one minor version", h["host"])
		}
		if h["host"] == candidateHost && h["interceptability"] != "not-established" {
			t.Errorf("key-pinned host interceptability = %v, want not-established", h["interceptability"])
		}
	}
}

func TestMarkdownAndHTMLNeverPrintNoForUnestablishedHosts(t *testing.T) {
	t.Parallel()

	meta, results := keyPinnedInputs()
	rep := report.Build(meta, results, nil)

	var md, html bytes.Buffer
	if err := report.Markdown(&md, rep); err != nil {
		t.Fatalf("Markdown: %v", err)
	}
	if err := report.HTML(&html, rep); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	for name, out := range map[string]string{"markdown": md.String(), "html": html.String()} {
		for _, want := range []string{"1 undetermined (key-pinned)", "1 hardened", "not established"} {
			if !strings.Contains(out, want) {
				t.Errorf("%s missing %q:\n%s", name, want, out)
			}
		}
		for _, host := range []string{candidateHost, "quiet.example.com"} {
			assertRowNotEstablished(t, name, hostRow(out, host), host)
		}
	}
}

// hostRow returns the host's rendered table row: one line in Markdown, the
// lines up to the closing </tr> in HTML.
func hostRow(out, host string) string {
	lines := strings.Split(out, "\n")
	for i, line := range lines {
		if !strings.Contains(line, host) {
			continue
		}
		if strings.HasPrefix(line, "|") {
			return line
		}
		end := i
		for end < len(lines) && !strings.Contains(lines[end], "</tr>") {
			end++
		}
		return strings.Join(lines[i:min(end+1, len(lines))], "\n")
	}
	return ""
}

// assertRowNotEstablished checks that a host's row says "not established" and
// never a bare "no" in the interceptable column.
func assertRowNotEstablished(t *testing.T, format, row, host string) {
	t.Helper()
	if row == "" {
		t.Errorf("%s: no row for %s", format, host)
		return
	}
	if !strings.Contains(row, "not established") {
		t.Errorf("%s row for %s lacks \"not established\":\n%s", format, host, row)
	}
	if strings.Contains(row, "| no |") || strings.Contains(row, `class="no"`) {
		t.Errorf("%s prints a bare \"no\" for %s, which was not established:\n%s", format, host, row)
	}
}

func TestJUnitSkipsKeyPinnedRatherThanPassing(t *testing.T) {
	t.Parallel()

	meta, results := keyPinnedInputs()
	var buf bytes.Buffer
	if err := report.JUnit(&buf, report.Build(meta, results, nil)); err != nil {
		t.Fatalf("JUnit: %v", err)
	}
	var suites junitDoc
	if err := xml.Unmarshal(buf.Bytes(), &suites); err != nil {
		t.Fatalf("JUnit is not valid XML: %v\n%s", err, buf.String())
	}
	if suites.Tests != 4 || suites.Failures != 1 || suites.Suites[0].Skipped != 2 {
		t.Errorf("tests=%d failures=%d skipped=%d, want 4, 1 and 2 (key-pinned + inconclusive)", suites.Tests, suites.Failures, suites.Suites[0].Skipped)
	}
	cases := map[string]junitDocCase{}
	for _, c := range suites.Suites[0].Cases {
		cases[c.Name] = c
	}
	candidate := cases[candidateHost]
	if candidate.Failure != nil || candidate.Skipped == nil {
		t.Errorf("key-pinned host must be skipped, not passed or failed: %+v", candidate)
	} else if !strings.Contains(candidate.Skipped.Message, "cloned-issuer wave") {
		t.Errorf("key-pinned skip message %q does not say why", candidate.Skipped.Message)
	}
	if pinned := cases["pinned.example.com"]; pinned.Failure != nil || pinned.Skipped != nil {
		t.Errorf("spki host must pass: %+v", pinned)
	}
}

// junitDoc is the slice of JUnit XML these tests read back.
type junitDoc struct {
	Tests    int `xml:"tests,attr"`
	Failures int `xml:"failures,attr"`
	Suites   []struct {
		Skipped int            `xml:"skipped,attr"`
		Cases   []junitDocCase `xml:"testcase"`
	} `xml:"testsuite"`
}

type junitDocCase struct {
	Name    string `xml:"name,attr"`
	Skipped *struct {
		Message string `xml:"message,attr"`
	} `xml:"skipped"`
	Failure *struct{} `xml:"failure"`
}

func TestSARIFFilesKeyPinnedAsWarning(t *testing.T) {
	t.Parallel()

	meta, results := keyPinnedInputs()
	var buf bytes.Buffer
	if err := report.SARIF(&buf, report.Build(meta, results, nil)); err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	var log struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID                   string `json:"id"`
						DefaultConfiguration struct {
							Level string `json:"level"`
						} `json:"defaultConfiguration"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID  string                `json:"ruleId"`
				Level   string                `json:"level"`
				Message struct{ Text string } `json:"message"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}
	levels := map[string]string{}
	for _, r := range log.Runs[0].Results {
		levels[r.RuleID] = r.Level
	}
	want := map[string]string{
		"pinscan/open":         "error",
		"pinscan/spki":         "note",
		"pinscan/key-pinned":   "warning",
		"pinscan/inconclusive": "warning",
	}
	for rule, level := range want {
		if levels[rule] != level {
			t.Errorf("%s level = %q, want %q", rule, levels[rule], level)
		}
	}
	for _, r := range log.Runs[0].Tool.Driver.Rules {
		if r.ID == "pinscan/key-pinned" && r.DefaultConfiguration.Level != "warning" {
			t.Errorf("rule catalog files key-pinned as %q, want warning", r.DefaultConfiguration.Level)
		}
	}
}
