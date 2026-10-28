// Package report turns a scan's verdicts and captured exchanges into a
// shareable artifact (JSON, Markdown or HTML) for humans and CI.
//
// The report model holds body text as strings, not raw bytes: a body that is
// valid UTF-8 is carried verbatim, and anything else is replaced by a short
// "binary" note. This keeps every rendered artifact readable and safe to embed
// (the HTML renderer additionally escapes all content).
package report

import (
	_ "embed"
	"fmt"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/yinkoshield/pinscan/internal/capture"
	"github.com/yinkoshield/pinscan/internal/scan"
)

// SchemaVersion is the semantic version of the JSON report contract. A consumer
// refuses an unknown MAJOR; additive fields bump MINOR. See the JSON Schema
// returned by [Schema].
const SchemaVersion = "1.1.0"

// toolName is the tool name written into every report format.
const toolName = "pinscan"

//go:embed pinscan.v1.schema.json
var schemaJSON []byte

// Schema returns the JSON Schema (draft-07) for the report contract.
func Schema() []byte { return schemaJSON }

// Report is a self-contained, versioned snapshot of one scan. The core
// (schema_version, scan, summary, hosts) is deterministic and diffable; the
// volatile run block (timestamps) is omitted in canonical output so two
// identical-posture scans are byte-identical.
type Report struct {
	SchemaVersion string       `json:"schema_version"`
	Tool          Tool         `json:"tool"`
	Scan          ScanMeta     `json:"scan"`
	Summary       scan.Summary `json:"summary"`
	Hosts         []HostReport `json:"hosts"`
	Run           *RunMeta     `json:"run,omitempty"`
}

// Tool identifies the scanner that produced the report.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ScanMeta holds the deterministic inputs of a scan — the provenance a reader
// needs to know what was measured, and under what parameters.
type ScanMeta struct {
	Package       string `json:"package"`
	Mode          string `json:"mode"`
	Transparent   bool   `json:"transparent"`
	WindowSeconds int    `json:"window_seconds"`
	CASHA256      string `json:"ca_sha256"`
	// CATrust is how trust in the research CA was established: "verified",
	// "operator-asserted" or "unverified" (schema 1.1.0; hardened verdicts
	// are withheld when unverified).
	CATrust  string   `json:"ca_trust,omitempty"`
	WavesRun []string `json:"waves_run"`
}

// RunMeta holds the volatile, non-diffable facts about a particular run.
type RunMeta struct {
	StartedAt       string  `json:"started_at"`
	DurationSeconds float64 `json:"duration_seconds"`
}

// Meta is the input to [Build] beyond the results themselves.
type Meta struct {
	ToolVersion string
	Package     string
	Mode        string
	Transparent bool
	Window      time.Duration
	CASHA256    string
	// CATrust is the scan's trust status string (see scan.TrustStatus).
	CATrust   string
	StartedAt time.Time
	Duration  time.Duration
	// Canonical omits the volatile run block, for a stable baseline artifact.
	Canonical bool
}

// HostReport is one host's verdict, the per-wave evidence behind it, and (if
// captured) its exchanges.
type HostReport struct {
	Host          string           `json:"host"`
	Verdict       string           `json:"verdict"`
	Confidence    string           `json:"confidence"`
	Mechanism     string           `json:"mechanism"`
	Interceptable bool             `json:"interceptable"`
	Waves         []WaveReport     `json:"waves,omitempty"`
	Exchanges     []ExchangeReport `json:"exchanges,omitempty"`
}

// WaveReport is one wave's observation for a host — the auditable evidence
// behind a verdict (which cert was presented, what happened, and why).
type WaveReport struct {
	Wave    string `json:"wave"`    // "generic", "cloned" or "issuer"
	Outcome string `json:"outcome"` // "accepted", "rejected", "ambiguous", "not-observed"
	Reason  string `json:"reason"`  // alert name, transport failure, request probe result
}

// ExchangeReport is one captured request/response pair, with string bodies.
type ExchangeReport struct {
	Method        string              `json:"method"`
	URL           string              `json:"url"`
	Status        int                 `json:"status"`
	ReqHeaders    map[string][]string `json:"request_headers,omitempty"`
	ReqBody       string              `json:"request_body,omitempty"`
	ReqTruncated  bool                `json:"request_truncated,omitempty"`
	RespHeaders   map[string][]string `json:"response_headers,omitempty"`
	RespBody      string              `json:"response_body,omitempty"`
	RespTruncated bool                `json:"response_truncated,omitempty"`
	Err           string              `json:"error,omitempty"`
}

// waveOrder is the fixed display order of waves in a report.
var waveOrder = []string{"generic", "cloned", "issuer"}

// Build assembles a versioned Report from a scan's metadata, results and (if
// present) captured exchanges. Hosts are sorted; a host's exchanges appear only
// when it was captured. In canonical mode the volatile run block is omitted so
// the output is a stable baseline.
func Build(meta Meta, results []scan.HostResult, rec *capture.Recorder) Report {
	byHost := map[string][]capture.Exchange{}
	if rec != nil {
		byHost = rec.ByHost()
	}

	hosts := make([]HostReport, 0, len(results))
	for _, r := range results {
		hr := HostReport{
			Host:          r.Host,
			Verdict:       r.Verdict.String(),
			Confidence:    string(r.Confidence),
			Mechanism:     r.Verdict.Explain(),
			Interceptable: r.Verdict.Defeatable(),
			Waves:         wavesReport(r.Waves),
		}
		for _, ex := range byHost[r.Host] {
			hr.Exchanges = append(hr.Exchanges, toExchangeReport(ex))
		}
		hosts = append(hosts, hr)
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Host < hosts[j].Host })

	rep := Report{
		SchemaVersion: SchemaVersion,
		Tool:          Tool{Name: toolName, Version: meta.ToolVersion},
		Scan: ScanMeta{
			Package:       meta.Package,
			Mode:          meta.Mode,
			Transparent:   meta.Transparent,
			WindowSeconds: int(meta.Window.Seconds()),
			CASHA256:      meta.CASHA256,
			CATrust:       meta.CATrust,
			WavesRun:      wavesRun(results),
		},
		Summary: scan.Summarize(results),
		Hosts:   hosts,
	}
	if !meta.Canonical {
		rep.Run = &RunMeta{
			StartedAt:       meta.StartedAt.UTC().Format(time.RFC3339),
			DurationSeconds: meta.Duration.Seconds(),
		}
	}
	return rep
}

// wavesRun returns, in fixed order, the waves that observed at least one host.
func wavesRun(results []scan.HostResult) []string {
	seen := map[string]bool{}
	for _, r := range results {
		for name := range r.Waves {
			seen[name] = true
		}
	}
	run := make([]string, 0, len(waveOrder))
	for _, name := range waveOrder {
		if seen[name] {
			run = append(run, name)
		}
	}
	return run
}

// wavesReport renders the per-wave evidence in fixed wave order, including only
// the waves that actually observed the host.
func wavesReport(waves map[string]scan.WaveObservation) []WaveReport {
	out := make([]WaveReport, 0, len(waveOrder))
	for _, name := range waveOrder {
		obs, ok := waves[name]
		if !ok {
			continue
		}
		out = append(out, WaveReport{
			Wave:    name,
			Outcome: obs.Outcome.String(),
			Reason:  obs.Reason,
		})
	}
	return out
}

// toExchangeReport converts a captured exchange to its string-bodied view.
func toExchangeReport(ex capture.Exchange) ExchangeReport {
	return ExchangeReport{
		Method:        ex.Method,
		URL:           ex.URL,
		Status:        ex.Status,
		ReqHeaders:    ex.ReqHeaders,
		ReqBody:       bodyText(ex.ReqBody),
		ReqTruncated:  ex.ReqTruncated,
		RespHeaders:   ex.RespHeaders,
		RespBody:      bodyText(ex.RespBody),
		RespTruncated: ex.RespTruncated,
		Err:           ex.Err,
	}
}

// bodyText renders a body as text when it is valid UTF-8, else as a byte-count
// note so the artifact never embeds raw binary.
func bodyText(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	if utf8.Valid(b) {
		return string(b)
	}
	return fmt.Sprintf("<%d bytes binary>", len(b))
}
