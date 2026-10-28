package report_test

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/yinkoshield/pinscan/internal/report"
)

func TestSARIFIsValidAndLevelled(t *testing.T) {
	t.Parallel()

	meta, results, rec := sampleInputs(t)
	rep := report.Build(meta, results, rec)

	var buf bytes.Buffer
	if err := report.SARIF(&buf, rep); err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	var log struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string                `json:"ruleId"`
				Level     string                `json:"level"`
				Message   struct{ Text string } `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct{ URI string } `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v\n%s", err, buf.String())
	}
	if log.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", log.Version)
	}
	if len(log.Runs) != 1 || len(log.Runs[0].Results) != 2 {
		t.Fatalf("want 1 run with 2 results, got %+v", log.Runs)
	}
	byHost := map[string]string{}
	for _, r := range log.Runs[0].Results {
		if len(r.Locations) == 0 || r.Locations[0].PhysicalLocation.ArtifactLocation.URI == "" {
			t.Errorf("result %q has no physical location (code scanning needs one)", r.RuleID)
		}
		byHost[r.Message.Text[:strings.IndexByte(r.Message.Text, ':')]] = r.Level
	}
	if byHost["secure.example.com"] != "error" {
		t.Errorf("open host level = %q, want error", byHost["secure.example.com"])
	}
	if byHost["pinned.example.com"] != "note" {
		t.Errorf("spki host level = %q, want note", byHost["pinned.example.com"])
	}
}

func TestJUnitIsValidAndMapsVerdicts(t *testing.T) {
	t.Parallel()

	meta, results, rec := sampleInputs(t)
	rep := report.Build(meta, results, rec)

	var buf bytes.Buffer
	if err := report.JUnit(&buf, rep); err != nil {
		t.Fatalf("JUnit: %v", err)
	}
	if !strings.HasPrefix(buf.String(), xml.Header) {
		t.Error("JUnit output missing XML header")
	}
	var suites struct {
		Tests    int `xml:"tests,attr"`
		Failures int `xml:"failures,attr"`
		Suites   []struct {
			Cases []struct {
				Name    string `xml:"name,attr"`
				Failure *struct {
					Type string `xml:"type,attr"`
				} `xml:"failure"`
			} `xml:"testcase"`
		} `xml:"testsuite"`
	}
	if err := xml.Unmarshal(buf.Bytes(), &suites); err != nil {
		t.Fatalf("JUnit is not valid XML: %v\n%s", err, buf.String())
	}
	if suites.Tests != 2 || suites.Failures != 1 {
		t.Errorf("tests=%d failures=%d, want 2 and 1", suites.Tests, suites.Failures)
	}
	var openFailed bool
	for _, c := range suites.Suites[0].Cases {
		if c.Name == "secure.example.com" && c.Failure != nil && c.Failure.Type == "interceptable" {
			openFailed = true
		}
	}
	if !openFailed {
		t.Error("the open host should be a JUnit failure of type interceptable")
	}
}
