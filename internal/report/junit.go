package report

import (
	"encoding/xml"
	"fmt"
	"io"
)

// JUnit writes rep as JUnit XML, so a scan's hosts appear as test cases in a CI
// test pane. An interceptable host is a failure; an inconclusive host is skipped
// (ran, but no signal); a hardened host passes.
func JUnit(w io.Writer, rep Report) error {
	suite := junitSuite{
		Name:  rep.Scan.Package,
		Tests: len(rep.Hosts),
	}
	for _, h := range rep.Hosts {
		tc := junitCase{Name: h.Host, Classname: "pinscan.pinning"}
		switch {
		case h.Interceptable:
			suite.Failures++
			tc.Failure = &junitFailure{
				Message: fmt.Sprintf("%s (confidence: %s)", h.Verdict, h.Confidence),
				Type:    "interceptable",
				Text:    h.Mechanism,
			}
		case h.Verdict == "inconclusive":
			suite.Skipped++
			tc.Skipped = &junitSkipped{Message: h.Mechanism}
		}
		suite.Cases = append(suite.Cases, tc)
	}

	doc := junitSuites{
		Name:     toolName,
		Tests:    suite.Tests,
		Failures: suite.Failures,
		Suites:   []junitSuite{suite},
	}
	if _, err := io.WriteString(w, xml.Header); err != nil {
		return fmt.Errorf("report: write junit header: %w", err)
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("report: encode junit: %w", err)
	}
	_, err := io.WriteString(w, "\n")
	return err
}

type junitSuites struct {
	XMLName  xml.Name     `xml:"testsuites"`
	Name     string       `xml:"name,attr"`
	Tests    int          `xml:"tests,attr"`
	Failures int          `xml:"failures,attr"`
	Suites   []junitSuite `xml:"testsuite"`
}

type junitSuite struct {
	XMLName  xml.Name    `xml:"testsuite"`
	Name     string      `xml:"name,attr"`
	Tests    int         `xml:"tests,attr"`
	Failures int         `xml:"failures,attr"`
	Skipped  int         `xml:"skipped,attr"`
	Cases    []junitCase `xml:"testcase"`
}

type junitCase struct {
	XMLName   xml.Name      `xml:"testcase"`
	Name      string        `xml:"name,attr"`
	Classname string        `xml:"classname,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
	Skipped   *junitSkipped `xml:"skipped,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Text    string `xml:",chardata"`
}

type junitSkipped struct {
	Message string `xml:"message,attr"`
}
