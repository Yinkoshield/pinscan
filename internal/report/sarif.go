package report

import (
	"encoding/json"
	"fmt"
	"io"
)

// informationURI is the tool's home, surfaced in SARIF and read by code-scanning
// UIs.
const informationURI = "https://github.com/Yinkoshield/pinscan"

// SARIF writes rep as a SARIF 2.1.0 log, so a scan's findings land in a code-
// scanning UI (e.g. the GitHub PR "Security" tab). Interceptable hosts are
// errors; hosts whose interceptability is not established (inconclusive, and
// key-pinned, whose cloned-issuer wave did not decide) are warnings; hardened
// (spki) hosts are notes. A passthrough host yields no result: it was relayed,
// not tested, so there is no finding.
func SARIF(w io.Writer, rep Report) error {
	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           rep.Tool.Name,
				Version:        rep.Tool.Version,
				InformationURI: informationURI,
				Rules:          sarifRules(),
			}},
			Results: sarifResults(rep),
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(log); err != nil {
		return fmt.Errorf("report: encode sarif: %w", err)
	}
	return nil
}

// sarifResults renders one result per tested host; passthrough hosts have none.
func sarifResults(rep Report) []sarifResult {
	results := make([]sarifResult, 0, len(rep.Hosts))
	for _, h := range rep.Hosts {
		if h.Passthrough {
			continue
		}
		results = append(results, sarifResult{
			RuleID:  "pinscan/" + h.Verdict,
			Level:   sarifLevel(h),
			Message: sarifText{Text: fmt.Sprintf("%s: %s (confidence: %s). %s", h.Host, h.Verdict, h.Confidence, h.Mechanism)},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: "hosts/" + h.Host}},
				LogicalLocations: []sarifLogical{{FullyQualifiedName: h.Host, Kind: "resource"}},
			}},
			PartialFingerprints: map[string]string{"pinscan/host": h.Host},
		})
	}
	return results
}

// SARIF result levels: interceptable hosts are errors, hosts whose
// interceptability is not established are warnings, hardened hosts are
// informational notes.
const (
	sarifError   = "error"
	sarifWarning = "warning"
	sarifNote    = "note"
)

// sarifLevel maps a host's interceptability to a SARIF result level. Only a
// host shown resistant is a note; "not established" is a warning so a
// key-pinned candidate is never filed as informational.
func sarifLevel(h HostReport) string {
	switch h.Interceptability {
	case InterceptabilityYes:
		return sarifError
	case InterceptabilityNo:
		return sarifNote
	default:
		return sarifWarning
	}
}

// sarifRules is the stable rule catalog, one per verdict.
func sarifRules() []sarifRule {
	rules := []struct{ id, short, full, level string }{
		{"pinscan/open", "No TLS pinning", "The host sent a request over a forged certificate: no pinning. A trusted-CA attacker can intercept it.", sarifError},
		{"pinscan/metadata", "Metadata validation only", "The host validates certificate subject/SAN names, not the key. Defeatable by a cloned-name certificate under a trusted CA.", sarifError},
		{"pinscan/name-validation", "Issuer-name validation", "The host validates the issuer name/chain, not the key. Defeatable by a cloned-issuer chain under a trusted CA.", sarifError},
		{"pinscan/key-pinned", "Key-level check candidate, not established", "The host rejected the forged leaves, but the cloned-issuer wave did not separate a key-level check from issuer-name validation. Whether a trusted-CA attacker defeats it is not established; re-run until the wave decides before treating the host as hardened.", sarifWarning},
		{"pinscan/spki", "Rejects every forged chain", "The host rejected every forged chain, including the cloned-issuer chain: consistent with public-key pinning or a private trust store. The mechanism is not identified; a trusted-CA attacker does not intercept it under these parameters.", sarifNote},
		{"pinscan/inconclusive", "Inconclusive", "No usable signal: the scanned surface produced no classifiable TLS request, so the posture is unverified.", sarifWarning},
	}
	out := make([]sarifRule, 0, len(rules))
	for _, r := range rules {
		out = append(out, sarifRule{
			ID:                   r.id,
			Name:                 r.id,
			ShortDescription:     sarifText{Text: r.short},
			FullDescription:      sarifText{Text: r.full},
			DefaultConfiguration: sarifConfig{Level: r.level},
		})
	}
	return out
}

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string      `json:"id"`
	Name                 string      `json:"name"`
	ShortDescription     sarifText   `json:"shortDescription"`
	FullDescription      sarifText   `json:"fullDescription"`
	DefaultConfiguration sarifConfig `json:"defaultConfiguration"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical  `json:"physicalLocation"`
	LogicalLocations []sarifLogical `json:"logicalLocations,omitempty"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifLogical struct {
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind,omitempty"`
}
