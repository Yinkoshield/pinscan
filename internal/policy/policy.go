// Package policy loads a .pinscan.yaml expectation/allowlist file and evaluates
// a scan against it. It lets a team declare, per host and with a mandatory
// reason: a minimum expected verdict (expect), an accepted interceptable risk
// (allow), or exclusion from gating (ignore). Accepted risks are surfaced, never
// hidden.
package policy

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/yinkoshield/pinscan/internal/classify"
	"github.com/yinkoshield/pinscan/internal/scan"
	"gopkg.in/yaml.v3"
)

// Rule is the policy for one host. Every rule must carry a non-empty Reason.
type Rule struct {
	Expect string `yaml:"expect"`
	Allow  bool   `yaml:"allow"`
	Ignore bool   `yaml:"ignore"`
	Reason string `yaml:"reason"`
}

// Policy is a parsed .pinscan.yaml.
type Policy struct {
	Hosts map[string]Rule `yaml:"hosts"`
}

// Finding records a host the policy has something to say about.
type Finding struct {
	Host   string
	Detail string
	Reason string
}

// Evaluation is the outcome of applying a policy to a scan.
type Evaluation struct {
	Violations    []Finding // Expectations not met — always a failure.
	AcceptedRisks []Finding // Interceptable hosts explicitly allowed.
	Ignored       []Finding // Hosts excluded from gating.
	Unobserved    []Finding // Policy hosts not seen this scan (coverage gap).
	exempt        map[string]bool
	ignored       map[string]bool
}

// HasViolation reports whether any expectation was not met.
func (e Evaluation) HasViolation() bool { return len(e.Violations) > 0 }

// Exempt reports whether a host is exempt from the interceptable gate (because
// the policy allows or ignores it).
func (e Evaluation) Exempt(host string) bool { return e.exempt[host] }

// Excluded reports whether a host is excluded from gating generally (ignore).
// Unlike Exempt, allow does not count here: allow is scoped to the
// interceptable gate, while ignore removes the host from every gate.
func (e Evaluation) Excluded(host string) bool { return e.ignored[host] }

// Load reads and validates a policy file. Unknown fields and missing reasons are
// errors, so a typo cannot silently weaken the gate.
func Load(path string) (Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, fmt.Errorf("policy: read %q: %w", path, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return Policy{}, fmt.Errorf("policy: parse %q: %w", path, err)
	}
	if err := p.validate(); err != nil {
		return Policy{}, err
	}
	return p, nil
}

// validate enforces that every rule has a reason and a known expect verdict.
func (p Policy) validate() error {
	for _, host := range sortedHosts(p.Hosts) {
		rule := p.Hosts[host]
		if strings.TrimSpace(rule.Reason) == "" {
			return fmt.Errorf("policy: host %q needs a reason", host)
		}
		if rule.Expect != "" {
			if _, ok := classify.ParseVerdict(rule.Expect); !ok {
				return fmt.Errorf("policy: host %q has invalid expect %q", host, rule.Expect)
			}
		}
	}
	return nil
}

// Evaluate applies the policy to a scan's results.
func (p Policy) Evaluate(results []scan.HostResult) Evaluation {
	e := Evaluation{exempt: make(map[string]bool), ignored: make(map[string]bool)}
	seen := make(map[string]bool, len(results))

	for _, r := range results {
		seen[r.Host] = true
		if rule, has := p.Hosts[r.Host]; has {
			e.applyRule(r, rule)
		}
	}

	for _, host := range sortedHosts(p.Hosts) {
		rule := p.Hosts[host]
		if !seen[host] && !rule.Ignore {
			e.Unobserved = append(e.Unobserved, Finding{host, "not observed this scan", rule.Reason})
		}
	}
	return e
}

// applyRule evaluates one host against its rule, recording any finding and
// exemption.
func (e *Evaluation) applyRule(r scan.HostResult, rule Rule) {
	if rule.Ignore {
		e.Ignored = append(e.Ignored, Finding{r.Host, "ignored", rule.Reason})
		e.exempt[r.Host] = true
		e.ignored[r.Host] = true
		return
	}
	if rule.Allow {
		e.exempt[r.Host] = true
		if r.Verdict.Defeatable() {
			e.AcceptedRisks = append(e.AcceptedRisks, Finding{
				Host:   r.Host,
				Detail: "interceptable (accepted risk): " + r.Verdict.String(),
				Reason: rule.Reason,
			})
		}
	}
	if rule.Expect == "" {
		return
	}
	want, _ := classify.ParseVerdict(rule.Expect)
	if !r.Verdict.AtLeast(want) {
		e.Violations = append(e.Violations, Finding{
			Host:   r.Host,
			Detail: fmt.Sprintf("expected at least %s, got %s", rule.Expect, r.Verdict),
			Reason: rule.Reason,
		})
	}
}

// sortedHosts returns the policy's host keys in sorted order, for deterministic
// validation and output.
func sortedHosts(hosts map[string]Rule) []string {
	out := make([]string, 0, len(hosts))
	for host := range hosts {
		out = append(out, host)
	}
	sort.Strings(out)
	return out
}
