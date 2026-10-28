package policy_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/yinkoshield/pinscan/internal/classify"
	"github.com/yinkoshield/pinscan/internal/policy"
	"github.com/yinkoshield/pinscan/internal/scan"
)

func write(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".pinscan.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return path
}

func host(name string, v classify.Verdict) scan.HostResult {
	return scan.HostResult{Host: name, Verdict: v}
}

func TestLoadRequiresReason(t *testing.T) {
	t.Parallel()

	path := write(t, `
hosts:
  api.bank.example:
    expect: spki
`)
	if _, err := policy.Load(path); err == nil {
		t.Error("a host rule without a reason must fail to load")
	}
}

func TestLoadRejectsUnknownField(t *testing.T) {
	t.Parallel()

	path := write(t, `
hosts:
  api.bank.example:
    expct: spki
    reason: typo above
`)
	if _, err := policy.Load(path); err == nil {
		t.Error("an unknown field (expct) must fail to load")
	}
}

func TestLoadRejectsInvalidExpect(t *testing.T) {
	t.Parallel()

	path := write(t, `
hosts:
  api.bank.example:
    expect: super-secure
    reason: nonsense verdict
`)
	if _, err := policy.Load(path); err == nil {
		t.Error("an invalid expect verdict must fail to load")
	}
}

func loadOK(t *testing.T, body string) policy.Policy {
	t.Helper()
	p, err := policy.Load(write(t, body))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return p
}

func TestEvaluateExpectViolation(t *testing.T) {
	t.Parallel()

	p := loadOK(t, `
hosts:
  api.bank.example:
    expect: spki
    reason: core banking API must pin
`)
	// The host is only open — below the expected spki.
	e := p.Evaluate([]scan.HostResult{host("api.bank.example", classify.Open)})
	if !e.HasViolation() {
		t.Fatal("open where spki is expected must be a violation")
	}
	if e.Violations[0].Host != "api.bank.example" {
		t.Errorf("violation host = %q", e.Violations[0].Host)
	}
}

func TestEvaluateExpectMet(t *testing.T) {
	t.Parallel()

	p := loadOK(t, `
hosts:
  api.bank.example:
    expect: key-pinned
    reason: must pin
`)
	// spki is stronger than key-pinned — expectation met.
	e := p.Evaluate([]scan.HostResult{host("api.bank.example", classify.SPKI)})
	if e.HasViolation() {
		t.Errorf("spki satisfies expect key-pinned, got violations %+v", e.Violations)
	}
}

func TestEvaluateAllowIsAcceptedRiskAndExempt(t *testing.T) {
	t.Parallel()

	p := loadOK(t, `
hosts:
  analytics.vendor.example:
    allow: true
    reason: third-party analytics, no sensitive data
`)
	e := p.Evaluate([]scan.HostResult{host("analytics.vendor.example", classify.Open)})
	if e.HasViolation() {
		t.Errorf("an allowed interceptable host is not a violation: %+v", e.Violations)
	}
	if len(e.AcceptedRisks) != 1 {
		t.Errorf("want 1 accepted risk, got %+v", e.AcceptedRisks)
	}
	if !e.Exempt("analytics.vendor.example") {
		t.Error("an allowed host must be exempt from the interceptable gate")
	}
}

func TestEvaluateIgnoreExempt(t *testing.T) {
	t.Parallel()

	p := loadOK(t, `
hosts:
  legacy.example:
    ignore: true
    reason: deprecated, removed next release
`)
	e := p.Evaluate([]scan.HostResult{host("legacy.example", classify.Open)})
	if e.HasViolation() || len(e.AcceptedRisks) != 0 {
		t.Errorf("ignored host should neither violate nor be an accepted risk: %+v", e)
	}
	if !e.Exempt("legacy.example") || len(e.Ignored) != 1 {
		t.Errorf("ignored host should be exempt and listed: %+v", e)
	}
}

func TestEvaluateUnobserved(t *testing.T) {
	t.Parallel()

	p := loadOK(t, `
hosts:
  never.contacted.example:
    expect: spki
    reason: must pin
`)
	e := p.Evaluate([]scan.HostResult{host("other.example", classify.Open)})
	if len(e.Unobserved) != 1 || e.Unobserved[0].Host != "never.contacted.example" {
		t.Errorf("a policy host not seen this scan should be reported as unobserved: %+v", e.Unobserved)
	}
}

func TestEvaluateUnlistedHostUntouched(t *testing.T) {
	t.Parallel()

	p := loadOK(t, `
hosts:
  api.bank.example:
    expect: spki
    reason: must pin
`)
	// A host with no rule is neither violated nor exempt by the policy.
	e := p.Evaluate([]scan.HostResult{host("random.example", classify.Open)})
	if e.HasViolation() {
		t.Error("an unlisted host must not be a policy violation")
	}
	if e.Exempt("random.example") {
		t.Error("an unlisted host must not be exempt")
	}
}
