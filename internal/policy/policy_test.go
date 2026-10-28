package policy_test

import (
	"os"
	"path/filepath"
	"strings"
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

func TestLoadRejectsExpectWithPassthrough(t *testing.T) {
	t.Parallel()

	path := write(t, `
hosts:
  login.bank.example:
    passthrough: true
    expect: spki
    reason: an untested host cannot meet an expectation
`)
	if _, err := policy.Load(path); err == nil {
		t.Error("expect together with passthrough must fail to load")
	}
}

func TestLoadRequiresReasonForPassthrough(t *testing.T) {
	t.Parallel()

	path := write(t, `
hosts:
  login.bank.example:
    passthrough: true
`)
	if _, err := policy.Load(path); err == nil {
		t.Error("a passthrough rule without a reason must fail to load")
	}
}

func TestLoadAcceptsRelayEverythingPassthrough(t *testing.T) {
	t.Parallel()

	// The bare "*" is the explicit discovery run: relay every host, test
	// nothing, list what the app contacted. It loads, is reported by
	// PassthroughHosts, and is never listed as unobserved.
	p := loadOK(t, `
hosts:
  "*":
    passthrough: true
    reason: the first connection is pinned; list the hosts before scanning
`)
	if got := p.PassthroughHosts(); len(got) != 1 || got[0] != "*" {
		t.Errorf("PassthroughHosts() = %q, want [*]", got)
	}
	e := p.Evaluate([]scan.HostResult{host("any.example", classify.Inconclusive)})
	if len(e.Unobserved) != 0 {
		t.Errorf("unobserved = %+v, want none for the relay-everything rule", e.Unobserved)
	}
}

func TestLoadRejectsMalformedPassthroughWildcard(t *testing.T) {
	t.Parallel()

	for _, key := range []string{`"*."`, `"api.*.example"`} {
		path := write(t, `
hosts:
  `+key+`:
    passthrough: true
    reason: malformed wildcard
`)
		if _, err := policy.Load(path); err == nil {
			t.Errorf("host key %s must fail to load", key)
		}
	}
}

func TestLoadRejectsRelayEverythingWithoutPassthrough(t *testing.T) {
	t.Parallel()

	path := write(t, `
hosts:
  "*":
    ignore: true
    reason: only passthrough may name every host
`)
	if _, err := policy.Load(path); err == nil {
		t.Error("a bare * on a non-passthrough rule must fail to load")
	}
}

func TestLoadRejectsWildcardWithoutPassthrough(t *testing.T) {
	t.Parallel()

	path := write(t, `
hosts:
  "*.bank.example":
    expect: spki
    reason: expectations are matched by exact host
`)
	if _, err := policy.Load(path); err == nil {
		t.Error("a wildcard host on a non-passthrough rule must fail to load")
	}
}

func TestPassthroughHosts(t *testing.T) {
	t.Parallel()

	p := loadOK(t, `
hosts:
  "*.auth.bank.example":
    passthrough: true
    reason: SSO front doors are SPKI-pinned
  login.bank.example:
    passthrough: true
    ignore: true
    reason: SPKI-pinned login API; let the app log in so the rest is exercised
  api.bank.example:
    expect: spki
    reason: core banking API must pin
`)
	got := p.PassthroughHosts()
	want := []string{"*.auth.bank.example", "login.bank.example"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("PassthroughHosts() = %q, want %q", got, want)
	}
}

func TestEvaluatePassthroughHostFollowsOtherFlags(t *testing.T) {
	t.Parallel()

	p := loadOK(t, `
hosts:
  login.bank.example:
    passthrough: true
    reason: SPKI-pinned login API
  sso.bank.example:
    passthrough: true
    ignore: true
    reason: SPKI-pinned SSO; do not gate on it
  "*.cdn.bank.example":
    passthrough: true
    reason: wildcard family, never matched by name
`)
	// A passthrough host comes out of the scan inconclusive. Without ignore it
	// still counts against -fail-on-inconclusive (it is not excluded); with
	// ignore it is excluded like any other host. The wildcard is never listed as
	// unobserved: it names a family, not a host.
	e := p.Evaluate([]scan.HostResult{
		host("login.bank.example", classify.Inconclusive),
		host("sso.bank.example", classify.Inconclusive),
	})
	if e.HasViolation() {
		t.Errorf("passthrough hosts must not violate: %+v", e.Violations)
	}
	if e.Excluded("login.bank.example") {
		t.Error("a passthrough host without ignore must still count for the inconclusive gate")
	}
	if !e.Excluded("sso.bank.example") {
		t.Error("a passthrough host with ignore must be excluded from gating")
	}
	if len(e.Unobserved) != 0 {
		t.Errorf("unobserved = %+v, want none (a wildcard family is not a host to observe)", e.Unobserved)
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
