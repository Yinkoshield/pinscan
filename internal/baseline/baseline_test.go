package baseline_test

import (
	"testing"

	"github.com/yinkoshield/pinscan/internal/baseline"
	"github.com/yinkoshield/pinscan/internal/report"
)

// Verdict strings reused across the table, named to keep the literals single.
const (
	vOpen         = "open"
	vSPKI         = "spki"
	vInconclusive = "inconclusive"
)

func rep(hosts ...report.HostReport) report.Report {
	return report.Report{SchemaVersion: report.SchemaVersion, Hosts: hosts}
}

func host(name, verdict string) report.HostReport {
	return report.HostReport{Host: name, Verdict: verdict, Interceptable: interceptable(verdict)}
}

func interceptable(v string) bool {
	switch v {
	case vOpen, "metadata", "name-validation":
		return true
	default:
		return false
	}
}

func TestDiffWeakeningIsRegression(t *testing.T) {
	t.Parallel()

	old := rep(host("api.bank", vSPKI))
	cur := rep(host("api.bank", vOpen))
	d := baseline.Diff(old, cur)

	if !d.HasRegression() {
		t.Fatal("spki -> open must be a regression")
	}
	if len(d.Regressions) != 1 || d.Regressions[0].Host != "api.bank" {
		t.Errorf("regressions = %+v", d.Regressions)
	}
	if d.Regressions[0].From != vSPKI || d.Regressions[0].To != vOpen {
		t.Errorf("regression change = %+v", d.Regressions[0])
	}
}

func TestDiffStrengtheningIsImprovement(t *testing.T) {
	t.Parallel()

	d := baseline.Diff(rep(host("api.bank", vOpen)), rep(host("api.bank", vSPKI)))
	if d.HasRegression() {
		t.Error("open -> spki must not be a regression")
	}
	if len(d.Improvements) != 1 {
		t.Errorf("improvements = %+v", d.Improvements)
	}
}

func TestDiffDecidedToInconclusiveIsNeedsReview(t *testing.T) {
	t.Parallel()

	d := baseline.Diff(rep(host("api.bank", vSPKI)), rep(host("api.bank", vInconclusive)))
	if d.HasRegression() {
		t.Error("spki -> inconclusive must NOT be a silent regression")
	}
	if len(d.NeedsReview) != 1 {
		t.Fatalf("needs-review = %+v, want 1 (a scan that went quiet is suspicious, not clean)", d.NeedsReview)
	}
}

func TestDiffNewInterceptableHostIsRegression(t *testing.T) {
	t.Parallel()

	d := baseline.Diff(rep(), rep(host("new.api", vOpen)))
	if !d.HasRegression() {
		t.Error("a newly-appeared interceptable host must be a regression")
	}
}

func TestDiffInconclusiveToInterceptableIsRegression(t *testing.T) {
	t.Parallel()

	// A host that was inconclusive (no classifiable request that run) and is now
	// demonstrably interceptable must fail the gate exactly like a newly-appeared
	// interceptable host — silence before it must not read as safe.
	d := baseline.Diff(rep(host("api.bank", vInconclusive)), rep(host("api.bank", vOpen)))
	if !d.HasRegression() {
		t.Fatal("inconclusive -> open must be a regression, not an improvement")
	}
	if len(d.Regressions) != 1 || d.Regressions[0].From != vInconclusive || d.Regressions[0].To != vOpen {
		t.Errorf("regressions = %+v, want one inconclusive->open", d.Regressions)
	}
	if len(d.Improvements) != 0 {
		t.Errorf("improvements = %+v, want none (a now-interceptable host is not coverage)", d.Improvements)
	}
}

func TestDiffInconclusiveToHardenedIsImprovement(t *testing.T) {
	t.Parallel()

	// The companion case: inconclusive -> a hardened verdict is genuine coverage.
	d := baseline.Diff(rep(host("api.bank", vInconclusive)), rep(host("api.bank", vSPKI)))
	if d.HasRegression() {
		t.Error("inconclusive -> spki must not be a regression")
	}
	if len(d.Improvements) != 1 {
		t.Errorf("improvements = %+v, want 1", d.Improvements)
	}
}

func TestDiffNewHardenedHostIsAdded(t *testing.T) {
	t.Parallel()

	d := baseline.Diff(rep(), rep(host("new.api", vSPKI)))
	if d.HasRegression() {
		t.Error("a newly-appeared hardened host is not a regression")
	}
	if len(d.Added) != 1 {
		t.Errorf("added = %+v, want 1", d.Added)
	}
}

func TestDiffRemovedHostListed(t *testing.T) {
	t.Parallel()

	d := baseline.Diff(rep(host("gone.api", vSPKI)), rep())
	if len(d.Removed) != 1 {
		t.Errorf("removed = %+v, want 1", d.Removed)
	}
	if d.HasRegression() {
		t.Error("a removed host is not, by itself, a regression")
	}
}

func TestDiffUnchangedIsClean(t *testing.T) {
	t.Parallel()

	d := baseline.Diff(rep(host("api.bank", vSPKI)), rep(host("api.bank", vSPKI)))
	if d.HasRegression() || len(d.Regressions)+len(d.Improvements)+len(d.NeedsReview)+len(d.Added)+len(d.Removed) != 0 {
		t.Errorf("identical reports should diff clean, got %+v", d)
	}
}
