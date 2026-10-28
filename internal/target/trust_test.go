package target_test

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/yinkoshield/pinscan/internal/device"
	"github.com/yinkoshield/pinscan/internal/scan"
	"github.com/yinkoshield/pinscan/internal/target"
)

// Both targets report trust to the orchestrator.
var (
	_ scan.TrustReporter = (*target.Android)(nil)
	_ scan.TrustReporter = (*target.Manual)(nil)
)

func androidWithCA(mode device.Mode, probeOut string) (*target.Android, *fakeRunner) {
	r := &fakeRunner{rootOut: map[string]string{"id -u": "0"}, rootDefault: probeOut}
	ctrl := device.New(r, mode)
	ctrl.SetCA("71ee3f50.0", "deadbeef")
	a := target.NewAndroid(ctrl, "com.example.app", false)
	a.SetTrustWait(0)
	return a, r
}

func TestAndroidStartsUnverified(t *testing.T) {
	t.Parallel()

	a, _ := androidWithCA(device.Scoped, "1/1")
	if a.TrustStatus() != scan.TrustUnverified {
		t.Errorf("before any probe TrustStatus = %s, want unverified", a.TrustStatus())
	}
}

func TestAndroidSystemPreflightVerifiesTrust(t *testing.T) {
	t.Parallel()

	a, r := androidWithCA(device.System, "2/2")
	if err := a.Preflight(context.Background()); err != nil {
		t.Fatalf("Preflight: %v", err)
	}
	if a.TrustStatus() != scan.TrustVerified {
		t.Errorf("CA in every zygote namespace: TrustStatus = %s, want verified", a.TrustStatus())
	}
	if !anyContains(r.rootCmds, "pidof zygote64 zygote") {
		t.Errorf("system-mode Preflight did not probe the zygote namespaces: %v", r.rootCmds)
	}
}

func TestAndroidSystemPreflightRefusesUntrustedCA(t *testing.T) {
	t.Parallel()

	// The setup failure the reviewer described: everything else works, the CA
	// is simply not trusted. Running the waves would read every host as
	// hardened, so the scan must stop here with a fix, not proceed.
	a, _ := androidWithCA(device.System, "0/2")
	err := a.Preflight(context.Background())
	if err == nil {
		t.Fatal("Preflight succeeded although the research CA is not trusted")
	}
	if !strings.Contains(err.Error(), "not trusted") || !strings.Contains(err.Error(), "ca-module") {
		t.Errorf("error should say the CA is not trusted and how to fix it: %v", err)
	}
	if a.TrustStatus() != scan.TrustUnverified {
		t.Errorf("TrustStatus after refusal = %s, want unverified", a.TrustStatus())
	}
}

func TestAndroidScopedExerciseVerifiesTrustInTheApp(t *testing.T) {
	t.Parallel()

	a, r := androidWithCA(device.Scoped, "1/1")
	if err := a.Preflight(context.Background()); err != nil {
		t.Fatalf("Preflight: %v", err)
	}
	if a.TrustStatus() != scan.TrustUnverified {
		t.Errorf("scoped Preflight cannot verify (app not running yet): TrustStatus = %s", a.TrustStatus())
	}
	if err := a.Exercise(context.Background()); err != nil {
		t.Fatalf("Exercise: %v", err)
	}
	if a.TrustStatus() != scan.TrustVerified {
		t.Errorf("CA bound in the app's namespace: TrustStatus = %s, want verified", a.TrustStatus())
	}
	if !anyContains(r.rootCmds, "pidof com.example.app") {
		t.Errorf("scoped Exercise did not probe the app's own processes: %v", r.rootCmds)
	}
}

func TestAndroidScopedExerciseRefusesUntrustedCA(t *testing.T) {
	t.Parallel()

	a, _ := androidWithCA(device.Scoped, "0/1")
	err := a.Exercise(context.Background())
	if err == nil {
		t.Fatal("Exercise succeeded although the app does not trust the research CA")
	}
	if !strings.Contains(err.Error(), "ykzpinscan") {
		t.Errorf("error should point at the scoped-mode module: %v", err)
	}
}

func TestAndroidScopedExerciseStaysUnverifiedWithoutAProcess(t *testing.T) {
	t.Parallel()

	// The app never came up (root detection, crash): nothing can be verified
	// and nothing is observed either. Not an error, but not trust.
	a, _ := androidWithCA(device.Scoped, "0/0")
	if err := a.Exercise(context.Background()); err != nil {
		t.Fatalf("Exercise with no app process: %v", err)
	}
	if a.TrustStatus() != scan.TrustUnverified {
		t.Errorf("no process to inspect: TrustStatus = %s, want unverified", a.TrustStatus())
	}
}

func TestAndroidVerifiedTrustIsNotRevokedByAMissingProcess(t *testing.T) {
	t.Parallel()

	a, r := androidWithCA(device.Scoped, "1/1")
	if err := a.Exercise(context.Background()); err != nil {
		t.Fatalf("first Exercise: %v", err)
	}
	r.rootDefault = "0/0" // the app is gone during a later wave
	if err := a.Exercise(context.Background()); err != nil {
		t.Fatalf("second Exercise: %v", err)
	}
	if a.TrustStatus() != scan.TrustVerified {
		t.Errorf("a verified setup must not be downgraded by a later wave with no process: %s", a.TrustStatus())
	}
}

func TestAndroidWithoutCAIdentityDoesNotProbeOrWait(t *testing.T) {
	t.Parallel()

	r := &fakeRunner{rootOut: map[string]string{"id -u": "0"}, rootDefault: "1/1"}
	a := target.NewAndroid(device.New(r, device.Scoped), "com.example.app", false)
	// Deliberately a long wait: it must not be used when there is nothing to
	// compare against.
	a.SetTrustWait(time.Hour)

	start := time.Now()
	if err := a.Exercise(context.Background()); err != nil {
		t.Fatalf("Exercise: %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Error("Exercise waited for a process although no CA identity was set")
	}
	if anyContains(r.rootCmds, "nsenter") {
		t.Errorf("no CA identity: the trust probe must not run: %v", r.rootCmds)
	}
	if a.TrustStatus() != scan.TrustUnverified {
		t.Errorf("TrustStatus = %s, want unverified", a.TrustStatus())
	}
}

func TestManualTrustIsOperatorAsserted(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	m := target.NewManual(&buf, "my-desktop-app", "/path/ca.pem", 45*time.Second, false)
	if m.TrustStatus() != scan.TrustAsserted {
		t.Errorf("manual TrustStatus = %s, want operator-asserted", m.TrustStatus())
	}
	if err := m.Preflight(context.Background()); err != nil {
		t.Fatalf("Preflight: %v", err)
	}
	if !strings.Contains(buf.String(), "cannot verify") {
		t.Errorf("manual Preflight should say trust is not verified: %q", buf.String())
	}
}
