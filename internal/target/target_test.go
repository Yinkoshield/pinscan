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

// Both targets must satisfy the orchestrator's interface.
var (
	_ scan.Target = (*target.Android)(nil)
	_ scan.Target = (*target.Manual)(nil)
)

// fakeRunner implements device.Runner, recording issued commands.
type fakeRunner struct {
	rootOut   map[string]string
	shellCmds []string
	rootCmds  []string
}

func (f *fakeRunner) State(context.Context) (string, error) { return "device", nil }

func (f *fakeRunner) Shell(_ context.Context, cmd string) (string, error) {
	f.shellCmds = append(f.shellCmds, cmd)
	return "", nil
}

func (f *fakeRunner) Root(_ context.Context, cmd string) (string, error) {
	f.rootCmds = append(f.rootCmds, cmd)
	return f.rootOut[cmd], nil
}

func anyContains(cmds []string, sub string) bool {
	for _, c := range cmds {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

func TestAndroidProxyRouteAndExercise(t *testing.T) {
	t.Parallel()

	r := &fakeRunner{rootOut: map[string]string{"id -u": "0"}}
	a := target.NewAndroid(device.New(r, device.Scoped), "com.example.app", false)

	if a.Transparent() {
		t.Error("non-transparent Android target reported transparent")
	}
	restore, err := a.Route(context.Background(), "192.168.1.5:8080")
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if !anyContains(r.shellCmds, "http_proxy 192.168.1.5:8080") {
		t.Errorf("Route did not set the HTTP proxy: %v", r.shellCmds)
	}
	restore()
	if !anyContains(r.shellCmds, "http_proxy :0") {
		t.Errorf("restore did not clear the proxy: %v", r.shellCmds)
	}

	if err := a.Exercise(context.Background()); err != nil {
		t.Fatalf("Exercise: %v", err)
	}
	if !anyContains(r.shellCmds, "force-stop com.example.app") || !anyContains(r.shellCmds, "monkey -p com.example.app") {
		t.Errorf("Exercise did not restart the app: %v", r.shellCmds)
	}
}

func TestAndroidTransparentRouteUsesDNAT(t *testing.T) {
	t.Parallel()

	r := &fakeRunner{rootOut: map[string]string{
		"id -u":                                 "0",
		"stat -c %u /data/data/com.example.app": "10234",
	}}
	a := target.NewAndroid(device.New(r, device.Scoped), "com.example.app", true)
	if !a.Transparent() {
		t.Error("transparent Android target reported non-transparent")
	}
	restore, err := a.Route(context.Background(), "192.168.1.5:8080")
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	restore()
	if !anyContains(r.rootCmds, "iptables -t nat -A OUTPUT") {
		t.Errorf("transparent Route did not install a DNAT rule: %v", r.rootCmds)
	}
	if !anyContains(r.rootCmds, "iptables -t nat -D OUTPUT") {
		t.Errorf("restore did not delete the DNAT rule: %v", r.rootCmds)
	}
}

func TestAndroidPreflightTargetsScopedModule(t *testing.T) {
	t.Parallel()

	r := &fakeRunner{rootOut: map[string]string{"id -u": "0"}}
	a := target.NewAndroid(device.New(r, device.Scoped), "com.example.app", false)
	if err := a.Preflight(context.Background()); err != nil {
		t.Fatalf("Preflight: %v", err)
	}
	if !anyContains(r.rootCmds, "/data/adb/ykzpinscan/targets") {
		t.Errorf("scoped Preflight did not write the module target file: %v", r.rootCmds)
	}
}

func TestManualPrintsInstructions(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	m := target.NewManual(&buf, "my-desktop-app", "/path/ca.pem", 45*time.Second, false)

	if m.Transparent() {
		t.Error("non-transparent Manual reported transparent")
	}
	if err := m.Preflight(context.Background()); err != nil {
		t.Fatalf("Preflight: %v", err)
	}
	restore, err := m.Route(context.Background(), "192.168.1.5:8080")
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if err := m.Exercise(context.Background()); err != nil {
		t.Fatalf("Exercise: %v", err)
	}
	restore()

	out := buf.String()
	for _, want := range []string{"my-desktop-app", "/path/ca.pem", "HTTPS_PROXY=http://192.168.1.5:8080", "45s", "Scan window closed"} {
		if !strings.Contains(out, want) {
			t.Errorf("manual output missing %q\n---\n%s", want, out)
		}
	}
}

func TestManualTransparentGuidance(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	m := target.NewManual(&buf, "iot-device", "/ca.pem", time.Minute, true)
	if !m.Transparent() {
		t.Error("transparent Manual reported non-transparent")
	}
	if _, err := m.Route(context.Background(), "10.0.0.2:8080"); err != nil {
		t.Fatalf("Route: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "tcp/443") || !strings.Contains(out, "10.0.0.2:8080") {
		t.Errorf("transparent guidance missing routing detail:\n%s", out)
	}
	if strings.Contains(out, "HTTPS_PROXY") {
		t.Error("transparent guidance should not mention HTTPS_PROXY")
	}
}
