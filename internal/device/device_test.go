package device_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/yinkoshield/pinscan/internal/device"
)

// fakeRunner records the commands a Controller issues and returns canned
// results, so the control logic is tested without a device.
type fakeRunner struct {
	state     string
	stateErr  error
	rootOut   map[string]string
	rootErr   map[string]error
	shellOut  map[string]string
	shellErr  error
	shellCmds []string
	rootCmds  []string
	// rootDefault is returned for any root command with no explicit rootOut
	// entry, for probes whose command text is long or generated.
	rootDefault string
}

func (f *fakeRunner) State(context.Context) (string, error) { return f.state, f.stateErr }

func (f *fakeRunner) Shell(_ context.Context, cmd string) (string, error) {
	f.shellCmds = append(f.shellCmds, cmd)
	return f.shellOut[cmd], f.shellErr
}

func (f *fakeRunner) Root(_ context.Context, cmd string) (string, error) {
	f.rootCmds = append(f.rootCmds, cmd)
	if err, ok := f.rootErr[cmd]; ok {
		return "", err
	}
	if out, ok := f.rootOut[cmd]; ok {
		return out, nil
	}
	return f.rootDefault, nil
}

func TestModeString(t *testing.T) {
	t.Parallel()

	cases := map[device.Mode]string{
		device.Scoped:  "scoped",
		device.System:  "system",
		device.Mode(9): "invalid",
	}
	for m, want := range cases {
		if got := m.String(); got != want {
			t.Errorf("Mode(%d).String() = %q, want %q", m, got, want)
		}
	}
}

func TestPreflightSucceeds(t *testing.T) {
	t.Parallel()

	r := &fakeRunner{state: "device\n", rootOut: map[string]string{"id -u": "0\n"}}
	if err := device.New(r, device.Scoped).Preflight(context.Background()); err != nil {
		t.Errorf("Preflight: %v", err)
	}
}

func TestPreflightFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		r    *fakeRunner
	}{
		{"state error", &fakeRunner{stateErr: errors.New("no adb")}},
		{"not connected", &fakeRunner{state: "offline"}},
		{"root error", &fakeRunner{state: "device", rootErr: map[string]error{"id -u": errors.New("su failed")}}},
		{"not rooted", &fakeRunner{state: "device", rootOut: map[string]string{"id -u": "2000"}}},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if err := device.New(tt.r, device.Scoped).Preflight(context.Background()); err == nil {
				t.Error("Preflight = nil error, want an error")
			}
		})
	}
}

func TestProxyCommands(t *testing.T) {
	t.Parallel()

	r := &fakeRunner{}
	c := device.New(r, device.Scoped)
	ctx := context.Background()
	if err := c.SetProxy(ctx, "192.168.0.2:8080"); err != nil {
		t.Fatalf("SetProxy: %v", err)
	}
	if err := c.ClearProxy(ctx); err != nil {
		t.Fatalf("ClearProxy: %v", err)
	}
	want := []string{
		"settings put global http_proxy 192.168.0.2:8080",
		"settings put global http_proxy :0",
	}
	if !slices.Equal(r.shellCmds, want) {
		t.Errorf("shell commands = %v, want %v", r.shellCmds, want)
	}
}

func TestSetProxyRejectsBadHostPort(t *testing.T) {
	t.Parallel()

	c := device.New(&fakeRunner{}, device.Scoped)
	bad := []string{
		"noport", "host:notaport", ":8080",
		// Shell-injection payloads that split cleanly to a numeric port but carry
		// metacharacters in the host — they reach su -c / adb shell verbatim.
		"$(reboot):8080", "`id`:8080", "1.1.1.1 && reboot #:8080", "a;b:8080", "a b:8080",
	}
	for _, b := range bad {
		if err := c.SetProxy(context.Background(), b); err == nil {
			t.Errorf("SetProxy(%q) = nil error, want an error", b)
		}
	}
}

func TestSetProxyReportsRunnerError(t *testing.T) {
	t.Parallel()

	c := device.New(&fakeRunner{shellErr: errors.New("boom")}, device.Scoped)
	if err := c.SetProxy(context.Background(), "1.2.3.4:8080"); err == nil {
		t.Error("SetProxy with a failing runner = nil error, want an error")
	}
}

func TestForceStopAndLaunch(t *testing.T) {
	t.Parallel()

	r := &fakeRunner{}
	c := device.New(r, device.Scoped)
	ctx := context.Background()
	if err := c.ForceStop(ctx, "com.example.app"); err != nil {
		t.Fatalf("ForceStop: %v", err)
	}
	if err := c.Launch(ctx, "com.example.app"); err != nil {
		t.Fatalf("Launch: %v", err)
	}
	want := []string{
		"am force-stop com.example.app",
		"monkey -p com.example.app -c android.intent.category.LAUNCHER 1",
	}
	if !slices.Equal(r.shellCmds, want) {
		t.Errorf("shell commands = %v, want %v", r.shellCmds, want)
	}
}

func TestPackageOpsRejectBadPackage(t *testing.T) {
	t.Parallel()

	c := device.New(&fakeRunner{}, device.Scoped)
	ctx := context.Background()
	const bad = "com.evil; rm -rf /"
	if err := c.ForceStop(ctx, bad); err == nil {
		t.Error("ForceStop with a bad package = nil error, want an error")
	}
	if err := c.Launch(ctx, bad); err == nil {
		t.Error("Launch with a bad package = nil error, want an error")
	}
	if err := c.Target(ctx, bad); err == nil {
		t.Error("Target with a bad package = nil error, want an error")
	}
}

func TestTargetScopedWritesModuleFile(t *testing.T) {
	t.Parallel()

	r := &fakeRunner{}
	c := device.New(r, device.Scoped)
	if err := c.Target(context.Background(), "com.example.app"); err != nil {
		t.Fatalf("Target: %v", err)
	}
	want := []string{
		"mkdir -p /data/adb/ykzpinscan && echo com.example.app > /data/adb/ykzpinscan/targets && chmod 600 /data/adb/ykzpinscan/targets",
	}
	if !slices.Equal(r.rootCmds, want) {
		t.Errorf("root commands = %v, want %v", r.rootCmds, want)
	}
}

func TestTargetSystemIsNoOp(t *testing.T) {
	t.Parallel()

	r := &fakeRunner{}
	c := device.New(r, device.System)
	if err := c.Target(context.Background(), "com.example.app"); err != nil {
		t.Fatalf("Target: %v", err)
	}
	if len(r.rootCmds) != 0 {
		t.Errorf("System-mode Target ran %v, want no root commands", r.rootCmds)
	}
}

func TestTargetScopedReportsRunnerError(t *testing.T) {
	t.Parallel()

	const cmd = "mkdir -p /data/adb/ykzpinscan && echo com.example.app > /data/adb/ykzpinscan/targets && chmod 600 /data/adb/ykzpinscan/targets"
	r := &fakeRunner{rootErr: map[string]error{cmd: errors.New("boom")}}
	c := device.New(r, device.Scoped)
	if err := c.Target(context.Background(), "com.example.app"); err == nil {
		t.Error("Target with a failing runner = nil error, want an error")
	}
}

func checkByName(checks []device.Check, name string) (device.Check, bool) {
	for _, c := range checks {
		if c.Name == name {
			return c, true
		}
	}
	return device.Check{}, false
}

func TestDiagnosticsAllGood(t *testing.T) {
	t.Parallel()

	r := &fakeRunner{
		state: "device\n",
		rootOut: map[string]string{
			"id -u": "0\n",
			"[ -e /data/adb/modules/ykzpinscan ] && echo PRESENT || echo ABSENT":  "PRESENT\n",
			"command -v iptables >/dev/null 2>&1 && echo PRESENT || echo ABSENT":  "PRESENT\n",
			"command -v ip6tables >/dev/null 2>&1 && echo PRESENT || echo ABSENT": "PRESENT\n",
		},
		shellOut: map[string]string{"pm path com.example.app": "package:/data/app/com.example.app/base.apk\n"},
	}
	c := device.New(r, device.Scoped)
	checks := c.Diagnostics(context.Background(), "com.example.app")

	for _, name := range []string{"device connected", "root (su)", "ykzpinscan module (scoped CA)", "target app installed", "iptables", "ip6tables"} {
		chk, ok := checkByName(checks, name)
		if !ok {
			t.Fatalf("missing check %q", name)
		}
		if !chk.OK {
			t.Errorf("check %q = not OK (detail %q)", name, chk.Detail)
		}
	}
}

func TestDiagnosticsMissingModuleAndApp(t *testing.T) {
	t.Parallel()

	r := &fakeRunner{
		state: "device\n",
		rootOut: map[string]string{
			"id -u": "0\n",
			"[ -e /data/adb/modules/ykzpinscan ] && echo PRESENT || echo ABSENT": "ABSENT\n",
		},
	}
	c := device.New(r, device.Scoped)
	checks := c.Diagnostics(context.Background(), "com.example.app")

	mod, _ := checkByName(checks, "ykzpinscan module (scoped CA)")
	if mod.OK || !mod.Required {
		t.Errorf("module check should be a failing required check: %+v", mod)
	}
	app, _ := checkByName(checks, "target app installed")
	if app.OK { // pm path returned nothing
		t.Errorf("app check should fail when pm path is empty: %+v", app)
	}
}

func TestDiagnosticsSystemModeSkipsModule(t *testing.T) {
	t.Parallel()

	r := &fakeRunner{state: "device\n", rootOut: map[string]string{"id -u": "0\n"}}
	checks := device.New(r, device.System).Diagnostics(context.Background(), "")
	if _, ok := checkByName(checks, "ykzpinscan module (scoped CA)"); ok {
		t.Error("system mode should not probe the scoped module")
	}
	if _, ok := checkByName(checks, "system CA trust (system mode)"); !ok {
		t.Error("system mode should include a system-CA-trust check")
	}
	if _, ok := checkByName(checks, "target app installed"); ok {
		t.Error("empty package should skip the app check")
	}
}

func TestDiagnosticsSystemCATrustIsMeasured(t *testing.T) {
	t.Parallel()

	// A CA visible in every zygote namespace is genuinely trusted.
	probe := func(out string) device.Check {
		r := &fakeRunner{state: "device\n", rootOut: map[string]string{"id -u": "0\n"}, rootDefault: out}
		c := device.New(r, device.System)
		c.SetCA("71ee3f50.0", "deadbeef")
		checks := c.Diagnostics(context.Background(), "")
		got, ok := checkByName(checks, "system CA trust (system mode)")
		if !ok {
			t.Fatal("system-CA-trust check missing")
		}
		return got
	}

	if got := probe("2/2\n"); !got.OK {
		t.Errorf("CA visible in every zygote namespace should pass: %+v", got)
	}
	// Visible globally but not inside zygote means apps do NOT trust it. The
	// check must say so instead of reporting a green, unverified [ok].
	if got := probe("0/2\n"); got.OK {
		t.Errorf("CA invisible to zygote must not report trusted: %+v", got)
	}
	if got := probe("1/2\n"); got.OK {
		t.Errorf("partial zygote coverage must not report trusted: %+v", got)
	}
}

func TestSetRedirectInstallsScopedDNAT(t *testing.T) {
	t.Parallel()

	r := &fakeRunner{rootOut: map[string]string{
		"stat -c %u /data/data/com.example.app":                               "10234\n",
		"command -v ip6tables >/dev/null 2>&1 && echo PRESENT || echo ABSENT": "PRESENT\n",
	}}
	c := device.New(r, device.Scoped)
	if err := c.SetRedirect(context.Background(), "com.example.app", "192.168.1.5:8443"); err != nil {
		t.Fatalf("SetRedirect: %v", err)
	}
	want := []string{
		"stat -c %u /data/data/com.example.app",
		"command -v ip6tables >/dev/null 2>&1 && echo PRESENT || echo ABSENT",
		"iptables -t nat -A OUTPUT -p tcp --dport 443 -m owner --uid-owner 10234 -j DNAT --to-destination 192.168.1.5:8443",
		"iptables -I OUTPUT -p udp --dport 443 -m owner --uid-owner 10234 -j REJECT",
		"ip6tables -I OUTPUT -p tcp --dport 443 -m owner --uid-owner 10234 -j REJECT",
		"ip6tables -I OUTPUT -p udp --dport 443 -m owner --uid-owner 10234 -j REJECT",
	}
	if !slices.Equal(r.rootCmds, want) {
		t.Errorf("root commands =\n%v\nwant\n%v", r.rootCmds, want)
	}
}

func TestSetRedirectSkipsIPv6RulesWithoutIP6Tables(t *testing.T) {
	t.Parallel()

	r := &fakeRunner{rootOut: map[string]string{
		"stat -c %u /data/data/com.example.app":                               "10234\n",
		"command -v ip6tables >/dev/null 2>&1 && echo PRESENT || echo ABSENT": "ABSENT\n",
	}}
	var logged bytes.Buffer
	c := device.New(r, device.Scoped)
	c.SetLogger(slog.New(slog.NewTextHandler(&logged, nil)))
	if err := c.SetRedirect(context.Background(), "com.example.app", "192.168.1.5:8443"); err != nil {
		t.Fatalf("SetRedirect: %v", err)
	}
	if !strings.Contains(logged.String(), "ipv6 tls not blocked") {
		t.Errorf("no warning on the injected logger: %q", logged.String())
	}
	want := []string{
		"stat -c %u /data/data/com.example.app",
		"command -v ip6tables >/dev/null 2>&1 && echo PRESENT || echo ABSENT",
		"iptables -t nat -A OUTPUT -p tcp --dport 443 -m owner --uid-owner 10234 -j DNAT --to-destination 192.168.1.5:8443",
		"iptables -I OUTPUT -p udp --dport 443 -m owner --uid-owner 10234 -j REJECT",
	}
	if !slices.Equal(r.rootCmds, want) {
		t.Errorf("root commands =\n%v\nwant\n%v", r.rootCmds, want)
	}
}

func TestSetRedirectRollsBackOnPartialFailure(t *testing.T) {
	t.Parallel()

	const last = "ip6tables -I OUTPUT -p udp --dport 443 -m owner --uid-owner 10234 -j REJECT"
	r := &fakeRunner{
		rootOut: map[string]string{
			"stat -c %u /data/data/com.example.app":                               "10234\n",
			"command -v ip6tables >/dev/null 2>&1 && echo PRESENT || echo ABSENT": "PRESENT\n",
		},
		rootErr: map[string]error{last: errors.New("ip6tables: No chain/target/match by that name")},
	}
	if err := device.New(r, device.Scoped).SetRedirect(context.Background(), "com.example.app", "192.168.1.5:8443"); err == nil {
		t.Fatal("SetRedirect with a failing rule = nil error, want an error")
	}
	want := []string{
		"stat -c %u /data/data/com.example.app",
		"command -v ip6tables >/dev/null 2>&1 && echo PRESENT || echo ABSENT",
		"iptables -t nat -A OUTPUT -p tcp --dport 443 -m owner --uid-owner 10234 -j DNAT --to-destination 192.168.1.5:8443",
		"iptables -I OUTPUT -p udp --dport 443 -m owner --uid-owner 10234 -j REJECT",
		"ip6tables -I OUTPUT -p tcp --dport 443 -m owner --uid-owner 10234 -j REJECT",
		last,
		"ip6tables -D OUTPUT -p tcp --dport 443 -m owner --uid-owner 10234 -j REJECT",
		"iptables -D OUTPUT -p udp --dport 443 -m owner --uid-owner 10234 -j REJECT",
		"iptables -t nat -D OUTPUT -p tcp --dport 443 -m owner --uid-owner 10234 -j DNAT --to-destination 192.168.1.5:8443",
	}
	if !slices.Equal(r.rootCmds, want) {
		t.Errorf("root commands =\n%v\nwant\n%v", r.rootCmds, want)
	}
}

func TestClearRedirectDeletesSameRule(t *testing.T) {
	t.Parallel()

	r := &fakeRunner{rootOut: map[string]string{
		"stat -c %u /data/data/com.example.app":                               "10234\n",
		"command -v ip6tables >/dev/null 2>&1 && echo PRESENT || echo ABSENT": "PRESENT\n",
	}}
	c := device.New(r, device.Scoped)
	if err := c.SetRedirect(context.Background(), "com.example.app", "192.168.1.5:8443"); err != nil {
		t.Fatalf("SetRedirect: %v", err)
	}
	r.rootCmds = nil
	if err := c.ClearRedirect(context.Background(), "com.example.app", "192.168.1.5:8443"); err != nil {
		t.Fatalf("ClearRedirect: %v", err)
	}
	// Teardown must be the exact add rule with -D so iptables matches it.
	want := []string{
		"stat -c %u /data/data/com.example.app",
		"ip6tables -D OUTPUT -p udp --dport 443 -m owner --uid-owner 10234 -j REJECT",
		"ip6tables -D OUTPUT -p tcp --dport 443 -m owner --uid-owner 10234 -j REJECT",
		"iptables -D OUTPUT -p udp --dport 443 -m owner --uid-owner 10234 -j REJECT",
		"iptables -t nat -D OUTPUT -p tcp --dport 443 -m owner --uid-owner 10234 -j DNAT --to-destination 192.168.1.5:8443",
	}
	if !slices.Equal(r.rootCmds, want) {
		t.Errorf("root commands =\n%v\nwant\n%v", r.rootCmds, want)
	}
}

func TestClearRedirectContinuesAfterFailedDelete(t *testing.T) {
	t.Parallel()

	const quic = "iptables -D OUTPUT -p udp --dport 443 -m owner --uid-owner 10234 -j REJECT"
	quicErr := errors.New("iptables: Bad rule")
	r := &fakeRunner{
		rootOut: map[string]string{"stat -c %u /data/data/com.example.app": "10234\n"},
		rootErr: map[string]error{quic: quicErr},
	}
	err := device.New(r, device.Scoped).ClearRedirect(context.Background(), "com.example.app", "192.168.1.5:8443")
	if !errors.Is(err, quicErr) {
		t.Fatalf("ClearRedirect error = %v, want it to wrap %v", err, quicErr)
	}
	want := []string{
		"stat -c %u /data/data/com.example.app",
		quic,
		"iptables -t nat -D OUTPUT -p tcp --dport 443 -m owner --uid-owner 10234 -j DNAT --to-destination 192.168.1.5:8443",
	}
	if !slices.Equal(r.rootCmds, want) {
		t.Errorf("root commands =\n%v\nwant\n%v", r.rootCmds, want)
	}
}

func TestSetRedirectRejectsBadPackage(t *testing.T) {
	t.Parallel()

	r := &fakeRunner{}
	if err := device.New(r, device.Scoped).SetRedirect(context.Background(), "bad pkg!", "192.168.1.5:8443"); err == nil {
		t.Error("SetRedirect with a bad package = nil error, want an error")
	}
	if len(r.rootCmds) != 0 {
		t.Errorf("ran %v before validation, want nothing", r.rootCmds)
	}
}

func TestSetRedirectRejectsBadHostPort(t *testing.T) {
	t.Parallel()

	r := &fakeRunner{}
	if err := device.New(r, device.Scoped).SetRedirect(context.Background(), "com.example.app", "nonsense"); err == nil {
		t.Error("SetRedirect with a bad host:port = nil error, want an error")
	}
}

func TestSetRedirectRejectsNonNumericUID(t *testing.T) {
	t.Parallel()

	// A stat result that is not a UID must not be interpolated into a command.
	r := &fakeRunner{rootOut: map[string]string{"stat -c %u /data/data/com.example.app": "no such file\n"}}
	if err := device.New(r, device.Scoped).SetRedirect(context.Background(), "com.example.app", "192.168.1.5:8443"); err == nil {
		t.Error("SetRedirect with a non-numeric UID = nil error, want an error")
	}
}

func TestSetRedirectReportsRunnerError(t *testing.T) {
	t.Parallel()

	const rule = "iptables -t nat -A OUTPUT -p tcp --dport 443 -m owner --uid-owner 10234 -j DNAT --to-destination 192.168.1.5:8443"
	r := &fakeRunner{
		rootOut: map[string]string{"stat -c %u /data/data/com.example.app": "10234\n"},
		rootErr: map[string]error{rule: errors.New("iptables: Permission denied")},
	}
	if err := device.New(r, device.Scoped).SetRedirect(context.Background(), "com.example.app", "192.168.1.5:8443"); err == nil {
		t.Error("SetRedirect with a failing iptables = nil error, want an error")
	}
}
