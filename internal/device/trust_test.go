package device_test

import (
	"context"
	"strings"
	"testing"

	"github.com/yinkoshield/pinscan/internal/device"
)

func trustController(t *testing.T, mode device.Mode, probeOut string, withCA bool) (*device.Controller, *fakeRunner) {
	t.Helper()

	r := &fakeRunner{state: "device\n", rootOut: map[string]string{"id -u": "0\n"}, rootDefault: probeOut}
	c := device.New(r, mode)
	if withCA {
		c.SetCA("71ee3f50.0", "deadbeef")
	}
	return c, r
}

func TestVerifyTrustSystemModeInspectsZygote(t *testing.T) {
	t.Parallel()

	c, r := trustController(t, device.System, "2/2\n", true)
	res := c.VerifyTrust(context.Background(), "com.example.app")
	if !res.Checked || !res.Verified || res.Trusted != 2 || res.Total != 2 {
		t.Errorf("CA in every zygote namespace: %+v, want checked and verified 2/2", res)
	}
	last := r.rootCmds[len(r.rootCmds)-1]
	if !strings.Contains(last, "pidof zygote64 zygote") || !strings.Contains(last, "nsenter --mount=/proc/$p/ns/mnt") {
		t.Errorf("system-mode probe must enter the zygote namespaces: %q", last)
	}
	if !strings.Contains(last, "deadbeef") || !strings.Contains(last, "71ee3f50.0") {
		t.Errorf("probe must compare the CA by content and name: %q", last)
	}
}

func TestVerifyTrustScopedModeInspectsTheApp(t *testing.T) {
	t.Parallel()

	c, r := trustController(t, device.Scoped, "1/1\n", true)
	res := c.VerifyTrust(context.Background(), "com.example.app")
	if !res.Checked || !res.Verified {
		t.Errorf("CA bound in the app's namespace: %+v, want checked and verified", res)
	}
	last := r.rootCmds[len(r.rootCmds)-1]
	if !strings.Contains(last, "pidof com.example.app") {
		t.Errorf("scoped-mode probe must inspect the app's own processes: %q", last)
	}
	if strings.Contains(last, "echo 1/1") {
		t.Errorf("scoped-mode probe must not fall back to the global namespace, where the CA never is: %q", last)
	}
}

func TestVerifyTrustReportsAbsentCA(t *testing.T) {
	t.Parallel()

	// The case the rule exists for: the device is rooted, the proxy works, and
	// the CA is simply not trusted. This must come back checked and NOT
	// verified, never as an unknown that a caller could wave through.
	for _, mode := range []device.Mode{device.System, device.Scoped} {
		c, _ := trustController(t, mode, "0/2\n", true)
		res := c.VerifyTrust(context.Background(), "com.example.app")
		if !res.Checked || res.Verified {
			t.Errorf("%s: CA absent from the trust store: %+v, want checked and not verified", mode, res)
		}
	}
	// Partial coverage is not trust either.
	c, _ := trustController(t, device.System, "1/2\n", true)
	if res := c.VerifyTrust(context.Background(), "com.example.app"); !res.Checked || res.Verified {
		t.Errorf("partial zygote coverage: %+v, want checked and not verified", res)
	}
}

func TestVerifyTrustIsUncheckedWithoutEvidence(t *testing.T) {
	t.Parallel()

	// No fingerprint: nothing to compare against.
	c, r := trustController(t, device.Scoped, "1/1\n", false)
	if res := c.VerifyTrust(context.Background(), "com.example.app"); res.Checked {
		t.Errorf("without a CA fingerprint the probe must not claim a result: %+v", res)
	}
	if len(r.rootCmds) != 0 {
		t.Errorf("without a CA fingerprint no device command should run: %v", r.rootCmds)
	}

	// No running process to inspect (scoped mode, app not up yet).
	c, _ = trustController(t, device.Scoped, "0/0\n", true)
	if res := c.VerifyTrust(context.Background(), "com.example.app"); res.Checked {
		t.Errorf("no app process: %+v, want unchecked", res)
	}

	// Probe output that cannot be parsed.
	c, _ = trustController(t, device.System, "garbage\n", true)
	if res := c.VerifyTrust(context.Background(), "com.example.app"); res.Checked || res.Verified {
		t.Errorf("unparseable probe output: %+v, want unchecked", res)
	}

	// A bad package name never reaches the shell.
	c, r = trustController(t, device.Scoped, "1/1\n", true)
	if res := c.VerifyTrust(context.Background(), "com.example.app; id"); res.Checked {
		t.Errorf("invalid package: %+v, want unchecked", res)
	}
	if len(r.rootCmds) != 0 {
		t.Errorf("invalid package must not reach the shell: %v", r.rootCmds)
	}
}

func TestControllerModeAndCAKnown(t *testing.T) {
	t.Parallel()

	c, _ := trustController(t, device.System, "", false)
	if c.Mode() != device.System || c.CAKnown() {
		t.Errorf("fresh controller: mode=%s caKnown=%v", c.Mode(), c.CAKnown())
	}
	c.SetCA("71ee3f50.0", "deadbeef")
	if !c.CAKnown() {
		t.Error("CAKnown after SetCA = false")
	}
}
