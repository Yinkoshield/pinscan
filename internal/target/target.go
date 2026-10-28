// Package target provides the scan targets: the thing whose TLS client is
// probed. Android drives a device over adb; Manual drives any other TLS client
// (a desktop app, a server-side SDK, an IoT device) by instructing an operator.
//
// Both satisfy the scan.Target interface structurally. The methodology, proxy,
// classifier and report are identical across targets — only how traffic is
// routed to the proxy and how the client is exercised differ.
package target

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/yinkoshield/pinscan/internal/device"
	"github.com/yinkoshield/pinscan/internal/scan"
)

// defaultTrustWait bounds how long a scoped-mode scan waits, after launching
// the app, for a process to appear whose trust store can be inspected.
const defaultTrustWait = 8 * time.Second

// Android scans an app on a connected, rooted Android device over adb.
type Android struct {
	ctrl        *device.Controller
	pkg         string
	transparent bool
	logger      *slog.Logger
	// trust is what the device-side verification established so far; it
	// starts unverified and is reported through [Android.TrustStatus].
	trust scan.TrustStatus
	// trustWait bounds the wait for a scoped-mode app process after launch.
	trustWait time.Duration
}

// TrustStatus reports whether the research CA was verified, from the mount
// namespace the app actually reads, to be in the trust store.
func (a *Android) TrustStatus() scan.TrustStatus { return a.trust }

// SetTrustWait bounds how long scoped mode waits for the app's process after
// launch before giving up on verifying trust for that wave. Tests set it low.
func (a *Android) SetTrustWait(d time.Duration) { a.trustWait = d }

// discardLogger drops all records; used when an Android target has no logger.
var discardLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

// SetLogger sets the logger for teardown failures, such as a redirect rule left
// on the device. Without one they are dropped.
func (a *Android) SetLogger(logger *slog.Logger) { a.logger = logger }

// log returns the target's logger, or one that discards when none is set.
func (a *Android) log() *slog.Logger {
	if a.logger != nil {
		return a.logger
	}
	return discardLogger
}

// NewAndroid returns an Android target for pkg. When transparent is set, routing
// uses an iptables DNAT redirect (raw TLS) instead of the global HTTP proxy.
func NewAndroid(ctrl *device.Controller, pkg string, transparent bool) *Android {
	return &Android{ctrl: ctrl, pkg: pkg, transparent: transparent, trustWait: defaultTrustWait}
}

// Preflight verifies the device and, in scoped mode, points the research CA at
// the target app. In system mode it also verifies, from the zygote mount
// namespaces, that the CA is trusted: a scan against an untrusted CA would
// read every host as hardened, so that setup is refused here.
func (a *Android) Preflight(ctx context.Context) error {
	if err := a.ctrl.Preflight(ctx); err != nil {
		return err
	}
	if err := a.ctrl.Target(ctx, a.pkg); err != nil {
		return err
	}
	if a.ctrl.Mode() == device.System && a.ctrl.CAKnown() {
		return a.recordTrust(a.ctrl.VerifyTrust(ctx, a.pkg))
	}
	if !a.ctrl.CAKnown() {
		a.log().Warn("research CA not identified; trust cannot be verified and hardened verdicts will be withheld")
	}
	return nil
}

// recordTrust folds one verification result into the target's trust status.
// A checked-and-absent CA is an error that stops the scan; an unchecked
// result keeps whatever was established before (a verified status is not
// revoked because a later probe found no process) but never upgrades it.
func (a *Android) recordTrust(res device.TrustResult) error {
	switch {
	case res.Checked && res.Verified:
		a.trust = scan.TrustVerified
		a.log().Info("research CA trust verified", "target", a.pkg, "detail", res.Detail)
		return nil
	case res.Checked:
		a.trust = scan.TrustUnverified
		return fmt.Errorf("device: the research CA is not trusted by %s (%s); install it (pinscan ca-module for system mode, or the ykzpinscan module with this package as target), reboot, and re-run pinscan doctor", a.pkg, res.Detail)
	default:
		if a.trust != scan.TrustVerified {
			a.log().Warn("research CA trust could not be verified; hardened verdicts will be withheld", "target", a.pkg, "detail", res.Detail)
		}
		return nil
	}
}

// verifyScopedTrust waits for the freshly launched app to have a process,
// then verifies the CA from inside that process's mount namespace, which is
// where the ykzpinscan module binds it.
func (a *Android) verifyScopedTrust(ctx context.Context) error {
	if !a.ctrl.CAKnown() {
		return a.recordTrust(a.ctrl.VerifyTrust(ctx, a.pkg))
	}
	deadline := time.Now().Add(a.trustWait)
	for {
		res := a.ctrl.VerifyTrust(ctx, a.pkg)
		if res.Checked || !time.Now().Before(deadline) {
			return a.recordTrust(res)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// Transparent reports whether routing delivers raw TLS (no HTTP CONNECT).
func (a *Android) Transparent() bool { return a.transparent }

// Route points the app's TLS traffic at proxyAddr and returns a restore func.
func (a *Android) Route(ctx context.Context, proxyAddr string) (func(), error) {
	if a.transparent {
		if err := a.ctrl.SetRedirect(ctx, a.pkg, proxyAddr); err != nil {
			return nil, err
		}
		return func() {
			if err := a.ctrl.ClearRedirect(context.Background(), a.pkg, proxyAddr); err != nil {
				a.log().Error("redirect not removed", "target", a.pkg, "error", err)
			}
		}, nil
	}
	if err := a.ctrl.SetProxy(ctx, proxyAddr); err != nil {
		return nil, err
	}
	return func() { _ = a.ctrl.ClearProxy(context.Background()) }, nil
}

// Exercise restarts the app so it re-establishes its TLS connections. In
// scoped mode it then verifies that the research CA is bound into the app's
// own mount namespace, which only exists once the app is running.
func (a *Android) Exercise(ctx context.Context) error {
	if err := a.ctrl.ForceStop(ctx, a.pkg); err != nil {
		return err
	}
	if err := a.ctrl.Launch(ctx, a.pkg); err != nil {
		return err
	}
	if a.ctrl.Mode() == device.Scoped {
		return a.verifyScopedTrust(ctx)
	}
	return nil
}

// Manual scans any TLS client the operator exercises by hand. It automates
// nothing on the client; it prints what to do and holds the scan window open
// while the operator drives the client through the proxy.
type Manual struct {
	out         io.Writer
	name        string
	caPath      string
	window      time.Duration
	transparent bool
}

// NewManual returns a Manual target. The name labels the client, caPath is the
// research CA the operator must make the client trust, window is printed in the
// prompt, and transparent selects raw-TLS routing guidance over HTTP-proxy.
func NewManual(out io.Writer, name, caPath string, window time.Duration, transparent bool) *Manual {
	return &Manual{out: out, name: name, caPath: caPath, window: window, transparent: transparent}
}

// Preflight reminds the operator of the one-time trust setup.
func (m *Manual) Preflight(_ context.Context) error {
	_, err := fmt.Fprintf(m.out,
		"manual driver: scanning %q.\nMake the client trust the research CA before scanning:\n  %s\n"+
			"pinscan cannot verify that on a manual target; a hardened verdict is only as good as that setup.\n",
		m.name, m.caPath)
	return err
}

// TrustStatus reports that CA trust rests on the operator's setup: the manual
// driver has no way to inspect the client's trust store.
func (m *Manual) TrustStatus() scan.TrustStatus { return scan.TrustAsserted }

// Transparent reports whether the operator routes raw TLS to the proxy.
func (m *Manual) Transparent() bool { return m.transparent }

// Route prints how to send the client's traffic to the proxy.
func (m *Manual) Route(_ context.Context, proxyAddr string) (func(), error) {
	if m.transparent {
		_, err := fmt.Fprintf(m.out,
			"\nRoute the client's TLS (tcp/443) to %s — e.g. an iptables/pf DNAT or a VPN.\n", proxyAddr)
		if err != nil {
			return nil, err
		}
	} else {
		_, err := fmt.Fprintf(m.out,
			"\nPoint the client at the HTTP proxy %s — e.g. HTTPS_PROXY=http://%s.\n", proxyAddr, proxyAddr)
		if err != nil {
			return nil, err
		}
	}
	return func() {
		_, _ = fmt.Fprintln(m.out, "Scan window closed; you may reset the client's proxy/routing.")
	}, nil
}

// Exercise prompts the operator to drive the client for the window.
func (m *Manual) Exercise(_ context.Context) error {
	_, err := fmt.Fprintf(m.out,
		"Exercise the client now — make it perform its HTTPS requests. Capturing for %s...\n", m.window)
	return err
}
