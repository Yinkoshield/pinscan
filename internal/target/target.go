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
)

// Android scans an app on a connected, rooted Android device over adb.
type Android struct {
	ctrl        *device.Controller
	pkg         string
	transparent bool
	logger      *slog.Logger
}

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
	return &Android{ctrl: ctrl, pkg: pkg, transparent: transparent}
}

// Preflight verifies the device and, in scoped mode, points the research CA at
// the target app.
func (a *Android) Preflight(ctx context.Context) error {
	if err := a.ctrl.Preflight(ctx); err != nil {
		return err
	}
	return a.ctrl.Target(ctx, a.pkg)
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

// Exercise restarts the app so it re-establishes its TLS connections.
func (a *Android) Exercise(ctx context.Context) error {
	if err := a.ctrl.ForceStop(ctx, a.pkg); err != nil {
		return err
	}
	return a.ctrl.Launch(ctx, a.pkg)
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
		"manual driver: scanning %q.\nMake the client trust the research CA before scanning:\n  %s\n",
		m.name, m.caPath)
	return err
}

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
