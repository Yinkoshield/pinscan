package scan

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/yinkoshield/pinscan/internal/capture"
	"github.com/yinkoshield/pinscan/internal/certmint"
	"github.com/yinkoshield/pinscan/internal/proxy"
)

// Target is the client being scanned, abstracted so the orchestrator works for
// an Android app (driven over adb) or any other TLS client (driven manually).
// The implementations live in the target package.
type Target interface {
	// Preflight verifies the target can be scanned and sets up CA trust.
	Preflight(ctx context.Context) error
	// Transparent reports whether traffic arrives as raw TLS with no HTTP
	// CONNECT, so the proxy must read the host from the SNI.
	Transparent() bool
	// Route sends the target's TLS traffic to proxyAddr and returns a restore
	// func that undoes it. restore is always non-nil when err is nil.
	Route(ctx context.Context, proxyAddr string) (restore func(), err error)
	// Exercise makes the target establish its TLS connections for a scan window.
	// It returns promptly; the orchestrator holds the window open.
	Exercise(ctx context.Context) error
}

// discardLogger drops all records; used when a Config carries no logger.
var discardLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

// loopbackIPv4 is the IPv4 loopback address the scan listener binds when it is
// scoped to this host only.
const loopbackIPv4 = "127.0.0.1"

// Config holds the live dependencies for a scan.
type Config struct {
	CA       *certmint.CA
	Target   Target
	Resolver *proxy.Resolver
	Logger   *slog.Logger
	HostIP   string
	Port     int
	Window   time.Duration
	// CaptureMax caps each recorded body in bytes; 0 uses the default.
	CaptureMax int
}

func (cfg Config) log() *slog.Logger {
	if cfg.Logger != nil {
		return cfg.Logger
	}
	return discardLogger
}

// WaveFunc returns a [WaveFunc] that runs one wave against the live device.
func (cfg Config) WaveFunc() WaveFunc {
	return cfg.runWave
}

func (cfg Config) runWave(ctx context.Context, wave proxy.Wave) (map[string]WaveObservation, error) {
	log := cfg.log().With("wave", wave.String())
	log.Info("wave started", "port", cfg.Port)

	obs := proxy.NewObserver()
	srv := proxy.NewServer(cfg.CA, wave, cfg.Resolver.Cert, obs, cfg.serverOpts()...)
	if err := cfg.serveWhileDriving(ctx, log, srv); err != nil {
		return nil, err
	}

	observations := observerObservations(obs)
	for _, host := range obs.Hosts() {
		o := obs.Observation(host)
		log.Debug("host observed", "host", host, "outcome", o.Outcome.String(), "reason", o.Reason)
	}
	log.Info("wave finished", "hosts", len(observations))
	return observations, nil
}

// RunCapture drives the device through one capture pass: a Generic-wave proxy
// that forwards each request to the real upstream and records it. Only hosts
// with no effective pinning complete the handshake, so the returned recorder
// holds exactly the exchanges an interceptable host exposes on the scanned
// surface. The forwarder validates upstream certificates against the system
// roots.
func (cfg Config) RunCapture(ctx context.Context) (*capture.Recorder, error) {
	log := cfg.log().With("pass", "capture")
	log.Info("capture pass started", "port", cfg.Port)

	bodyCap := capture.DefaultBodyCap
	if cfg.CaptureMax > 0 {
		bodyCap = cfg.CaptureMax
	}
	rec := capture.NewRecorder()
	fwd := capture.NewForwarder(nil, bodyCap)
	srv := proxy.NewServer(cfg.CA, proxy.Generic, cfg.Resolver.Cert, proxy.NewObserver(),
		cfg.serverOpts(proxy.WithCapture(rec, fwd, nil), proxy.WithLogger(log))...)
	if err := cfg.serveWhileDriving(ctx, log, srv); err != nil {
		return nil, err
	}

	log.Info("capture pass finished", "hosts", len(rec.Hosts()), "exchanges", len(rec.Exchanges()))
	return rec, nil
}

// serverOpts returns the proxy server options for this scan, appending any
// extra options. A transparent target adds [proxy.WithTransparent].
func (cfg Config) serverOpts(extra ...proxy.ServerOption) []proxy.ServerOption {
	if cfg.Target.Transparent() {
		return append(extra, proxy.WithTransparent())
	}
	return extra
}

// serveWhileDriving starts srv on the scan port, drives the target for one
// window, then stops the server and waits for it to drain. It is the shared
// body of a classification wave and a capture pass.
func (cfg Config) serveWhileDriving(ctx context.Context, log *slog.Logger, srv *proxy.Server) error {
	host, scoped := cfg.bindHost()
	addr := net.JoinHostPort(host, strconv.Itoa(cfg.Port))
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("scan: listen on %s: %w", addr, err)
	}
	if !scoped {
		log.Warn("proxy reachable on every interface", "addr", ln.Addr().String(), "host_ip", cfg.HostIP)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()
	defer func() {
		_ = ln.Close()
		// A closed listener returns nil; anything else happened during the
		// window and is worth a line, but the observations stand.
		if err := <-serveErr; err != nil {
			log.Warn("proxy stopped with an error", "err", err)
		}
	}()
	return cfg.driveTarget(ctx, log)
}

// emulatorHostAlias is the address the Android emulator gives the host. Inside
// the guest it is an alias for the host's loopback interface, so a proxy bound
// to 127.0.0.1 is reachable from the emulator and from nothing else.
var emulatorHostAlias = net.IPv4(10, 0, 2, 2)

// bindHost returns the address the scan listener binds and whether that bind is
// scoped to a single address. It scopes to HostIP when it is an IP this host
// owns, and otherwise to loopback for the emulator alias. Failing both (a
// hostname, an unspecified IP or an address the host does not have) it returns
// the wildcard address and false, so the caller can warn that the proxy is
// exposed.
func (cfg Config) bindHost() (string, bool) {
	ip := net.ParseIP(cfg.HostIP)
	switch {
	case ip == nil || ip.IsUnspecified():
		return "0.0.0.0", false
	case hostHasAddress(ip):
		return cfg.HostIP, true
	case ip.Equal(emulatorHostAlias):
		return loopbackIPv4, true
	default:
		return "0.0.0.0", false
	}
}

// hostHasAddress reports whether ip is assigned to one of this host's network
// interfaces, and so can be bound. It reports false if the interfaces cannot be
// listed.
func hostHasAddress(ip net.IP) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
			return true
		}
	}
	return false
}

// driveTarget routes the target's traffic to the proxy, exercises it for one
// scan window, then restores routing. Teardown runs even if ctx was canceled.
func (cfg Config) driveTarget(ctx context.Context, log *slog.Logger) error {
	addr := net.JoinHostPort(cfg.HostIP, strconv.Itoa(cfg.Port))
	log.Debug("routing target", "addr", addr, "transparent", cfg.Target.Transparent())
	restore, err := cfg.Target.Route(ctx, addr)
	if err != nil {
		return err
	}
	defer restore()

	if err := cfg.Target.Exercise(ctx); err != nil {
		return err
	}

	// Logged at info so the operator sees the scan is working during the window
	// (nothing else prints until it ends), with the per-wave duration.
	log.Info("scanning window — capturing traffic", "window", cfg.Window.String())
	select {
	case <-time.After(cfg.Window):
	case <-ctx.Done():
	}
	return nil
}

// observerObservations snapshots an observer into a plain map of outcome+reason.
func observerObservations(obs *proxy.Observer) map[string]WaveObservation {
	out := make(map[string]WaveObservation)
	for _, host := range obs.Hosts() {
		o := obs.Observation(host)
		out[host] = WaveObservation{
			Outcome:  o.Outcome,
			Reason:   o.Reason,
			Attempts: o.Attempts,
			Conflict: o.Conflict,
		}
	}
	return out
}

// LocalIP returns a non-loopback IPv4 address of the host, for the device to
// reach the proxy over the LAN. The UDP "connection" sends nothing; it only
// selects the outbound interface.
func LocalIP() (string, error) {
	conn, err := (&net.Dialer{}).DialContext(context.Background(), "udp", "8.8.8.8:80")
	if err != nil {
		return "", fmt.Errorf("scan: detect local IP: %w", err)
	}
	defer func() { _ = conn.Close() }()
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return "", fmt.Errorf("scan: unexpected local address type %T", conn.LocalAddr())
	}
	return addr.IP.String(), nil
}
