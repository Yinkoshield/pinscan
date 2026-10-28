package scan

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yinkoshield/pinscan/internal/certmint"
	"github.com/yinkoshield/pinscan/internal/classify"
	"github.com/yinkoshield/pinscan/internal/proxy"
)

func TestObserverOutcomesSnapshot(t *testing.T) {
	t.Parallel()

	obs := proxy.NewObserver()
	obs.Record("a.example.com", classify.Accepted, "request_observed")
	obs.Record("b.example.com", classify.Rejected, "tls_alert_bad_certificate")

	got := observerObservations(obs)
	want := map[string]WaveObservation{
		"a.example.com": {Outcome: classify.Accepted, Reason: "request_observed", Attempts: 1},
		"b.example.com": {Outcome: classify.Rejected, Reason: "tls_alert_bad_certificate", Attempts: 1},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d: %v", len(got), len(want), got)
	}
	for host, obs := range want {
		if got[host] != obs {
			t.Errorf("%s = %+v, want %+v", host, got[host], obs)
		}
	}
}

func TestLocalIP(t *testing.T) {
	t.Parallel()

	ip, err := LocalIP()
	if err != nil {
		t.Skipf("LocalIP unavailable (no network?): %v", err)
	}
	if net.ParseIP(ip) == nil {
		t.Errorf("LocalIP() = %q, not a valid IP", ip)
	}
}

type bindProbeTarget struct {
	port    int
	hosts   []string
	reached map[string]bool
}

func (p *bindProbeTarget) Preflight(context.Context) error { return nil }

func (p *bindProbeTarget) Transparent() bool { return false }

func (p *bindProbeTarget) Route(context.Context, string) (func(), error) {
	return func() {}, nil
}

func (p *bindProbeTarget) Exercise(context.Context) error {
	for _, host := range p.hosts {
		addr := net.JoinHostPort(host, strconv.Itoa(p.port))
		// A generous timeout: on macOS hosts with virtual interfaces (Parallels,
		// Docker) a connection to the host's own LAN address can take close to a
		// second, and these tests run in parallel under the race detector. The
		// timeout only bounds the failing case; a reachable listener answers fast.
		conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
		p.reached[host] = err == nil
		if conn != nil {
			_ = conn.Close()
		}
	}
	return nil
}

func freeTCPPort(t *testing.T) int {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	defer func() { _ = ln.Close() }()
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("unexpected listener address type %T", ln.Addr())
	}
	return addr.Port
}

func newProbeServer(t *testing.T) *proxy.Server {
	t.Helper()

	ca, err := certmint.NewCA("pinscan scan bind test CA")
	if err != nil {
		t.Fatalf("new CA: %v", err)
	}
	return proxy.NewServer(ca, proxy.Generic, nil, proxy.NewObserver())
}

func TestServeWhileDrivingScopesListenerToHostIP(t *testing.T) {
	t.Parallel()

	lan, err := LocalIP()
	if err != nil {
		t.Skipf("LocalIP unavailable (no network?): %v", err)
	}
	if lan == loopbackIPv4 {
		t.Skip("no distinct non-loopback address on this host")
	}

	port := freeTCPPort(t)
	probe := &bindProbeTarget{port: port, hosts: []string{loopbackIPv4, lan}, reached: map[string]bool{}}
	var logged bytes.Buffer
	cfg := Config{Target: probe, HostIP: loopbackIPv4, Port: port, Window: time.Millisecond}

	if err := cfg.serveWhileDriving(context.Background(), slog.New(slog.NewTextHandler(&logged, nil)), newProbeServer(t)); err != nil {
		t.Fatalf("serveWhileDriving: %v", err)
	}

	if !probe.reached[loopbackIPv4] {
		t.Error("loopback could not reach the proxy")
	}
	if probe.reached[lan] {
		t.Errorf("proxy reachable on %s: listener was not scoped to HostIP", lan)
	}
	if strings.Contains(logged.String(), "every interface") {
		t.Errorf("warned about a wildcard bind while scoped: %s", logged.String())
	}
}

func TestServeWhileDrivingBindsLoopbackForEmulatorAlias(t *testing.T) {
	t.Parallel()

	lan, err := LocalIP()
	if err != nil {
		t.Skipf("LocalIP unavailable (no network?): %v", err)
	}
	if lan == loopbackIPv4 {
		t.Skip("no distinct non-loopback address on this host")
	}

	port := freeTCPPort(t)
	probe := &bindProbeTarget{port: port, hosts: []string{loopbackIPv4, lan}, reached: map[string]bool{}}
	var logged bytes.Buffer
	cfg := Config{Target: probe, HostIP: "10.0.2.2", Port: port, Window: time.Millisecond}

	if err := cfg.serveWhileDriving(context.Background(), slog.New(slog.NewTextHandler(&logged, nil)), newProbeServer(t)); err != nil {
		t.Fatalf("serveWhileDriving: %v", err)
	}

	if !probe.reached[loopbackIPv4] {
		t.Error("loopback could not reach the proxy for the emulator alias")
	}
	if probe.reached[lan] {
		t.Errorf("proxy reachable on %s: emulator alias was not scoped to loopback", lan)
	}
	if strings.Contains(logged.String(), "every interface") {
		t.Errorf("warned about a wildcard bind for the emulator alias: %s", logged.String())
	}
}

func TestServeWhileDrivingWarnsWhenHostIPUnbindable(t *testing.T) {
	t.Parallel()

	port := freeTCPPort(t)
	probe := &bindProbeTarget{port: port, hosts: []string{loopbackIPv4}, reached: map[string]bool{}}
	var logged bytes.Buffer
	cfg := Config{Target: probe, HostIP: "192.0.2.1", Port: port, Window: time.Millisecond}

	if err := cfg.serveWhileDriving(context.Background(), slog.New(slog.NewTextHandler(&logged, nil)), newProbeServer(t)); err != nil {
		t.Fatalf("serveWhileDriving: %v", err)
	}

	if !probe.reached[loopbackIPv4] {
		t.Error("wildcard fallback listener did not accept on loopback")
	}
	if !strings.Contains(logged.String(), "every interface") {
		t.Errorf("no warning for the wildcard fallback: %s", logged.String())
	}
}

func TestServeWhileDrivingFailsWhenScopedAddressIsTaken(t *testing.T) {
	t.Parallel()

	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("hold address: %v", err)
	}
	defer func() { _ = held.Close() }()
	addr, ok := held.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("unexpected listener address type %T", held.Addr())
	}

	probe := &bindProbeTarget{port: addr.Port, reached: map[string]bool{}}
	var logged bytes.Buffer
	cfg := Config{Target: probe, HostIP: loopbackIPv4, Port: addr.Port, Window: time.Millisecond}

	err = cfg.serveWhileDriving(context.Background(), slog.New(slog.NewTextHandler(&logged, nil)), newProbeServer(t))
	if err == nil {
		t.Fatal("serveWhileDriving succeeded while 127.0.0.1 was already bound")
	}
	if want := "listen on " + net.JoinHostPort(loopbackIPv4, strconv.Itoa(addr.Port)); !strings.Contains(err.Error(), want) {
		t.Errorf("error = %q, does not name the scoped bind %q", err, want)
	}
	if strings.Contains(logged.String(), "every interface") {
		t.Errorf("fell back to a wildcard bind on a port conflict: %s", logged.String())
	}
}

func TestServeWhileDrivingDoesNotScopeToAResolvedHostname(t *testing.T) {
	t.Parallel()

	lan, err := LocalIP()
	if err != nil {
		t.Skipf("LocalIP unavailable (no network?): %v", err)
	}
	if lan == loopbackIPv4 {
		t.Skip("no distinct non-loopback address on this host")
	}

	port := freeTCPPort(t)
	probe := &bindProbeTarget{port: port, hosts: []string{lan}, reached: map[string]bool{}}
	var logged bytes.Buffer
	cfg := Config{Target: probe, HostIP: "localhost", Port: port, Window: time.Millisecond}

	if err := cfg.serveWhileDriving(context.Background(), slog.New(slog.NewTextHandler(&logged, nil)), newProbeServer(t)); err != nil {
		t.Fatalf("serveWhileDriving: %v", err)
	}

	if !probe.reached[lan] {
		t.Errorf("a hostname HostIP scoped the listener away from %s with no warning", lan)
	}
	if !strings.Contains(logged.String(), "every interface") {
		t.Errorf("no warning although the listener is unscoped: %s", logged.String())
	}
}
