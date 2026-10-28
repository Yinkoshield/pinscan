package proxy_test

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/yinkoshield/pinscan/internal/certmint"
	"github.com/yinkoshield/pinscan/internal/classify"
	"github.com/yinkoshield/pinscan/internal/proxy"
)

func TestServerRecordsAcceptedForTrustingClient(t *testing.T) {
	t.Parallel()

	ca := newCA(t)
	obs := proxy.NewObserver()
	addr := startServer(t, ca, proxy.Generic, nil, obs)

	if err := connectAndHandshake(t, addr, "app.example.com", trusting(ca, "app.example.com")); err != nil {
		t.Fatalf("a client trusting our CA failed to handshake through the proxy: %v", err)
	}
	waitForOutcome(t, obs, "app.example.com", classify.Accepted)
}

func TestServerRecordsRejectedForPinningClient(t *testing.T) {
	t.Parallel()

	ca := newCA(t)
	obs := proxy.NewObserver()
	addr := startServer(t, ca, proxy.Generic, nil, obs)

	pinning := &tls.Config{RootCAs: x509.NewCertPool(), ServerName: "app.example.com", MinVersion: tls.VersionTLS12}
	if err := connectAndHandshake(t, addr, "app.example.com", pinning); err == nil {
		t.Error("a pinning client unexpectedly completed the handshake through the proxy")
	}
	waitForOutcome(t, obs, "app.example.com", classify.Rejected)
}

func TestServerHandshakeWithoutRequestIsAmbiguous(t *testing.T) {
	t.Parallel()

	ca := newCA(t)
	obs := proxy.NewObserver()
	addr := startServer(t, ca, proxy.Generic, nil, obs)

	// Complete the handshake, then close WITHOUT sending a request — the
	// app-layer-pinning shape (e.g. OkHttp CertificatePinner pins after the TLS
	// handshake). A completed handshake alone must NOT read as acceptance.
	handshakeNoRequest(t, addr, "app.example.com", trusting(ca, "app.example.com"))
	waitForOutcome(t, obs, "app.example.com", classify.Ambiguous)
	if got := obs.Observation("app.example.com").Reason; got != "handshake_ok_no_request" {
		t.Errorf("reason = %q, want handshake_ok_no_request", got)
	}
}

func TestServerIgnoresNonConnectRequest(t *testing.T) {
	t.Parallel()

	ca := newCA(t)
	obs := proxy.NewObserver()
	addr := startServer(t, ca, proxy.Generic, nil, obs)

	drainAfter(t, addr, "GET / HTTP/1.1\r\nHost: app.example.com\r\n\r\n")
	if hosts := obs.Hosts(); len(hosts) != 0 {
		t.Errorf("recorded %v, want nothing for a non-CONNECT request", hosts)
	}
}

func TestServerIgnoresMalformedRequest(t *testing.T) {
	t.Parallel()

	ca := newCA(t)
	obs := proxy.NewObserver()
	addr := startServer(t, ca, proxy.Generic, nil, obs)

	drainAfter(t, addr, "this is not a valid request line\r\n\r\n")
	if hosts := obs.Hosts(); len(hosts) != 0 {
		t.Errorf("recorded %v, want nothing for a malformed request", hosts)
	}
}

func TestServerFallsBackToConnectHostWithoutSNI(t *testing.T) {
	t.Parallel()

	ca := newCA(t)
	obs := proxy.NewObserver()
	addr := startServer(t, ca, proxy.Generic, nil, obs)

	// No ServerName means no SNI, which exercises the CONNECT-host fallback in
	// the server. Verification is skipped so the client still completes.
	noSNI := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12} //nolint:gosec // exercises the no-SNI path; trust is not under test.
	if err := connectAndHandshake(t, addr, "app.example.com", noSNI); err != nil {
		t.Fatalf("no-SNI client failed to handshake: %v", err)
	}
	waitForOutcome(t, obs, "app.example.com", classify.Accepted)
}

func TestServerServesClonedWaveEndToEnd(t *testing.T) {
	t.Parallel()

	ca := newCA(t)
	realCert := makeRealCert(t)
	obs := proxy.NewObserver()
	addr := startServer(t, ca, proxy.Cloned, func(string) *x509.Certificate { return realCert }, obs)

	if err := connectAndHandshake(t, addr, "api.realbank.com", trusting(ca, "api.realbank.com")); err != nil {
		t.Fatalf("trusting client failed on the cloned wave: %v", err)
	}
	waitForOutcome(t, obs, "api.realbank.com", classify.Accepted)
}

func TestServerClonedWaveWithoutRealCertFailsCleanly(t *testing.T) {
	t.Parallel()

	ca := newCA(t)
	obs := proxy.NewObserver()
	// Cloned wave but the resolver yields no real certificate: the proxy cannot
	// mint the leaf, so the handshake must fail cleanly rather than panic or
	// hang. (The orchestrator pre-resolves real certificates before a cloned
	// wave; this only asserts graceful failure.)
	addr := startServer(t, ca, proxy.Cloned, func(string) *x509.Certificate { return nil }, obs)
	if err := connectAndHandshake(t, addr, "api.realbank.com", trusting(ca, "api.realbank.com")); err == nil {
		t.Error("handshake unexpectedly succeeded with no real certificate available")
	}
	// The scanner's own failure to present a cert must be recorded ambiguous —
	// never as a rejection that would read as pinning.
	waitForOutcome(t, obs, "api.realbank.com", classify.Ambiguous)
	if got := obs.Observation("api.realbank.com").Reason; got != "cert_unavailable" {
		t.Errorf("reason = %q, want cert_unavailable", got)
	}
}

func startServer(t *testing.T, ca *certmint.CA, wave proxy.Wave, realFor proxy.RealCertFunc, obs *proxy.Observer) string {
	t.Helper()

	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := proxy.NewServer(ca, wave, realFor, obs)
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	t.Cleanup(func() {
		_ = ln.Close()
		if err := <-done; err != nil {
			t.Errorf("Serve returned: %v", err)
		}
	})
	return ln.Addr().String()
}

// connectAndHandshake performs the client half: CONNECT to the proxy, then a
// TLS handshake with clientCfg. It returns the handshake result.
func connectAndHandshake(t *testing.T, proxyAddr, host string, clientCfg *tls.Config) error {
	t.Helper()

	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(t.Context(), "tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	if _, err := fmt.Fprintf(conn, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", host, host); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
	}
	if n := reader.Buffered(); n != 0 {
		t.Fatalf("proxy sent %d unexpected bytes after CONNECT 200", n)
	}

	tlsConn := tls.Client(conn, clientCfg)
	if err := tlsConn.HandshakeContext(t.Context()); err != nil {
		return err
	}
	// A successful handshake alone is no longer "accepted": the server probes
	// for an application request. Send a minimal one so a trusting client is
	// recorded Accepted (a pinning client never reaches here).
	_, _ = fmt.Fprintf(tlsConn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host)
	return nil
}

// handshakeNoRequest does CONNECT + a successful TLS handshake, then closes the
// tunnel without sending any application request.
func handshakeNoRequest(t *testing.T, proxyAddr, host string, clientCfg *tls.Config) {
	t.Helper()

	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(t.Context(), "tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := fmt.Fprintf(conn, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", host, host); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	_ = resp.Body.Close()
	tlsConn := tls.Client(conn, clientCfg)
	if err := tlsConn.HandshakeContext(t.Context()); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	_ = tlsConn.Close() // Close without a request.
}

func waitForOutcome(t *testing.T, obs *proxy.Observer, host string, want classify.WaveOutcome) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if obs.Outcome(host) == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("outcome for %s = %s, want %s", host, obs.Outcome(host), want)
}

// drainAfter sends request to the proxy and reads until the proxy closes the
// connection, so the handler has finished before the caller inspects state.
func drainAfter(t *testing.T, proxyAddr, request string) {
	t.Helper()

	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(t.Context(), "tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatalf("write request: %v", err)
	}
	_, _ = io.Copy(io.Discard, conn)
}
