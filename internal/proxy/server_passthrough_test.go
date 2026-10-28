package proxy_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yinkoshield/pinscan/internal/certmint"
	"github.com/yinkoshield/pinscan/internal/classify"
	"github.com/yinkoshield/pinscan/internal/proxy"
)

// passthroughHost is the name the httptest TLS certificate is valid for, so a
// client verifying the real server's chain proves the proxy did not forge it.
const passthroughHost = "example.com"

const relayedBody = `{"ok":true}`

// realServer is an in-process stand-in for a passthrough host's real server,
// with a client config that trusts only its certificate.
type realServer struct {
	srv    *httptest.Server
	client *tls.Config
}

func startRealServer(t *testing.T) realServer {
	t.Helper()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, relayedBody)
	}))
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return realServer{
		srv:    srv,
		client: &tls.Config{RootCAs: pool, ServerName: passthroughHost, MinVersion: tls.VersionTLS12},
	}
}

// dialer returns a PassthroughDialer that reaches this server for any host.
func (r realServer) dialer() proxy.PassthroughDialer {
	addr := r.srv.Listener.Addr().String()
	return func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}
}

// failingDialer stands in for a real server that is down or unresolvable.
func failingDialer(context.Context, string) (net.Conn, error) {
	return nil, errors.New("no route to host")
}

// isPassthroughHost is the passthrough list under test: exactly one host.
func isPassthroughHost(host string) bool { return host == passthroughHost }

func startPassthroughServer(t *testing.T, ca *certmint.CA, obs *proxy.Observer, opts ...proxy.ServerOption) string {
	t.Helper()

	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := proxy.NewServer(ca, proxy.Generic, nil, obs, opts...)
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	t.Cleanup(func() {
		_ = ln.Close()
		// Serve waits for in-flight relays: a relay that never ended would hang
		// here, so returning is the clean-close assertion.
		if err := <-done; err != nil {
			t.Errorf("Serve returned: %v", err)
		}
	})
	return ln.Addr().String()
}

// connectExchange does CONNECT host through the proxy, a TLS handshake with
// clientCfg, one GET, and returns the CONNECT status and the response body.
func connectExchange(t *testing.T, proxyAddr, host string, clientCfg *tls.Config) (int, string, error) {
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
		return resp.StatusCode, "", nil
	}
	tlsConn := tls.Client(conn, clientCfg)
	if err := tlsConn.HandshakeContext(t.Context()); err != nil {
		return resp.StatusCode, "", err
	}
	if _, err := fmt.Fprintf(tlsConn, "GET /login HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host); err != nil {
		t.Fatalf("write GET: %v", err)
	}
	body, err := readBody(tlsConn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp.StatusCode, body, nil
}

func readBody(r io.Reader) (string, error) {
	resp, err := http.ReadResponse(bufio.NewReader(r), &http.Request{Method: http.MethodGet})
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	return string(body), err
}

func TestPassthroughConnectRelaysToRealServer(t *testing.T) {
	t.Parallel()

	ca := newCA(t)
	upstream := startRealServer(t)
	obs := proxy.NewObserver()
	addr := startPassthroughServer(t, ca, obs,
		proxy.WithPassthrough(isPassthroughHost), proxy.WithPassthroughDialer(upstream.dialer()))

	// The client trusts only the real server's certificate, not the research
	// CA: a completed handshake proves the proxy presented no forged leaf.
	status, body, err := connectExchange(t, addr, passthroughHost, upstream.client)
	if err != nil {
		t.Fatalf("handshake against the relayed real server failed: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200", status)
	}
	if body != relayedBody {
		t.Errorf("relayed body = %q, want %q", body, relayedBody)
	}
	waitForOutcome(t, obs, passthroughHost, classify.Ambiguous)
	if got := obs.Observation(passthroughHost).Reason; got != proxy.ReasonPassthrough {
		t.Errorf("reason = %q, want %q", got, proxy.ReasonPassthrough)
	}
}

func TestPassthroughConnectDialFailureIsAmbiguous(t *testing.T) {
	t.Parallel()

	ca := newCA(t)
	obs := proxy.NewObserver()
	addr := startPassthroughServer(t, ca, obs,
		proxy.WithPassthrough(isPassthroughHost), proxy.WithPassthroughDialer(failingDialer))

	status, _, _ := connectExchange(t, addr, passthroughHost, trusting(ca, passthroughHost))
	if status != http.StatusBadGateway {
		t.Errorf("CONNECT status = %d, want 502 when the real server is unreachable", status)
	}
	waitForOutcome(t, obs, passthroughHost, classify.Ambiguous)
	if got := obs.Observation(passthroughHost).Reason; got != proxy.ReasonPassthroughDialFailed {
		t.Errorf("reason = %q, want %q", got, proxy.ReasonPassthroughDialFailed)
	}
}

func TestPassthroughConnectLeavesOtherHostsForged(t *testing.T) {
	t.Parallel()

	ca := newCA(t)
	upstream := startRealServer(t)
	obs := proxy.NewObserver()
	addr := startPassthroughServer(t, ca, obs,
		proxy.WithPassthrough(isPassthroughHost), proxy.WithPassthroughDialer(upstream.dialer()))

	// A host off the list still gets the wave certificate and is measured.
	if err := connectAndHandshake(t, addr, "app.example.com", trusting(ca, "app.example.com")); err != nil {
		t.Fatalf("non-passthrough host failed to handshake against the forged leaf: %v", err)
	}
	waitForOutcome(t, obs, "app.example.com", classify.Accepted)
	if obs.Outcome(passthroughHost) != classify.NotObserved {
		t.Errorf("passthrough host recorded %s without being contacted", obs.Outcome(passthroughHost))
	}
}

func TestPassthroughTransparentRelaysFromSNI(t *testing.T) {
	t.Parallel()

	ca := newCA(t)
	upstream := startRealServer(t)
	obs := proxy.NewObserver()
	addr := startPassthroughServer(t, ca, obs, proxy.WithTransparent(),
		proxy.WithPassthrough(isPassthroughHost), proxy.WithPassthroughDialer(upstream.dialer()))

	// No CONNECT: the only name on the wire is the SNI in the ClientHello, which
	// the proxy must read without consuming before deciding to relay.
	body := directCaptureExchange(t, addr, upstream.client, passthroughHost, "/login")
	if body != relayedBody {
		t.Errorf("relayed body = %q, want %q", body, relayedBody)
	}
	waitForOutcome(t, obs, passthroughHost, classify.Ambiguous)
	if got := obs.Observation(passthroughHost).Reason; got != proxy.ReasonPassthrough {
		t.Errorf("reason = %q, want %q", got, proxy.ReasonPassthrough)
	}
}

func TestPassthroughTransparentFallsThroughForOtherHosts(t *testing.T) {
	t.Parallel()

	ca := newCA(t)
	upstream := startRealServer(t)
	obs := proxy.NewObserver()
	addr := startPassthroughServer(t, ca, obs, proxy.WithTransparent(),
		proxy.WithPassthrough(isPassthroughHost), proxy.WithPassthroughDialer(upstream.dialer()))

	// The peeked ClientHello must reach tls.Server intact: a trusting client
	// to a non-listed host still completes the forged handshake.
	if err := directHandshake(t, addr, trusting(ca, "app.example.com")); err != nil {
		t.Fatalf("non-passthrough transparent handshake failed after the SNI peek: %v", err)
	}
	waitForOutcome(t, obs, "app.example.com", classify.Accepted)

	// And a pinning client is still a genuine rejection, attributed by SNI.
	pinning := &tls.Config{RootCAs: x509.NewCertPool(), ServerName: "pinned.example.com", MinVersion: tls.VersionTLS12}
	if err := directHandshake(t, addr, pinning); err == nil {
		t.Error("pinning client unexpectedly completed the transparent handshake")
	}
	waitForOutcome(t, obs, "pinned.example.com", classify.Rejected)
}

func TestPassthroughTransparentWithoutSNIRecordsNothing(t *testing.T) {
	t.Parallel()

	ca := newCA(t)
	obs := proxy.NewObserver()
	addr := startPassthroughServer(t, ca, obs, proxy.WithTransparent(),
		proxy.WithPassthrough(isPassthroughHost), proxy.WithPassthroughDialer(failingDialer))

	noSNI := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12} //nolint:gosec // no-SNI path; trust is not under test.
	_ = directHandshake(t, addr, noSNI)
	if hosts := obs.Hosts(); len(hosts) != 0 {
		t.Errorf("recorded %v, want nothing without SNI", hosts)
	}
}

func TestPassthroughTransparentDialFailureIsAmbiguous(t *testing.T) {
	t.Parallel()

	ca := newCA(t)
	obs := proxy.NewObserver()
	addr := startPassthroughServer(t, ca, obs, proxy.WithTransparent(),
		proxy.WithPassthrough(isPassthroughHost), proxy.WithPassthroughDialer(failingDialer))

	if err := directHandshake(t, addr, trusting(ca, passthroughHost)); err == nil {
		t.Error("handshake unexpectedly completed while the real server was unreachable")
	}
	waitForOutcome(t, obs, passthroughHost, classify.Ambiguous)
	if got := obs.Observation(passthroughHost).Reason; got != proxy.ReasonPassthroughDialFailed {
		t.Errorf("reason = %q, want %q", got, proxy.ReasonPassthroughDialFailed)
	}
}

func TestPassthroughNonConnectRequestStillIgnored(t *testing.T) {
	t.Parallel()

	ca := newCA(t)
	obs := proxy.NewObserver()
	addr := startPassthroughServer(t, ca, obs,
		proxy.WithPassthrough(func(string) bool { return true }), proxy.WithPassthroughDialer(failingDialer))

	drainAfter(t, addr, "GET / HTTP/1.1\r\nHost: "+passthroughHost+"\r\n\r\n")
	if hosts := obs.Hosts(); len(hosts) != 0 {
		t.Errorf("recorded %v, want nothing for a non-CONNECT request", hosts)
	}
}
