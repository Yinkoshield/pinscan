package proxy_test

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yinkoshield/pinscan/internal/capture"
	"github.com/yinkoshield/pinscan/internal/certmint"
	"github.com/yinkoshield/pinscan/internal/classify"
	"github.com/yinkoshield/pinscan/internal/proxy"
)

func TestTransparentRecordsAcceptedFromSNI(t *testing.T) {
	t.Parallel()

	ca := newCA(t)
	obs := proxy.NewObserver()
	addr := startTransparentServer(t, ca, proxy.Generic, nil, obs)

	// No CONNECT: dial the listener directly and do TLS, as a redirected
	// connection would. The host comes only from the SNI.
	if err := directHandshake(t, addr, trusting(ca, "app.example.com")); err != nil {
		t.Fatalf("trusting client failed transparent handshake: %v", err)
	}
	waitForOutcome(t, obs, "app.example.com", classify.Accepted)
}

func TestTransparentRecordsRejectedFromSNI(t *testing.T) {
	t.Parallel()

	ca := newCA(t)
	obs := proxy.NewObserver()
	addr := startTransparentServer(t, ca, proxy.Generic, nil, obs)

	// A pinning client still sends SNI in its ClientHello, so the rejection is
	// still attributed to the right host.
	pinning := &tls.Config{RootCAs: x509.NewCertPool(), ServerName: "app.example.com", MinVersion: tls.VersionTLS12}
	if err := directHandshake(t, addr, pinning); err == nil {
		t.Error("pinning client unexpectedly completed the transparent handshake")
	}
	waitForOutcome(t, obs, "app.example.com", classify.Rejected)
}

func TestTransparentNoSNIRecordsNothing(t *testing.T) {
	t.Parallel()

	ca := newCA(t)
	obs := proxy.NewObserver()
	addr := startTransparentServer(t, ca, proxy.Generic, nil, obs)

	// Without SNI there is no host to attribute, so nothing is recorded.
	noSNI := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12} //nolint:gosec // no-SNI path; trust is not under test.
	_ = directHandshake(t, addr, noSNI)
	if hosts := obs.Hosts(); len(hosts) != 0 {
		t.Errorf("recorded %v, want nothing without SNI", hosts)
	}
}

func TestTransparentCaptureForwardsAndRecords(t *testing.T) {
	t.Parallel()

	const wantBody = `{"ok":true}`
	realSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, wantBody)
	}))
	t.Cleanup(realSrv.Close)

	ca := newCA(t)
	rec := capture.NewRecorder()
	pool := x509.NewCertPool()
	pool.AddCert(realSrv.Certificate())
	fwd := capture.NewForwarder(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, capture.DefaultBodyCap)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := proxy.NewServer(ca, proxy.Generic, nil, proxy.NewObserver(),
		proxy.WithTransparent(), proxy.WithCapture(rec, fwd, func(string) string { return realSrv.URL }))
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	t.Cleanup(func() {
		_ = ln.Close()
		if err := <-done; err != nil {
			t.Errorf("Serve returned: %v", err)
		}
	})

	got := directCaptureExchange(t, ln.Addr().String(), trusting(ca, "secure.example.com"), "secure.example.com", "/x")
	if got != wantBody {
		t.Errorf("relayed body = %q, want %q", got, wantBody)
	}
	exchanges := rec.Exchanges()
	if len(exchanges) != 1 || exchanges[0].Host != "secure.example.com" {
		t.Fatalf("recorded %+v, want one exchange for secure.example.com", exchanges)
	}
}

func startTransparentServer(t *testing.T, ca *certmint.CA, wave proxy.Wave, realFor proxy.RealCertFunc, obs *proxy.Observer) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := proxy.NewServer(ca, wave, realFor, obs, proxy.WithTransparent())
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

// directHandshake dials addr and performs a TLS handshake with no CONNECT, as a
// transparently redirected connection would arrive.
func directHandshake(t *testing.T, addr string, clientCfg *tls.Config) error {
	t.Helper()

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	tlsConn := tls.Client(conn, clientCfg)
	if err := tlsConn.Handshake(); err != nil {
		return err
	}
	// Send a request so a trusting client is recorded Accepted (the server now
	// requires an observed request, not just a completed handshake).
	_, _ = fmt.Fprint(tlsConn, "GET / HTTP/1.1\r\nHost: app.example.com\r\nConnection: close\r\n\r\n")
	return nil
}

// directCaptureExchange does a no-CONNECT TLS handshake, sends one GET, and
// returns the relayed response body.
func directCaptureExchange(t *testing.T, addr string, clientCfg *tls.Config, host, path string) string {
	t.Helper()

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	tlsConn := tls.Client(conn, clientCfg)
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if _, err := fmt.Fprintf(tlsConn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host); err != nil {
		t.Fatalf("write GET: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(body)
}
