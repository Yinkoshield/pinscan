package proxy_test

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yinkoshield/pinscan/internal/capture"
	"github.com/yinkoshield/pinscan/internal/certmint"
	"github.com/yinkoshield/pinscan/internal/proxy"
)

func TestServerCaptureForwardsAndRecords(t *testing.T) {
	t.Parallel()

	const wantBody = `{"toggles":["pkg.a","pkg.b"]}`
	var gotPath string
	realSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, wantBody)
	}))
	t.Cleanup(realSrv.Close)

	ca := newCA(t)
	rec := capture.NewRecorder()
	pool := x509.NewCertPool()
	pool.AddCert(realSrv.Certificate())
	fwd := capture.NewForwarder(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, capture.DefaultBodyCap)
	baseURL := func(string) string { return realSrv.URL }

	addr := startCaptureServer(t, ca, rec, fwd, baseURL)

	resp := captureClientExchange(t, ca, addr, "secure.example.com", "/unleash/api/frontend")
	if resp != wantBody {
		t.Errorf("relayed body = %q, want %q (app must receive the real upstream reply)", resp, wantBody)
	}
	if gotPath != "/unleash/api/frontend" {
		t.Errorf("upstream saw path %q, want /unleash/api/frontend", gotPath)
	}

	exchanges := rec.Exchanges()
	if len(exchanges) != 1 {
		t.Fatalf("recorded %d exchanges, want 1: %+v", len(exchanges), exchanges)
	}
	ex := exchanges[0]
	if ex.Host != "secure.example.com" {
		t.Errorf("recorded Host = %q", ex.Host)
	}
	if ex.URL != "/unleash/api/frontend" {
		t.Errorf("recorded URL = %q", ex.URL)
	}
	if ex.Status != http.StatusOK {
		t.Errorf("recorded Status = %d, want 200", ex.Status)
	}
	if string(ex.RespBody) != wantBody {
		t.Errorf("recorded RespBody = %q, want %q", ex.RespBody, wantBody)
	}
}

func TestServerCapturePinningClientRecordsNothing(t *testing.T) {
	t.Parallel()

	realSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(realSrv.Close)

	ca := newCA(t)
	rec := capture.NewRecorder()
	fwd := capture.NewForwarder(&tls.Config{MinVersion: tls.VersionTLS12}, capture.DefaultBodyCap)
	addr := startCaptureServer(t, ca, rec, fwd, func(string) string { return realSrv.URL })

	// A pinning client refuses our forged leaf: the handshake fails, so there is
	// nothing to forward and nothing to record.
	pinning := &tls.Config{RootCAs: x509.NewCertPool(), ServerName: "secure.example.com", MinVersion: tls.VersionTLS12}
	if err := connectAndHandshake(t, addr, "secure.example.com", pinning); err == nil {
		t.Error("pinning client unexpectedly completed the handshake")
	}
	if n := len(rec.Exchanges()); n != 0 {
		t.Errorf("recorded %d exchanges for a pinning client, want 0", n)
	}
}

func TestServerCaptureLogsEachExchange(t *testing.T) {
	t.Parallel()

	realSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(realSrv.Close)

	ca := newCA(t)
	rec := capture.NewRecorder()
	pool := x509.NewCertPool()
	pool.AddCert(realSrv.Certificate())
	fwd := capture.NewForwarder(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, capture.DefaultBodyCap)

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := proxy.NewServer(ca, proxy.Generic, nil, proxy.NewObserver(),
		proxy.WithCapture(rec, fwd, func(string) string { return realSrv.URL }),
		proxy.WithLogger(logger))
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	t.Cleanup(func() {
		_ = ln.Close()
		if err := <-done; err != nil {
			t.Errorf("Serve returned: %v", err)
		}
	})

	_ = captureClientExchange(t, ca, ln.Addr().String(), "secure.example.com", "/api/thing")

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(logBuf.String(), "intercepted") {
		time.Sleep(10 * time.Millisecond)
	}
	out := logBuf.String()
	for _, want := range []string{"intercepted", "secure.example.com", "/api/thing", "status=200"} {
		if !strings.Contains(out, want) {
			t.Errorf("exchange log missing %q\n---\n%s", want, out)
		}
	}
}

func startCaptureServer(t *testing.T, ca *certmint.CA, rec *capture.Recorder, fwd *capture.Forwarder, baseURL func(string) string) string {
	t.Helper()

	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := proxy.NewServer(ca, proxy.Generic, nil, proxy.NewObserver(),
		proxy.WithCapture(rec, fwd, baseURL))
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

// captureClientExchange performs CONNECT + TLS (trusting ca, the server's
// signing CA), sends one GET over the tunnel, and returns the relayed body.
func TestServerCaptureRelaysKeepAliveTunnel(t *testing.T) {
	t.Parallel()

	realSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.URL.Path) //nolint:gosec // G705: a test upstream echoing the path so the tunnel relay can be asserted.
	}))
	t.Cleanup(realSrv.Close)

	ca := newCA(t)
	rec := capture.NewRecorder()
	pool := x509.NewCertPool()
	pool.AddCert(realSrv.Certificate())
	fwd := capture.NewForwarder(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, capture.DefaultBodyCap)
	addr := startCaptureServer(t, ca, rec, fwd, func(string) string { return realSrv.URL })

	const host = "secure.example.com"
	tlsConn := openCaptureTunnel(t, ca, addr, host)

	// Two requests over ONE tunnel (the first without Connection: close), so the
	// capture loop relays more than once — the per-exchange write-deadline refresh.
	reader := bufio.NewReader(tlsConn)
	for i, path := range []string{"/first", "/second"} {
		closeHdr := ""
		if i == 1 {
			closeHdr = "Connection: close\r\n"
		}
		if _, err := fmt.Fprintf(tlsConn, "GET %s HTTP/1.1\r\nHost: %s\r\n%s\r\n", path, host, closeHdr); err != nil {
			t.Fatalf("write GET %s: %v", path, err)
		}
		resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
		if err != nil {
			t.Fatalf("read relayed response %d: %v", i, err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			t.Fatalf("read relayed body %d: %v", i, err)
		}
		if string(body) != path {
			t.Errorf("exchange %d relayed body = %q, want %q", i, body, path)
		}
	}
	if n := len(rec.Exchanges()); n != 2 {
		t.Errorf("recorded %d exchanges, want 2 (keep-alive tunnel)", n)
	}
}

// openCaptureTunnel dials the proxy, completes the CONNECT + TLS handshake for
// host, and returns the ready tls.Conn for the caller to drive.
func openCaptureTunnel(t *testing.T, ca *certmint.CA, proxyAddr, host string) *tls.Conn {
	t.Helper()

	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(t.Context(), "tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := fmt.Fprintf(conn, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", host, host); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	connResp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	_ = connResp.Body.Close()
	tlsConn := tls.Client(conn, trusting(ca, host))
	if err := tlsConn.HandshakeContext(t.Context()); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	return tlsConn
}

func captureClientExchange(t *testing.T, ca *certmint.CA, proxyAddr, host, path string) string {
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
	br := bufio.NewReader(conn)
	connResp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	_ = connResp.Body.Close()

	tlsConn := tls.Client(conn, trusting(ca, host))
	if err := tlsConn.HandshakeContext(t.Context()); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if _, err := fmt.Fprintf(tlsConn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host); err != nil {
		t.Fatalf("write GET: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read relayed response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read relayed body: %v", err)
	}
	return string(body)
}
