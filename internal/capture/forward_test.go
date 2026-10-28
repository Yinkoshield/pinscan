package capture_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yinkoshield/pinscan/internal/capture"
)

// newReq builds a request with a context, satisfying the noctx linter.
func newReq(t *testing.T, method, rawURL string, body io.Reader) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, rawURL, body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	return req
}

// upstream starts a TLS test server and returns it plus a Forwarder that trusts
// its certificate.
func upstream(t *testing.T, bodyCap int, h http.HandlerFunc) (*httptest.Server, *capture.Forwarder) {
	t.Helper()

	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	fwd := capture.NewForwarder(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, bodyCap)
	return srv, fwd
}

func mustRequest(t *testing.T, method, path, body string) *http.Request {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	return newReq(t, method, "https://placeholder"+path, r)
}

func TestForwardRecordsAndRelays(t *testing.T) {
	t.Parallel()

	srv, fwd := upstream(t, capture.DefaultBodyCap, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"flags":["a","b"]}`)
	})

	req := mustRequest(t, http.MethodGet, "/unleash/api/frontend?x=1", "")
	ex, resp := fwd.Forward(context.Background(), "secure.example.com", srv.URL, req)

	if ex.Err != "" {
		t.Fatalf("unexpected forward error: %s", ex.Err)
	}
	if ex.Host != "secure.example.com" {
		t.Errorf("Host = %q, want secure.example.com", ex.Host)
	}
	if ex.Method != http.MethodGet {
		t.Errorf("Method = %q, want GET", ex.Method)
	}
	if ex.URL != "/unleash/api/frontend?x=1" {
		t.Errorf("URL = %q, want the request-URI", ex.URL)
	}
	if ex.Status != http.StatusOK {
		t.Errorf("Status = %d, want 200", ex.Status)
	}
	if got := string(ex.RespBody); got != `{"flags":["a","b"]}` {
		t.Errorf("recorded RespBody = %q", got)
	}
	if ct := ex.RespHeaders.Get("Content-Type"); ct != "application/json" {
		t.Errorf("recorded Content-Type = %q", ct)
	}
	if resp == nil {
		t.Fatal("relay Response is nil, want the buffered upstream response")
	}
	if string(resp.Body) != `{"flags":["a","b"]}` {
		t.Errorf("relay body = %q", resp.Body)
	}
	if resp.Status != http.StatusOK {
		t.Errorf("relay status = %d, want 200", resp.Status)
	}
}

func TestForwardRedactsRecordButForwardsRealHeaders(t *testing.T) {
	t.Parallel()

	var gotAuth string
	srv, fwd := upstream(t, capture.DefaultBodyCap, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		http.SetCookie(w, &http.Cookie{Name: "sess", Value: "secret"})
		w.WriteHeader(http.StatusOK)
	})

	req := mustRequest(t, http.MethodGet, "/", "")
	req.Header.Set("Authorization", "Bearer real-token")
	ex, resp := fwd.Forward(context.Background(), "secure.example.com", srv.URL, req)

	// The record must hide the credential...
	if v := ex.ReqHeaders.Get("Authorization"); v != capture.RedactedValue {
		t.Errorf("recorded Authorization = %q, want redacted", v)
	}
	if v := ex.RespHeaders.Get("Set-Cookie"); v != capture.RedactedValue {
		t.Errorf("recorded Set-Cookie = %q, want redacted", v)
	}
	// ...but the real upstream must have received the true header, so the app's
	// startup proceeds exactly as it would unintercepted.
	if gotAuth != "Bearer real-token" {
		t.Errorf("upstream saw Authorization = %q, want the real token forwarded", gotAuth)
	}
	// ...and the relay back to the app must carry the real Set-Cookie.
	if resp == nil || resp.Header.Get("Set-Cookie") == capture.RedactedValue || resp.Header.Get("Set-Cookie") == "" {
		t.Errorf("relay Set-Cookie not faithful: %+v", resp)
	}
}

func TestForwardDecodesRecordKeepsRelayCompressed(t *testing.T) {
	t.Parallel()

	const plain = sampleBody
	gz := gzipBytes(t)
	srv, fwd := upstream(t, capture.DefaultBodyCap, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(gz)
	})

	req := mustRequest(t, http.MethodGet, "/unleash/api/frontend", "")
	ex, resp := fwd.Forward(context.Background(), "secure.example.com", srv.URL, req)

	// The record must be the decoded, human-readable body.
	if string(ex.RespBody) != plain {
		t.Errorf("recorded RespBody = %q, want decoded %q", ex.RespBody, plain)
	}
	// The relay must carry the original compressed bytes, with the encoding
	// header intact, so the app decodes them exactly as it would unintercepted.
	if resp == nil {
		t.Fatal("relay Response is nil")
	}
	if !bytes.Equal(resp.Body, gz) {
		t.Errorf("relay body was altered; want the original gzip bytes")
	}
	if resp.Header.Get("Content-Encoding") != "gzip" {
		t.Errorf("relay Content-Encoding = %q, want gzip preserved", resp.Header.Get("Content-Encoding"))
	}
}

func TestForwardCapsRecordedBodies(t *testing.T) {
	t.Parallel()

	big := strings.Repeat("A", 100)
	srv, fwd := upstream(t, 8, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, big)
	})

	req := mustRequest(t, http.MethodGet, "/", "")
	ex, resp := fwd.Forward(context.Background(), "secure.example.com", srv.URL, req)

	if !ex.RespTruncated {
		t.Error("RespTruncated = false, want true for an oversize body")
	}
	if len(ex.RespBody) != 8 {
		t.Errorf("recorded RespBody len = %d, want 8 (the cap)", len(ex.RespBody))
	}
	// The relay must still carry the full body so the app is not corrupted.
	if resp == nil || len(resp.Body) != 100 {
		t.Errorf("relay body len = %d, want 100 (full)", len(resp.Body))
	}
}

func TestForwardCappedBodyDoesNotPinBackingArray(t *testing.T) {
	t.Parallel()

	// A body far larger than the cap: the recorded slice must copy out its window,
	// not sub-slice the full drained buffer — a sub-slice would pin the whole
	// backing array for the exchange's lifetime, defeating the per-body bound.
	big := strings.Repeat("A", 1<<16) // 64 KiB.
	srv, fwd := upstream(t, 16, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, big)
	})

	req := mustRequest(t, http.MethodGet, "/", "")
	ex, _ := fwd.Forward(context.Background(), "secure.example.com", srv.URL, req)

	if len(ex.RespBody) != 16 {
		t.Fatalf("recorded RespBody len = %d, want 16 (the cap)", len(ex.RespBody))
	}
	if cap(ex.RespBody) >= len(big) {
		t.Errorf("recorded RespBody cap = %d: the capped window must not pin the full %d-byte backing array",
			cap(ex.RespBody), len(big))
	}
}

func TestForwardCapsRecordedRequestBody(t *testing.T) {
	t.Parallel()

	var gotLen int
	srv, fwd := upstream(t, 4, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotLen = len(b)
		w.WriteHeader(http.StatusOK)
	})

	req := mustRequest(t, http.MethodPost, "/submit", "abcdefghij")
	ex, _ := fwd.Forward(context.Background(), "secure.example.com", srv.URL, req)

	if !ex.ReqTruncated {
		t.Error("ReqTruncated = false, want true")
	}
	if len(ex.ReqBody) != 4 {
		t.Errorf("recorded ReqBody len = %d, want 4", len(ex.ReqBody))
	}
	if gotLen != 10 {
		t.Errorf("upstream received %d request bytes, want the full 10 forwarded", gotLen)
	}
}

func TestForwardUpstreamErrorIsRecorded(t *testing.T) {
	t.Parallel()

	// A forwarder that trusts nothing, pointed at an unreachable base URL.
	fwd := capture.NewForwarder(&tls.Config{MinVersion: tls.VersionTLS12}, capture.DefaultBodyCap)
	req := mustRequest(t, http.MethodGet, "/", "")
	ex, resp := fwd.Forward(context.Background(), "secure.example.com", "https://127.0.0.1:1", req)

	if ex.Err == "" {
		t.Error("Err is empty, want the forward failure recorded")
	}
	if ex.Status != 0 {
		t.Errorf("Status = %d, want 0 on failure", ex.Status)
	}
	if resp != nil {
		t.Error("Response is non-nil on failure, want nil (nothing to relay)")
	}
}
