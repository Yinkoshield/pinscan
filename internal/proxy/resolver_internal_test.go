package proxy

import (
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestResolverCachesDialResult(t *testing.T) {
	t.Parallel()

	calls := 0
	want := &x509.Certificate{}
	r := &Resolver{
		cache: make(map[string]*x509.Certificate),
		dial: func(string) (*x509.Certificate, error) {
			calls++
			return want, nil
		},
	}

	if got := r.Cert("h"); got != want {
		t.Errorf("first Cert = %v, want the dialed certificate", got)
	}
	if got := r.Cert("h"); got != want {
		t.Errorf("second Cert = %v, want the cached certificate", got)
	}
	if calls != 1 {
		t.Errorf("dial called %d times, want 1 (result cached)", calls)
	}
}

func TestResolverCachesMiss(t *testing.T) {
	t.Parallel()

	calls := 0
	r := &Resolver{
		cache: make(map[string]*x509.Certificate),
		dial: func(string) (*x509.Certificate, error) {
			calls++
			return nil, errors.New("unreachable")
		},
	}

	if got := r.Cert("h"); got != nil {
		t.Errorf("Cert on dial error = %v, want nil", got)
	}
	if got := r.Cert("h"); got != nil {
		t.Errorf("second Cert = %v, want nil (miss cached)", got)
	}
	if calls != 1 {
		t.Errorf("dial called %d times, want 1 (miss cached)", calls)
	}
}

func TestResolverDistinctHostsDialConcurrently(t *testing.T) {
	t.Parallel()

	// A slow/unreachable host's dial must not block resolution of a different
	// host: the mutex is never held across the dial.
	slowEntered := make(chan struct{})
	release := make(chan struct{})
	r := &Resolver{
		cache:    make(map[string]*x509.Certificate),
		inflight: make(map[string]chan struct{}),
		dial: func(host string) (*x509.Certificate, error) {
			if host == "slow" {
				close(slowEntered)
				<-release // Hold this host's dial open.
			}
			return &x509.Certificate{}, nil
		},
	}

	go r.Cert("slow")
	<-slowEntered // "slow" is now parked inside its dial.

	done := make(chan struct{})
	go func() { r.Cert("fast"); close(done) }()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error(`Cert("fast") blocked behind an in-progress dial of a different host`)
	}
	close(release)
}

func TestResolverCoalescesConcurrentDialsOfSameHost(t *testing.T) {
	t.Parallel()

	// Concurrent requests for the same host dial once; the rest wait and read
	// the cached result.
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	calls := 0
	r := &Resolver{
		cache:    make(map[string]*x509.Certificate),
		inflight: make(map[string]chan struct{}),
		dial: func(string) (*x509.Certificate, error) {
			calls++
			entered <- struct{}{}
			<-release
			return &x509.Certificate{}, nil
		},
	}

	const n = 8
	done := make(chan struct{}, n)
	for i := 0; i < n; i++ {
		go func() { r.Cert("h"); done <- struct{}{} }()
	}
	<-entered // One dial is in progress; the rest must be coalescing behind it.
	close(release)
	for i := 0; i < n; i++ {
		<-done
	}
	if calls != 1 {
		t.Errorf("dial called %d times, want 1 (concurrent dials coalesced)", calls)
	}
}

func TestDialCertReadsServerCertificate(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(srv.Close)

	cert, err := dialCert("example.com", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dialCert: %v", err)
	}
	if cert == nil {
		t.Fatal("dialCert returned a nil certificate")
	}
}

func TestDialCertReportsDialFailure(t *testing.T) {
	t.Parallel()

	// 127.0.0.1:1 is reserved and refuses connections, exercising the error path.
	if _, err := dialCert("example.com", "127.0.0.1:1"); err == nil {
		t.Error("dialCert to a closed port = nil error, want an error")
	}
}
