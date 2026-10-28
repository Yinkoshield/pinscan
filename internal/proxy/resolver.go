package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// realCertDialTimeout bounds fetching a real endpoint certificate.
const realCertDialTimeout = 10 * time.Second

// Resolver fetches and caches the real certificate for a host so the cloned
// waves can imitate it. It is safe for concurrent use, and its [Resolver.Cert]
// method satisfies [RealCertFunc].
type Resolver struct {
	mu       sync.Mutex
	cache    map[string]*x509.Certificate
	inflight map[string]chan struct{} // Per-host dial in progress, closed on completion.
	dial     func(host string) (*x509.Certificate, error)
}

// NewResolver returns a Resolver that fetches certificates over TLS on port 443.
func NewResolver() *Resolver {
	return &Resolver{
		cache:    make(map[string]*x509.Certificate),
		inflight: make(map[string]chan struct{}),
		dial:     dialRealCert,
	}
}

// Cert returns the real certificate for host, dialing once and caching the
// result (including a nil miss, so an unreachable host is not retried).
//
// The mutex is never held across the dial: a per-host single-flight lets
// distinct hosts resolve concurrently (so one slow or unreachable host cannot
// stall every other handshake in the window) while duplicate dials for the same
// host coalesce onto one call.
func (r *Resolver) Cert(host string) *x509.Certificate {
	for {
		r.mu.Lock()
		if cert, ok := r.cache[host]; ok {
			r.mu.Unlock()
			return cert
		}
		if r.inflight == nil {
			r.inflight = make(map[string]chan struct{})
		}
		if wait, ok := r.inflight[host]; ok {
			// Another goroutine owns this host's dial; wait for it, then re-check.
			r.mu.Unlock()
			<-wait
			continue
		}
		done := make(chan struct{})
		r.inflight[host] = done
		r.mu.Unlock()

		cert, err := r.dial(host)
		if err != nil {
			cert = nil
		}

		r.mu.Lock()
		r.cache[host] = cert
		delete(r.inflight, host)
		r.mu.Unlock()
		close(done)
		return cert
	}
}

// dialRealCert returns the leaf certificate presented by host on port 443.
func dialRealCert(host string) (*x509.Certificate, error) {
	return dialCert(host, net.JoinHostPort(host, "443"))
}

// dialCert connects to addr, presenting serverName, and returns the leaf
// certificate. It does not verify the chain — it only reads what is presented.
func dialCert(serverName, addr string) (*x509.Certificate, error) {
	// The timeout bounds the dial and the handshake together, as
	// tls.DialWithDialer used to.
	ctx, cancel := context.WithTimeout(context.Background(), realCertDialTimeout)
	defer cancel()
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{},
		Config: &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true, //nolint:gosec // we read the presented certificate; we do not trust the connection.
			MinVersion:         tls.VersionTLS12,
		},
	}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %q: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("proxy: unexpected connection type %T", conn)
	}
	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, errors.New("proxy: endpoint presented no certificate")
	}
	return certs[0], nil
}
