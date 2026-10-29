// Package selftest proves the pinscan methodology end-to-end without a device.
//
// It stands up, for each known client posture (no pinning, metadata validation,
// issuer-name validation, public-key pinning, a client that does not trust the
// research CA at all, and a key-pinning client whose host is on the passthrough
// list), a loopback client that pins on exactly that property, and runs the
// real waves through the real certmint → proxy → observer → classify path, then
// the trust rule. It asserts the verdict equals the known posture. A green
// selftest demonstrates — rather than merely asserts — that the
// metadata/name/key distinctions hold, that an untrusted test CA is not
// mistaken for pinning, that a relayed host reads inconclusive rather than
// hardened, and catches a silent certmint regression (e.g. ClonedIssuer no
// longer cloning the issuer DN) that a unit test of the pure classifier cannot
// see.
//
// It is not a model of every real TLS stack: each posture is a deliberately
// simple pin on one property, chosen to exercise one branch of the classifier.
package selftest

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"time"

	"github.com/yinkoshield/pinscan/internal/certmint"
	"github.com/yinkoshield/pinscan/internal/classify"
	"github.com/yinkoshield/pinscan/internal/proxy"
	"github.com/yinkoshield/pinscan/internal/scan"
)

// host is the endpoint name every posture is scanned against.
const host = "api.selftest.local"

// PostureCount is how many postures [Run] exercises. The README states this
// number in words; a test keeps the two from drifting apart.
const PostureCount = 6

// Case is the result of one posture: the verdict expected versus produced, and
// the reason the generic wave recorded, so the proof shows why a verdict came
// out as it did (for the passthrough posture, that reason is the assertion).
type Case struct {
	Posture string
	Want    string
	Got     string
	Reason  string
	Pass    bool
}

// posture is a client that pins on one property, with the verdict it should
// produce.
type posture struct {
	name string
	want classify.Verdict
	// wantReason, when set, is the generic-wave reason the host must carry for
	// the posture to pass, on top of the verdict.
	wantReason string
	// passthrough puts the selftest host on the proxy's passthrough list, so the
	// client is relayed to the in-process real server instead of being tested.
	passthrough bool
	// trust is what a real scan would have established about the research CA
	// for this client; the trust rule is applied with it, as in a scan.
	trust  scan.TrustStatus
	config func(ca *certmint.CA, realLeaf *x509.Certificate) *tls.Config
}

// Run executes every posture and returns one Case each. The error is non-nil
// only on a harness failure (key generation, listener), not on a verdict
// mismatch — those surface as Case.Pass == false.
func Run(ctx context.Context) ([]Case, error) {
	ca, err := certmint.NewCA("pinscan selftest CA")
	if err != nil {
		return nil, fmt.Errorf("selftest: new CA: %w", err)
	}
	realCert, err := makeRealLeaf()
	if err != nil {
		return nil, fmt.Errorf("selftest: real leaf: %w", err)
	}
	realLeaf := realCert.Leaf
	upstream, err := startRealServer(ctx, realCert)
	if err != nil {
		return nil, fmt.Errorf("selftest: real server: %w", err)
	}
	defer upstream.close()

	cases := make([]Case, 0, len(postures()))
	for _, p := range postures() {
		var opts []proxy.ServerOption
		if p.passthrough {
			opts = upstream.passthroughOpts()
		}
		results, err := scan.Run(ctx, waveFunc(ca, realLeaf, p.config(ca, realLeaf), opts...))
		if err != nil {
			return nil, fmt.Errorf("selftest: posture %q: %w", p.name, err)
		}
		got, reason := resultOf(scan.ApplyTrust(results, p.trust))
		cases = append(cases, Case{
			Posture: p.name,
			Want:    p.want.String(),
			Got:     got.String(),
			Reason:  reason,
			Pass:    got == p.want && (p.wantReason == "" || reason == p.wantReason),
		})
	}
	return cases, nil
}

// resultOf returns the verdict recorded for the selftest host and the reason
// behind its generic-wave observation, or Inconclusive and "not_observed" when
// the host was never seen.
func resultOf(results []scan.HostResult) (classify.Verdict, string) {
	for _, r := range results {
		if r.Host == host {
			return r.Verdict, r.Waves[proxy.Generic.String()].Reason
		}
	}
	return classify.Inconclusive, "not_observed"
}

func postures() []posture {
	return []posture{
		{"no-pinning", classify.Open, "", false, scan.TrustVerified, func(ca *certmint.CA, _ *x509.Certificate) *tls.Config {
			pool := x509.NewCertPool()
			pool.AddCert(ca.Cert())
			return &tls.Config{RootCAs: pool, ServerName: host, MinVersion: tls.VersionTLS12}
		}},
		{"metadata-validation", classify.Metadata, "", false, scan.TrustVerified, func(_ *certmint.CA, realLeaf *x509.Certificate) *tls.Config {
			return pinningConfig(func(leaf *x509.Certificate) bool {
				// Accepts any certificate whose subject names match the real
				// endpoint, regardless of key or issuer.
				return leaf.Subject.String() == realLeaf.Subject.String()
			})
		}},
		{"name-validation", classify.NameValidation, "", false, scan.TrustVerified, func(_ *certmint.CA, realLeaf *x509.Certificate) *tls.Config {
			return pinningConfig(func(leaf *x509.Certificate) bool {
				// Accepts any leaf whose issuer name matches the real issuer,
				// regardless of key — defeated by a cloned-issuer chain.
				return leaf.Issuer.String() == realLeaf.Issuer.String()
			})
		}},
		{"spki-pinning", classify.SPKI, "", false, scan.TrustVerified, func(_ *certmint.CA, realLeaf *x509.Certificate) *tls.Config {
			realSPKI := spki(realLeaf)
			return pinningConfig(func(leaf *x509.Certificate) bool {
				// Accepts only the real endpoint's public key — never matched by
				// a forged chain, which always uses our keys.
				return bytes.Equal(spki(leaf), realSPKI)
			})
		}},
		{"untrusted-ca", classify.Inconclusive, "", false, scan.TrustUnverified, func(_ *certmint.CA, _ *x509.Certificate) *tls.Config {
			// A plain client that was never made to trust the research CA: it
			// rejects every forged chain with a certificate alert, which on the
			// wire is indistinguishable from key pinning. Trust is unverified for
			// this posture, so the hardened verdict must be withheld — a broken
			// setup must not read as protection.
			return &tls.Config{RootCAs: x509.NewCertPool(), ServerName: host, MinVersion: tls.VersionTLS12}
		}},
		{"passthrough", classify.Inconclusive, proxy.ReasonPassthrough, true, scan.TrustVerified, func(_ *certmint.CA, realLeaf *x509.Certificate) *tls.Config {
			// The same key-pinning client as spki-pinning, but its host is on
			// the passthrough list: the proxy relays it to the real server, the
			// pin matches the real key, and the app proceeds. Nothing was tested,
			// so the host must read inconclusive with reason "passthrough", never
			// spki — a relayed host must not look hardened.
			realSPKI := spki(realLeaf)
			return pinningConfig(func(leaf *x509.Certificate) bool {
				return bytes.Equal(spki(leaf), realSPKI)
			})
		}},
	}
}

// pinningConfig builds a client that does its own verification: it accepts the
// presented leaf iff accept reports true, and otherwise aborts the handshake
// (which the server records as a genuine certificate rejection).
func pinningConfig(accept func(leaf *x509.Certificate) bool) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // emulates a pinning client that verifies the leaf itself below.
		MinVersion:         tls.VersionTLS12,
		// No ClientSessionCache is set and tickets are off, so every connection
		// performs a full handshake and VerifyPeerCertificate always runs.
		SessionTicketsDisabled: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("selftest: no certificate presented")
			}
			leaf, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("selftest: parse leaf: %w", err)
			}
			if accept(leaf) {
				return nil
			}
			return errors.New("selftest: certificate rejected by posture")
		},
	}
}

// spki returns the DER-encoded SubjectPublicKeyInfo of cert's public key.
func spki(cert *x509.Certificate) []byte {
	der, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return nil
	}
	return der
}

// waveFunc returns a [scan.WaveFunc] that runs one wave over a loopback proxy
// with the posture's client connecting to it. The options configure the proxy
// (the passthrough posture adds its list and the in-process real server).
func waveFunc(ca *certmint.CA, realLeaf *x509.Certificate, clientCfg *tls.Config, opts ...proxy.ServerOption) scan.WaveFunc {
	realFor := func(string) *x509.Certificate { return realLeaf }
	return func(ctx context.Context, wave proxy.Wave) (map[string]scan.WaveObservation, error) {
		obs := proxy.NewObserver()
		ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
		if err != nil {
			return nil, fmt.Errorf("selftest: listen: %w", err)
		}
		srv := proxy.NewServer(ca, wave, realFor, obs, opts...)
		done := make(chan error, 1)
		go func() { done <- srv.Serve(ln) }()

		runClient(ctx, ln.Addr().String(), clientCfg)

		_ = ln.Close()
		if err := <-done; err != nil { // A closed listener returns nil.
			return nil, fmt.Errorf("selftest: proxy: %w", err)
		}

		out := make(map[string]scan.WaveObservation)
		for _, h := range obs.Hosts() {
			o := obs.Observation(h)
			out[h] = scan.WaveObservation{Outcome: o.Outcome, Reason: o.Reason}
		}
		return out, nil
	}
}

// runClient performs the client half against the loopback proxy: CONNECT, a TLS
// handshake with clientCfg, and — on success — a minimal request so the server
// records an observed use. Errors are expected for pinning postures and ignored.
func runClient(ctx context.Context, proxyAddr string, clientCfg *tls.Config) {
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := fmt.Fprintf(conn, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", host, host); err != nil {
		return
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return
	}
	_ = resp.Body.Close()

	tlsConn := tls.Client(conn, clientCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return
	}
	_, _ = fmt.Fprintf(tlsConn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host)
}

// realServer is the in-process "real endpoint" a passthrough host is relayed
// to: a TLS listener serving the real leaf, answering any request with a
// minimal response. The key-pinning client accepts it (the key is the pinned
// one), proving the relay carried the real chain, not a forged one.
type realServer struct {
	ln   net.Listener
	done chan struct{}
}

// startRealServer listens on loopback and serves cert until close is called.
func startRealServer(ctx context.Context, cert tls.Certificate) (*realServer, error) {
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &realServer{ln: ln, done: make(chan struct{})}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	go s.serve(ctx, cfg)
	return s, nil
}

// serve accepts connections until the listener closes, answering each in turn
// (the selftest client is sequential, so no concurrency is needed).
func (s *realServer) serve(ctx context.Context, cfg *tls.Config) {
	defer close(s.done)
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		answer(ctx, conn, cfg)
	}
}

// answer completes the TLS handshake with the real certificate, reads one HTTP
// request and writes a minimal response, then closes.
func answer(ctx context.Context, conn net.Conn, cfg *tls.Config) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	tlsConn := tls.Server(conn, cfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return
	}
	if _, err := http.ReadRequest(bufio.NewReader(tlsConn)); err != nil {
		return
	}
	_, _ = io.WriteString(tlsConn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
}

// close stops the server and waits for the accept loop to exit.
func (s *realServer) close() {
	_ = s.ln.Close()
	<-s.done
}

// passthroughOpts configures a proxy to relay the selftest host to this server.
func (s *realServer) passthroughOpts() []proxy.ServerOption {
	addr := s.ln.Addr().String()
	return []proxy.ServerOption{
		proxy.WithPassthrough(func(h string) bool { return h == host }),
		proxy.WithPassthroughDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		}),
	}
}

// makeRealLeaf builds a fixture "real endpoint" certificate: a leaf with a
// distinctive subject (CN plus organization) signed by a distinct root, so the
// subject, the issuer, and the key are each distinguishable from the scanner's
// own CA and from a generic leaf. The returned certificate carries the leaf's
// private key and the root, so the in-process real server can serve it.
func makeRealLeaf() (tls.Certificate, error) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Real Endpoint Root CA", Organization: []string{"Real Endpoint Ltd"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, rootKey.Public(), rootKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return tls.Certificate{}, err
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: host, Organization: []string{"Real Endpoint Ltd"}},
		DNSNames:              []string{host},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, root, leafKey.Public(), rootKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{leafDER, rootDER}, PrivateKey: leafKey, Leaf: leaf}, nil
}
