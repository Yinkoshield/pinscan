// Package selftest proves the pinscan methodology end-to-end without a device.
//
// It stands up, for each known client posture (no pinning, metadata validation,
// issuer-name validation, genuine SPKI pinning), a loopback client that pins on
// exactly that property, and runs the real waves through the real
// certmint → proxy → observer → classify path. It then asserts the verdict
// equals the known posture. A green selftest demonstrates — rather than merely
// asserts — that the metadata/name/SPKI distinctions hold, and catches a silent
// certmint regression (e.g. ClonedIssuer no longer cloning the issuer DN) that a
// unit test of the pure classifier cannot see.
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

// Case is the result of one posture: the verdict expected versus produced.
type Case struct {
	Posture string
	Want    string
	Got     string
	Pass    bool
}

// posture is a client that pins on one property, with the verdict it should
// produce.
type posture struct {
	name   string
	want   classify.Verdict
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
	realLeaf, err := makeRealLeaf()
	if err != nil {
		return nil, fmt.Errorf("selftest: real leaf: %w", err)
	}

	cases := make([]Case, 0, len(postures()))
	for _, p := range postures() {
		results, err := scan.Run(ctx, waveFunc(ca, realLeaf, p.config(ca, realLeaf)))
		if err != nil {
			return nil, fmt.Errorf("selftest: posture %q: %w", p.name, err)
		}
		got := verdictOf(results)
		cases = append(cases, Case{
			Posture: p.name,
			Want:    p.want.String(),
			Got:     got.String(),
			Pass:    got == p.want,
		})
	}
	return cases, nil
}

// verdictOf returns the verdict recorded for the selftest host, or Inconclusive.
func verdictOf(results []scan.HostResult) classify.Verdict {
	for _, r := range results {
		if r.Host == host {
			return r.Verdict
		}
	}
	return classify.Inconclusive
}

func postures() []posture {
	return []posture{
		{"no-pinning", classify.Open, func(ca *certmint.CA, _ *x509.Certificate) *tls.Config {
			pool := x509.NewCertPool()
			pool.AddCert(ca.Cert())
			return &tls.Config{RootCAs: pool, ServerName: host, MinVersion: tls.VersionTLS12}
		}},
		{"metadata-validation", classify.Metadata, func(_ *certmint.CA, realLeaf *x509.Certificate) *tls.Config {
			return pinningConfig(func(leaf *x509.Certificate) bool {
				// Accepts any certificate whose subject names match the real
				// endpoint, regardless of key or issuer.
				return leaf.Subject.String() == realLeaf.Subject.String()
			})
		}},
		{"name-validation", classify.NameValidation, func(_ *certmint.CA, realLeaf *x509.Certificate) *tls.Config {
			return pinningConfig(func(leaf *x509.Certificate) bool {
				// Accepts any leaf whose issuer name matches the real issuer,
				// regardless of key — defeated by a cloned-issuer chain.
				return leaf.Issuer.String() == realLeaf.Issuer.String()
			})
		}},
		{"spki-pinning", classify.SPKI, func(_ *certmint.CA, realLeaf *x509.Certificate) *tls.Config {
			realSPKI := spki(realLeaf)
			return pinningConfig(func(leaf *x509.Certificate) bool {
				// Accepts only the real endpoint's public key — never matched by
				// a forged chain, which always uses our keys.
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
// with the posture's client connecting to it.
func waveFunc(ca *certmint.CA, realLeaf *x509.Certificate, clientCfg *tls.Config) scan.WaveFunc {
	realFor := func(string) *x509.Certificate { return realLeaf }
	return func(ctx context.Context, wave proxy.Wave) (map[string]scan.WaveObservation, error) {
		obs := proxy.NewObserver()
		ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
		if err != nil {
			return nil, fmt.Errorf("selftest: listen: %w", err)
		}
		srv := proxy.NewServer(ca, wave, realFor, obs)
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

// makeRealLeaf builds a fixture "real endpoint" certificate: a leaf with a
// distinctive subject (CN plus organization) signed by a distinct root, so the
// subject, the issuer, and the key are each distinguishable from the scanner's
// own CA and from a generic leaf.
func makeRealLeaf() (*x509.Certificate, error) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
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
		return nil, err
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return nil, err
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
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
		return nil, err
	}
	return x509.ParseCertificate(leafDER)
}
