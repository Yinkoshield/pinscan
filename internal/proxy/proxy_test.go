package proxy_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/yinkoshield/pinscan/internal/certmint"
	"github.com/yinkoshield/pinscan/internal/proxy"
)

func TestWaveString(t *testing.T) {
	t.Parallel()

	cases := map[proxy.Wave]string{
		proxy.Generic: "generic",
		proxy.Cloned:  "cloned",
		proxy.Issuer:  "issuer",
		proxy.Wave(9): "invalid",
	}
	for w, want := range cases {
		if got := w.String(); got != want {
			t.Errorf("Wave(%d).String() = %q, want %q", w, got, want)
		}
	}
}

func TestGenericLeafAcceptedByTrustingClient(t *testing.T) {
	t.Parallel()

	ca := newCA(t)
	server := &tls.Config{GetCertificate: proxy.GetCertificate(ca, proxy.Generic, nil), MinVersion: tls.VersionTLS12}
	state, err := handshake(t, server, trusting(ca, "app.example.com"))
	if err != nil {
		t.Fatalf("a client trusting our CA rejected the forged leaf: %v", err)
	}
	if got := state.PeerCertificates[0].Subject.CommonName; got != "app.example.com" {
		t.Errorf("served leaf CN = %q, want %q", got, "app.example.com")
	}
}

func TestForgedLeafRejectedByPinningClient(t *testing.T) {
	t.Parallel()

	ca := newCA(t)
	server := &tls.Config{GetCertificate: proxy.GetCertificate(ca, proxy.Generic, nil), MinVersion: tls.VersionTLS12}
	// A client that does not trust our CA stands in for a pinning app: it must
	// reject the forged leaf at the handshake.
	pinning := &tls.Config{RootCAs: x509.NewCertPool(), ServerName: "app.example.com", MinVersion: tls.VersionTLS12}
	if _, err := handshake(t, server, pinning); err == nil {
		t.Error("a client that does not trust our CA accepted the forged leaf")
	}
}

func TestClonedWaveServesClonedSubject(t *testing.T) {
	t.Parallel()

	ca := newCA(t)
	realCert := makeRealCert(t)
	realFor := func(string) *x509.Certificate { return realCert }
	server := &tls.Config{GetCertificate: proxy.GetCertificate(ca, proxy.Cloned, realFor), MinVersion: tls.VersionTLS12}
	state, err := handshake(t, server, trusting(ca, "api.realbank.com"))
	if err != nil {
		t.Fatalf("a client trusting our CA rejected the cloned leaf: %v", err)
	}
	if got, want := state.PeerCertificates[0].Subject.String(), realCert.Subject.String(); got != want {
		t.Errorf("served subject = %q, want cloned %q", got, want)
	}
}

func TestClonedWaveWithoutResolverFails(t *testing.T) {
	t.Parallel()

	ca := newCA(t)
	getCert := proxy.GetCertificate(ca, proxy.Cloned, nil)
	if _, err := getCert(&tls.ClientHelloInfo{ServerName: "api.realbank.com"}); err == nil {
		t.Error("cloned wave without a real-cert resolver = nil error, want an error")
	}
}

func TestIssuerWaveServesClonedChain(t *testing.T) {
	t.Parallel()

	ca := newCA(t)
	realCert := makeRealCert(t)
	realFor := func(string) *x509.Certificate { return realCert }
	server := &tls.Config{GetCertificate: proxy.GetCertificate(ca, proxy.Issuer, realFor), MinVersion: tls.VersionTLS12}
	state, err := handshake(t, server, trusting(ca, "api.realbank.com"))
	if err != nil {
		t.Fatalf("a client trusting our CA rejected the cloned-issuer chain: %v", err)
	}
	if got := len(state.PeerCertificates); got != 2 {
		t.Fatalf("served chain length = %d, want 2 (leaf + cloned intermediate)", got)
	}
	if got, want := state.PeerCertificates[1].Subject.String(), realCert.Issuer.String(); got != want {
		t.Errorf("intermediate subject = %q, want cloned issuer %q", got, want)
	}
}

func TestClonedWaveResolverReturnsNilFails(t *testing.T) {
	t.Parallel()

	ca := newCA(t)
	realFor := func(string) *x509.Certificate { return nil }
	getCert := proxy.GetCertificate(ca, proxy.Issuer, realFor)
	if _, err := getCert(&tls.ClientHelloInfo{ServerName: "api.realbank.com"}); err == nil {
		t.Error("a resolver returning nil = nil error, want an error")
	}
}

func TestUnknownWaveFails(t *testing.T) {
	t.Parallel()

	ca := newCA(t)
	getCert := proxy.GetCertificate(ca, proxy.Wave(9), nil)
	if _, err := getCert(&tls.ClientHelloInfo{ServerName: "app.example.com"}); err == nil {
		t.Error("an unknown wave = nil error, want an error")
	}
}

func trusting(ca *certmint.CA, serverName string) *tls.Config {
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert())
	return &tls.Config{RootCAs: roots, ServerName: serverName, MinVersion: tls.VersionTLS12}
}

// handshake runs a TLS handshake between an in-memory server and client and
// returns the client's connection state, or the first side's error.
func handshake(t *testing.T, serverCfg, clientCfg *tls.Config) (tls.ConnectionState, error) {
	t.Helper()

	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() {
		_ = serverConn.Close()
		_ = clientConn.Close()
	})
	deadline := time.Now().Add(5 * time.Second) // guard against a stuck handshake.
	_ = serverConn.SetDeadline(deadline)
	_ = clientConn.SetDeadline(deadline)

	server := tls.Server(serverConn, serverCfg)
	client := tls.Client(clientConn, clientCfg)

	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Handshake() }()

	if err := client.Handshake(); err != nil {
		<-serverErr // let the server goroutine finish.
		return tls.ConnectionState{}, err
	}
	if err := <-serverErr; err != nil {
		return tls.ConnectionState{}, err
	}
	return client.ConnectionState(), nil
}

func newCA(t *testing.T) *certmint.CA {
	t.Helper()

	ca, err := certmint.NewCA("pinscan test CA")
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	return ca
}

// makeRealCert builds an endpoint certificate with a distinct issuer for the
// cloned waves to imitate.
func makeRealCert(t *testing.T) *x509.Certificate {
	t.Helper()

	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("real CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Real Issuing CA", Organization: []string{"RealCorp"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caCert := mustSign(t, caTmpl, caTmpl, caKey.Public(), caKey)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("real leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "api.realbank.com", Organization: []string{"RealBank"}},
		DNSNames:              []string{"api.realbank.com"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	return mustSign(t, leafTmpl, caCert, leafKey.Public(), caKey)
}

func mustSign(t *testing.T, tmpl, parent *x509.Certificate, pub crypto.PublicKey, parentKey crypto.Signer) *x509.Certificate {
	t.Helper()

	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, parentKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}
