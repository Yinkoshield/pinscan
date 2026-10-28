package certmint_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/yinkoshield/pinscan/internal/certmint"
)

// oidOrganizationIdentifier is 2.5.4.97 — an attribute crypto/x509 parses into
// Subject.Names but never into a structured field, so a non-raw re-encode drops
// it. PSD2/eIDAS QWACs carry it, which is squarely pinscan's target domain.
var oidOrganizationIdentifier = asn1.ObjectIdentifier{2, 5, 4, 97}

func TestGeneric(t *testing.T) {
	t.Parallel()

	ca := newCA(t)
	cert, err := ca.Generic("app.example.com")
	if err != nil {
		t.Fatalf("Generic: %v", err)
	}
	if got := cert.Leaf.Subject.CommonName; got != "app.example.com" {
		t.Errorf("leaf CN = %q, want %q", got, "app.example.com")
	}
	if !slices.Contains(cert.Leaf.DNSNames, "app.example.com") {
		t.Errorf("leaf SANs = %v, want them to contain the host", cert.Leaf.DNSNames)
	}
	if got, want := cert.Leaf.Issuer.String(), ca.Cert().Subject.String(); got != want {
		t.Errorf("leaf issuer = %q, want our CA %q", got, want)
	}
	verifyChain(t, ca, cert)
}

func TestClonedMetadata(t *testing.T) {
	t.Parallel()

	ca := newCA(t)
	realCert := makeRealCert(t)
	cert, err := ca.ClonedMetadata(realCert)
	if err != nil {
		t.Fatalf("ClonedMetadata: %v", err)
	}
	if got, want := cert.Leaf.Subject.String(), realCert.Subject.String(); got != want {
		t.Errorf("leaf subject = %q, want cloned %q", got, want)
	}
	if !slices.Equal(cert.Leaf.DNSNames, realCert.DNSNames) {
		t.Errorf("leaf SANs = %v, want cloned %v", cert.Leaf.DNSNames, realCert.DNSNames)
	}
	if got, want := cert.Leaf.Issuer.String(), ca.Cert().Subject.String(); got != want {
		t.Errorf("leaf issuer = %q, want our CA %q", got, want)
	}
	if samePublicKey(cert.Leaf.PublicKey, realCert.PublicKey) {
		t.Error("cloned leaf reuses the real key; it must be ours")
	}
	verifyChain(t, ca, cert)
}

func TestClonedWavesReproduceRawSubjectFaithfully(t *testing.T) {
	t.Parallel()

	ca := newCA(t)
	realCert := makeRealCertWithExtraOID(t)

	// Wave B: the leaf subject must be byte-identical, preserving the unmapped
	// organizationIdentifier a structured re-encode would silently drop.
	meta, err := ca.ClonedMetadata(realCert)
	if err != nil {
		t.Fatalf("ClonedMetadata: %v", err)
	}
	if !bytes.Equal(meta.Leaf.RawSubject, realCert.RawSubject) {
		t.Error("ClonedMetadata leaf subject is not byte-identical to the real DN")
	}

	// Wave C: both the leaf subject and the issuer DN (via the cloned
	// intermediate) must be byte-faithful.
	issuer, err := ca.ClonedIssuer(realCert)
	if err != nil {
		t.Fatalf("ClonedIssuer: %v", err)
	}
	if !bytes.Equal(issuer.Leaf.RawSubject, realCert.RawSubject) {
		t.Error("ClonedIssuer leaf subject is not byte-identical to the real DN")
	}
	if !bytes.Equal(issuer.Leaf.RawIssuer, realCert.RawIssuer) {
		t.Error("ClonedIssuer leaf issuer is not byte-identical to the real issuer DN")
	}
}

func TestClonedIssuer(t *testing.T) {
	t.Parallel()

	ca := newCA(t)
	realCert := makeRealCert(t)
	cert, err := ca.ClonedIssuer(realCert)
	if err != nil {
		t.Fatalf("ClonedIssuer: %v", err)
	}
	if len(cert.Certificate) != 2 {
		t.Fatalf("chain length = %d, want 2 (leaf + cloned intermediate)", len(cert.Certificate))
	}
	inter, err := x509.ParseCertificate(cert.Certificate[1])
	if err != nil {
		t.Fatalf("parse intermediate: %v", err)
	}
	if got, want := inter.Subject.String(), realCert.Issuer.String(); got != want {
		t.Errorf("intermediate subject = %q, want cloned issuer %q", got, want)
	}
	if got, want := cert.Leaf.Issuer.String(), realCert.Issuer.String(); got != want {
		t.Errorf("leaf issuer = %q, want cloned issuer %q", got, want)
	}
	if got, want := cert.Leaf.Subject.String(), realCert.Subject.String(); got != want {
		t.Errorf("leaf subject = %q, want %q", got, want)
	}
	verifyChain(t, ca, cert)
}

func TestClonedWavesRejectNilReal(t *testing.T) {
	t.Parallel()

	ca := newCA(t)
	if _, err := ca.ClonedMetadata(nil); err == nil {
		t.Error("ClonedMetadata(nil) = nil error, want an error")
	}
	if _, err := ca.ClonedIssuer(nil); err == nil {
		t.Error("ClonedIssuer(nil) = nil error, want an error")
	}
}

func TestWavesUseFreshKeys(t *testing.T) {
	t.Parallel()

	ca := newCA(t)
	first, err := ca.Generic("x.example.com")
	if err != nil {
		t.Fatalf("Generic (first): %v", err)
	}
	second, err := ca.Generic("x.example.com")
	if err != nil {
		t.Fatalf("Generic (second): %v", err)
	}
	if samePublicKey(first.Leaf.PublicKey, second.Leaf.PublicKey) {
		t.Error("two mints reused the same key; each must be fresh")
	}
}

func newCA(t *testing.T) *certmint.CA {
	t.Helper()

	ca, err := certmint.NewCA("pinscan test CA")
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	return ca
}

// makeRealCert builds a realistic endpoint leaf with a distinctive issuer, so
// the cloned waves have something non-trivial to imitate.
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
		DNSNames:              []string{"api.realbank.com", "realbank.com"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	return mustSign(t, leafTmpl, caCert, leafKey.Public(), caKey)
}

// makeRealCertWithExtraOID is like makeRealCert but both the issuing CA and the
// leaf carry organizationIdentifier (2.5.4.97) in their subjects, so a lossy
// (structured, non-raw) clone would drop it — the regression this guards.
func makeRealCertWithExtraOID(t *testing.T) *x509.Certificate {
	t.Helper()

	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("real CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Real Issuing CA",
			Organization: []string{"RealCorp"},
			ExtraNames:   []pkix.AttributeTypeAndValue{{Type: oidOrganizationIdentifier, Value: "VATGB-123456789"}},
		},
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
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "api.realbank.com",
			Organization: []string{"RealBank"},
			ExtraNames:   []pkix.AttributeTypeAndValue{{Type: oidOrganizationIdentifier, Value: "PSDGB-FCA-123456"}},
		},
		DNSNames:              []string{"api.realbank.com", "realbank.com"},
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

func verifyChain(t *testing.T, ca *certmint.CA, cert tls.Certificate) {
	t.Helper()

	if cert.Leaf == nil {
		t.Fatal("tls.Certificate.Leaf is nil")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert())
	intermediates := x509.NewCertPool()
	for _, der := range cert.Certificate[1:] {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("parse intermediate: %v", err)
		}
		intermediates.AddCert(c)
	}
	if _, err := cert.Leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("chain does not verify against the CA: %v", err)
	}
}

func samePublicKey(a, b crypto.PublicKey) bool {
	ak, ok := a.(*ecdsa.PublicKey)
	if !ok {
		return false
	}
	bk, ok := b.(*ecdsa.PublicKey)
	if !ok {
		return false
	}
	return ak.Equal(bk)
}

func TestEncodePEMRoundTripsThroughLoadCA(t *testing.T) {
	t.Parallel()

	// A generated CA, serialized and loaded back, must be a working CA — the
	// property that lets `pinscan ca-new` replace an external tool.
	gen := newCA(t)
	pemBytes, err := gen.EncodePEM()
	if err != nil {
		t.Fatalf("EncodePEM: %v", err)
	}
	if !bytes.Contains(pemBytes, []byte("BEGIN CERTIFICATE")) ||
		!bytes.Contains(pemBytes, []byte("BEGIN PRIVATE KEY")) {
		t.Fatalf("PEM bundle missing a certificate or key block:\n%s", pemBytes)
	}

	// The same bundle in both arguments (LoadCA selects each block by type).
	loaded, err := certmint.LoadCA(pemBytes, pemBytes)
	if err != nil {
		t.Fatalf("LoadCA(EncodePEM): %v", err)
	}
	if loaded.Cert().Subject.String() != gen.Cert().Subject.String() {
		t.Errorf("round-trip subject = %q, want %q", loaded.Cert().Subject, gen.Cert().Subject)
	}
	cert, err := loaded.Generic("app.example.com")
	if err != nil {
		t.Fatalf("Generic from round-tripped CA: %v", err)
	}
	verifyChain(t, loaded, cert)
}

func TestLoadCAECDSARoundTrip(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	ca, err := certmint.LoadCA(selfSignedCAPEM(t, key), pkcs8KeyPEM(t, key))
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	cert, err := ca.Generic("app.example.com")
	if err != nil {
		t.Fatalf("Generic from loaded CA: %v", err)
	}
	verifyChain(t, ca, cert)
}

func TestLoadCARSAPKCS1SignsClonedIssuer(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	ca, err := certmint.LoadCA(selfSignedCAPEM(t, key), pkcs1KeyPEM(t, key))
	if err != nil {
		t.Fatalf("LoadCA (RSA PKCS#1): %v", err)
	}
	cert, err := ca.ClonedIssuer(makeRealCert(t))
	if err != nil {
		t.Fatalf("ClonedIssuer from RSA CA: %v", err)
	}
	verifyChain(t, ca, cert)
}

func TestLoadCAAcceptsECKeyAndCombinedBundle(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	if _, err := certmint.LoadCA(selfSignedCAPEM(t, key), ecKeyPEM(t, key)); err != nil {
		t.Errorf("LoadCA with EC PRIVATE KEY: %v", err)
	}
	bundle := append(selfSignedCAPEM(t, key), pkcs8KeyPEM(t, key)...)
	if _, err := certmint.LoadCA(bundle, bundle); err != nil {
		t.Errorf("LoadCA from a combined bundle: %v", err)
	}
}

func TestLoadCARejectsBadInput(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("other key: %v", err)
	}
	validCert := selfSignedCAPEM(t, key)
	validKey := pkcs8KeyPEM(t, key)
	badBlock := func(blockType string) []byte {
		return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: []byte("garbage der")})
	}

	tests := []struct {
		name    string
		certPEM []byte
		keyPEM  []byte
	}{
		{"no cert block", []byte("not a pem"), validKey},
		{"no key block", validCert, []byte("not a pem")},
		{"key does not match cert", validCert, pkcs8KeyPEM(t, other)},
		{"certificate is not a CA", selfSignedLeafPEM(t, key), validKey},
		{"cert block with bad DER", badBlock("CERTIFICATE"), validKey},
		{"pkcs8 block with bad DER", validCert, badBlock("PRIVATE KEY")},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := certmint.LoadCA(tt.certPEM, tt.keyPEM); err == nil {
				t.Error("LoadCA = nil error, want an error")
			}
		})
	}
}

func selfSignedCAPEM(t *testing.T, key crypto.Signer) []byte {
	t.Helper()

	return selfSignedPEM(t, key, true)
}

func selfSignedLeafPEM(t *testing.T, key crypto.Signer) []byte {
	t.Helper()

	return selfSignedPEM(t, key, false)
}

func selfSignedPEM(t *testing.T, key crypto.Signer, isCA bool) []byte {
	t.Helper()

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Loaded Test Cert"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func pkcs8KeyPEM(t *testing.T, key crypto.Signer) []byte {
	t.Helper()

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func pkcs1KeyPEM(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()

	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func ecKeyPEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()

	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal ec: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}
