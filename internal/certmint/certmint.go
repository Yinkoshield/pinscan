// Package certmint mints the forged certificates for the three pinscan waves.
//
// All chains are signed by a [CA] whose certificate is the research CA trusted
// by the target device, so every forged chain is cryptographically valid; what
// differs is how closely the leaf (and its issuer) imitate the real endpoint:
//
//	Generic        — Wave A: a leaf with a generic identity for the host.
//	ClonedMetadata — Wave B: a leaf copying the real leaf's subject and SANs.
//	ClonedIssuer   — Wave C: that leaf under an intermediate whose DN clones
//	                 the real issuer, so the chain imitates the real issuer name
//	                 while the keys remain ours.
//
// Minting never uses the real endpoint's key — pinscan does not have it. That
// is precisely what public-key (SPKI) pinning detects.
package certmint

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"
)

// leafValidity is how long minted leaves remain valid. It is generous so a
// scan's certificates never expire mid-run, and bounded so they are not
// long-lived artifacts.
const leafValidity = 397 * 24 * time.Hour

// Errors returned by [LoadCA] and the cloned waves.
var (
	// Returned when a cloned wave is asked to imitate a nil certificate.
	errNilReal = errors.New("certmint: real certificate is nil")
	// Returned when a loaded certificate is not a CA.
	errNotCA = errors.New("certmint: certificate is not a CA")
	// Returned when a loaded key does not match the certificate.
	errKeyMismatch = errors.New("certmint: private key does not match certificate")
	// Returned when no CERTIFICATE PEM block is found.
	errNoCertBlock = errors.New("certmint: no CERTIFICATE PEM block found")
	// Returned when no private-key PEM block is found.
	errNoKeyBlock = errors.New("certmint: no private key PEM block found")
)

// randReader is the entropy source for key, serial and signature generation.
// It is a package variable so tests can inject failures; production always
// uses crypto/rand.
var randReader io.Reader = rand.Reader

// CA is the authority pinscan signs forged chains with. In production its
// certificate is the research CA injected into the device's trust store.
type CA struct {
	cert *x509.Certificate
	key  crypto.Signer
}

// NewCA generates a fresh self-signed CA with the given common name.
func NewCA(commonName string) (*CA, error) {
	key, err := newKey()
	if err != nil {
		return nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"pinscan research"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1, // allow one cloned intermediate (Wave C).
	}
	_, cert, err := sign(tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	return &CA{cert: cert, key: key}, nil
}

// LoadCA builds a CA from a PEM-encoded certificate and private key, so pinscan
// can sign with the research CA the device already trusts (for example the one
// injected into its system trust store). Each argument may be a combined PEM
// bundle; the relevant block is selected by type, and the key may be RSA or
// ECDSA. The key must match the certificate.
func LoadCA(certPEM, keyPEM []byte) (*CA, error) {
	cert, err := parseCertPEM(certPEM)
	if err != nil {
		return nil, err
	}
	if !cert.IsCA {
		return nil, errNotCA
	}
	key, err := parseKeyPEM(keyPEM)
	if err != nil {
		return nil, err
	}
	if matcher, ok := cert.PublicKey.(interface{ Equal(crypto.PublicKey) bool }); ok {
		if !matcher.Equal(key.Public()) {
			return nil, errKeyMismatch
		}
	}
	return &CA{cert: cert, key: key}, nil
}

// parseCertPEM returns the first CERTIFICATE block in pemBytes.
func parseCertPEM(pemBytes []byte) (*x509.Certificate, error) {
	for {
		var block *pem.Block
		block, pemBytes = pem.Decode(pemBytes)
		if block == nil {
			return nil, errNoCertBlock
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse certificate: %w", err)
			}
			return cert, nil
		}
	}
}

// parseKeyPEM returns the first private-key block in pemBytes, supporting
// PKCS#8, PKCS#1 (RSA) and SEC1 (EC) encodings.
func parseKeyPEM(pemBytes []byte) (crypto.Signer, error) {
	for {
		var block *pem.Block
		block, pemBytes = pem.Decode(pemBytes)
		if block == nil {
			return nil, errNoKeyBlock
		}
		switch block.Type {
		case "PRIVATE KEY":
			return pkcs8Signer(block.Bytes)
		case "RSA PRIVATE KEY":
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse pkcs1 key: %w", err)
			}
			return key, nil
		case "EC PRIVATE KEY":
			key, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse ec key: %w", err)
			}
			return key, nil
		}
	}
}

// pkcs8Signer parses a PKCS#8 key and asserts it can sign.
func pkcs8Signer(der []byte) (crypto.Signer, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse pkcs8 key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("certmint: pkcs#8 key is not a signer")
	}
	return signer, nil
}

// Cert returns the CA's certificate (the trust anchor for every forged chain).
func (ca *CA) Cert() *x509.Certificate { return ca.cert }

// EncodePEM serializes the CA as a PEM bundle — the certificate followed by its
// private key (PKCS#8). This is exactly the format [LoadCA] reads back and that
// ca-module embeds, so a CA from [NewCA] is a drop-in for one from a file.
func (ca *CA) EncodePEM() ([]byte, error) {
	keyDER, err := x509.MarshalPKCS8PrivateKey(ca.key)
	if err != nil {
		return nil, fmt.Errorf("certmint: marshal key: %w", err)
	}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw}); err != nil {
		return nil, fmt.Errorf("certmint: encode certificate: %w", err)
	}
	if err := pem.Encode(&buf, &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}); err != nil {
		return nil, fmt.Errorf("certmint: encode key: %w", err)
	}
	return buf.Bytes(), nil
}

// Generic mints a Wave A leaf with a generic identity for host.
func (ca *CA) Generic(host string) (tls.Certificate, error) {
	return mintLeaf(ca.cert, ca.key, pkix.Name{CommonName: host}, nil, []string{host})
}

// ClonedMetadata mints a Wave B leaf copying realCert's subject and SANs, signed
// directly by the CA (so the issuer is ours, but the names match the endpoint).
// The subject is copied via RawSubject so the DN is byte-faithful, preserving
// attributes Go does not map to structured fields (e.g. the eIDAS/PSD2
// organizationIdentifier, EV businessCategory) that a strict validator checks.
func (ca *CA) ClonedMetadata(realCert *x509.Certificate) (tls.Certificate, error) {
	if realCert == nil {
		return tls.Certificate{}, errNilReal
	}
	return mintLeaf(ca.cert, ca.key, realCert.Subject, realCert.RawSubject, realCert.DNSNames)
}

// ClonedIssuer mints a Wave C chain: a leaf copying realCert's subject and SANs,
// issued by an intermediate whose Distinguished Name clones realCert's issuer and
// which chains to the CA. The returned chain is [leaf, intermediate].
func (ca *CA) ClonedIssuer(realCert *x509.Certificate) (tls.Certificate, error) {
	if realCert == nil {
		return tls.Certificate{}, errNilReal
	}
	interKey, err := newKey()
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := newSerial()
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	interTmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      realCert.Issuer,
		// Clone the issuer DN byte-for-byte so the leaf's issuer (derived from
		// this intermediate's subject) matches the real chain exactly.
		RawSubject:            realCert.RawIssuer,
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(leafValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	interDER, interCert, err := sign(interTmpl, ca.cert, interKey.Public(), ca.key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := mintLeaf(interCert, interKey, realCert.Subject, realCert.RawSubject, realCert.DNSNames)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf.Certificate = append(leaf.Certificate, interDER)
	return leaf, nil
}

// mintLeaf mints a fresh-keyed server leaf for subject/dns, signed by parent. A
// non-nil rawSubject is used verbatim as the DER subject (x509.CreateCertificate
// honors RawSubject over Subject), so a cloned wave reproduces the real DN
// byte-for-byte; pass nil to encode from the structured subject.
func mintLeaf(parent *x509.Certificate, parentKey crypto.Signer, subject pkix.Name, rawSubject []byte, dns []string) (tls.Certificate, error) {
	key, err := newKey()
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := newSerial()
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		RawSubject:            rawSubject,
		DNSNames:              dns,
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(leafValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, cert, err := sign(tmpl, parent, key.Public(), parentKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}, nil
}

// sign creates and parses a certificate from tmpl, signed by parent/parentKey.
//
// It requires tmpl to carry a serial number. Go 1.22 relaxed
// x509.CreateCertificate to synthesize a serial when the template omits one;
// pinscan always sets one (see newSerial), so a missing serial signals a
// malformed template and is rejected here rather than silently accepted.
func sign(tmpl, parent *x509.Certificate, pub crypto.PublicKey, parentKey crypto.Signer) ([]byte, *x509.Certificate, error) {
	if tmpl == nil || tmpl.SerialNumber == nil {
		return nil, nil, fmt.Errorf("create certificate: template is missing a serial number")
	}
	der, err := x509.CreateCertificate(randReader, tmpl, parent, pub, parentKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parse certificate: %w", err)
	}
	return der, cert, nil
}

// newKey generates a fresh P-256 ECDSA key.
func newKey() (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), randReader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	return key, nil
}

// newSerial returns a random 128-bit certificate serial number.
func newSerial() (*big.Int, error) {
	serial, err := rand.Int(randReader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	return serial, nil
}
