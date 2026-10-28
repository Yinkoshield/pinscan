package certmint

import (
	"crypto/x509"
	"errors"
	"testing"
)

// failingReader yields no entropy, to exercise key/serial error paths.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("no entropy")
}

// TestMintPropagatesEntropyFailure checks that every mint surfaces an entropy
// failure instead of panicking or returning a half-built certificate.
//
// It swaps the package entropy source, so it must not run in parallel; the
// source is restored on cleanup, before any parallel test resumes.
func TestMintPropagatesEntropyFailure(t *testing.T) { //nolint:paralleltest // mutates package entropy source; must be serial.
	ca, err := NewCA("pinscan test CA")
	if err != nil {
		t.Fatalf("NewCA with real entropy: %v", err)
	}

	orig := randReader
	t.Cleanup(func() { randReader = orig })
	randReader = failingReader{}

	if _, err := newKey(); err == nil {
		t.Error("newKey without entropy = nil error, want an error")
	}
	if _, err := newSerial(); err == nil {
		t.Error("newSerial without entropy = nil error, want an error")
	}
	if _, err := NewCA("x"); err == nil {
		t.Error("NewCA without entropy = nil error, want an error")
	}
	if _, err := ca.Generic("x.example.com"); err == nil {
		t.Error("Generic without entropy = nil error, want an error")
	}
	if _, err := ca.ClonedMetadata(ca.Cert()); err == nil {
		t.Error("ClonedMetadata without entropy = nil error, want an error")
	}
	if _, err := ca.ClonedIssuer(ca.Cert()); err == nil {
		t.Error("ClonedIssuer without entropy = nil error, want an error")
	}
}

// TestSignRejectsBadTemplate covers sign's certificate-creation error path: a
// template without a serial number is rejected by x509.CreateCertificate.
func TestSignRejectsBadTemplate(t *testing.T) {
	t.Parallel()

	ca, err := NewCA("pinscan test CA")
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	if _, _, err := sign(&x509.Certificate{}, ca.cert, ca.key.Public(), ca.key); err == nil {
		t.Error("sign with an empty template = nil error, want an error")
	}
}
