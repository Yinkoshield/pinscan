// Package proxy serves the per-wave forged certificates over TLS.
//
// This slice provides certificate selection: a [tls.Config.GetCertificate]
// callback that mints the right forged chain for the requested wave and SNI. A
// not-pinned client completes the handshake; a client that pins the real key
// rejects it — which is the measurement. The interception listener and the
// accept/reject observer build on this in a following slice.
package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"github.com/yinkoshield/pinscan/internal/certmint"
)

// Wave identifies which forged certificate the proxy presents.
type Wave uint8

const (
	// Generic presents a generic leaf (Wave A).
	Generic Wave = iota
	// Cloned presents a leaf copying the real endpoint's metadata (Wave B).
	Cloned
	// Issuer presents that leaf under a cloned-issuer intermediate (Wave C).
	Issuer
)

// String implements [fmt.Stringer].
func (w Wave) String() string {
	switch w {
	case Generic:
		return "generic"
	case Cloned:
		return "cloned"
	case Issuer:
		return "issuer"
	default:
		return "invalid"
	}
}

// RealCertFunc resolves the real endpoint certificate for a host. The cloned
// waves need it; [Generic] does not and may be given a nil resolver.
type RealCertFunc func(host string) *x509.Certificate

// GetCertificate returns a [tls.Config.GetCertificate] callback that serves the
// forged certificate for wave, resolving the real certificate (for the cloned
// waves) via realFor.
func GetCertificate(ca *certmint.CA, wave Wave, realFor RealCertFunc) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		cert, err := certFor(ca, wave, hello.ServerName, realFor)
		if err != nil {
			return nil, err
		}
		return &cert, nil
	}
}

// certFor mints the forged certificate for host under wave.
func certFor(ca *certmint.CA, wave Wave, host string, realFor RealCertFunc) (tls.Certificate, error) {
	switch wave {
	case Generic:
		return ca.Generic(host)
	case Cloned:
		realCert, err := resolveReal(realFor, host, wave)
		if err != nil {
			return tls.Certificate{}, err
		}
		return ca.ClonedMetadata(realCert)
	case Issuer:
		realCert, err := resolveReal(realFor, host, wave)
		if err != nil {
			return tls.Certificate{}, err
		}
		return ca.ClonedIssuer(realCert)
	default:
		return tls.Certificate{}, fmt.Errorf("proxy: unknown wave %d", wave)
	}
}

// resolveReal looks up the real certificate a cloned wave imitates.
func resolveReal(realFor RealCertFunc, host string, wave Wave) (*x509.Certificate, error) {
	if realFor == nil {
		return nil, fmt.Errorf("proxy: wave %s needs the real certificate for %q, but no resolver was provided", wave, host)
	}
	realCert := realFor(host)
	if realCert == nil {
		return nil, fmt.Errorf("proxy: no real certificate available for %q", host)
	}
	return realCert, nil
}
