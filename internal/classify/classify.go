// Package classify turns per-host SSL-pinning wave observations into a verdict.
//
// The pinscan methodology presents a target application with up to three forged
// certificates, each signed so the device's (injected) trust store accepts the
// chain, and records whether the app proceeds (Accepted) or refuses (Rejected):
//
//	Wave A — generic leaf:         a leaf with a generic identity.
//	Wave B — cloned-metadata leaf: a leaf copying the real endpoint's
//	                               subject/SAN/issuer *names*, but our key.
//	Wave C — cloned-issuer chain:  a leaf under an intermediate whose
//	                               Distinguished Name clones the real issuer,
//	                               signed by our trusted CA.
//
// Which forged certificate an app accepts reveals how much validation it does.
// Accepting the generic leaf means no pinning; rejecting every forged leaf and
// the cloned issuer is the strongest observable posture, consistent with
// public-key pinning. Verdicts name observed behavior under these forgeries,
// not the mechanism that produced it, which the classifier cannot see.
//
// Classification is a pure function of the three observed outcomes so that the
// methodology is fully specified and exhaustively testable.
package classify

// WaveOutcome is the observed result of a single wave for a single host.
type WaveOutcome uint8

const (
	// NotObserved means the host produced no classifiable traffic in the wave.
	NotObserved WaveOutcome = iota
	// Accepted means the app completed the TLS handshake with the forged
	// certificate and sent an application request over it.
	Accepted
	// Rejected means the app refused the forged certificate with a genuine
	// certificate-class TLS alert (e.g. bad_certificate, unknown_ca): positive
	// evidence that some certificate validation rejected our chain.
	Rejected
	// Ambiguous means the wave produced a signal that does not distinguish
	// pinning from noise: a non-certificate handshake failure, a timeout, a
	// reset, a connection the app opened but sent no request over (possible
	// app-layer pinning), or a failure to present the forged certificate at all.
	// It is never treated as evidence of pinning — the classifier maps it to
	// [Inconclusive] rather than letting silence read as "hardened".
	Ambiguous
)

// String implements [fmt.Stringer].
func (o WaveOutcome) String() string {
	switch o {
	case NotObserved:
		return "not-observed"
	case Accepted:
		return "accepted"
	case Rejected:
		return "rejected"
	case Ambiguous:
		return "ambiguous"
	default:
		return "invalid"
	}
}

// HostObservation is the per-host outcome across the three waves.
//
// Issuer (Wave C) is only exercised for hosts that reject both Wave A and
// Wave B, so for most hosts it is [NotObserved].
type HostObservation struct {
	Host    string
	Generic WaveOutcome // Wave A — generic leaf.
	Cloned  WaveOutcome // Wave B — cloned-metadata leaf.
	Issuer  WaveOutcome // Wave C — cloned-issuer chain.
}

// Verdict is the pinning posture inferred for a host.
type Verdict uint8

const (
	// Inconclusive means no wave produced enough signal to classify the host.
	Inconclusive Verdict = iota
	// Open means the host has no pinning: it accepted a generic forged leaf.
	Open
	// Metadata means the host validates certificate metadata (subject/CN/SAN)
	// only: it rejected the generic leaf but accepted the cloned-metadata leaf.
	Metadata
	// NameValidation means the host validates the issuer name or chain but not
	// the key: it accepted a leaf under an intermediate whose DN clones the
	// real issuer. Such pinning is defeated by any trusted-CA-signed cert.
	NameValidation
	// KeyPinned means the host rejected the forged leaves (an SPKI-pinning
	// candidate) but Wave C did not conclusively separate key pinning from
	// name validation.
	KeyPinned
	// SPKI means the host rejected the forged leaves and the cloned-issuer
	// chain alike: a key-level check, consistent with public-key pinning or a
	// private trust store. The name is historical; it does not assert that an
	// SPKI pin set is the mechanism.
	SPKI
)

// String implements [fmt.Stringer].
func (v Verdict) String() string {
	switch v {
	case Inconclusive:
		return "inconclusive"
	case Open:
		return "open"
	case Metadata:
		return "metadata"
	case NameValidation:
		return "name-validation"
	case KeyPinned:
		return "key-pinned"
	case SPKI:
		return "spki"
	default:
		return "invalid"
	}
}

// verdictStrength ranks verdicts from weakest to strongest hardening, so an
// expectation ("at least spki") can be checked. Inconclusive is weakest: an
// unknown posture never satisfies a positive bar.
var verdictStrength = map[Verdict]int{
	Inconclusive:   0,
	Open:           1,
	Metadata:       2,
	NameValidation: 3,
	KeyPinned:      4,
	SPKI:           5,
}

// Strength returns the verdict's hardening rank (see [verdictStrength]).
func (v Verdict) Strength() int { return verdictStrength[v] }

// AtLeast reports whether v is at least as hardened as min.
func (v Verdict) AtLeast(floor Verdict) bool { return v.Strength() >= floor.Strength() }

// ParseVerdict maps a verdict name to a Verdict.
func ParseVerdict(s string) (Verdict, bool) {
	for v := Inconclusive; v <= SPKI; v++ {
		if v.String() == s {
			return v, true
		}
	}
	return Inconclusive, false
}

// Explain returns a one-line, plain-language account of the mechanism a verdict
// implies: what the host validated, and whether a trusted-CA attacker defeats
// it. It is the human-readable companion to [Verdict.String].
func (v Verdict) Explain() string {
	switch v {
	case Inconclusive:
		return "No usable signal: the app made no classifiable TLS request during the scan window."
	case Open:
		return "No pinning: the app trusts any certificate under a CA in its trust store, so an injected CA intercepts it."
	case Metadata:
		return "Metadata validation only: the app checks the certificate's subject/SAN/CN names, not its key — a cloned-name cert under a trusted CA defeats it."
	case NameValidation:
		return "Issuer-name/chain validation, not key pinning: the app accepts any leaf under an issuer whose name matches — a trusted-CA cert with a cloned issuer name defeats it."
	case KeyPinned:
		return "Rejected the forged leaves, but the cloned-issuer wave was inconclusive, so a key-level check is not yet separated from issuer-name validation."
	case SPKI:
		return "Rejected every forged chain, including the cloned-issuer chain: consistent with public-key pinning or a private trust store (the mechanism is not identified); not defeated by a trusted-CA attacker under these parameters."
	default:
		return "Unknown verdict."
	}
}

// Defeatable reports whether a network attacker holding a certificate the
// device trusts could intercept the host despite its (claimed) pinning.
//
// Open, Metadata and NameValidation are demonstrably defeatable. SPKI resists;
// KeyPinned and Inconclusive are not shown defeatable, so both report false.
func (v Verdict) Defeatable() bool {
	switch v {
	case Open, Metadata, NameValidation:
		return true
	case Inconclusive, KeyPinned, SPKI:
		return false
	default:
		return false
	}
}

// Result is the classification of a single host.
type Result struct {
	Host    string
	Verdict Verdict
}

// Classify infers a host's pinning posture from its wave outcomes.
//
// The rules are applied in order of decreasing strength:
//
//  1. Any accepted forged certificate makes the host interceptable; the weakest
//     certificate accepted names the verdict (generic → Open, cloned-metadata →
//     Metadata, cloned-issuer → NameValidation).
//  2. Otherwise, a certificate-alert rejection of the cloned-issuer chain is the
//     strongest observable evidence of a key-level check (SPKI).
//  3. Otherwise, a certificate-alert rejection of any forged leaf marks a
//     key-level-check candidate (KeyPinned).
//  4. Otherwise, there was no usable signal (Inconclusive).
//
// Only [Rejected] (a genuine certificate-class rejection) is treated as pinning
// evidence; [Ambiguous] is deliberately not, so a timeout, reset, or silent
// connection never reads as "hardened".
func Classify(o HostObservation) Result {
	verdict := classifyOutcomes(o.Generic, o.Cloned, o.Issuer)
	return Result{Host: o.Host, Verdict: verdict}
}

func classifyOutcomes(generic, cloned, issuer WaveOutcome) Verdict {
	switch {
	case generic == Accepted:
		return Open
	case cloned == Accepted:
		return Metadata
	case issuer == Accepted:
		return NameValidation
	case issuer == Rejected:
		return SPKI
	case generic == Rejected || cloned == Rejected:
		return KeyPinned
	default:
		return Inconclusive
	}
}
