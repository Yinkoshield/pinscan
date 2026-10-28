package proxy

import (
	"bufio"
	"errors"
	"fmt"
	"testing"

	"github.com/yinkoshield/pinscan/internal/classify"
)

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestHandshakeOutcome(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		err         error
		wantOutcome classify.WaveOutcome
		wantReason  string
	}{
		{"our cert miss is ambiguous", fmt.Errorf("%w: boom", errCertUnavailable), classify.Ambiguous, "cert_unavailable"},
		{"timeout is ambiguous", timeoutError{}, classify.Ambiguous, "timeout"},
		{"bad certificate alert is a genuine rejection", errors.New("remote error: tls: bad certificate"), classify.Rejected, "tls_alert_bad_certificate"},
		{"unsupported certificate alert is a genuine rejection", errors.New("remote error: tls: unsupported certificate"), classify.Rejected, "tls_alert_unsupported_certificate"},
		{"revoked certificate alert is a genuine rejection", errors.New("remote error: tls: revoked certificate"), classify.Rejected, "tls_alert_certificate_revoked"},
		{"expired certificate alert is a genuine rejection", errors.New("remote error: tls: expired certificate"), classify.Rejected, "tls_alert_certificate_expired"},
		{"unknown certificate alert is a genuine rejection", errors.New("remote error: tls: unknown certificate"), classify.Rejected, "tls_alert_certificate_unknown"},
		{"unknown CA alert is a genuine rejection", errors.New("remote error: tls: unknown certificate authority"), classify.Rejected, "tls_alert_unknown_ca"},
		{"certificate required alert is a genuine rejection", errors.New("remote error: tls: certificate required"), classify.Rejected, "tls_alert_certificate_required"},
		{"wrapped certificate alert is a genuine rejection", fmt.Errorf("handshake: %w", errors.New("remote error: tls: unknown certificate authority")), classify.Rejected, "tls_alert_unknown_ca"},
		{"bad certificate status response alert is ambiguous", errors.New("remote error: tls: bad certificate status response"), classify.Ambiguous, "tls_alert_noncert"},
		{"bad certificate hash value alert is ambiguous", errors.New("remote error: tls: bad certificate hash value"), classify.Ambiguous, "tls_alert_noncert"},
		{"certificate unobtainable alert is ambiguous", errors.New("remote error: tls: certificate unobtainable"), classify.Ambiguous, "tls_alert_noncert"},
		{"non-certificate alert is ambiguous", errors.New("remote error: tls: handshake failure"), classify.Ambiguous, "tls_alert_noncert"},
		{"plain transport error is ambiguous", errors.New("connection reset by peer"), classify.Ambiguous, "transport_error"},
		{"EOF is ambiguous", errors.New("EOF"), classify.Ambiguous, "transport_error"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotOutcome, gotReason := handshakeOutcome(tt.err)
			if gotOutcome != tt.wantOutcome || gotReason != tt.wantReason {
				t.Errorf("handshakeOutcome(%q) = (%s, %q), want (%s, %q)",
					tt.err, gotOutcome, gotReason, tt.wantOutcome, tt.wantReason)
			}
		})
	}
}

func TestHostnameOnly(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"secure.example.com:443": "secure.example.com",
		"host.example.com:8080":  "host.example.com",
		"secure.example.com":     "secure.example.com", // no port.
	}
	for authority, want := range cases {
		if got := hostnameOnly(authority); got != want {
			t.Errorf("hostnameOnly(%q) = %q, want %q", authority, got, want)
		}
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func TestBufferedConnReadWrapsError(t *testing.T) {
	t.Parallel()

	bc := &bufferedConn{reader: bufio.NewReader(errReader{})}
	if _, err := bc.Read(make([]byte, 4)); err == nil {
		t.Error("bufferedConn.Read over a failing reader = nil error, want an error")
	}
}
