package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/yinkoshield/pinscan/internal/capture"
	"github.com/yinkoshield/pinscan/internal/certmint"
	"github.com/yinkoshield/pinscan/internal/classify"
)

// handshakeTimeout bounds reading the CONNECT request and the TLS handshake for
// a single connection, so a stuck client cannot hold a goroutine forever.
const handshakeTimeout = 10 * time.Second

// maxConcurrentConns bounds how many connections the proxy handles at once. This
// caps memory under a connection burst (hostile or misbehaving LAN host) while
// staying well above a real device's startup fan-out. Excess connections wait in
// the kernel backlog.
const maxConcurrentConns = 128

// maxConnectBytes bounds the CONNECT request line and headers. We call
// [http.ReadRequest] directly, so net/http applies no header limit of its own;
// this stops a peer from forcing an unbounded allocation in the handshake window.
const maxConnectBytes = 16 << 10 // 16 KiB — ample for CONNECT + Host.

// requestProbeTimeout bounds how long, after a successful handshake, the server
// waits for the app to send an application request before concluding it sent
// none (possible app-layer pinning).
const requestProbeTimeout = 5 * time.Second

// errCertUnavailable marks a failure to present the forged certificate at all
// (e.g. the real certificate for a cloned wave could not be resolved). A
// handshake that fails for this reason is the scanner's own miss, not evidence
// that the app rejected anything, so it is recorded as ambiguous.
var errCertUnavailable = errors.New("proxy: forged certificate unavailable")

// certAlertReasons maps the certificate-class TLS alert descriptions that count
// as a genuine certificate rejection to a stable reason label. Any alert not
// listed here is treated as ambiguous, never as pinning evidence. Keys are
// crypto/tls alert strings and are matched exactly, so a longer alert that
// merely starts with one ("bad certificate status response") stays ambiguous.
var certAlertReasons = map[string]string{
	"bad certificate":               "tls_alert_bad_certificate",
	"unknown certificate authority": "tls_alert_unknown_ca",
	"expired certificate":           "tls_alert_certificate_expired",
	"revoked certificate":           "tls_alert_certificate_revoked",
	"unknown certificate":           "tls_alert_certificate_unknown",
	"certificate required":          "tls_alert_certificate_required",
	"unsupported certificate":       "tls_alert_unsupported_certificate",
}

// remoteAlertPrefix precedes the alert description in the error crypto/tls
// returns when the peer sends an alert.
const remoteAlertPrefix = "remote error: tls: "

// Server is an HTTP CONNECT proxy that terminates TLS with a wave certificate
// and records, per host, whether the client accepted or rejected it.
//
// With a capture option (see [WithCapture]) a connection whose handshake
// succeeds is additionally served as plaintext HTTP, forwarded to the real
// upstream, and recorded — surfacing exactly what an interceptable host exposes.
type Server struct {
	ca      *certmint.CA
	wave    Wave
	realFor RealCertFunc
	obs     *Observer

	// cap is nil unless capture is enabled via WithCapture.
	cap *captureConfig
	// transparent switches handling from HTTP CONNECT to direct, SNI-driven TLS
	// (see WithTransparent).
	transparent bool
	// logger, when set via WithLogger, logs each captured exchange live.
	logger *slog.Logger
	// passthrough, when set via WithPassthrough, names the hosts relayed to
	// their real server untouched (see server_passthrough.go).
	passthrough func(host string) bool
	// passthroughDial reaches a passthrough host's real server; nil means
	// host:443 (see WithPassthroughDialer).
	passthroughDial PassthroughDialer
}

// discardLogger drops all records; used when a Server has no logger.
var discardLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

// log returns the server's logger, or a discarding one.
func (s *Server) log() *slog.Logger {
	if s.logger != nil {
		return s.logger
	}
	return discardLogger
}

// captureConfig holds the dependencies for capture mode.
type captureConfig struct {
	rec     *capture.Recorder
	fwd     *capture.Forwarder
	baseURL func(host string) string
}

// ServerOption configures a [Server] at construction.
type ServerOption func(*Server)

// WithCapture enables capture mode: after a successful handshake the proxy
// serves the tunnel as HTTP, forwards each request to the real upstream via fwd
// (recording a redacted, capped exchange in rec), and relays the real response
// back so the app proceeds unchanged. The baseURL callback maps a host to the
// upstream origin to dial; passing nil defaults to https://<host>:443.
func WithCapture(rec *capture.Recorder, fwd *capture.Forwarder, baseURL func(host string) string) ServerOption {
	return func(s *Server) {
		if baseURL == nil {
			baseURL = defaultBaseURL
		}
		s.cap = &captureConfig{rec: rec, fwd: fwd, baseURL: baseURL}
	}
}

// defaultBaseURL is the production upstream origin for a host: TLS on 443.
func defaultBaseURL(host string) string {
	return "https://" + host + ":443"
}

// WithLogger makes the server log each captured exchange live: one info line per
// request/response, with request and response body previews at debug level.
func WithLogger(logger *slog.Logger) ServerOption {
	return func(s *Server) { s.logger = logger }
}

// WithTransparent switches the server to transparent mode: it expects raw TLS
// connections (no HTTP CONNECT), as delivered by a device-side redirect of the
// target's port 443, and takes the host from the TLS SNI. It catches apps that
// ignore the system HTTP proxy.
func WithTransparent() ServerOption {
	return func(s *Server) { s.transparent = true }
}

// NewServer returns a Server that presents wave certificates signed by ca and
// records outcomes into obs. The realFor callback supplies real certificates
// for the cloned waves and may be nil for [Generic].
func NewServer(ca *certmint.CA, wave Wave, realFor RealCertFunc, obs *Observer, opts ...ServerOption) *Server {
	s := &Server{ca: ca, wave: wave, realFor: realFor, obs: obs}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Serve accepts connections until ln is closed, handling each concurrently and
// waiting for in-flight connections before returning. A clean close returns nil.
func (s *Server) Serve(ln net.Listener) error {
	// ctx spans this Serve call. It is deliberately not canceled when the
	// listener closes: in-flight handshakes must finish (bounded by the
	// connection deadline) so their outcome is recorded, not abandoned.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrentConns)
	for {
		conn, err := ln.Accept()
		if err != nil {
			wg.Wait()
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}
		sem <- struct{}{} // Bound concurrent handlers; blocks when all slots are busy.
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			s.handle(ctx, conn)
		}()
	}
}

// handle dispatches a connection to the CONNECT or transparent handler.
func (s *Server) handle(ctx context.Context, conn net.Conn) {
	if s.transparent {
		s.handleTransparent(ctx, conn)
		return
	}
	s.handleConn(ctx, conn)
}

// handleTransparent terminates TLS directly on a redirected connection (no
// CONNECT), taking the host from the SNI, and records the outcome. On a
// successful handshake with capture enabled it serves the tunnel like the
// CONNECT path. With a passthrough list, the SNI is first read from the raw
// ClientHello so a listed host is relayed instead of terminated.
func (s *Server) handleTransparent(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return
	}
	raw, terminate := s.transparentConn(ctx, conn)
	if !terminate {
		return // Relayed to the real server; nothing to terminate.
	}
	var sni string
	tlsConn := tls.Server(raw, s.transparentConfig(&sni))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		if sni != "" {
			outcome, reason := handshakeOutcome(err)
			s.obs.Record(sni, outcome, reason)
		}
		return
	}
	if sni == "" {
		return // No host to attribute the outcome to.
	}
	s.recordUse(tlsConn, sni)
}

// transparentConn decides, for a redirected connection, between relaying a
// passthrough host and terminating TLS. It returns the connection to hand to
// [tls.Server] and true, or false once the connection was relayed. Without a
// passthrough list the connection is returned as is; with one, the ClientHello
// is peeked through a buffer large enough for a whole record, and the buffered
// bytes reach tls.Server unchanged when the host is not listed.
func (s *Server) transparentConn(ctx context.Context, conn net.Conn) (net.Conn, bool) {
	if s.passthrough == nil {
		return conn, true
	}
	reader := bufio.NewReaderSize(conn, maxClientHelloBytes)
	if host := transparentSNI(reader); s.isPassthrough(host) {
		s.passthroughTransparent(ctx, conn, reader, host)
		return nil, false
	}
	return &bufferedConn{reader: reader, Conn: conn}, true
}

// handshakeOutcome maps a failed TLS handshake to a wave outcome and a reason.
// Only a genuine certificate-class alert from the peer counts as a rejection
// ([classify.Rejected]); everything else — our own failure to present a cert, a
// timeout, a transport error, or a non-certificate alert — is
// [classify.Ambiguous], so silence never reads as pinning.
func handshakeOutcome(err error) (classify.WaveOutcome, string) {
	if errors.Is(err, errCertUnavailable) {
		return classify.Ambiguous, "cert_unavailable"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return classify.Ambiguous, "timeout"
	}
	msg := err.Error()
	if i := strings.LastIndex(msg, remoteAlertPrefix); i >= 0 {
		if reason, ok := certAlertReasons[msg[i+len(remoteAlertPrefix):]]; ok {
			return classify.Rejected, reason
		}
		return classify.Ambiguous, "tls_alert_noncert"
	}
	return classify.Ambiguous, "transport_error"
}

// recordUse runs after a successful handshake: it probes whether the app sends
// an application request over the forged tunnel. A request means the app truly
// used the forged certificate ([classify.Accepted]); handshake-but-no-request
// is possible app-layer pinning (e.g. OkHttp CertificatePinner) and is recorded
// [classify.Ambiguous], not as acceptance. With capture enabled and a request
// observed, it serves the tunnel.
func (s *Server) recordUse(tlsConn net.Conn, host string) {
	if err := tlsConn.SetReadDeadline(time.Now().Add(requestProbeTimeout)); err != nil {
		return
	}
	reader := bufio.NewReader(tlsConn)
	if _, err := reader.Peek(1); err != nil {
		s.obs.Record(host, classify.Ambiguous, "handshake_ok_no_request")
		return
	}
	s.obs.Record(host, classify.Accepted, "request_observed")
	if s.cap != nil {
		s.captureServe(tlsConn, reader, host)
	}
}

// transparentConfig serves the wave certificate for the SNI and records the SNI
// into sni (set before the handshake returns, so a rejection is still
// attributable). The callback runs on the handshaking goroutine, so the write
// to sni is not shared concurrently.
func (s *Server) transparentConfig(sni *string) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			*sni = hello.ServerName
			cert, err := certFor(s.ca, s.wave, hello.ServerName, s.realFor)
			if err != nil {
				return nil, fmt.Errorf("%w: %w", errCertUnavailable, err)
			}
			return &cert, nil
		},
	}
}

// handleConn reads the CONNECT target, terminates TLS with the wave certificate,
// and records whether the client accepted (handshake completed) or rejected it.
// A passthrough host is relayed to its real server instead (see
// server_passthrough.go).
func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return
	}
	// Bound the CONNECT request parse; lift the cap afterward for the TLS bytes.
	limited := &io.LimitedReader{R: conn, N: maxConnectBytes}
	reader := bufio.NewReader(limited)
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}
	if req.Method != http.MethodConnect {
		return
	}
	host := hostnameOnly(req.Host)
	limited.N = math.MaxInt64
	if s.isPassthrough(host) {
		s.passthroughConnect(ctx, conn, reader, host)
		return
	}
	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	tlsConn := tls.Server(&bufferedConn{reader: reader, Conn: conn}, s.tlsConfigFor(host))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		outcome, reason := handshakeOutcome(err)
		s.obs.Record(host, outcome, reason)
		return
	}
	s.recordUse(tlsConn, host)
}

// tlsConfigFor builds a TLS config that serves the wave certificate for the
// connection, preferring the SNI and falling back to the CONNECT host.
func (s *Server) tlsConfigFor(connectHost string) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host := hello.ServerName
			if host == "" {
				host = connectHost
			}
			cert, err := certFor(s.ca, s.wave, host, s.realFor)
			if err != nil {
				return nil, fmt.Errorf("%w: %w", errCertUnavailable, err)
			}
			return &cert, nil
		},
	}
}

// hostnameOnly strips an optional :port from a CONNECT authority.
func hostnameOnly(authority string) string {
	if host, _, err := net.SplitHostPort(authority); err == nil {
		return host
	}
	return authority
}

// bufferedConn lets [tls.Server] consume bytes that bufio already buffered after
// the CONNECT request, while delegating writes and close to the raw connection.
type bufferedConn struct {
	reader *bufio.Reader
	net.Conn
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	n, err := c.reader.Read(p)
	if err != nil {
		return n, fmt.Errorf("buffered read: %w", err)
	}
	return n, nil
}
