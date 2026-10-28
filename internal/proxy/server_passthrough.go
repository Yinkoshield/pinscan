package proxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"time"

	"github.com/yinkoshield/pinscan/internal/classify"
)

// Reasons recorded for a passthrough host. Both are [classify.Ambiguous]: a
// relayed host was never presented a forged certificate, so nothing about its
// pinning was measured and it must read as inconclusive, never as hardened.
const (
	// ReasonPassthrough marks a host relayed byte for byte to its real server.
	ReasonPassthrough = "passthrough"
	// ReasonPassthroughDialFailed marks a passthrough host whose real server
	// could not be reached, so the app saw a closed connection instead.
	ReasonPassthroughDialFailed = "passthrough_dial_failed"
)

// passthroughIdleTimeout bounds how long a relayed connection may sit idle in
// either direction before the relay closes it, so an app holding a keep-alive
// tunnel cannot keep the wave from finishing. It matches captureIdleTimeout.
const passthroughIdleTimeout = 20 * time.Second

// relayBufferBytes is the copy buffer per relay direction.
const relayBufferBytes = 32 << 10

// PassthroughDialer connects to the real server for host. The default dials
// host:443 over TCP; tests and the selftest harness substitute an in-process
// server.
type PassthroughDialer func(ctx context.Context, host string) (net.Conn, error)

// WithPassthrough names the hosts the proxy relays to their real server
// untouched instead of presenting a forged certificate: no TLS termination, no
// forged leaf, nothing measured. Each such host is recorded
// [classify.Ambiguous] with [ReasonPassthrough] so it reads as inconclusive. It
// exists so an app whose first connection is key-pinned can get past it and
// exercise the hosts the scan is actually after.
func WithPassthrough(match func(host string) bool) ServerOption {
	return func(s *Server) { s.passthrough = match }
}

// WithPassthroughDialer replaces how a passthrough host's real server is
// reached. It is for tests and the selftest harness, which stand in for the real
// server; a scan uses the default, host:443.
func WithPassthroughDialer(dial PassthroughDialer) ServerOption {
	return func(s *Server) { s.passthroughDial = dial }
}

// dialPassthrough is the default [PassthroughDialer]: TCP to host:443, bounded
// like a real-certificate fetch.
func dialPassthrough(ctx context.Context, host string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, realCertDialTimeout)
	defer cancel()
	return (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(host, "443"))
}

// isPassthrough reports whether host is on the passthrough list.
func (s *Server) isPassthrough(host string) bool {
	return s.passthrough != nil && host != "" && s.passthrough(host)
}

// dialUpstream connects to host's real server, recording the outcome: a relay
// that can start is [ReasonPassthrough], one that cannot is
// [ReasonPassthroughDialFailed]. Both are ambiguous.
func (s *Server) dialUpstream(ctx context.Context, host string) (net.Conn, bool) {
	dial := s.passthroughDial
	if dial == nil {
		dial = dialPassthrough
	}
	upstream, err := dial(ctx, host)
	if err != nil {
		s.log().Warn("passthrough dial failed", "host", host, "err", err)
		s.obs.Record(host, classify.Ambiguous, ReasonPassthroughDialFailed)
		return nil, false
	}
	s.obs.Record(host, classify.Ambiguous, ReasonPassthrough)
	return upstream, true
}

// relay copies bytes both ways between the client and its real server until
// either side closes or goes idle, then closes both. Bytes the client sent
// before the decision (the CONNECT read-ahead, or the peeked ClientHello) are
// still in clientIn, so the client is read through it and written to directly.
func relay(client net.Conn, clientIn *bufio.Reader, upstream net.Conn) {
	// The accept-time deadline covered the CONNECT or the ClientHello; from
	// here the per-read idle deadline governs.
	_ = client.SetDeadline(time.Time{})
	done := make(chan struct{}, 2)
	go func() {
		copyIdle(upstream, clientIn, client)
		done <- struct{}{}
	}()
	go func() {
		copyIdle(client, upstream, upstream)
		done <- struct{}{}
	}()
	<-done
	_ = client.Close()
	_ = upstream.Close()
	<-done
}

// copyIdle copies src to dst until src ends or either side stalls for the idle
// timeout. The read deadline is set on srcConn, the connection src reads from,
// so it lands on the socket even when src is a buffered reader over it.
func copyIdle(dst net.Conn, src io.Reader, srcConn net.Conn) {
	buf := make([]byte, relayBufferBytes)
	for {
		if err := srcConn.SetReadDeadline(time.Now().Add(passthroughIdleTimeout)); err != nil {
			return
		}
		n, err := src.Read(buf)
		if n > 0 {
			if werr := dst.SetWriteDeadline(time.Now().Add(passthroughIdleTimeout)); werr != nil {
				return
			}
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// passthroughConnect handles a CONNECT to a passthrough host: it dials the real
// server, answers the CONNECT accordingly, and relays the tunnel.
func (s *Server) passthroughConnect(ctx context.Context, conn net.Conn, reader *bufio.Reader, host string) {
	upstream, ok := s.dialUpstream(ctx, host)
	if !ok {
		_, _ = conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer func() { _ = upstream.Close() }()
	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	relay(conn, reader, upstream)
}

// transparentSNI reads the server name from the ClientHello buffered on reader
// without consuming it. It returns "" when the bytes are not a parseable
// ClientHello or carry no SNI, in which case the caller falls back to
// [tls.Server], which attributes the connection (or not) as before.
func transparentSNI(reader *bufio.Reader) string {
	record, err := peekClientHello(reader)
	if err != nil {
		return ""
	}
	sni, err := clientHelloSNI(record)
	if err != nil {
		return ""
	}
	return sni
}

// passthroughTransparent relays a redirected connection whose SNI names a
// passthrough host. The ClientHello is still buffered on reader, so it reaches
// the real server first, byte for byte.
func (s *Server) passthroughTransparent(ctx context.Context, conn net.Conn, reader *bufio.Reader, host string) {
	upstream, ok := s.dialUpstream(ctx, host)
	if !ok {
		return // Closing the connection is all a raw TLS client can be told.
	}
	defer func() { _ = upstream.Close() }()
	relay(conn, reader, upstream)
}
