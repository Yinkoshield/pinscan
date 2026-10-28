package proxy

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/yinkoshield/pinscan/internal/capture"
)

// captureIdleTimeout bounds how long a captured tunnel waits for each request
// before giving up, so an idle app does not hold the connection open forever.
const captureIdleTimeout = 20 * time.Second

// relayWriteTimeout bounds writing one relayed response back to the client. It
// is refreshed per exchange so a captured tunnel that outlives the one-shot
// handshake deadline can still deliver the real response.
const relayWriteTimeout = 15 * time.Second

// captureServe serves conn as plaintext HTTP after a successful handshake:
// every request is forwarded to the real upstream, recorded (redacted and
// capped), and the real response relayed back so the app proceeds unchanged.
// The reader is read from (it already holds any bytes peeked during the request
// probe); conn is used only for deadlines. It returns when the client closes
// the tunnel, a side signals close, or an error occurs.
func (s *Server) captureServe(conn net.Conn, reader *bufio.Reader, host string) {
	for {
		if err := conn.SetReadDeadline(time.Now().Add(captureIdleTimeout)); err != nil {
			return
		}
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}

		ex, resp := s.cap.fwd.Forward(context.Background(), host, s.cap.baseURL(host), req)
		s.cap.rec.Add(ex)
		s.logExchange(ex)
		if resp == nil {
			return // Forwarding failed; nothing faithful to relay, so close.
		}

		// The accept-time deadline (handshakeTimeout) governs writes too and is
		// never otherwise refreshed; set a fresh write deadline per exchange so a
		// slow upstream or a reused keep-alive tunnel can still relay its response.
		if err := conn.SetWriteDeadline(time.Now().Add(relayWriteTimeout)); err != nil {
			return
		}
		closeAfter := req.Close || strings.EqualFold(resp.Header.Get("Connection"), "close")
		if err := writeRelay(conn, resp, closeAfter); err != nil {
			return
		}
		if closeAfter {
			return
		}
	}
}

// logExchangePreviewBytes bounds the body preview logged per exchange at debug.
const logExchangePreviewBytes = 512

// logExchange logs one intercepted request/response: an info line with the
// request, status and size, and the request/response body previews at debug.
func (s *Server) logExchange(ex capture.Exchange) {
	if ex.Err != "" {
		s.log().Info("intercepted", "host", ex.Host, "method", ex.Method, "url", ex.URL, "error", ex.Err)
		return
	}
	s.log().Info("intercepted",
		"host", ex.Host, "method", ex.Method, "url", ex.URL, "status", ex.Status,
		"content_type", ex.RespHeaders.Get("Content-Type"), "resp_bytes", len(ex.RespBody))
	s.log().Debug("intercepted body",
		"host", ex.Host, "url", ex.URL,
		"request", logPreview(ex.ReqBody), "response", logPreview(ex.RespBody))
}

// logPreview renders up to a bounded number of body bytes on one line, with
// control characters flattened, for a readable log entry.
func logPreview(body []byte) string {
	s := string(body)
	truncated := false
	if len(s) > logExchangePreviewBytes {
		s = s[:logExchangePreviewBytes]
		truncated = true
	}
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		return r
	}, s)
	if truncated {
		s += " …"
	}
	return s
}

// writeRelay writes the buffered upstream response back to the client in
// HTTP/1.1 wire format, setting Content-Length from the buffered body.
func writeRelay(w io.Writer, resp *capture.Response, closeConn bool) error {
	out := &http.Response{
		StatusCode:    resp.Status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        relayHeaders(resp.Header),
		Body:          io.NopCloser(bytes.NewReader(resp.Body)),
		ContentLength: int64(len(resp.Body)),
		Close:         closeConn,
	}
	if err := out.Write(w); err != nil {
		return fmt.Errorf("proxy: relay response: %w", err)
	}
	return nil
}

// relayHeaders copies h minus the framing headers that [http.Response.Write]
// derives itself (Content-Length, Transfer-Encoding) and the connection token.
func relayHeaders(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for key, values := range h {
		switch http.CanonicalHeaderKey(key) {
		case "Content-Length", "Transfer-Encoding", "Connection":
			continue
		default:
			out[key] = append([]string(nil), values...)
		}
	}
	return out
}
