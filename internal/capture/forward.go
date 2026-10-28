package capture

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"time"
)

// maxForwardBody hard-bounds how many body bytes are buffered in memory per
// message, independent of the record cap. It protects the proxy against an
// upstream (or app) that streams without end; the scanned startup surface is
// far below it.
const maxForwardBody = 10 << 20 // 10 MiB.

// forwardTimeout bounds one forwarded round trip to the real upstream.
const forwardTimeout = 15 * time.Second

// hopByHop headers are connection-scoped (RFC 7230 §6.1) and are not forwarded
// upstream or relayed back.
var hopByHop = map[string]struct{}{
	"Connection":        {},
	"Proxy-Connection":  {},
	"Keep-Alive":        {},
	"Te":                {},
	"Trailer":           {},
	"Transfer-Encoding": {},
	"Upgrade":           {},
}

// Response is the real upstream's reply, buffered so the caller can both record
// it and relay it back to the client unchanged.
type Response struct {
	Status int
	Header http.Header // The real upstream headers, unredacted, for a faithful relay.
	Body   []byte      // The full body, for relay.
}

// Forwarder sends intercepted requests to the real upstream over TLS and
// buffers the reply. It records a redacted, size-capped [Exchange]; the
// returned [Response] carries the faithful bytes for relay.
type Forwarder struct {
	client  *http.Client
	bodyCap int
}

// NewForwarder returns a Forwarder that validates upstream certificates with
// tlsCfg (pass a config with system roots in production) and caps each recorded
// body at bodyCap bytes. A nil tlsCfg uses Go's defaults (system roots).
func NewForwarder(tlsCfg *tls.Config, bodyCap int) *Forwarder {
	transport := &http.Transport{
		TLSClientConfig:   tlsCfg,
		ForceAttemptHTTP2: false,
		DisableKeepAlives: true,
		// Never let the transport negotiate or transparently decode gzip: the
		// relay must carry the upstream's exact bytes, and the record decodes a
		// copy itself (see DecodeBody) so decoding is uniform regardless of the
		// Accept-Encoding the app sent.
		DisableCompression: true,
	}
	return &Forwarder{
		client:  &http.Client{Transport: transport, Timeout: forwardTimeout},
		bodyCap: bodyCap,
	}
}

// Forward sends req to baseURL (scheme://host:port of the real upstream),
// labeling the record with recordHost. It always returns an [Exchange]: on a
// forward failure the Exchange has Err set and the returned [Response] is nil.
func (f *Forwarder) Forward(ctx context.Context, recordHost, baseURL string, req *http.Request) (Exchange, *Response) {
	ex := Exchange{Host: recordHost, Method: req.Method, URL: req.URL.RequestURI()}

	reqFull, err := drain(req.Body)
	if err != nil {
		ex.Err = fmt.Sprintf("read request body: %v", err)
		return ex, nil
	}
	ex.ReqHeaders = RedactHeaders(req.Header)
	ex.ReqBody, ex.ReqTruncated = capBytes(DecodeBody(reqFull, req.Header.Get("Content-Encoding")), f.bodyCap)

	out, err := f.buildOutbound(ctx, recordHost, baseURL, req, reqFull)
	if err != nil {
		ex.Err = fmt.Sprintf("build request: %v", err)
		return ex, nil
	}

	resp, err := f.client.Do(out)
	if err != nil {
		ex.Err = fmt.Sprintf("forward: %v", err)
		return ex, nil
	}
	defer func() { _ = resp.Body.Close() }()

	respFull, err := drain(resp.Body)
	if err != nil {
		ex.Err = fmt.Sprintf("read response body: %v", err)
		return ex, nil
	}
	ex.Status = resp.StatusCode
	ex.RespHeaders = RedactHeaders(resp.Header)
	ex.RespBody, ex.RespTruncated = capBytes(DecodeBody(respFull, resp.Header.Get("Content-Encoding")), f.bodyCap)

	// The relay carries the original (possibly compressed) bytes unchanged, so
	// the app decodes them exactly as it would without interception.
	return ex, &Response{Status: resp.StatusCode, Header: resp.Header.Clone(), Body: respFull}
}

// buildOutbound clones req as an outbound client request to baseURL, carrying
// the full (unredacted) body and headers so the upstream behaves exactly as if
// the app reached it directly. The Host header is set to the real hostname.
func (f *Forwarder) buildOutbound(ctx context.Context, recordHost, baseURL string, req *http.Request, body []byte) (*http.Request, error) {
	out, err := http.NewRequestWithContext(ctx, req.Method, baseURL+req.URL.RequestURI(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("capture: %w", err)
	}
	out.Header = forwardHeaders(req.Header)
	out.Host = recordHost
	return out, nil
}

// forwardHeaders copies h minus hop-by-hop headers. Credential headers are kept
// (the app chose to send them to the real upstream); only the *record* redacts.
func forwardHeaders(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for key, values := range h {
		if _, drop := hopByHop[http.CanonicalHeaderKey(key)]; drop {
			continue
		}
		out[key] = append([]string(nil), values...)
	}
	return out
}

// drain reads r fully, bounded by maxForwardBody. A nil reader yields no bytes.
func drain(r io.Reader) ([]byte, error) {
	if r == nil {
		return nil, nil
	}
	buf, err := io.ReadAll(io.LimitReader(r, maxForwardBody))
	if err != nil {
		return nil, fmt.Errorf("capture: %w", err)
	}
	return buf, nil
}

// capBytes returns the first limit bytes of b and whether it was longer. The
// capped window is copied out, not sub-sliced, so the full (up to
// maxForwardBody) backing array is freed rather than pinned for the exchange's
// lifetime — honoring the documented per-body memory bound.
func capBytes(b []byte, limit int) (capped []byte, truncated bool) {
	if len(b) > limit {
		return append([]byte(nil), b[:limit]...), true
	}
	return b, false
}
