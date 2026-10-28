// Package capture records the plaintext HTTP exchanges a capture pass forwards
// to the real upstream, so an operator can see exactly what an interceptable
// host exposes on the scanned surface.
//
// Capture is meaningful only for hosts with no effective pinning: an attacker
// holding a certificate the device trusts would observe the same bytes. It is
// intended for the startup, unauthenticated surface and must never be pointed
// at an authenticated flow. As defense in depth — not as a license to capture
// credentials — sensitive headers are redacted and bodies are size-capped
// regardless of what the caller does.
package capture

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
)

// RedactedValue replaces a sensitive header's value in a recorded exchange.
const RedactedValue = "[redacted]"

// DefaultBodyCap bounds how many bytes of each body an exchange retains.
const DefaultBodyCap = 16 << 10 // 16 KiB.

// sensitiveHeaders are never recorded in cleartext. Keys are canonical
// ([http.CanonicalHeaderKey]); lookups canonicalise first, so any casing the
// client sends is matched. This is defense in depth over the body size cap and
// the startup-surface scope — not a guarantee, so the set errs toward breadth.
var sensitiveHeaders = map[string]struct{}{
	"Authorization":        {},
	"Proxy-Authorization":  {},
	"Authentication":       {},
	"Www-Authenticate":     {},
	"Cookie":               {},
	"Set-Cookie":           {},
	"Api-Key":              {},
	"X-Api-Key":            {},
	"X-Api-Token":          {},
	"X-Auth-Token":         {},
	"X-Access-Token":       {},
	"X-Session-Token":      {},
	"X-Csrf-Token":         {},
	"X-Xsrf-Token":         {},
	"X-Amz-Security-Token": {},
	"X-Goog-Api-Key":       {},
	"X-Functions-Key":      {},
}

// Exchange is one request/response pair captured for a host.
type Exchange struct {
	Host          string      // SNI or CONNECT host the exchange was observed on.
	Method        string      // HTTP request method.
	URL           string      // Request path and query; the authority is Host.
	ReqHeaders    http.Header // Request headers, after redaction.
	ReqBody       []byte      // Request body, truncated to the cap.
	ReqTruncated  bool        // Reports whether the request body exceeded the cap.
	Status        int         // Response status code, or 0 if forwarding failed.
	RespHeaders   http.Header // Response headers, after redaction.
	RespBody      []byte      // Response body, truncated to the cap.
	RespTruncated bool        // Reports whether the response body exceeded the cap.
	Err           string      // Non-empty if forwarding to the real upstream failed.
}

// RedactHeaders returns a deep copy of h with sensitive values replaced by
// [RedactedValue]. Keys are canonicalised (matching how [http.ReadRequest]
// parses them), so the result is a well-formed [http.Header]. The input is
// never mutated.
func RedactHeaders(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for key, values := range h {
		canonical := http.CanonicalHeaderKey(key)
		if _, bad := sensitiveHeaders[canonical]; bad {
			out[canonical] = []string{RedactedValue}
			continue
		}
		out[canonical] = append([]string(nil), values...)
	}
	return out
}

// CapBody reads up to limit+1 bytes from r, returning the first limit bytes and
// whether more remained. A clean end of input is not an error.
func CapBody(r io.Reader, limit int) (body []byte, truncated bool, err error) {
	buf, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil {
		return nil, false, fmt.Errorf("capture: read body: %w", err)
	}
	if len(buf) > limit {
		return buf[:limit], true, nil
	}
	return buf, false, nil
}

// Recorder is a concurrency-safe, insertion-ordered store of exchanges.
type Recorder struct {
	mu        sync.Mutex
	exchanges []Exchange
}

// NewRecorder returns an empty Recorder.
func NewRecorder() *Recorder {
	return &Recorder{}
}

// Add appends one exchange.
func (r *Recorder) Add(x Exchange) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.exchanges = append(r.exchanges, x)
}

// Exchanges returns a copy of the recorded exchanges in insertion order.
func (r *Recorder) Exchanges() []Exchange {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Exchange(nil), r.exchanges...)
}

// Hosts returns the distinct hosts seen, in sorted order.
func (r *Recorder) Hosts() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	seen := make(map[string]struct{}, len(r.exchanges))
	for _, x := range r.exchanges {
		seen[x.Host] = struct{}{}
	}
	hosts := make([]string, 0, len(seen))
	for host := range seen {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	return hosts
}

// ByHost groups the recorded exchanges by host, preserving insertion order
// within each host.
func (r *Recorder) ByHost() map[string][]Exchange {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string][]Exchange)
	for _, x := range r.exchanges {
		out[x.Host] = append(out[x.Host], x)
	}
	return out
}
