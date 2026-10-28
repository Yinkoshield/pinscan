package report

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/yinkoshield/pinscan/internal/capture"
)

// TranscriptEntry is one captured exchange in a flat dump: the request and the
// response, with headers redacted and bodies rendered as text (a non-UTF-8 body
// becomes a byte-count note, as elsewhere).
type TranscriptEntry struct {
	Host              string              `json:"host"`
	Method            string              `json:"method"`
	URL               string              `json:"url"`
	Status            int                 `json:"status"`
	RequestHeaders    map[string][]string `json:"request_headers,omitempty"`
	RequestBody       string              `json:"request_body,omitempty"`
	RequestTruncated  bool                `json:"request_truncated,omitempty"`
	ResponseHeaders   map[string][]string `json:"response_headers,omitempty"`
	ResponseBody      string              `json:"response_body,omitempty"`
	ResponseTruncated bool                `json:"response_truncated,omitempty"`
	Error             string              `json:"error,omitempty"`
}

// Transcript flattens a recorder's exchanges into dumpable entries, in capture
// order.
func Transcript(rec *capture.Recorder) []TranscriptEntry {
	if rec == nil {
		return nil
	}
	exs := rec.Exchanges()
	out := make([]TranscriptEntry, 0, len(exs))
	for _, ex := range exs {
		out = append(out, TranscriptEntry{
			Host:              ex.Host,
			Method:            ex.Method,
			URL:               ex.URL,
			Status:            ex.Status,
			RequestHeaders:    ex.ReqHeaders,
			RequestBody:       bodyText(ex.ReqBody),
			RequestTruncated:  ex.ReqTruncated,
			ResponseHeaders:   ex.RespHeaders,
			ResponseBody:      bodyText(ex.RespBody),
			ResponseTruncated: ex.RespTruncated,
			Error:             ex.Err,
		})
	}
	return out
}

// TranscriptFormat maps a dump path's extension to a writer name.
func TranscriptFormat(ext string) (string, bool) {
	switch ext {
	case ".json":
		return "json", true
	case ".har":
		return "har", true
	default:
		return "", false
	}
}

// WriteTranscript dumps every captured exchange to w in the given format
// ("json" or "har").
func WriteTranscript(w io.Writer, format string, meta Meta, rec *capture.Recorder) error {
	switch format {
	case "json":
		return writeTranscriptJSON(w, meta, rec)
	case "har":
		return writeHAR(w, meta, rec)
	default:
		return fmt.Errorf("report: unknown transcript format %q", format)
	}
}

// transcriptDoc is the JSON transcript envelope.
type transcriptDoc struct {
	Tool      Tool              `json:"tool"`
	Package   string            `json:"package"`
	Exchanges []TranscriptEntry `json:"exchanges"`
}

func writeTranscriptJSON(w io.Writer, meta Meta, rec *capture.Recorder) error {
	doc := transcriptDoc{
		Tool:      Tool{Name: toolName, Version: meta.ToolVersion},
		Package:   meta.Package,
		Exchanges: Transcript(rec),
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("report: encode transcript: %w", err)
	}
	return nil
}

// writeHAR writes an HTTP Archive 1.2 log, openable in browser devtools and
// HTTP analysis tools.
func writeHAR(w io.Writer, meta Meta, rec *capture.Recorder) error {
	started := meta.StartedAt.UTC().Format(time.RFC3339)
	txs := Transcript(rec)
	entries := make([]harEntry, 0, len(txs))
	for _, e := range txs {
		entries = append(entries, harEntry{
			StartedDateTime: started,
			Time:            0,
			Request: harRequest{
				Method:      e.Method,
				URL:         "https://" + e.Host + e.URL,
				HTTPVersion: "HTTP/1.1",
				Headers:     harHeaders(e.RequestHeaders),
				QueryString: []harNV{},
				Cookies:     []harNV{},
				HeadersSize: -1,
				BodySize:    len(e.RequestBody),
				PostData:    harPostData(e.RequestHeaders, e.RequestBody),
			},
			Response: harResponse{
				Status:      e.Status,
				StatusText:  "",
				HTTPVersion: "HTTP/1.1",
				Headers:     harHeaders(e.ResponseHeaders),
				Cookies:     []harNV{},
				Content: harContent{
					Size:     len(e.ResponseBody),
					MimeType: headerValue(e.ResponseHeaders, "Content-Type"),
					Text:     e.ResponseBody,
				},
				RedirectURL: "",
				HeadersSize: -1,
				BodySize:    len(e.ResponseBody),
			},
			Cache:   map[string]any{},
			Timings: harTimings{Send: 0, Wait: 0, Receive: 0},
		})
	}
	doc := harDoc{Log: harLog{
		Version: "1.2",
		Creator: Tool{Name: toolName, Version: meta.ToolVersion},
		Entries: entries,
	}}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("report: encode har: %w", err)
	}
	return nil
}

func harHeaders(h map[string][]string) []harNV {
	out := []harNV{}
	for name, values := range h {
		for _, v := range values {
			out = append(out, harNV{Name: name, Value: v})
		}
	}
	return out
}

func headerValue(h map[string][]string, name string) string {
	if vs := h[name]; len(vs) > 0 {
		return vs[0]
	}
	return ""
}

func harPostData(h map[string][]string, body string) *harPostDataT {
	if body == "" {
		return nil
	}
	return &harPostDataT{MimeType: headerValue(h, "Content-Type"), Text: body}
}

type harDoc struct {
	Log harLog `json:"log"`
}

type harLog struct {
	Version string     `json:"version"`
	Creator Tool       `json:"creator"`
	Entries []harEntry `json:"entries"`
}

type harEntry struct {
	StartedDateTime string         `json:"startedDateTime"`
	Time            int            `json:"time"`
	Request         harRequest     `json:"request"`
	Response        harResponse    `json:"response"`
	Cache           map[string]any `json:"cache"`
	Timings         harTimings     `json:"timings"`
}

type harRequest struct {
	Method      string        `json:"method"`
	URL         string        `json:"url"`
	HTTPVersion string        `json:"httpVersion"`
	Headers     []harNV       `json:"headers"`
	QueryString []harNV       `json:"queryString"`
	Cookies     []harNV       `json:"cookies"`
	HeadersSize int           `json:"headersSize"`
	BodySize    int           `json:"bodySize"`
	PostData    *harPostDataT `json:"postData,omitempty"`
}

type harResponse struct {
	Status      int        `json:"status"`
	StatusText  string     `json:"statusText"`
	HTTPVersion string     `json:"httpVersion"`
	Headers     []harNV    `json:"headers"`
	Cookies     []harNV    `json:"cookies"`
	Content     harContent `json:"content"`
	RedirectURL string     `json:"redirectURL"`
	HeadersSize int        `json:"headersSize"`
	BodySize    int        `json:"bodySize"`
}

type harContent struct {
	Size     int    `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text,omitempty"`
}

type harPostDataT struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

type harNV struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type harTimings struct {
	Send    int `json:"send"`
	Wait    int `json:"wait"`
	Receive int `json:"receive"`
}
