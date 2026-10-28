package report_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/yinkoshield/pinscan/internal/capture"
	"github.com/yinkoshield/pinscan/internal/report"
)

func transcriptRec(t *testing.T) *capture.Recorder {
	t.Helper()
	rec := capture.NewRecorder()
	rec.Add(capture.Exchange{
		Host: "secure.example.com", Method: "POST", URL: "/api/update",
		Status: 200, RespHeaders: http.Header{"Content-Type": {"application/json"}},
		ReqBody: []byte(`{"q":1}`), RespBody: []byte(`{"ok":true}`),
	})
	rec.Add(capture.Exchange{
		Host: "secure.example.com", Method: "POST", URL: "/log", Err: "forward: timeout",
	})
	return rec
}

func TestTranscriptFormat(t *testing.T) {
	t.Parallel()
	for ext, want := range map[string]string{".json": "json", ".har": "har"} {
		if got, ok := report.TranscriptFormat(ext); !ok || got != want {
			t.Errorf("TranscriptFormat(%q) = (%q,%v), want %q", ext, got, ok, want)
		}
	}
	if _, ok := report.TranscriptFormat(".txt"); ok {
		t.Error("TranscriptFormat(.txt) ok=true, want false")
	}
}

func TestWriteTranscriptJSON(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	meta := report.Meta{ToolVersion: "1.2.3", Package: samplePackage}
	if err := report.WriteTranscript(&buf, "json", meta, transcriptRec(t)); err != nil {
		t.Fatalf("WriteTranscript json: %v", err)
	}
	var doc struct {
		Package   string `json:"package"`
		Exchanges []struct {
			Host         string `json:"host"`
			Method       string `json:"method"`
			URL          string `json:"url"`
			RequestBody  string `json:"request_body"`
			ResponseBody string `json:"response_body"`
			Error        string `json:"error"`
		} `json:"exchanges"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, buf.String())
	}
	if doc.Package != samplePackage || len(doc.Exchanges) != 2 {
		t.Fatalf("doc = %+v", doc)
	}
	if doc.Exchanges[0].ResponseBody != `{"ok":true}` || doc.Exchanges[0].RequestBody != `{"q":1}` {
		t.Errorf("exchange 0 bodies = %+v", doc.Exchanges[0])
	}
	if doc.Exchanges[1].Error == "" {
		t.Error("forward error should be dumped")
	}
}

func TestWriteTranscriptHAR(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	meta := report.Meta{ToolVersion: "1.2.3", Package: samplePackage, StartedAt: time.Unix(1000, 0)}
	if err := report.WriteTranscript(&buf, "har", meta, transcriptRec(t)); err != nil {
		t.Fatalf("WriteTranscript har: %v", err)
	}
	var har struct {
		Log struct {
			Version string `json:"version"`
			Entries []struct {
				Request  struct{ Method, URL string } `json:"request"`
				Response struct {
					Status  int                   `json:"status"`
					Content struct{ Text string } `json:"content"`
				} `json:"response"`
			} `json:"entries"`
		} `json:"log"`
	}
	if err := json.Unmarshal(buf.Bytes(), &har); err != nil {
		t.Fatalf("HAR not valid JSON: %v\n%s", err, buf.String())
	}
	if har.Log.Version != "1.2" || len(har.Log.Entries) != 2 {
		t.Fatalf("har log = %+v", har.Log)
	}
	e0 := har.Log.Entries[0]
	if e0.Request.URL != "https://secure.example.com/api/update" {
		t.Errorf("har request url = %q", e0.Request.URL)
	}
	if e0.Response.Status != 200 || !strings.Contains(e0.Response.Content.Text, `"ok":true`) {
		t.Errorf("har response = %+v", e0.Response)
	}
}

func TestTranscriptNilRecorder(t *testing.T) {
	t.Parallel()
	if got := report.Transcript(nil); got != nil {
		t.Errorf("Transcript(nil) = %v, want nil", got)
	}
}
