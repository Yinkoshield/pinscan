package capture_test

import (
	"bytes"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/yinkoshield/pinscan/internal/capture"
)

func TestRedactHeadersHidesSensitiveValues(t *testing.T) {
	t.Parallel()

	in := http.Header{
		"Authorization":       {"Bearer secret-token"},
		"Cookie":              {"session=abc"},
		"Proxy-Authorization": {"Basic Zm9v"},
		"X-Api-Key":           {"key-123"},
		"X-Auth-Token":        {"tok-456"},
		"Content-Type":        {"application/json"},
		"User-Agent":          {"pinscan-test"},
	}
	got := capture.RedactHeaders(in)

	for _, redacted := range []string{"Authorization", "Cookie", "Proxy-Authorization", "X-Api-Key", "X-Auth-Token"} {
		if v := got.Get(redacted); v != capture.RedactedValue {
			t.Errorf("%s = %q, want %q", redacted, v, capture.RedactedValue)
		}
	}
	if got := got.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want it preserved", got)
	}
	if got := got.Get("User-Agent"); got != "pinscan-test" {
		t.Errorf("User-Agent = %q, want it preserved", got)
	}
}

func TestRedactHeadersCoversCommonCredentialHeaders(t *testing.T) {
	t.Parallel()

	// Credential-bearing headers beyond the original six must also be redacted,
	// whatever casing the client sends.
	in := http.Header{
		"authentication":       {"tok"},
		"www-authenticate":     {"Bearer realm=x"},
		"api-key":              {"ak-live-1"},
		"x-api-token":          {"apitok"},
		"x-access-token":       {"access-xyz"},
		"x-session-token":      {"sess-123"},
		"x-csrf-token":         {"csrf-abc"},
		"x-xsrf-token":         {"xsrf-abc"},
		"x-amz-security-token": {"aws-session-token"},
		"x-goog-api-key":       {"goog-key"},
		"x-functions-key":      {"fn-key"},
	}
	got := capture.RedactHeaders(in)

	// Every one of the headers added to the denylist must be redacted, in any case.
	for _, h := range []string{
		"Authentication", "Www-Authenticate", "Api-Key", "X-Api-Token",
		"X-Access-Token", "X-Session-Token", "X-Csrf-Token", "X-Xsrf-Token",
		"X-Amz-Security-Token", "X-Goog-Api-Key", "X-Functions-Key",
	} {
		if v := got.Get(h); v != capture.RedactedValue {
			t.Errorf("%s = %q, want %q", h, v, capture.RedactedValue)
		}
	}
}

func TestRedactHeadersIsCaseInsensitive(t *testing.T) {
	t.Parallel()

	// Non-canonical casing must still be redacted.
	in := http.Header{"authorization": {"Bearer x"}, "SET-COOKIE": {"a=b"}}
	got := capture.RedactHeaders(in)
	if v := got.Get("authorization"); v != capture.RedactedValue {
		t.Errorf("lowercase authorization = %q, want redacted", v)
	}
	if v := got.Get("Set-Cookie"); v != capture.RedactedValue {
		t.Errorf("uppercase set-cookie = %q, want redacted", v)
	}
}

func TestRedactHeadersDoesNotMutateInput(t *testing.T) {
	t.Parallel()

	in := http.Header{"Authorization": {"Bearer secret"}}
	_ = capture.RedactHeaders(in)
	if in.Get("Authorization") != "Bearer secret" {
		t.Errorf("input mutated: Authorization = %q", in.Get("Authorization"))
	}
}

func TestCapBodyUnderLimit(t *testing.T) {
	t.Parallel()

	body, trunc, err := capture.CapBody(strings.NewReader("hello"), 16)
	if err != nil {
		t.Fatalf("CapBody: %v", err)
	}
	if trunc {
		t.Error("truncated = true, want false for a short body")
	}
	if !bytes.Equal(body, []byte("hello")) {
		t.Errorf("body = %q, want %q", body, "hello")
	}
}

func TestCapBodyExactlyAtLimit(t *testing.T) {
	t.Parallel()

	body, trunc, err := capture.CapBody(strings.NewReader("abcd"), 4)
	if err != nil {
		t.Fatalf("CapBody: %v", err)
	}
	if trunc {
		t.Error("truncated = true, want false when body length equals the cap")
	}
	if !bytes.Equal(body, []byte("abcd")) {
		t.Errorf("body = %q, want %q", body, "abcd")
	}
}

func TestCapBodyOverLimitTruncates(t *testing.T) {
	t.Parallel()

	body, trunc, err := capture.CapBody(strings.NewReader("abcdefghij"), 4)
	if err != nil {
		t.Fatalf("CapBody: %v", err)
	}
	if !trunc {
		t.Error("truncated = false, want true when body exceeds the cap")
	}
	if !bytes.Equal(body, []byte("abcd")) {
		t.Errorf("body = %q, want first 4 bytes %q", body, "abcd")
	}
}

func TestRecorderStoresInOrderAndCopies(t *testing.T) {
	t.Parallel()

	rec := capture.NewRecorder()
	rec.Add(capture.Exchange{Host: "b.example.com", Method: "GET", URL: "/2"})
	rec.Add(capture.Exchange{Host: "a.example.com", Method: "POST", URL: "/1"})

	got := rec.Exchanges()
	if len(got) != 2 {
		t.Fatalf("got %d exchanges, want 2", len(got))
	}
	if got[0].Host != "b.example.com" || got[1].Host != "a.example.com" {
		t.Errorf("exchanges not in insertion order: %q, %q", got[0].Host, got[1].Host)
	}

	// Mutating the returned slice must not affect the recorder.
	got[0].Host = "mutated"
	if rec.Exchanges()[0].Host != "b.example.com" {
		t.Error("Exchanges() returned a view into internal state, not a copy")
	}
}

func TestRecorderHostsSortedUnique(t *testing.T) {
	t.Parallel()

	rec := capture.NewRecorder()
	rec.Add(capture.Exchange{Host: "b.example.com", URL: "/1"})
	rec.Add(capture.Exchange{Host: "a.example.com", URL: "/2"})
	rec.Add(capture.Exchange{Host: "b.example.com", URL: "/3"})

	got := rec.Hosts()
	want := []string{"a.example.com", "b.example.com"}
	if !slices.Equal(got, want) {
		t.Errorf("Hosts() = %v, want %v", got, want)
	}
}

func TestRecorderByHostGroups(t *testing.T) {
	t.Parallel()

	rec := capture.NewRecorder()
	rec.Add(capture.Exchange{Host: "a.example.com", URL: "/1"})
	rec.Add(capture.Exchange{Host: "a.example.com", URL: "/2"})
	rec.Add(capture.Exchange{Host: "b.example.com", URL: "/3"})

	byHost := rec.ByHost()
	if len(byHost["a.example.com"]) != 2 {
		t.Errorf("a.example.com has %d exchanges, want 2", len(byHost["a.example.com"]))
	}
	if len(byHost["b.example.com"]) != 1 {
		t.Errorf("b.example.com has %d exchanges, want 1", len(byHost["b.example.com"]))
	}
}
