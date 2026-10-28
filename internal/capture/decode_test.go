package capture_test

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/yinkoshield/pinscan/internal/capture"
)

func brotliBytes(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := brotli.NewWriter(&buf)
	if _, err := w.Write([]byte(sampleBody)); err != nil {
		t.Fatalf("brotli write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("brotli close: %v", err)
	}
	return buf.Bytes()
}

// sampleBody is the plaintext the compression helpers round-trip; keeping it
// shared keeps the helpers parameter-free (and the linter happy).
const sampleBody = `{"toggles":["pkg.a","pkg.b"]}`

func gzipBytes(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write([]byte(sampleBody)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func zlibBytes(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write([]byte(sampleBody)); err != nil {
		t.Fatalf("zlib write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}
	return buf.Bytes()
}

func rawDeflate(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		t.Fatalf("flate writer: %v", err)
	}
	if _, err := w.Write([]byte(sampleBody)); err != nil {
		t.Fatalf("flate write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("flate close: %v", err)
	}
	return buf.Bytes()
}

func TestDecodeBody(t *testing.T) {
	t.Parallel()

	const plain = sampleBody
	tests := []struct {
		name     string
		raw      []byte
		encoding string
		want     string
	}{
		{"identity empty", []byte(plain), "", plain},
		{"identity named", []byte(plain), "identity", plain},
		{"gzip", gzipBytes(t), "gzip", plain},
		{"gzip x-gzip", gzipBytes(t), "x-gzip", plain},
		{"gzip case-insensitive", gzipBytes(t), "GZIP", plain},
		{"deflate zlib", zlibBytes(t), "deflate", plain},
		{"deflate raw", rawDeflate(t), "deflate", plain},
		{"brotli", brotliBytes(t), "br", plain},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := capture.DecodeBody(tt.raw, tt.encoding)
			if string(got) != tt.want {
				t.Errorf("DecodeBody(%s) = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}

func TestDecodeBodyUnsupportedReturnsRaw(t *testing.T) {
	t.Parallel()

	raw := []byte{0x1f, 0x2e, 0x00, 0xff} // Bytes in some unknown encoding.
	if got := capture.DecodeBody(raw, "zstd"); !bytes.Equal(got, raw) {
		t.Errorf("DecodeBody(zstd) = %v, want the raw bytes unchanged for an unknown encoding", got)
	}
}

func TestDecodeBodyMalformedReturnsRaw(t *testing.T) {
	t.Parallel()

	raw := []byte("not actually gzip")
	if got := capture.DecodeBody(raw, "gzip"); !bytes.Equal(got, raw) {
		t.Errorf("DecodeBody of malformed gzip = %q, want the raw bytes unchanged", got)
	}
}
