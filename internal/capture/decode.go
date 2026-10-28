package capture

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
)

// DecodeBody decompresses raw for the human-readable record, according to the
// Content-Encoding value enc. It is used only for what is stored and displayed;
// the proxy always relays the original bytes to the app unchanged.
//
// It handles gzip, deflate and brotli — the encodings a browser or modern SDK
// negotiates. It never fails: an empty, unknown, or malformed stream returns raw
// unchanged, so a capture is always faithful even when it cannot be decoded.
// Decompression output is bounded to guard against decompression bombs.
func DecodeBody(raw []byte, enc string) []byte {
	switch strings.ToLower(strings.TrimSpace(enc)) {
	case "", "identity":
		return raw
	case "gzip", "x-gzip":
		return decodeWith(raw, func(r io.Reader) (io.ReadCloser, error) {
			return gzip.NewReader(r)
		})
	case "deflate":
		return decodeDeflate(raw)
	case "br":
		return decodeWith(raw, func(r io.Reader) (io.ReadCloser, error) {
			return io.NopCloser(brotli.NewReader(r)), nil
		})
	default:
		return raw
	}
}

// decodeDeflate handles both HTTP "deflate" dialects: zlib-wrapped (the common,
// standards-correct form) and, failing that, a raw DEFLATE stream.
func decodeDeflate(raw []byte) []byte {
	if out := decodeWith(raw, zlib.NewReader); !bytes.Equal(out, raw) {
		return out
	}
	return decodeWith(raw, func(r io.Reader) (io.ReadCloser, error) {
		return flate.NewReader(r), nil
	})
}

// decodeWith runs raw through the reader newReader builds, returning the
// decompressed bytes or, on any error, raw unchanged.
func decodeWith(raw []byte, newReader func(io.Reader) (io.ReadCloser, error)) []byte {
	r, err := newReader(bytes.NewReader(raw))
	if err != nil {
		return raw
	}
	defer func() { _ = r.Close() }()
	out, err := io.ReadAll(io.LimitReader(r, maxForwardBody))
	if err != nil {
		return raw
	}
	return out
}
