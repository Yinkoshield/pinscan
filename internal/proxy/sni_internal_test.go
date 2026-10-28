package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"testing"
)

// helloOption mutates a hand-built ClientHello body before it is framed.
type helloOption func(h *helloBuilder)

// helloBuilder assembles a minimal ClientHello so each table case can state
// exactly which field it bends.
type helloBuilder struct {
	sessionID   []byte
	cipherSuite []byte
	extensions  []byte
	noExtBlock  bool
}

// sniExtension encodes a server_name extension with one entry of the given
// name type.
func sniExtension(nameType byte, name string) []byte {
	entry := append([]byte{nameType}, u16(len(name))...)
	entry = append(entry, name...)
	list := append(u16(len(entry)), entry...)
	return extension(extensionServerName, list)
}

// extension frames one extension (type, length, data).
func extension(typ uint16, data []byte) []byte {
	out := binary.BigEndian.AppendUint16(nil, typ)
	out = append(out, u16(len(data))...)
	return append(out, data...)
}

func u16(n int) []byte { return binary.BigEndian.AppendUint16(nil, uint16(n&0xffff)) }

// u8 and u24 encode small test lengths in one and three bytes.
func u8(n int) byte    { return byte(n & 0xff) }
func u24(n int) []byte { return []byte{u8(n >> 16), u8(n >> 8), u8(n)} }

// clientHelloRecord frames a ClientHello body as one TLS handshake record.
func clientHelloRecord(opts ...helloOption) []byte {
	h := &helloBuilder{cipherSuite: []byte{0x13, 0x01}}
	for _, opt := range opts {
		opt(h)
	}
	body := []byte{0x03, 0x03}                             // legacy_version TLS 1.2.
	body = append(body, bytes.Repeat([]byte{0xAB}, 32)...) // random.
	body = append(body, u8(len(h.sessionID)))
	body = append(body, h.sessionID...)
	body = append(body, u16(len(h.cipherSuite))...)
	body = append(body, h.cipherSuite...)
	body = append(body, 0x01, 0x00) // one compression method: null.
	if !h.noExtBlock {
		body = append(body, u16(len(h.extensions))...)
		body = append(body, h.extensions...)
	}
	msg := append([]byte{handshakeClientHello}, u24(len(body))...)
	msg = append(msg, body...)
	record := []byte{recordTypeHandshake, 0x03, 0x01}
	record = append(record, u16(len(msg))...)
	return append(record, msg...)
}

func withSNI(name string) helloOption {
	return func(h *helloBuilder) { h.extensions = append(h.extensions, sniExtension(sniNameTypeHostName, name)...) }
}

func withExtension(typ uint16, data []byte) helloOption {
	return func(h *helloBuilder) { h.extensions = append(h.extensions, extension(typ, data)...) }
}

func TestClientHelloSNI(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		record  []byte
		want    string
		wantErr bool
	}{
		{"plain SNI", clientHelloRecord(withSNI("api.example.com")), "api.example.com", false},
		{"SNI after other extensions", clientHelloRecord(
			withExtension(0x000a, []byte{0x00, 0x02, 0x00, 0x1d}), // supported_groups.
			withSNI("login.example.net"),
			withExtension(0x002b, []byte{0x02, 0x03, 0x04}), // supported_versions.
		), "login.example.net", false},
		{"session id and SNI", clientHelloRecord(
			func(h *helloBuilder) { h.sessionID = bytes.Repeat([]byte{0x11}, 32) },
			withSNI("a.b.example"),
		), "a.b.example", false},
		{"no SNI among extensions", clientHelloRecord(withExtension(0x000a, []byte{0x00, 0x02, 0x00, 0x1d})), "", false},
		{"no extensions block", clientHelloRecord(func(h *helloBuilder) { h.noExtBlock = true }), "", false},
		{"empty extensions block", clientHelloRecord(), "", false},
		{"SNI with a non-hostname entry only", clientHelloRecord(
			func(h *helloBuilder) { h.extensions = sniExtension(0x01, "x") },
		), "", false},
		{"not a handshake record", []byte{0x17, 0x03, 0x03, 0x00, 0x01, 0x00}, "", true},
		{"too short for a header", []byte{0x16, 0x03}, "", true},
		{"record length mismatch", append(clientHelloRecord(withSNI("x.example"))[:3], 0x00, 0x01, 0x01), "", true},
		{"not a ClientHello message", func() []byte {
			r := clientHelloRecord(withSNI("x.example"))
			r[tlsRecordHeaderLen] = 0x02 // ServerHello.
			return r
		}(), "", true},
		{"hello spans records", func() []byte {
			r := clientHelloRecord(withSNI("x.example"))
			r[tlsRecordHeaderLen+3]++ // Declares one more byte than the record holds.
			return r
		}(), "", true},
		{"truncated in cipher suites", func() []byte {
			r := clientHelloRecord(withSNI("x.example"))
			cut := r[:tlsRecordHeaderLen+4+2+32+1+1]
			copy(cut[3:5], u16(len(cut)-tlsRecordHeaderLen))
			n := len(cut) - tlsRecordHeaderLen - 4
			copy(cut[tlsRecordHeaderLen+1:tlsRecordHeaderLen+4], u24(n))
			return cut
		}(), "", true},
		{"SNI entry longer than its extension", clientHelloRecord(
			withExtension(extensionServerName, []byte{0x00, 0x20, 0x00, 0x00, 0x30}),
		), "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := clientHelloSNI(tt.record)
			if (err != nil) != tt.wantErr {
				t.Fatalf("clientHelloSNI() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("clientHelloSNI() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestClientHelloSNIFromCryptoTLS reads the ClientHello crypto/tls actually
// sends (with its real extension set, key shares included) and checks the
// parser finds the SNI in it.
func TestClientHelloSNIFromCryptoTLS(t *testing.T) {
	t.Parallel()

	const want = "real.example.com"
	clientSide, serverSide := net.Pipe()
	t.Cleanup(func() { _ = clientSide.Close(); _ = serverSide.Close() })

	go func() {
		cfg := &tls.Config{ServerName: want, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12} //nolint:gosec // only the ClientHello bytes are under test.
		_ = tls.Client(clientSide, cfg).HandshakeContext(t.Context())
	}()

	reader := bufio.NewReaderSize(serverSide, maxClientHelloBytes)
	record, err := peekClientHello(reader)
	if err != nil {
		t.Fatalf("peekClientHello: %v", err)
	}
	got, err := clientHelloSNI(record)
	if err != nil {
		t.Fatalf("clientHelloSNI: %v", err)
	}
	if got != want {
		t.Errorf("SNI = %q, want %q", got, want)
	}
	// The peek must leave the record in place for tls.Server to consume.
	if reader.Buffered() != len(record) {
		t.Errorf("buffered %d bytes after peek, want the whole %d-byte record", reader.Buffered(), len(record))
	}
}

func TestPeekClientHelloRejectsNonHandshake(t *testing.T) {
	t.Parallel()

	cases := map[string][]byte{
		"HTTP request":          []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
		"application data":      {0x17, 0x03, 0x03, 0x00, 0x01, 0x00},
		"oversized record body": {0x16, 0x03, 0x01, 0xFF, 0xFF},
		"short read":            {0x16, 0x03},
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := peekClientHello(bufio.NewReader(bytes.NewReader(input))); err == nil {
				t.Error("peekClientHello = nil error, want an error")
			}
		})
	}
	if _, err := peekClientHello(bufio.NewReader(bytes.NewReader([]byte{0x17, 0x03, 0x03, 0x00, 0x01, 0x00}))); !errors.Is(err, errNotClientHello) {
		t.Errorf("application data error = %v, want errNotClientHello", err)
	}
}
