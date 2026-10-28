package proxy

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
)

// TLS wire constants used to read the server name out of a raw ClientHello.
// The standard library exposes no parser for a record it has not consumed, and
// the transparent passthrough decision has to be made before the handshake.
const (
	recordTypeHandshake   = 0x16
	handshakeClientHello  = 0x01
	extensionServerName   = 0x0000
	sniNameTypeHostName   = 0x00
	tlsRecordHeaderLen    = 5
	tlsRecordMaxBodyBytes = 16 << 10 // RFC 8446 §5.1: a record body is at most 2^14 bytes.
	maxClientHelloBytes   = tlsRecordHeaderLen + tlsRecordMaxBodyBytes
)

// errNotClientHello marks bytes that are not a TLS handshake record carrying a
// ClientHello, so the caller can hand the connection to crypto/tls untouched.
var errNotClientHello = errors.New("proxy: not a TLS ClientHello")

// peekClientHello returns the first TLS record on reader without consuming it,
// provided it is a handshake record that fits the reader's buffer. The record
// stays buffered, so the connection can still be handed to [tls.Server].
func peekClientHello(reader *bufio.Reader) ([]byte, error) {
	header, err := reader.Peek(tlsRecordHeaderLen)
	if err != nil {
		return nil, fmt.Errorf("peek record header: %w", err)
	}
	if header[0] != recordTypeHandshake {
		return nil, errNotClientHello
	}
	n := int(binary.BigEndian.Uint16(header[3:5]))
	if n > tlsRecordMaxBodyBytes {
		return nil, fmt.Errorf("record body %d bytes exceeds the TLS maximum", n)
	}
	record, err := reader.Peek(tlsRecordHeaderLen + n)
	if err != nil {
		return nil, fmt.Errorf("peek record: %w", err)
	}
	return record, nil
}

// clientHelloSNI returns the host name in the server_name extension of the
// ClientHello carried by record (one complete TLS record, header included), or
// "" when the hello carries no SNI. It errors on anything that is not a
// well-formed ClientHello, including a hello fragmented across records, which
// is rare in practice and simply falls back to normal handling.
func clientHelloSNI(record []byte) (string, error) {
	if len(record) < tlsRecordHeaderLen || record[0] != recordTypeHandshake {
		return "", errNotClientHello
	}
	body := record[tlsRecordHeaderLen:]
	if int(binary.BigEndian.Uint16(record[3:5])) != len(body) {
		return "", errors.New("proxy: record length does not match the record")
	}
	// Handshake header: type (1), length (3).
	if len(body) < 4 || body[0] != handshakeClientHello {
		return "", errNotClientHello
	}
	msgLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	hello := body[4:]
	if msgLen != len(hello) {
		return "", errors.New("proxy: ClientHello spans more than one record")
	}
	return helloServerName(hello)
}

// helloServerName walks a ClientHello body (after the handshake header) to its
// extensions and returns the server_name host, or "" without one.
func helloServerName(hello []byte) (string, error) {
	r := &byteReader{buf: hello}
	// legacy_version (2) + random (32).
	r.skip(2 + 32)
	r.skip(int(r.u8()))  // legacy_session_id.
	r.skip(int(r.u16())) // cipher_suites.
	r.skip(int(r.u8()))  // legacy_compression_methods.
	if r.err != nil {
		return "", r.err
	}
	if r.done() {
		return "", nil // No extensions block at all: no SNI.
	}
	ext := r.bytes(int(r.u16()))
	if r.err != nil {
		return "", r.err
	}
	return extensionsServerName(ext)
}

// extensionsServerName finds the server_name extension in a ClientHello
// extensions block and returns its host_name entry, or "" when absent.
func extensionsServerName(ext []byte) (string, error) {
	r := &byteReader{buf: ext}
	for !r.done() {
		typ := r.u16()
		data := r.bytes(int(r.u16()))
		if r.err != nil {
			return "", r.err
		}
		if typ != extensionServerName {
			continue
		}
		list := &byteReader{buf: data}
		names := &byteReader{buf: list.bytes(int(list.u16()))}
		for !names.done() {
			nameType := names.u8()
			name := names.bytes(int(names.u16()))
			if names.err != nil {
				return "", names.err
			}
			if nameType == sniNameTypeHostName {
				return string(name), nil
			}
		}
		return "", list.err
	}
	return "", r.err
}

// errShortClientHello marks a ClientHello that ends before a field it declares.
var errShortClientHello = errors.New("proxy: truncated ClientHello")

// byteReader is a bounds-checked cursor over a byte slice. The first short read
// sets err and every later read returns zero, so a parse is one straight walk
// followed by a single error check.
type byteReader struct {
	buf []byte
	pos int
	err error
}

func (r *byteReader) done() bool { return r.err != nil || r.pos >= len(r.buf) }

func (r *byteReader) bytes(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || r.pos+n > len(r.buf) {
		r.err = errShortClientHello
		return nil
	}
	out := r.buf[r.pos : r.pos+n]
	r.pos += n
	return out
}

func (r *byteReader) skip(n int) { r.bytes(n) }

func (r *byteReader) u8() uint8 {
	b := r.bytes(1)
	if b == nil {
		return 0
	}
	return b[0]
}

func (r *byteReader) u16() uint16 {
	b := r.bytes(2)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}
