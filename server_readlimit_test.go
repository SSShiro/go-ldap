package ldap

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// pipeConn feeds fixed bytes to readLimitedPacket as if from a network conn.
type pipeConn struct {
	r io.Reader
}

func (p *pipeConn) Read(b []byte) (int, error)  { return p.r.Read(b) }
func (p *pipeConn) Write(b []byte) (int, error) { return len(b), nil }
func (p *pipeConn) Close() error                { return nil }
func (p *pipeConn) LocalAddr() net.Addr         { return nil }
func (p *pipeConn) RemoteAddr() net.Addr        { return nil }
func (p *pipeConn) SetDeadline(time.Time) error      { return nil }
func (p *pipeConn) SetReadDeadline(time.Time) error  { return nil }
func (p *pipeConn) SetWriteDeadline(time.Time) error { return nil }

func connFrom(b []byte) net.Conn { return &pipeConn{r: bytes.NewReader(b)} }

// The exact packet that crashed the process pre-fix: SEQUENCE, long-form length
// with 8 octets all 0xFF (~1.8e19). Pre-fix this reached asn1-ber's
// make([]byte, idx+datalen), overflowed, and panicked the whole process.
func TestReadLimitedPacketRejectsHugeLength(t *testing.T) {
	malicious := []byte{0x30, 0x88, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	if _, err := readLimitedPacket(connFrom(malicious), MaxMessageSize); err == nil {
		t.Fatal("expected an error for an oversized declared length, got nil")
	}
}

// A length just over the limit must be rejected before any large allocation.
func TestReadLimitedPacketRejectsOverLimit(t *testing.T) {
	over := MaxMessageSize + 1
	pkt := []byte{0x30, 0x84,
		byte(over >> 24), byte(over >> 16), byte(over >> 8), byte(over)}
	if _, err := readLimitedPacket(connFrom(pkt), MaxMessageSize); err == nil {
		t.Fatal("expected an error for a length above the limit, got nil")
	}
}

// The indefinite/absurd length-of-length forms must be rejected.
func TestReadLimitedPacketRejectsBadLengthOctets(t *testing.T) {
	for name, pkt := range map[string][]byte{
		"indefinite (n=0)": {0x30, 0x80},
		"n>8":              {0x30, 0x89, 1, 2, 3, 4, 5, 6, 7, 8, 9},
	} {
		if _, err := readLimitedPacket(connFrom(pkt), MaxMessageSize); err == nil {
			t.Fatalf("%s: expected an error, got nil", name)
		}
	}
}

// A well-formed small packet must still parse correctly and identically to the
// unbounded parser — the limiter must not corrupt normal traffic.
func TestReadLimitedPacketAcceptsValid(t *testing.T) {
	// Minimal anonymous simple bind, msgID 1, version 3, empty DN, empty pw.
	valid := []byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00}
	pkt, err := readLimitedPacket(connFrom(valid), MaxMessageSize)
	if err != nil {
		t.Fatalf("valid packet rejected: %v", err)
	}
	if len(pkt.Children) < 2 {
		t.Fatalf("parsed packet malformed: got %d children", len(pkt.Children))
	}
}

// A clean client close (0 bytes) must surface as io.EOF so the dispatch loop
// treats it as a normal disconnect, not an error.
func TestReadLimitedPacketEOFOnCleanClose(t *testing.T) {
	if _, err := readLimitedPacket(connFrom(nil), MaxMessageSize); err != io.EOF {
		t.Fatalf("expected io.EOF on empty stream, got %v", err)
	}
}
