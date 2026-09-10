package sender

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// A deterministic net.Conn double exercises legal short writes and failures.
type shortConn struct {
	net.Conn
	buf       bytes.Buffer
	chunk     int
	fail      bool
	zero      bool
	closed    bool
	deadlines int
}

func (c *shortConn) SetWriteDeadline(time.Time) error { c.deadlines++; return nil }
func (c *shortConn) Close() error                     { c.closed = true; return nil }
func (c *shortConn) Write(p []byte) (int, error) {
	if c.zero {
		return 0, nil
	}
	if len(p) > c.chunk {
		p = p[:c.chunk]
	}
	n, _ := c.buf.Write(p)
	if c.fail {
		return n, io.ErrUnexpectedEOF
	}
	return n, nil
}

func TestPartialTCPWriteCompletesUnderOneDeadline(t *testing.T) {
	c := &shortConn{chunk: 3}
	s := &Sender{transport: "tcp", conn: c}
	p := []byte("HEP3-complete-record")
	s.write(p)
	sent, errs, _ := s.Stats()
	if !bytes.Equal(c.buf.Bytes(), p) || sent != 1 || errs != 0 || c.deadlines != 1 {
		t.Fatalf("short write lost data: bytes=%d sent=%d errors=%d deadlines=%d", c.buf.Len(), sent, errs, c.deadlines)
	}
}

func TestFailedOrZeroWritesCloseConnection(t *testing.T) {
	for _, transport := range []string{"tcp", "udp"} {
		for _, zero := range []bool{false, true} {
			c := &shortConn{chunk: 3, zero: zero, fail: transport == "tcp"}
			s := &Sender{transport: transport, conn: c}
			s.write([]byte("HEP3-record"))
			sent, errs, _ := s.Stats()
			if sent != 0 || errs != 1 || !c.closed || s.conn != nil {
				t.Fatalf("%s zero=%t: partial/failed record counted as sent", transport, zero)
			}
		}
	}
}

func TestConcurrentCloseAndSendAccountEveryAttempt(t *testing.T) {
	s := New("udp", "127.0.0.1:9", 8)
	const attempts = 1000
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < attempts; i++ {
			s.Send([]byte("record"))
		}
	}()
	go func() { defer wg.Done(); s.Close(); s.Close() }()
	wg.Wait()
	s.Close()
	if s.Send([]byte("after-close")) {
		t.Fatal("accepted after Close")
	}
	sent, errs, dropped := s.Stats()
	if sent+errs+dropped != attempts+1 {
		t.Fatalf("accounting: sent=%d errors=%d dropped=%d", sent, errs, dropped)
	}
}

func TestTransportSizeAdmission(t *testing.T) {
	s := &Sender{transport: "udp", queue: make(chan []byte, 1)}
	for _, n := range []int{0, 65508, 65536} {
		if s.Send(make([]byte, n)) {
			t.Fatalf("UDP accepted %d bytes", n)
		}
	}
	if !s.Send(make([]byte, 65507)) {
		t.Fatal("rejected maximum conservative UDP datagram")
	}
}

func TestTCPReconnectAfterWriteFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	result := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			result <- err
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		b := make([]byte, 4)
		_, err = io.ReadFull(conn, b)
		if err == nil && string(b) != "next" {
			err = errors.New("incorrect reconnect record")
		}
		result <- err
	}()
	s := &Sender{transport: "tcp", addr: ln.Addr().String(), conn: &shortConn{chunk: 2, fail: true}}
	s.write([]byte("failed"))
	s.write([]byte("next"))
	if s.conn != nil {
		defer s.conn.Close()
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	sent, errs, _ := s.Stats()
	if sent != 1 || errs != 1 {
		t.Fatalf("sent=%d errors=%d", sent, errs)
	}
}
