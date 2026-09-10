package sender

import (
	"net"
	"sync"
	"testing"
	"time"
)

type observedWriteConn struct {
	net.Conn
	entered chan struct{}
	once    sync.Once
}

func (c *observedWriteConn) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.entered) })
	return c.Conn.Write(p)
}

func TestBlockedTCPKeepsCaptureAndHealthResponsive(t *testing.T) {
	writer, reader := net.Pipe()
	conn := &observedWriteConn{Conn: writer, entered: make(chan struct{})}
	s := &Sender{transport: "tcp", conn: conn, queue: make(chan []byte, 1), stop: make(chan struct{}), done: make(chan struct{})}
	go s.run()
	closeDone := make(chan struct{})
	var closeOnce sync.Once
	startClose := func() {
		closeOnce.Do(func() {
			go func() { s.Close(); close(closeDone) }()
		})
	}
	t.Cleanup(func() {
		// Release the deliberately blocked write even when an assertion fails.
		_ = reader.Close()
		_ = writer.Close()
		startClose()
		select {
		case <-closeDone:
		case <-time.After(3 * time.Second):
			t.Error("sender did not stop after test connection cleanup")
		}
	})
	if !s.Send([]byte("HEP3-first")) {
		t.Fatal("first packet was not enqueued")
	}
	select {
	case <-conn.entered:
	case <-time.After(time.Second):
		t.Fatal("sender did not begin writing")
	}
	if !s.Send([]byte("HEP3-queued")) {
		t.Fatal("queue did not accept its one pending packet")
	}
	sendDone := make(chan bool, 1)
	go func() { sendDone <- s.Send([]byte("HEP3-overflow")) }()
	select {
	case accepted := <-sendDone:
		if accepted {
			t.Error("full queue accepted a packet")
		}
	case <-time.After(200 * time.Millisecond):
		t.Error("Send blocked behind a stalled TCP write instead of dropping")
	}
	statsDone := make(chan struct{})
	go func() { s.Stats(); close(statsDone) }()
	select {
	case <-statsDone:
	case <-time.After(200 * time.Millisecond):
		t.Error("Stats blocked behind a stalled TCP write")
	}
	startClose()
	select {
	case <-closeDone:
	case <-time.After(1500 * time.Millisecond):
		t.Error("Close exceeded its bounded drain interval with a stalled TCP write")
	}
}
