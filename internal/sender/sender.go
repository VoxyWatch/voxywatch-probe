// Package sender owns bounded asynchronous HEP delivery over UDP or TCP.
// It reconnects lazily after a write failure; it provides neither disk spooling
// nor TLS, so operators must protect the network path and monitor drops.
package sender

import (
	"io"
	"net"
	"sync"
	"time"
)

// Sender owns one bounded queue, its delivery worker, and at most one network connection.
// It is constructed by New and is not safe for copying.
type Sender struct {
	transport string
	addr      string
	mu        sync.Mutex
	conn      net.Conn
	sent      uint64
	errs      uint64
	dropped   uint64
	queue     chan []byte
	stop      chan struct{}
	done      chan struct{}
	closed    bool
	closeOnce sync.Once
}

const ioTimeout = 250 * time.Millisecond
const drainTimeout = 500 * time.Millisecond

// New starts the sender worker with a bounded packet queue. The caller owns the
// returned Sender and must call Close to stop it and release its connection.
func New(transport, addr string, queueSize int) *Sender {
	s := &Sender{transport: transport, addr: addr, queue: make(chan []byte, queueSize), stop: make(chan struct{}), done: make(chan struct{})}
	go s.run()
	return s
}

// dial bounds connection establishment independently of capture and health reads.
func (s *Sender) dial() error {
	c, err := net.DialTimeout(s.transport, s.addr, ioTimeout)
	if err != nil {
		return err
	}
	s.conn = c
	return nil
}

// write attempts one HEP record write. For TCP, HEP's own bytes 4-5 carry the
// record length; no additional framing is added. The worker alone owns conn.
// Partial TCP writes continue on the same connection under one record deadline;
// failure closes that connection rather than replaying an ambiguous partial record.
// A complete local write is not confirmation of receiver processing.
func (s *Sender) write(pkt []byte) {
	if s.conn == nil {
		if err := s.dial(); err != nil {
			s.mu.Lock()
			s.errs++
			s.mu.Unlock()
			return
		}
	}
	err := s.conn.SetWriteDeadline(time.Now().Add(ioTimeout))
	for err == nil && len(pkt) > 0 {
		var n int
		n, err = s.conn.Write(pkt)
		if n < 0 || n > len(pkt) || (n == 0 && err == nil) {
			err = io.ErrShortWrite
			break
		}
		if s.transport != "tcp" && n != len(pkt) && err == nil {
			err = io.ErrShortWrite
		}
		pkt = pkt[n:]
	}
	if err != nil {
		s.mu.Lock()
		s.errs++
		s.mu.Unlock()
		_ = s.conn.Close()
		s.conn = nil // Force a lazy reconnect on the next queued record.
		return
	}
	s.mu.Lock()
	s.sent++
	s.mu.Unlock()
}

// Send copies and normally queues one HEP record without waiting for queue capacity.
// A full queue, closed sender, or unrepresentable transport record is counted once
// here and returns false. No mutex is held during network I/O.
func (s *Sender) Send(pkt []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || len(pkt) == 0 || len(pkt) > 65535 || (s.transport == "udp" && len(pkt) > 65507) {
		s.dropped++
		return false
	}
	copyPkt := append([]byte(nil), pkt...)
	select {
	case s.queue <- copyPkt:
		return true
	default:
		s.dropped++
		return false
	}
}

func (s *Sender) run() {
	defer close(s.done)
	defer func() {
		if s.conn != nil {
			_ = s.conn.Close()
		}
	}()
	for {
		// Prefer an expired shutdown budget over another queued write.
		select {
		case <-s.stop:
			s.mu.Lock()
			s.dropped += uint64(len(s.queue))
			s.mu.Unlock()
			return
		default:
		}
		select {
		case pkt, ok := <-s.queue:
			if !ok {
				return
			}
			s.write(pkt)
		case <-s.stop:
			s.mu.Lock()
			s.dropped += uint64(len(s.queue))
			s.mu.Unlock()
			return
		}
	}
}

// Close rejects new sends, drains for up to 500 ms, then accounts pending records
// as drops. At most one bounded dial/write remains. Concurrent/repeated calls are
// safe; return means worker completion, not remote delivery confirmation.
func (s *Sender) Close() {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		close(s.queue)
		s.mu.Unlock()
		timer := time.NewTimer(drainTimeout)
		defer timer.Stop()
		select {
		case <-s.done:
		case <-timer.C:
			close(s.stop)
		}
	})
	<-s.done
}

// Stats returns cumulative local sender counters. sent is local write success only.
func (s *Sender) Stats() (sent, errs, dropped uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sent, s.errs, s.dropped
}
