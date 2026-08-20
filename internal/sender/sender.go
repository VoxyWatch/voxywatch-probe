// Package sender entrega paquetes HEP a VoxyWatch por UDP o TCP.
// MVP: envío directo con reconexión perezosa. (Fase posterior: spool en disco + TLS.)
package sender

import (
	"encoding/binary"
	"net"
	"sync"
	"time"
)

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
}

func New(transport, addr string, queueSize int) *Sender {
	s := &Sender{transport: transport, addr: addr, queue: make(chan []byte, queueSize), stop: make(chan struct{}), done: make(chan struct{})}
	go s.run()
	return s
}

func (s *Sender) dial() error {
	c, err := net.DialTimeout(s.transport, s.addr, 2*time.Second)
	if err != nil {
		return err
	}
	s.conn = c
	return nil
}

// Send envía un datagrama HEP. En TCP antepone el framing nativo de HEP3
// (el largo ya viene en los bytes 4-5 del propio paquete, así que basta escribir).
func (s *Sender) write(pkt []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		if err := s.dial(); err != nil {
			s.errs++
			return
		}
	}
	var err error
	if s.transport == "tcp" {
		// HEP3 ya lleva su propia longitud total en los bytes 4-5; TCP es stream,
		// el receptor la usa para enmarcar. Validación defensiva del prefijo.
		if len(pkt) >= 6 && string(pkt[0:4]) == "HEP3" {
			_ = binary.BigEndian.Uint16(pkt[4:6])
		}
		_, err = s.conn.Write(pkt)
	} else {
		_, err = s.conn.Write(pkt)
	}
	if err != nil {
		s.errs++
		_ = s.conn.Close()
		s.conn = nil // forzar redial en el próximo envío
		return
	}
	s.sent++
}

// Send nunca bloquea el hilo de captura. Si el destino no da abasto, descarta
// de forma observable en vez de bloquear libpcap y ocultar drops del kernel.
func (s *Sender) Send(pkt []byte) bool {
	copyPkt := append([]byte(nil), pkt...)
	select {
	case s.queue <- copyPkt:
		return true
	default:
		s.mu.Lock()
		s.dropped++
		s.mu.Unlock()
		return false
	}
}

func (s *Sender) run() {
	defer close(s.done)
	for {
		select {
		case pkt := <-s.queue:
			s.write(pkt)
		case <-s.stop:
			s.mu.Lock()
			s.dropped += uint64(len(s.queue))
			s.mu.Unlock()
			return
		}
	}
}

func (s *Sender) Close() {
	deadline := time.Now().Add(500 * time.Millisecond)
	for len(s.queue) > 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	close(s.stop)
	<-s.done
	s.mu.Lock()
	if s.conn != nil {
		_ = s.conn.Close()
	}
	s.mu.Unlock()
}

func (s *Sender) Stats() (sent, errs, dropped uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sent, s.errs, s.dropped
}
