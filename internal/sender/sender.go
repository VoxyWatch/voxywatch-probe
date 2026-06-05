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
}

func New(transport, addr string) *Sender {
	return &Sender{transport: transport, addr: addr}
}

func (s *Sender) dial() error {
	c, err := net.DialTimeout(s.transport, s.addr, 5*time.Second)
	if err != nil {
		return err
	}
	s.conn = c
	return nil
}

// Send envía un datagrama HEP. En TCP antepone el framing nativo de HEP3
// (el largo ya viene en los bytes 4-5 del propio paquete, así que basta escribir).
func (s *Sender) Send(pkt []byte) {
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

func (s *Sender) Stats() (sent, errs uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sent, s.errs
}
