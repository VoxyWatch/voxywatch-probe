package hep

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestEncodeRejectsOversizedHEPFrames(t *testing.T) {
	for _, tc := range []struct {
		name, src, dst string
	}{
		{"IPv4", "192.0.2.1", "198.51.100.1"},
		{"IPv6", "2001:db8::1", "2001:db8::2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &Packet{SrcIP: net.ParseIP(tc.src), DstIP: net.ParseIP(tc.dst), SrcPort: 5060, DstPort: 5060, IPProto: 17, Proto: ProtoSIP}
			overhead := len(Encode(p))
			p.Payload = make([]byte, 65535-overhead)
			encoded := Encode(p)
			if len(encoded) != 65535 || int(binary.BigEndian.Uint16(encoded[4:6])) != len(encoded) {
				t.Fatal("maximum representable HEP frame did not retain its exact length")
			}
			p.Payload = append(p.Payload, 0)
			if encoded = Encode(p); len(encoded) != 0 {
				t.Fatalf("oversized HEP frame was emitted: actual length %d, advertised length %d", len(encoded), binary.BigEndian.Uint16(encoded[4:6]))
			}
		})
	}
}
