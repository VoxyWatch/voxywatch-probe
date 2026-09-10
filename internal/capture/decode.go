package capture

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type packetView struct {
	srcIP, dstIP     net.IP
	srcPort, dstPort uint16
	ipProto          byte
	payload          []byte
}

// decodeView selects the innermost UDP or TCP tuple exposed by supported decoders.
// gopacket unwraps Ethernet, VLAN/QinQ, and VXLAN; ERSPAN requires removing its
// GRE shim first. This is packet-local decoding: it does not reassemble TCP
// streams or IP fragments, so fragmented traffic may be unavailable to callers.
func decodeView(pkt gopacket.Packet) (packetView, error) {
	return decodeLayers(pkt, 0)
}

func decodeLayers(pkt gopacket.Packet, depth int) (packetView, error) {
	if depth > 2 {
		return packetView{}, fmt.Errorf("encapsulation too deep")
	}
	for i := len(pkt.Layers()) - 1; i >= 0; i-- {
		gre, ok := pkt.Layers()[i].(*layers.GRE)
		if !ok {
			continue
		}
		proto := uint16(gre.Protocol)
		if proto != 0x88be && proto != 0x22eb {
			continue
		}
		off := 8
		if proto == 0x22eb {
			off = 12
			// ERSPAN III's O bit adds an 8-byte platform-specific subheader.
			if len(gre.Payload) >= 12 && (gre.Payload[11]&0x01) != 0 {
				off += 8
			}
		}
		if len(gre.Payload) <= off {
			return packetView{}, fmt.Errorf("truncated ERSPAN")
		}
		inner := gopacket.NewPacket(gre.Payload[off:], layers.LayerTypeEthernet, gopacket.Default)
		return decodeLayers(inner, depth+1)
	}

	var src, dst net.IP
	for i := len(pkt.Layers()) - 1; i >= 0; i-- {
		switch ip := pkt.Layers()[i].(type) {
		case *layers.IPv4:
			src, dst = append(net.IP(nil), ip.SrcIP...), append(net.IP(nil), ip.DstIP...)
		case *layers.IPv6:
			src, dst = append(net.IP(nil), ip.SrcIP...), append(net.IP(nil), ip.DstIP...)
		}
		if src != nil {
			break
		}
	}
	if src == nil {
		return packetView{}, fmt.Errorf("no inner IP")
	}
	for i := len(pkt.Layers()) - 1; i >= 0; i-- {
		switch tr := pkt.Layers()[i].(type) {
		case *layers.UDP:
			return packetView{src, dst, uint16(tr.SrcPort), uint16(tr.DstPort), 17, tr.Payload}, nil
		case *layers.TCP:
			return packetView{src, dst, uint16(tr.SrcPort), uint16(tr.DstPort), 6, tr.Payload}, nil
		}
	}
	return packetView{}, fmt.Errorf("no inner UDP/TCP")
}

// erspanFrameForTest builds the minimal ERSPAN payload used by package tests.
// It is not a general ERSPAN encoder and must not be used for live traffic.
func erspanFrameForTest(proto uint16, inner []byte) []byte {
	off := 8
	if proto == 0x22eb {
		off = 12
	}
	b := make([]byte, off+len(inner))
	binary.BigEndian.PutUint16(b[0:2], 0x1000)
	copy(b[off:], inner)
	return b
}
