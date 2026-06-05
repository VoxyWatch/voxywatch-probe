// Package capture lee paquetes de la red con AF_PACKET (sin libpcap), clasifica
// SIP / RTP / RTCP y los entrega ya encapsulados en HEPv3 al sender.
package capture

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"

	"github.com/voxywatch/voxywatch-probe/internal/config"
	"github.com/voxywatch/voxywatch-probe/internal/hep"
	"github.com/voxywatch/voxywatch-probe/internal/sender"
)

type Capturer struct {
	cfg     *config.Config
	tp      *afpacket.TPacket
	snd     *sender.Sender
	sipSet  map[uint16]bool
	counts  struct{ sip, rtp, rtcp, other uint64 }
}

func New(cfg *config.Config, snd *sender.Sender) (*Capturer, error) {
	var tp *afpacket.TPacket
	var err error
	if cfg.Iface == "" || cfg.Iface == "any" {
		tp, err = afpacket.NewTPacket() // todas las interfaces
	} else {
		tp, err = afpacket.NewTPacket(afpacket.OptInterface(cfg.Iface))
	}
	if err != nil {
		return nil, fmt.Errorf("afpacket: %w (¿permisos root/CAP_NET_RAW?)", err)
	}
	c := &Capturer{cfg: cfg, tp: tp, snd: snd, sipSet: map[uint16]bool{}}
	for _, p := range cfg.SIPPorts {
		c.sipSet[p] = true
	}
	return c, nil
}

func (c *Capturer) Close() { c.tp.Close() }

// Run bloquea leyendo y procesando paquetes hasta error fatal.
func (c *Capturer) Run() error {
	src := gopacket.NewPacketSource(c.tp, layers.LayerTypeEthernet)
	src.DecodeOptions.Lazy = true
	src.DecodeOptions.NoCopy = true
	log.Printf("[capture] escuchando iface=%s modo=%s → %s/%s sip_ports=%v",
		c.cfg.Iface, c.cfg.Mode, c.cfg.HEPServer, c.cfg.Transport, c.cfg.SIPPorts)
	for pkt := range src.Packets() {
		c.handle(pkt)
	}
	return nil
}

func (c *Capturer) handle(pkt gopacket.Packet) {
	netLayer := pkt.NetworkLayer()
	if netLayer == nil {
		return
	}
	var srcIP, dstIP net.IP
	var ipProto byte
	switch ip := netLayer.(type) {
	case *layers.IPv4:
		srcIP, dstIP, ipProto = ip.SrcIP, ip.DstIP, byte(ip.Protocol)
	case *layers.IPv6:
		srcIP, dstIP, ipProto = ip.SrcIP, ip.DstIP, byte(ip.NextHeader)
	default:
		return
	}

	// MVP: solo UDP (SIP/RTP/RTCP sobre UDP). SIP-TCP/TLS en fase posterior.
	udp, ok := pkt.TransportLayer().(*layers.UDP)
	if !ok {
		return
	}
	payload := udp.Payload
	if len(payload) == 0 {
		return
	}
	srcPort, dstPort := uint16(udp.SrcPort), uint16(udp.DstPort)

	proto, want := c.classify(srcPort, dstPort, payload)
	if !want {
		return
	}

	ts := pkt.Metadata().Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	out := hep.Encode(&hep.Packet{
		SrcIP: srcIP, DstIP: dstIP, SrcPort: srcPort, DstPort: dstPort,
		IPProto: ipProto, Proto: proto,
		TsSec: uint32(ts.Unix()), TsUsec: uint32(ts.Nanosecond() / 1000),
		CaptureID: c.cfg.CaptureID, Payload: payload,
	})
	c.snd.Send(out)
}

// classify decide el tipo de payload y si debe enviarse según el modo.
func (c *Capturer) classify(srcPort, dstPort uint16, p []byte) (proto byte, want bool) {
	// SIP: por puerto conocido o por firma textual.
	if c.sipSet[srcPort] || c.sipSet[dstPort] || isSIP(p) {
		c.counts.sip++
		return hep.ProtoSIP, true
	}
	// RTP/RTCP: versión 2 en los 2 bits altos del primer byte.
	if len(p) >= 2 && (p[0]>>6) == 2 {
		pt := p[1] & 0x7f
		// RFC 5761: payload types 64-95 reservados → RTCP (SR=200..XR=207 → &0x7f = 72..79).
		if pt >= 64 && pt <= 95 {
			if c.cfg.WantRTCP {
				c.counts.rtcp++
				return hep.ProtoRTCP, true
			}
			return 0, false
		}
		if c.cfg.WantRTP {
			c.counts.rtp++
			return hep.ProtoRTP, true
		}
		return 0, false
	}
	c.counts.other++
	return 0, false
}

// isSIP detecta un mensaje SIP por su línea inicial (request o status-line).
func isSIP(p []byte) bool {
	if len(p) < 8 {
		return false
	}
	// Respuesta: "SIP/2.0 ..."
	if string(p[0:7]) == "SIP/2.0" {
		return true
	}
	// Request: "<MÉTODO> sip:..." — checar métodos comunes.
	for _, m := range sipMethods {
		if len(p) >= len(m) && string(p[0:len(m)]) == m {
			return true
		}
	}
	return false
}

var sipMethods = []string{
	"INVITE ", "ACK ", "BYE ", "CANCEL ", "REGISTER ", "OPTIONS ",
	"PRACK ", "SUBSCRIBE ", "NOTIFY ", "PUBLISH ", "INFO ", "REFER ", "MESSAGE ", "UPDATE ",
}

// Counts devuelve los contadores acumulados (para logging periódico).
func (c *Capturer) Counts() (sip, rtp, rtcp, other uint64) {
	return c.counts.sip, c.counts.rtp, c.counts.rtcp, c.counts.other
}
