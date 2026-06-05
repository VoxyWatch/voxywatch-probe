// Package capture lee paquetes de la red con libpcap (gopacket/pcap) — captura
// AMBOS sentidos del tráfico (incl. el saliente del propio host, que afpacket no
// entrega), clasifica SIP / RTP / RTCP y los entrega encapsulados en HEPv3.
package capture

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/voxywatch/voxywatch-probe/internal/config"
	"github.com/voxywatch/voxywatch-probe/internal/hep"
	"github.com/voxywatch/voxywatch-probe/internal/sender"
)

type Capturer struct {
	cfg    *config.Config
	handle *pcap.Handle
	snd    *sender.Sender
	sipSet map[uint16]bool
	counts struct{ sip, rtp, rtcp, other, rtpSelf, rtpPeer uint64 }
}

func isPrivate(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	return ip4[0] == 10 ||
		(ip4[0] == 192 && ip4[1] == 168) ||
		(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31)
}

func New(cfg *config.Config, snd *sender.Sender) (*Capturer, error) {
	iface := cfg.Iface
	if iface == "" {
		iface = "any"
	}
	// promisc=true + timeout corto para baja latencia. Snaplen del config.
	h, err := pcap.OpenLive(iface, int32(cfg.Snaplen), true, 100*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("pcap.OpenLive(%s): %w (¿permisos root/CAP_NET_RAW?)", iface, err)
	}
	if cfg.BPF != "" {
		if err := h.SetBPFFilter(cfg.BPF); err != nil {
			h.Close()
			return nil, fmt.Errorf("BPF %q: %w", cfg.BPF, err)
		}
	}
	c := &Capturer{cfg: cfg, handle: h, snd: snd, sipSet: map[uint16]bool{}}
	for _, p := range cfg.SIPPorts {
		c.sipSet[p] = true
	}
	return c, nil
}

func (c *Capturer) Close() {
	if c.handle != nil {
		c.handle.Close()
	}
}

// Run bloquea leyendo y procesando paquetes hasta error fatal.
func (c *Capturer) Run() error {
	src := gopacket.NewPacketSource(c.handle, c.handle.LinkType())
	src.DecodeOptions.Lazy = true
	src.DecodeOptions.NoCopy = true
	log.Printf("[capture] libpcap iface=%s link=%s modo=%s → %s/%s sip_ports=%v",
		c.cfg.Iface, c.handle.LinkType(), c.cfg.Mode, c.cfg.HEPServer, c.cfg.Transport, c.cfg.SIPPorts)
	for pkt := range src.Packets() {
		c.handle_(pkt)
	}
	return nil
}

func (c *Capturer) handle_(pkt gopacket.Packet) {
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
	if proto == hep.ProtoRTP {
		if isPrivate(srcIP) {
			c.counts.rtpSelf++
		} else {
			c.counts.rtpPeer++
		}
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
// Endurecido para evitar falsos positivos (DNS, multicast, STUN) clasificados como RTP.
func (c *Capturer) classify(srcPort, dstPort uint16, p []byte) (proto byte, want bool) {
	// SIP: por puerto conocido o por firma textual.
	if c.sipSet[srcPort] || c.sipSet[dstPort] || isSIP(p) {
		c.counts.sip++
		return hep.ProtoSIP, true
	}
	if !c.cfg.WantRTP && !c.cfg.WantRTCP {
		return 0, false
	}
	// RTP/RTCP: versión 2 en los 2 bits altos del primer byte.
	if len(p) < 12 || (p[0]>>6) != 2 {
		c.counts.other++
		return 0, false
	}
	// Descartar puertos de servicios bien conocidos (DNS 53, STUN 3478, etc.) y
	// puertos de señalización; el media RTP usa puertos efímeros altos.
	if isWellKnown(srcPort) || isWellKnown(dstPort) || srcPort < 1024 || dstPort < 1024 {
		c.counts.other++
		return 0, false
	}
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

func isWellKnown(p uint16) bool {
	switch p {
	case 53, 67, 68, 123, 137, 138, 161, 162, 3478, 5060, 5061, 1900, 5353:
		return true
	}
	return false
}

// isSIP detecta un mensaje SIP por su línea inicial (request o status-line).
func isSIP(p []byte) bool {
	if len(p) < 8 {
		return false
	}
	if string(p[0:7]) == "SIP/2.0" {
		return true
	}
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

// RtpDirs: RTP con IP origen privada (saliente del host) vs pública (entrante).
func (c *Capturer) RtpDirs() (self, peer uint64) {
	return c.counts.rtpSelf, c.counts.rtpPeer
}
