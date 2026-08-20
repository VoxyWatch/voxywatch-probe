package capture

import (
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/voxywatch/voxywatch-probe/internal/config"
)

func ethernetUDP(t *testing.T, src, dst string, sp, dp uint16, payload []byte) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP(src), DstIP: net.ParseIP(dst)}
	udp := &layers.UDP{SrcPort: layers.UDPPort(sp), DstPort: layers.UDPPort(dp)}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		&layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4},
		ip, udp, gopacket.Payload(payload))
	if err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestDecodeSpanAndVXLANUsesInnerTuple(t *testing.T) {
	inner := ethernetUDP(t, "10.0.0.1", "198.51.100.2", 5060, 5060, []byte("INVITE sip:x SIP/2.0\r\n"))
	v, err := decodeView(gopacket.NewPacket(inner, layers.LayerTypeEthernet, gopacket.Default))
	if err != nil {
		t.Fatal(err)
	}
	if v.srcPort != 5060 || !v.srcIP.Equal(net.ParseIP("10.0.0.1")) {
		t.Fatalf("bad SPAN tuple: %+v", v)
	}

	buf := gopacket.NewSerializeBuffer()
	udp := &layers.UDP{SrcPort: 40000, DstPort: 4789}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2")}
	_ = udp.SetNetworkLayerForChecksum(ip)
	err = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		&layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}, ip, udp,
		&layers.VXLAN{ValidIDFlag: true, VNI: 42}, gopacket.Payload(inner))
	if err != nil {
		t.Fatal(err)
	}
	v, err = decodeView(gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default))
	if err != nil {
		t.Fatal(err)
	}
	if v.srcPort != 5060 || v.dstPort != 5060 || !v.dstIP.Equal(net.ParseIP("198.51.100.2")) {
		t.Fatalf("outer VXLAN leaked into tuple: %+v", v)
	}
}

func TestDecodeERSPANUsesMirroredTuple(t *testing.T) {
	inner := ethernetUDP(t, "10.10.0.1", "198.51.100.9", 5060, 5060, []byte("SIP/2.0 200 OK\r\n"))
	buf := gopacket.NewSerializeBuffer()
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolGRE, SrcIP: net.ParseIP("192.0.2.10"), DstIP: net.ParseIP("192.0.2.20")}
	err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		&layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}, ip,
		&layers.GRE{Protocol: layers.EthernetType(0x88be)}, gopacket.Payload(erspanFrameForTest(0x88be, inner)))
	if err != nil {
		t.Fatal(err)
	}
	v, err := decodeView(gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default))
	if err != nil {
		t.Fatal(err)
	}
	if v.srcPort != 5060 || !v.srcIP.Equal(net.ParseIP("10.10.0.1")) {
		t.Fatalf("outer ERSPAN leaked into tuple: %+v", v)
	}
}

func TestDecodeERSPANIIIOptionalSubheader(t *testing.T) {
	inner := ethernetUDP(t, "10.30.0.1", "198.51.100.30", 5060, 5060, []byte("OPTIONS sip:x SIP/2.0\r\n"))
	ers := make([]byte, 20+len(inner))
	ers[11] = 1
	copy(ers[20:], inner)
	buf := gopacket.NewSerializeBuffer()
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolGRE, SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2")}
	err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}, ip, &layers.GRE{Protocol: layers.EthernetType(0x22eb)}, gopacket.Payload(ers))
	if err != nil {
		t.Fatal(err)
	}
	v, err := decodeView(gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default))
	if err != nil {
		t.Fatal(err)
	}
	if !v.srcIP.Equal(net.ParseIP("10.30.0.1")) {
		t.Fatalf("ERSPAN III optional header not skipped: %+v", v)
	}
}

func TestLearnedMediaRejectsUnrelatedRTP(t *testing.T) {
	c := &Capturer{cfg: &config.Config{MediaPolicy: "learned", DedupeWindow: time.Second}, sipSet: map[uint16]bool{5060: true}, media: map[string]time.Time{}, dedup: map[[32]byte]time.Time{}}
	sdp := []byte("INVITE sip:x SIP/2.0\r\nContent-Type: application/sdp\r\n\r\nc=IN IP4 203.0.113.8\r\nm=audio 20000 RTP/AVP 0\r\n")
	c.learnSDP(sdp, net.ParseIP("10.0.0.1"), net.ParseIP("198.51.100.2"))
	if !c.isLearnedMedia(net.ParseIP("203.0.113.8"), net.ParseIP("10.0.0.1"), 20000, 30000) {
		t.Fatal("SDP media endpoint not learned")
	}
	if c.isLearnedMedia(net.ParseIP("203.0.113.9"), net.ParseIP("10.0.0.1"), 21000, 31000) {
		t.Fatal("unrelated RTP accepted")
	}
}

func TestLearnedMediaAcceptsMediaLevelConnectionAfterMLine(t *testing.T) {
	c := &Capturer{cfg: &config.Config{MediaPolicy: "learned"}, sipSet: map[uint16]bool{}, media: map[string]time.Time{}, dedup: map[[32]byte]time.Time{}}
	c.learnSDP([]byte("INVITE sip:x SIP/2.0\r\nContent-Type: application/sdp\r\n\r\nm=audio 21000 RTP/AVP 0\r\nc=IN IP4 203.0.113.21\r\n"), net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"))
	if !c.isLearnedMedia(net.ParseIP("203.0.113.21"), net.ParseIP("10.0.0.1"), 21000, 30000) {
		t.Fatal("media-level c= after m= was not learned")
	}
}
