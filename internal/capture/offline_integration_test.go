package capture

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/voxywatch/voxywatch-probe/internal/config"
	"github.com/voxywatch/voxywatch-probe/internal/sender"
)

func TestOfflinePCAPToHEP(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "mirror-*.pcap")
	if err != nil {
		t.Fatal(err)
	}
	w := pcapgo.NewWriter(f)
	if err = w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	frames := [][]byte{
		ethernetUDP(t, "10.0.0.1", "198.51.100.2", 5060, 5060, []byte("INVITE sip:x SIP/2.0\r\n\r\n")),
		ethernetUDP(t, "10.0.0.1", "198.51.100.2", 20000, 30000, []byte{0x80, 0x00, 0, 1, 0, 0, 0, 1, 0, 0, 0, 2}),
	}
	for _, frame := range frames {
		if err = w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(frame), Length: len(frame)}, frame); err != nil {
			t.Fatal(err)
		}
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}

	ln, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	snd := sender.New("udp", ln.LocalAddr().String(), 16)
	cfg := &config.Config{PCAPFile: f.Name(), HEPServer: ln.LocalAddr().String(), Transport: "udp", Mode: "siprtp", WantRTP: true, WantRTCP: true, MediaPolicy: "heuristic", SIPPorts: []uint16{5060}, Snaplen: 65535, QueueSize: 16, CaptureID: 2201}
	cap, err := New(cfg, snd)
	if err != nil {
		t.Fatal(err)
	}
	if err = cap.Run(); err != nil {
		t.Fatal(err)
	}
	cap.Close()
	snd.Close()
	buf := make([]byte, 65535)
	_ = ln.SetReadDeadline(time.Now().Add(time.Second))
	count := 0
	for {
		n, _, e := ln.ReadFrom(buf)
		if e != nil {
			break
		}
		if n < 6 || string(buf[:4]) != "HEP3" {
			t.Fatalf("invalid HEP packet")
		}
		count++
	}
	if count != 2 {
		t.Fatalf("got %d HEP packets, want 2", count)
	}
}
