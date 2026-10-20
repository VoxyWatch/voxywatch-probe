package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/voxywatch/voxywatch-probe/internal/config"
)

func TestOfflineShutdownWritesFinalCountersWithoutDoubleCounting(t *testing.T) {
	dir := t.TempDir()
	pcapPath := filepath.Join(dir, "input.pcap")
	f, err := os.Create(pcapPath)
	if err != nil {
		t.Fatal(err)
	}
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		payload := []byte("INVITE sip:x SIP/2.0\r\n\r\n")
		if i >= 2 {
			payload = make([]byte, 65420)
			copy(payload, "INVITE sip:x SIP/2.0\r\n\r\n")
		}
		ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2")}
		udp := &layers.UDP{SrcPort: 5060, DstPort: 5060}
		if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatal(err)
		}
		buf := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
			&layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}, ip, udp, gopacket.Payload(payload)); err != nil {
			t.Fatal(err)
		}
		frame := buf.Bytes()
		if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(frame), Length: len(frame)}, frame); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	ln, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	status := filepath.Join(dir, "status.json")
	cfg := &config.Config{PCAPFile: pcapPath, StatusFile: status, HEPServer: ln.LocalAddr().String(), Transport: "udp", QueueSize: 16, SIPPorts: []uint16{5060}, DedupeWindow: time.Second}
	if err := run(cfg); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(status)
	if err != nil {
		t.Fatal(err)
	}
	var counters map[string]any
	if err := json.Unmarshal(data, &counters); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]float64{"sip": 5, "sent": 2, "send_errors": 0, "queue_dropped": 3, "duplicates": 0} {
		if counters[name] != want {
			t.Fatalf("%s = %v, want %v", name, counters[name], want)
		}
	}
	_ = ln.SetReadDeadline(time.Now().Add(time.Second))
	for i := 0; i < 2; i++ {
		buf := make([]byte, 1024)
		n, _, err := ln.ReadFrom(buf)
		if err != nil || n < 6 || string(buf[:4]) != "HEP3" {
			t.Fatalf("missing drained HEP %d: %v", i, err)
		}
	}
}
