package capture

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/voxywatch/voxywatch-probe/internal/config"
	"github.com/voxywatch/voxywatch-probe/internal/sender"
)

func TestPCIRepresentationsAtCaptureBoundary(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		blocked     []uint32
	}{
		{"ambiguous", `"12345678"`, []uint32{12345678, 0x12345678}},
		{"decimal-number", `12345678`, []uint32{12345678}},
		{"prefixed-hex", `"0x12345678"`, []uint32{0x12345678}},
		{"uppercase-whitespace", `" 0XABCDEF12 "`, []uint32{0xabcdef12}},
		{"legacy-hex", `"deadbeef"`, []uint32{0xdeadbeef}},
		{"max-number", `4294967295`, []uint32{0xffffffff}},
		{"max-decimal-string", `"4294967295"`, []uint32{0xffffffff}},
		{"zero", `0`, []uint32{0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "pci.json")
			if err := os.WriteFile(path, []byte(`{"calls":[{"flows":{"ssrc_caller":`+tc.value+`}}]}`), 0600); err != nil {
				t.Fatal(err)
			}
			ln, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			snd := sender.New("udp", ln.LocalAddr().String(), 16)
			defer snd.Close()
			c := &Capturer{cfg: &config.Config{WantRTP: true, MediaPolicy: "heuristic"}, snd: snd, pciPath: path, pciSSRCs: map[uint32]bool{}}
			ssrcs := append(append([]uint32(nil), tc.blocked...), uint32(987654321))
			for _, ssrc := range ssrcs {
				p := make([]byte, 32)
				p[0] = 0x80
				binary.BigEndian.PutUint32(p[8:12], ssrc)
				frame := ethernetUDP(t, "192.0.2.1", "198.51.100.1", 20000, 30000, p)
				c.handle_(gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default))
			}
			snd.Close()
			sent, errs, drops := snd.Stats()
			if sent != 1 || errs != 0 || drops != 0 || c.counts.pciSuppressed != uint64(len(tc.blocked)) {
				t.Fatalf("sent=%d errors=%d drops=%d suppressed=%d", sent, errs, drops, c.counts.pciSuppressed)
			}
			if tc.name == "decimal-number" && c.pciSSRCs[0x12345678] {
				t.Fatal("JSON number was reinterpreted as hex")
			}
			_ = ln.SetReadDeadline(time.Now().Add(time.Second))
			buf := make([]byte, 1024)
			if n, _, err := ln.ReadFrom(buf); err != nil || n < 6 {
				t.Fatalf("unrelated media was not delivered: %v", err)
			}
		})
	}
}

func TestPCIMalformedValuesRetainLastValidSuppression(t *testing.T) {
	for _, value := range []string{`true`, `-1`, `1.5`, `1e2`, `4294967296`, `"10000000000"`, `"0x100000000"`, `"not-an-ssrc"`, `[]`, `{}`} {
		t.Run(value, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "pci.json")
			if err := os.WriteFile(path, []byte(`{"calls":[{"flows":{"ssrc_caller":"222","ssrc_callee":`+value+`}}]}`), 0600); err != nil {
				t.Fatal(err)
			}
			c := &Capturer{pciPath: path, pciSSRCs: map[uint32]bool{111: true}}
			c.reloadPCI()
			if len(c.pciSSRCs) != 1 || !c.pciSSRCs[111] || c.pciFileInfo != nil {
				t.Fatal("malformed update replaced or committed valid suppression")
			}
		})
	}
}

func TestPCIEmptyPlaceholdersClearSuppression(t *testing.T) {
	for _, value := range []string{`null`, `""`, `"Unknown"`, `"None"`} {
		path := filepath.Join(t.TempDir(), "pci.json")
		if err := os.WriteFile(path, []byte(`{"calls":[{"flows":{"ssrc_caller":`+value+`}}]}`), 0600); err != nil {
			t.Fatal(err)
		}
		c := &Capturer{pciPath: path, pciSSRCs: map[uint32]bool{111: true}}
		c.reloadPCI()
		if len(c.pciSSRCs) != 0 {
			t.Fatalf("placeholder %s did not clear suppression", value)
		}
	}
}
