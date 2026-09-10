package capture

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/voxywatch/voxywatch-probe/internal/config"
)

func TestSIPRetransmissionAt500msIsPreserved(t *testing.T) {
	c := &Capturer{cfg: &config.Config{DedupeWindow: 1500 * time.Millisecond}, dedup: make(map[[32]byte]time.Time)}
	src, dst := net.ParseIP("192.0.2.1"), net.ParseIP("198.51.100.1")
	payload := []byte("INVITE sip:test@example.invalid SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK-test\r\nCall-ID: synthetic-retransmission\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n")
	if c.isDuplicate(src, dst, 5060, 5060, payload) {
		t.Fatal("first SIP observation was treated as a duplicate")
	}
	// A protocol retransmission is evidence, not an extra mirror observation.
	time.Sleep(500 * time.Millisecond)
	if c.isDuplicate(src, dst, 5060, 5060, payload) {
		t.Fatal("legitimate SIP retransmission at 500 ms was suppressed")
	}
}

func TestPCIReloadDetectsUpdatesWithinSameSecond(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pci.json")
	base := time.Unix(1700000000, 0)
	write := func(content string, nanos time.Duration) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		stamp := base.Add(nanos)
		if err := os.Chtimes(path, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"calls":[{"flows":{"ssrc_caller":"111"}}]}`, 100*time.Millisecond)
	c := &Capturer{pciPath: path, pciSSRCs: make(map[uint32]bool)}
	c.reloadPCI()
	if !c.pciSSRCs[111] {
		t.Fatal("initial suppression was not loaded")
	}
	write(`{"calls":[{"flows":{"ssrc_caller":"222"}}]}`, 800*time.Millisecond)
	// Bypass the polling throttle, not file-change detection.
	c.pciLastCheck = 0
	c.reloadPCI()
	if !c.pciSSRCs[222] || c.pciSSRCs[111] {
		t.Fatal("a new suppression document with a distinct subsecond mtime was ignored")
	}
}
