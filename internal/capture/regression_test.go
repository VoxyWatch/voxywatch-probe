package capture

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/voxywatch/voxywatch-probe/internal/config"
)

func TestBoundedIndexesUnderSustainedChurn(t *testing.T) {
	c := &Capturer{cfg: &config.Config{DedupeWindow: time.Hour}, media: map[string]time.Time{}, dedup: map[[32]byte]time.Time{}}
	src, dst := net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")
	p := make([]byte, 12)
	for i := 0; i < maxTrackedEntries*3; i++ {
		binary.BigEndian.PutUint64(p, uint64(i))
		if c.isDuplicate(src, dst, 20000, 30000, p) {
			t.Fatal("new media treated as duplicate")
		}
		c.mediaKeys.put(c.media, fmt.Sprint(i), time.Now().Add(time.Hour))
		if len(c.media) > maxTrackedEntries || len(c.dedup) > maxTrackedEntries {
			t.Fatal("unbounded map")
		}
	}
	if len(c.mediaKeys.keys) != maxTrackedEntries || len(c.dedupKeys.keys) != maxTrackedEntries {
		t.Fatal("unbounded maintenance index")
	}
	if !c.isDuplicate(src, dst, 20000, 30000, p) {
		t.Fatal("recent media duplicate not suppressed")
	}
}

func TestLogicalExpiryAndRefresh(t *testing.T) {
	c := &Capturer{media: map[string]time.Time{}}
	ip := net.ParseIP("192.0.2.1")
	key := mediaKey(ip, 20000)
	c.mediaKeys.put(c.media, key, time.Now().Add(-time.Second))
	if c.isLearnedMedia(ip, ip, 20000, 20001) {
		t.Fatal("expired media admitted")
	}
	for i := 0; i < maxTrackedEntries*2; i++ {
		c.mediaKeys.put(c.media, key, time.Now().Add(time.Hour))
	}
	if len(c.mediaKeys.keys) != 1 || !c.isLearnedMedia(ip, ip, 20000, 20001) {
		t.Fatal("refresh grew index or lost media")
	}
}

func TestPCIRetriesInvalidSameIdentityAndAtomicReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pci.json")
	c := &Capturer{pciPath: path, pciSSRCs: map[uint32]bool{111: true}}
	stamp := time.Unix(1700000000, 123)
	write := func(p, data string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, stamp, stamp); err != nil {
			t.Fatal(err)
		}
		c.pciLastCheck = 0
	}
	valid := `{"calls":[{"flows":{"ssrc_caller":"222"}}]}`
	write(path, valid[:len(valid)-1]+"!")
	c.reloadPCI()
	if !c.pciSSRCs[111] {
		t.Fatal("parse failure cleared suppression")
	}
	write(path, valid)
	c.reloadPCI()
	if !c.pciSSRCs[222] {
		t.Fatal("failed document identity was committed")
	}
	write(path+".new", `{"calls":[{"flows":{"ssrc_caller":"333"}}]}`)
	if err := os.Rename(path+".new", path); err != nil {
		t.Fatal(err)
	}
	c.reloadPCI()
	if !c.pciSSRCs[333] || c.pciSSRCs[222] {
		t.Fatal("atomic replacement with equal mtime/size ignored")
	}
}

func TestSIPNeverDeduplicatedEvenImmediately(t *testing.T) {
	c := &Capturer{cfg: &config.Config{DedupeWindow: time.Second}, dedup: map[[32]byte]time.Time{}}
	ip := net.ParseIP("192.0.2.1")
	for i := 0; i < 3; i++ {
		if c.isDuplicate(ip, ip, 5060, 5060, []byte("INVITE sip:x SIP/2.0\r\n")) {
			t.Fatal("SIP evidence suppressed")
		}
	}
	if len(c.dedup) != 0 {
		t.Fatal("SIP consumed media dedup state")
	}
}

func BenchmarkLearnedMediaAtCapacity(b *testing.B) {
	c := &Capturer{media: map[string]time.Time{}}
	for i := 0; i < maxTrackedEntries; i++ {
		c.mediaKeys.put(c.media, fmt.Sprint(i), time.Now().Add(time.Hour))
	}
	ip := net.ParseIP("192.0.2.1")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.isLearnedMedia(ip, ip, 20000, 30000)
	}
}

func BenchmarkDedupeAtCapacity(b *testing.B) {
	c := &Capturer{cfg: &config.Config{DedupeWindow: time.Hour}, dedup: map[[32]byte]time.Time{}}
	ip := net.ParseIP("192.0.2.1")
	p := make([]byte, 12)
	for i := 0; i < maxTrackedEntries; i++ {
		binary.BigEndian.PutUint64(p, uint64(i))
		c.isDuplicate(ip, ip, 20000, 30000, p)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		binary.BigEndian.PutUint64(p, uint64(i+maxTrackedEntries))
		c.isDuplicate(ip, ip, 20000, 30000, p)
	}
}
