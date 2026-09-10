// Package capture owns packet acquisition and conservative SIP/RTP/RTCP
// classification. It reads libpcap packets in both observed directions and hands
// selected packets to the HEP sender. It is not a TCP-stream or IP-fragment
// reassembler, and capture visibility depends on the chosen interface and mirror.
package capture

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	"github.com/voxywatch/voxywatch-probe/internal/config"
	"github.com/voxywatch/voxywatch-probe/internal/hep"
	"github.com/voxywatch/voxywatch-probe/internal/sender"
)

// Capturer owns one libpcap handle and its in-memory classification state.
// Media and duplicate indexes have fixed cardinality caps and lazy TTL checks.
// Ring eviction gives constant maintenance work without per-packet full sweeps.
// It is not safe for copying.
type Capturer struct {
	cfg    *config.Config
	handle *pcap.Handle
	snd    *sender.Sender
	sipSet map[uint16]bool
	counts struct {
		sip, rtp, rtcp, other, rtpSelf, rtpPeer, pciSuppressed, duplicate, untrusted, queueDropped uint64
	}
	mu           sync.RWMutex
	media        map[string]time.Time
	dedup        map[[32]byte]time.Time
	mediaKeys    boundedKeys[string]
	dedupKeys    boundedKeys[[32]byte]
	closeOnce    sync.Once
	stop         chan struct{}
	handleMu     sync.Mutex
	handleClosed bool
	kernelStats  pcap.Stats
	// PCI suppression excludes RTP for listed SSRCs during a payment window at the
	// source. The portal-owned JSON is reloaded from pciPath; an empty set has no effect.
	pciSSRCs     map[uint32]bool
	pciPath      string
	pciMtime     int64
	pciLastCheck int64
	pciFileInfo  os.FileInfo
}

const maxTrackedEntries = 65536

// boundedKeys retains at most the cap in both the ring and its timestamp map.
// Refreshes reuse the existing slot. Expiry is logical on lookup; physical removal
// is FIFO under churn, so expired state can never accumulate beyond the cap.
type boundedKeys[K comparable] struct {
	keys []K
	next int
}

func (b *boundedKeys[K]) put(m map[K]time.Time, key K, until time.Time) {
	if _, exists := m[key]; !exists {
		if len(b.keys) < maxTrackedEntries {
			b.keys = append(b.keys, key)
		} else {
			delete(m, b.keys[b.next])
			b.keys[b.next] = key
			b.next = (b.next + 1) % maxTrackedEntries
		}
	}
	m[key] = until
}

// isPrivate recognizes only the RFC 1918 IPv4 ranges used for directional counters.
// It is a reporting heuristic, not an authorization or address-classification policy.
func isPrivate(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	return ip4[0] == 10 ||
		(ip4[0] == 192 && ip4[1] == 168) ||
		(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31)
}

// New opens the live interface or the requested offline PCAP and returns its owner.
// The caller must Close the returned Capturer. Live capture requires permissions
// granted by the host (normally CAP_NET_RAW and CAP_NET_ADMIN).
func New(cfg *config.Config, snd *sender.Sender) (*Capturer, error) {
	iface := cfg.Iface
	if iface == "" {
		iface = "any"
	}
	// Immediate mode returns packets without waiting for the kernel buffer to fill.
	// The 8 MiB libpcap buffer absorbs bursts; if inactive-handle setup fails, fall
	// back to OpenLive. Neither setting guarantees loss-free capture under load.
	var h *pcap.Handle
	var ierr error
	if cfg.PCAPFile != "" {
		h, ierr = pcap.OpenOffline(cfg.PCAPFile)
		if ierr != nil {
			return nil, fmt.Errorf("pcap.OpenOffline(%s): %w", cfg.PCAPFile, ierr)
		}
	}
	var ih *pcap.InactiveHandle
	if h == nil {
		ih, ierr = pcap.NewInactiveHandle(iface)
	}
	if h == nil && ierr == nil {
		_ = ih.SetSnapLen(int(cfg.Snaplen))
		_ = ih.SetPromisc(true)
		_ = ih.SetTimeout(100 * time.Millisecond)
		_ = ih.SetImmediateMode(true)
		_ = ih.SetBufferSize(8 * 1024 * 1024)
		h, ierr = ih.Activate()
		ih.CleanUp()
	}
	if ierr != nil || h == nil {
		var err error
		h, err = pcap.OpenLive(iface, int32(cfg.Snaplen), true, 100*time.Millisecond)
		if err != nil {
			return nil, fmt.Errorf("pcap.OpenLive(%s): %w (check root/CAP_NET_RAW permissions)", iface, err)
		}
	}
	if cfg.BPF != "" {
		if err := h.SetBPFFilter(cfg.BPF); err != nil {
			h.Close()
			return nil, fmt.Errorf("BPF %q: %w", cfg.BPF, err)
		}
	}
	pciPath := os.Getenv("VW_PROBE_PCI_FILE")
	if pciPath == "" {
		pciPath = "/etc/voxywatch-probe/pci_suppress.json"
	}
	c := &Capturer{cfg: cfg, handle: h, snd: snd, sipSet: map[uint16]bool{}, media: map[string]time.Time{}, dedup: map[[32]byte]time.Time{},
		pciSSRCs: map[uint32]bool{}, pciPath: pciPath, stop: make(chan struct{})}
	for _, p := range cfg.SIPPorts {
		c.sipSet[p] = true
	}
	return c, nil
}

// Close releases the libpcap handle. It may be called during signal handling.
func (c *Capturer) Close() {
	c.closeOnce.Do(func() {
		if c.stop != nil {
			close(c.stop)
		}
		c.handleMu.Lock()
		defer c.handleMu.Unlock()
		if c.handle != nil {
			if st, err := c.handle.Stats(); err == nil {
				c.kernelStats = *st
			}
			c.handle.Close()
		}
		c.handleClosed = true
	})
}

// Run blocks while packets are available and processes each packet once. A closed
// handle or exhausted offline PCAP ends the packet source without inventing a result.
func (c *Capturer) Run() error {
	c.handleMu.Lock()
	if c.handleClosed {
		c.handleMu.Unlock()
		return nil
	}
	src := gopacket.NewPacketSource(c.handle, c.handle.LinkType())
	src.DecodeOptions.Lazy = true
	src.DecodeOptions.NoCopy = true
	log.Printf("[capture] libpcap iface=%s link=%s mode=%s → %s/%s sip_ports=%v",
		c.cfg.Iface, c.handle.LinkType(), c.cfg.Mode, c.cfg.HEPServer, c.cfg.Transport, c.cfg.SIPPorts)
	c.handleMu.Unlock()
	// NextPacket avoids PacketSource's background buffered goroutine. Shutdown
	// stops acquisition rather than processing a hidden queue after Close.
	for {
		select {
		case <-c.stop:
			return nil
		default:
		}
		c.handleMu.Lock()
		if c.handleClosed {
			c.handleMu.Unlock()
			return nil
		}
		pkt, err := src.NextPacket()
		c.handleMu.Unlock()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		}
		if err == io.EOF || err == pcap.NextErrorNotActivated {
			return nil
		}
		if err != nil {
			return err
		}
		c.handle_(pkt)
	}
}

// pciSSRC accepts the portal's decimal numbers and legacy hexadecimal strings.
// Digit-only strings are ambiguous: suppress both valid uint32 interpretations
// rather than leaking payment audio. A malformed value rejects the entire update
// so the previous valid suppression set remains active.
type pciSSRC []uint32

func (s *pciSSRC) UnmarshalJSON(raw []byte) error {
	*s = nil
	if bytes.Equal(raw, []byte("null")) {
		return nil
	}
	if len(raw) > 0 && raw[0] == '"' {
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return err
		}
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" || value == "unknown" || value == "none" {
			return nil
		}
		if v, err := strconv.ParseUint(value, 10, 32); err == nil {
			*s = append(*s, uint32(v))
		}
		if v, err := strconv.ParseUint(strings.TrimPrefix(value, "0x"), 16, 32); err == nil {
			*s = append(*s, uint32(v))
		}
	} else if v, err := strconv.ParseUint(string(raw), 10, 32); err == nil {
		*s = append(*s, uint32(v))
	}
	if len(*s) == 0 {
		return fmt.Errorf("invalid PCI SSRC")
	}
	return nil
}

// reloadPCI refreshes the portal-owned calls[].flows.ssrc_* file at most once per
// second and only after its mtime changes. A missing file clears suppression; a valid
// JSON document with no listed SSRCs also clears it. An unreadable or invalid changed
// file leaves the previously loaded set in place.
func (c *Capturer) reloadPCI() {
	now := time.Now().Unix()
	if now-c.pciLastCheck < 1 {
		return
	}
	c.pciLastCheck = now
	fi, err := os.Stat(c.pciPath)
	if err != nil {
		if os.IsNotExist(err) {
			c.pciSSRCs = map[uint32]bool{}
			c.pciMtime = 0
			c.pciFileInfo = nil
		}
		return
	}
	if c.pciFileInfo != nil && os.SameFile(fi, c.pciFileInfo) && fi.ModTime().UnixNano() == c.pciMtime && fi.Size() == c.pciFileInfo.Size() {
		return
	}
	data, err := os.ReadFile(c.pciPath)
	if err != nil {
		return
	}
	var doc struct {
		Calls []struct {
			Flows struct {
				SsrcCaller pciSSRC `json:"ssrc_caller"`
				SsrcCallee pciSSRC `json:"ssrc_callee"`
			} `json:"flows"`
		} `json:"calls"`
	}
	if json.Unmarshal(data, &doc) != nil {
		return
	}
	set := map[uint32]bool{}
	for _, cl := range doc.Calls {
		for _, values := range []pciSSRC{cl.Flows.SsrcCaller, cl.Flows.SsrcCallee} {
			for _, v := range values {
				set[v] = true
			}
		}
	}
	c.pciSSRCs = set
	// Commit identity only after successful parsing, so transient failures retry.
	c.pciMtime = fi.ModTime().UnixNano()
	c.pciFileInfo = fi
}

func (c *Capturer) handle_(pkt gopacket.Packet) {
	v, err := decodeView(pkt)
	if err != nil {
		return
	}
	srcIP, dstIP, ipProto := v.srcIP, v.dstIP, v.ipProto
	payload := v.payload
	if len(payload) == 0 {
		return
	}
	srcPort, dstPort := v.srcPort, v.dstPort
	if !c.trusted(srcIP, dstIP) {
		c.mu.Lock()
		c.counts.untrusted++
		c.mu.Unlock()
		return
	}

	proto, want := c.classify(srcPort, dstPort, payload)
	if !want {
		return
	}
	if proto == hep.ProtoSIP {
		c.learnSDP(payload, srcIP, dstIP)
	}
	if proto != hep.ProtoSIP && c.isDuplicate(srcIP, dstIP, srcPort, dstPort, payload) {
		c.mu.Lock()
		c.counts.duplicate++
		c.mu.Unlock()
		return
	}
	if proto == hep.ProtoRTP {
		if c.cfg.MediaPolicy == "learned" && !c.isLearnedMedia(srcIP, dstIP, srcPort, dstPort) {
			return
		}
		c.mu.Lock()
		if isPrivate(srcIP) {
			c.counts.rtpSelf++
		} else {
			c.counts.rtpPeer++
		}
		c.mu.Unlock()
		// Do not forward RTP for an SSRC currently under portal-authorized suppression.
		// This cannot retract earlier delivery or cover a second independent capture path.
		c.reloadPCI()
		if len(c.pciSSRCs) > 0 && len(payload) >= 12 {
			if c.pciSSRCs[binary.BigEndian.Uint32(payload[8:12])] {
				c.mu.Lock()
				c.counts.pciSuppressed++
				c.mu.Unlock()
				return
			}
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
	if !c.snd.Send(out) {
		c.mu.Lock()
		c.counts.queueDropped++
		c.mu.Unlock()
	}
}

func (c *Capturer) trusted(src, dst net.IP) bool {
	if len(c.cfg.TrustedCIDRs) == 0 {
		return true
	}
	for _, n := range c.cfg.TrustedCIDRs {
		if n.Contains(src) || n.Contains(dst) {
			return true
		}
	}
	return false
}

func mediaKey(ip net.IP, port uint16) string {
	return net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
}

func (c *Capturer) learnSDP(payload []byte, src, dst net.IP) {
	if !bytes.Contains(bytes.ToLower(payload), []byte("content-type: application/sdp")) && !bytes.Contains(payload, []byte("\r\nm=")) {
		return
	}
	var conn net.IP
	var mediaPort uint16
	lines := strings.Split(strings.ReplaceAll(string(payload), "\r\n", "\n"), "\n")
	now := time.Now().Add(2 * time.Hour)
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, line := range lines {
		f := strings.Fields(line)
		if len(f) >= 3 && f[0] == "c=IN" {
			conn = net.ParseIP(f[len(f)-1])
			if conn != nil && mediaPort > 0 {
				c.mediaKeys.put(c.media, mediaKey(conn, mediaPort), now)
				if mediaPort < 65535 {
					c.mediaKeys.put(c.media, mediaKey(conn, mediaPort+1), now)
				}
			}
		}
		if len(f) >= 2 && strings.HasPrefix(f[0], "m=") {
			p, err := strconv.Atoi(f[1])
			if err != nil || p < 1 || p > 65535 {
				continue
			}
			ip := conn
			if ip == nil {
				ip = src
			}
			mediaPort = uint16(p)
			c.mediaKeys.put(c.media, mediaKey(ip, mediaPort), now)
			// RTCP often uses the adjacent odd port; an explicit a=rtcp is also learned below.
			if p < 65535 {
				c.mediaKeys.put(c.media, mediaKey(ip, uint16(p+1)), now)
			}
		}
		if len(f) >= 2 && strings.HasPrefix(f[0], "a=rtcp:") {
			p, err := strconv.Atoi(strings.TrimPrefix(f[0], "a=rtcp:"))
			if err == nil && p > 0 && p <= 65535 {
				ip := conn
				if ip == nil {
					ip = dst
				}
				c.mediaKeys.put(c.media, mediaKey(ip, uint16(p)), now)
			}
		}
	}
}

func (c *Capturer) isLearnedMedia(src, dst net.IP, sp, dp uint16) bool {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	return now.Before(c.media[mediaKey(src, sp)]) || now.Before(c.media[mediaKey(dst, dp)])
}

func (c *Capturer) isDuplicate(src, dst net.IP, sp, dp uint16, payload []byte) bool {
	// Equal SIP payloads are not proof of mirrored copies: all retransmissions
	// remain evidence, even inside the operator's media deduplication window.
	if c.cfg.DedupeWindow == 0 || isSIP(payload) || c.sipSet[sp] || c.sipSet[dp] {
		return false
	}
	h := sha256.New()
	h.Write(src)
	h.Write(dst)
	var ports [4]byte
	binary.BigEndian.PutUint16(ports[0:2], sp)
	binary.BigEndian.PutUint16(ports[2:4], dp)
	h.Write(ports[:])
	h.Write(payload)
	var key [32]byte
	copy(key[:], h.Sum(nil))
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if until, ok := c.dedup[key]; ok && now.Before(until) {
		return true
	}
	c.dedupKeys.put(c.dedup, key, now.Add(c.cfg.DedupeWindow))
	return false
}

// classify decides whether a packet matches the configured selection and returns
// its HEP payload type. It uses packet-local signatures and port heuristics, so it
// reduces rather than eliminates false positives; it does not reassemble TCP segments.
func (c *Capturer) classify(srcPort, dstPort uint16, p []byte) (proto byte, want bool) {
	// SIP matches a configured port or an initial-line signature.
	if c.sipSet[srcPort] || c.sipSet[dstPort] || isSIP(p) {
		c.mu.Lock()
		c.counts.sip++
		c.mu.Unlock()
		return hep.ProtoSIP, true
	}
	if !c.cfg.WantRTP && !c.cfg.WantRTCP {
		return 0, false
	}
	// RTP/RTCP packets use version 2 in the high two bits of the first byte.
	if len(p) < 12 || (p[0]>>6) != 2 {
		c.mu.Lock()
		c.counts.other++
		c.mu.Unlock()
		return 0, false
	}
	// Reject common service and signaling ports before treating an RTP-looking payload
	// as media. RTP port allocation is deployment-specific, so this is a guardrail.
	if isWellKnown(srcPort) || isWellKnown(dstPort) || srcPort < 1024 || dstPort < 1024 {
		c.mu.Lock()
		c.counts.other++
		c.mu.Unlock()
		return 0, false
	}
	pt := p[1] & 0x7f
	// RFC 5761 reserves payload types 64-95 for RTCP multiplexing (SR=200 through XR=207).
	if pt >= 64 && pt <= 95 {
		if c.cfg.WantRTCP {
			c.mu.Lock()
			c.counts.rtcp++
			c.mu.Unlock()
			return hep.ProtoRTCP, true
		}
		return 0, false
	}
	if c.cfg.WantRTP {
		c.mu.Lock()
		c.counts.rtp++
		c.mu.Unlock()
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

// isSIP recognizes only common SIP request methods and the SIP/2.0 status prefix.
// It intentionally does not parse headers, bodies, or TCP-reassembled messages.
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

// Counts returns cumulative classification counters for aggregate operational status.
func (c *Capturer) Counts() (sip, rtp, rtcp, other uint64) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.counts.sip, c.counts.rtp, c.counts.rtcp, c.counts.other
}

// RtpDirs returns the reporting heuristic split between RFC 1918 IPv4 source and
// every other source. It does not prove call direction, NAT direction, or ownership.
func (c *Capturer) RtpDirs() (self, peer uint64) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.counts.rtpSelf, c.counts.rtpPeer
}

// Health returns cumulative probe counters plus best-effort libpcap statistics.
// Kernel statistics are unavailable on some capture sources and are not an SLA.
func (c *Capturer) Health() (duplicate, untrusted, queueDropped, pciSuppressed uint64, kernelRecv, kernelDrop, ifaceDrop int) {
	c.mu.RLock()
	duplicate, untrusted, queueDropped, pciSuppressed = c.counts.duplicate, c.counts.untrusted, c.counts.queueDropped, c.counts.pciSuppressed
	c.mu.RUnlock()
	c.handleMu.Lock()
	defer c.handleMu.Unlock()
	if c.handle != nil && !c.handleClosed {
		if st, err := c.handle.Stats(); err == nil {
			c.kernelStats = *st
		}
	}
	kernelRecv, kernelDrop, ifaceDrop = c.kernelStats.PacketsReceived, c.kernelStats.PacketsDropped, c.kernelStats.PacketsIfDropped
	return
}
