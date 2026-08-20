// Package capture lee paquetes de la red con libpcap (gopacket/pcap) — captura
// AMBOS sentidos del tráfico (incl. el saliente del propio host, que afpacket no
// entrega), clasifica SIP / RTP / RTCP y los entrega encapsulados en HEPv3.
package capture

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
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

type Capturer struct {
	cfg    *config.Config
	handle *pcap.Handle
	snd    *sender.Sender
	sipSet map[uint16]bool
	counts struct {
		sip, rtp, rtcp, other, rtpSelf, rtpPeer, pciSuppressed, duplicate, untrusted, queueDropped uint64
	}
	mu    sync.RWMutex
	media map[string]time.Time
	dedup map[[32]byte]time.Time
	// Modo PCI (F1c): SSRC cuyo RTP NO se envía durante una ventana de pago (corte en ORIGEN).
	// Se relee de pciPath (JSON con calls[].flows.ssrc_*) en caliente. Vacío → sin efecto.
	pciSSRCs     map[uint32]bool
	pciPath      string
	pciMtime     int64
	pciLastCheck int64
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
	// Handle con IMMEDIATE MODE: entrega cada paquete en cuanto llega, sin esperar a que
	// se llene el buffer del kernel. Sin esto, en loopback (lo/any) la captura se "congela"
	// intermitentemente (el buffer no se vacía a tiempo y ReadPacketData se atasca). Además
	// subimos el buffer a 8 MB para absorber ráfagas. Fallback a OpenLive si algo falla.
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
			return nil, fmt.Errorf("pcap.OpenLive(%s): %w (¿permisos root/CAP_NET_RAW?)", iface, err)
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
		pciSSRCs: map[uint32]bool{}, pciPath: pciPath}
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

// reloadPCI relee pciPath (throttle 1s + mtime) → pciSSRCs. Mismo formato que escribe el portal
// (calls[].flows.ssrc_caller/ssrc_callee). Ausente/vacío → mapa vacío → sin efecto.
func (c *Capturer) reloadPCI() {
	now := time.Now().Unix()
	if now-c.pciLastCheck < 1 {
		return
	}
	c.pciLastCheck = now
	fi, err := os.Stat(c.pciPath)
	if err != nil {
		if len(c.pciSSRCs) > 0 {
			c.pciSSRCs = map[uint32]bool{}
			c.pciMtime = 0
		}
		return
	}
	if fi.ModTime().Unix() == c.pciMtime {
		return
	}
	c.pciMtime = fi.ModTime().Unix()
	data, err := os.ReadFile(c.pciPath)
	if err != nil {
		return
	}
	var doc struct {
		Calls []struct {
			Flows struct {
				SsrcCaller string `json:"ssrc_caller"`
				SsrcCallee string `json:"ssrc_callee"`
			} `json:"flows"`
		} `json:"calls"`
	}
	if json.Unmarshal(data, &doc) != nil {
		return
	}
	set := map[uint32]bool{}
	for _, cl := range doc.Calls {
		for _, s := range []string{cl.Flows.SsrcCaller, cl.Flows.SsrcCallee} {
			if s == "" || s == "Unknown" || s == "None" {
				continue
			}
			if v, e := strconv.ParseUint(s, 10, 32); e == nil {
				set[uint32(v)] = true
			} else if v, e := strconv.ParseUint(s, 16, 32); e == nil {
				set[uint32(v)] = true
			}
		}
	}
	c.pciSSRCs = set
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
	if c.isDuplicate(srcIP, dstIP, srcPort, dstPort, payload) {
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
		// Modo PCI (F1c): no enviar el RTP de un SSRC en ventana de pago → corte en ORIGEN,
		// el dato sensible no sale del entorno seguro. reloadPCI() está auto-throttled.
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
				c.media[mediaKey(conn, mediaPort)] = now
				if mediaPort < 65535 {
					c.media[mediaKey(conn, mediaPort+1)] = now
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
			c.media[mediaKey(ip, mediaPort)] = now
			// RTCP commonly uses the adjacent odd port; explicit a=rtcp is learned below.
			if p < 65535 {
				c.media[mediaKey(ip, uint16(p+1))] = now
			}
		}
		if len(f) >= 2 && strings.HasPrefix(f[0], "a=rtcp:") {
			p, err := strconv.Atoi(strings.TrimPrefix(f[0], "a=rtcp:"))
			if err == nil && p > 0 && p <= 65535 {
				ip := conn
				if ip == nil {
					ip = dst
				}
				c.media[mediaKey(ip, uint16(p))] = now
			}
		}
	}
}

func (c *Capturer) isLearnedMedia(src, dst net.IP, sp, dp uint16) bool {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, until := range c.media {
		if now.After(until) {
			delete(c.media, k)
		}
	}
	return now.Before(c.media[mediaKey(src, sp)]) || now.Before(c.media[mediaKey(dst, dp)])
}

func (c *Capturer) isDuplicate(src, dst net.IP, sp, dp uint16, payload []byte) bool {
	if c.cfg.DedupeWindow == 0 {
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
	c.dedup[key] = now.Add(c.cfg.DedupeWindow)
	if len(c.dedup) > 65536 {
		for k, until := range c.dedup {
			if now.After(until) {
				delete(c.dedup, k)
			}
		}
	}
	return false
}

// classify decide el tipo de payload y si debe enviarse según el modo.
// Endurecido para evitar falsos positivos (DNS, multicast, STUN) clasificados como RTP.
func (c *Capturer) classify(srcPort, dstPort uint16, p []byte) (proto byte, want bool) {
	// SIP: por puerto conocido o por firma textual.
	if c.sipSet[srcPort] || c.sipSet[dstPort] || isSIP(p) {
		c.mu.Lock()
		c.counts.sip++
		c.mu.Unlock()
		return hep.ProtoSIP, true
	}
	if !c.cfg.WantRTP && !c.cfg.WantRTCP {
		return 0, false
	}
	// RTP/RTCP: versión 2 en los 2 bits altos del primer byte.
	if len(p) < 12 || (p[0]>>6) != 2 {
		c.mu.Lock()
		c.counts.other++
		c.mu.Unlock()
		return 0, false
	}
	// Descartar puertos de servicios bien conocidos (DNS 53, STUN 3478, etc.) y
	// puertos de señalización; el media RTP usa puertos efímeros altos.
	if isWellKnown(srcPort) || isWellKnown(dstPort) || srcPort < 1024 || dstPort < 1024 {
		c.mu.Lock()
		c.counts.other++
		c.mu.Unlock()
		return 0, false
	}
	pt := p[1] & 0x7f
	// RFC 5761: payload types 64-95 reservados → RTCP (SR=200..XR=207 → &0x7f = 72..79).
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
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.counts.sip, c.counts.rtp, c.counts.rtcp, c.counts.other
}

// RtpDirs: RTP con IP origen privada (saliente del host) vs pública (entrante).
func (c *Capturer) RtpDirs() (self, peer uint64) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.counts.rtpSelf, c.counts.rtpPeer
}

func (c *Capturer) Health() (duplicate, untrusted, queueDropped, pciSuppressed uint64, kernelRecv, kernelDrop, ifaceDrop int) {
	c.mu.RLock()
	duplicate, untrusted, queueDropped, pciSuppressed = c.counts.duplicate, c.counts.untrusted, c.counts.queueDropped, c.counts.pciSuppressed
	c.mu.RUnlock()
	if st, err := c.handle.Stats(); err == nil {
		kernelRecv, kernelDrop, ifaceDrop = st.PacketsReceived, st.PacketsDropped, st.PacketsIfDropped
	}
	return
}
