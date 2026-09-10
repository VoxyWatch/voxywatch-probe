// Package config parses the probe's command-line configuration.
// It deliberately has no configuration-file reader at this stage.
package config

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// detectDefaultIface returns the Linux default-route interface from /proc/net/route.
// It is a convenience fallback, not voice-traffic detection: the default NIC may not
// carry the mirrored SIP/RTP traffic. It returns "" when no default route is found.
func detectDefaultIface() string {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n")[1:] {
		f := strings.Fields(line)
		// Field 1 is Destination; 00000000 denotes the IPv4 default route.
		if len(f) >= 4 && f[1] == "00000000" {
			return f[0]
		}
	}
	return ""
}

// Config owns the validated runtime settings shared by capture and delivery.
// Snaplen is bytes, QueueSize is a record count, and DedupeWindow is a Go duration.
type Config struct {
	Iface        string        // Resolved capture interface; "any" asks libpcap for all interfaces.
	IfaceAuto    bool          // True only when Iface came from the default-route fallback.
	HEPServer    string        // HEP receiver host:port.
	Transport    string        // HEP transport: "udp" or "tcp".
	Mode         string        // Capture selection: sip, siprtcp, siprtp, or all.
	SIPPorts     []uint16      // Ports treated as SIP in addition to payload signatures.
	BPF          string        // Optional operator-supplied libpcap BPF expression.
	CaptureID    uint32        // HEP capture-agent/site identifier.
	Snaplen      int           // Maximum captured bytes per packet.
	Verbose      bool          // Enables additional operational logging.
	Profile      string        // Declared mirror topology: span, rspan, erspan, aws-vxlan, or auto.
	MediaPolicy  string        // RTP admission: learned (SDP evidence) or heuristic (advanced).
	TrustedCIDRs []*net.IPNet  // Optional source/destination allowlist for observed packets.
	QueueSize    int           // Maximum in-memory HEP records waiting for delivery.
	DedupeWindow time.Duration // Media duplicate-suppression interval; SIP is never deduplicated.
	StatusFile   string        // Optional path for the best-effort JSON status snapshot.
	PCAPFile     string        // Offline replay input for validation; the service launcher does not set it.
	// Derived from Mode after validation:
	WantRTP  bool
	WantRTCP bool
}

// Parse validates command-line arguments and derives the capture selection.
// When -i is auto, it chooses the default-route NIC only; operators must select
// the mirror NIC explicitly whenever it differs.
func Parse(args []string) (*Config, error) {
	fs := flag.NewFlagSet("voxywatch-probe", flag.ContinueOnError)
	c := &Config{}
	fs.StringVar(&c.Iface, "i", "auto", "network interface (auto = default-route NIC; any = all interfaces)")
	fs.StringVar(&c.HEPServer, "hs", "127.0.0.1:9060", "VoxyWatch HEP destination (host:port)")
	fs.StringVar(&c.Transport, "t", "udp", "HEP transport: udp | tcp")
	fs.StringVar(&c.Mode, "m", "siprtp", "capture mode: sip | siprtcp | siprtp | all")
	sipPorts := fs.String("sip-ports", "5060,5061", "comma-separated SIP ports")
	fs.StringVar(&c.BPF, "bpf", "", "additional libpcap BPF filter (advanced)")
	capID := fs.String("capture-id", "2001", "capture/agent ID (decimal uint32; leading zeros remain decimal)")
	fs.IntVar(&c.Snaplen, "snaplen", 65535, "maximum captured bytes per packet")
	fs.BoolVar(&c.Verbose, "v", false, "verbose logging")
	fs.StringVar(&c.Profile, "profile", "auto", "encapsulation: auto | span | rspan | erspan | aws-vxlan")
	fs.StringVar(&c.MediaPolicy, "media-policy", "learned", "RTP: learned (SDP) | heuristic (advanced)")
	trusted := fs.String("trusted-cidrs", "", "comma-separated trusted SBC CIDRs/IPs (recommended)")
	fs.IntVar(&c.QueueSize, "queue-size", 8192, "bounded HEP queue size")
	dedupeMs := fs.Int("dedupe-ms", 1500, "media deduplication window in milliseconds; preserves SIP retransmissions")
	fs.StringVar(&c.StatusFile, "status-file", "/run/voxywatch-probe/status.json", "JSON health snapshot path")
	fs.StringVar(&c.PCAPFile, "read-pcap", "", "replay an offline PCAP (validation)")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	id, err := strconv.ParseUint(*capID, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("capture-id must be a decimal integer between 0 and 4294967295")
	}
	c.CaptureID = uint32(id)
	if c.QueueSize < 256 || c.QueueSize > 262144 {
		return nil, fmt.Errorf("queue-size out of range: %d", c.QueueSize)
	}
	if *dedupeMs < 0 || *dedupeMs > 10000 {
		return nil, fmt.Errorf("dedupe-ms out of range: %d", *dedupeMs)
	}
	c.DedupeWindow = time.Duration(*dedupeMs) * time.Millisecond
	if !map[string]bool{"auto": true, "span": true, "rspan": true, "erspan": true, "aws-vxlan": true}[c.Profile] {
		return nil, fmt.Errorf("invalid profile: %q", c.Profile)
	}
	if c.MediaPolicy != "learned" && c.MediaPolicy != "heuristic" {
		return nil, fmt.Errorf("invalid media-policy: %q", c.MediaPolicy)
	}
	for _, raw := range strings.Split(*trusted, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if !strings.Contains(raw, "/") {
			if strings.Contains(raw, ":") {
				raw += "/128"
			} else {
				raw += "/32"
			}
		}
		_, n, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted-cidrs: %q", raw)
		}
		c.TrustedCIDRs = append(c.TrustedCIDRs, n)
	}

	for _, p := range strings.Split(*sipPorts, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("invalid SIP port: %q", p)
		}
		c.SIPPorts = append(c.SIPPorts, uint16(n))
	}

	switch c.Mode {
	case "sip":
		c.WantRTP, c.WantRTCP = false, false
	case "siprtcp":
		c.WantRTP, c.WantRTCP = false, true
	case "siprtp":
		c.WantRTP, c.WantRTCP = true, true
	case "all":
		c.WantRTP, c.WantRTCP = true, true
	default:
		return nil, fmt.Errorf("invalid mode: %q (use sip|siprtcp|siprtp|all)", c.Mode)
	}
	if c.Transport != "udp" && c.Transport != "tcp" {
		return nil, fmt.Errorf("invalid transport: %q", c.Transport)
	}

	// Use the default-route NIC only as an explicit fallback, never as proof of voice visibility.
	if c.PCAPFile == "" && (c.Iface == "" || c.Iface == "auto") {
		if d := detectDefaultIface(); d != "" {
			c.Iface = d
			c.IfaceAuto = true
		} else {
			return nil, fmt.Errorf("could not detect an interface; use -i with the dedicated mirror NIC")
		}
	}
	return c, nil
}
