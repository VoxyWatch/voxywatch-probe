// Package config carga la configuración del probe desde flags de línea de comando.
// (Fase posterior: archivo YAML /etc/voxywatch-probe/probe.yml.)
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

// detectDefaultIface devuelve la interfaz de la ruta por defecto (la que lleva al
// gateway) leyendo /proc/net/route. Así el agente viene "preconfigurado": no hay
// que indicarle la interfaz, elige sola la del tráfico de voz. "" si no la encuentra.
func detectDefaultIface() string {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n")[1:] {
		f := strings.Fields(line)
		// Campo[1]=Destination, Campo[3]=Flags. Default route: Destination 00000000 + RTF_UP|RTF_GATEWAY.
		if len(f) >= 4 && f[1] == "00000000" {
			return f[0]
		}
	}
	return ""
}

type Config struct {
	Iface        string   // interfaz a capturar (resuelta; "any" = todas)
	IfaceAuto    bool     // true si se autodetectó
	HEPServer    string   // host:port destino HEP (VoxyWatch)
	Transport    string   // "udp" o "tcp"
	Mode         string   // sip | siprtcp | siprtp | all
	SIPPorts     []uint16 // puertos considerados SIP
	BPF          string   // filtro BPF extra (opcional)
	CaptureID    uint32   // id del agente/sitio
	Snaplen      int
	Verbose      bool
	Profile      string // span | rspan | erspan | aws-vxlan | auto
	MediaPolicy  string // learned (safe) | heuristic (advanced)
	TrustedCIDRs []*net.IPNet
	QueueSize    int
	DedupeWindow time.Duration
	StatusFile   string
	PCAPFile     string // offline replay for validation; never used by the service launcher
	// Derivados del modo:
	WantRTP  bool
	WantRTCP bool
}

func Parse(args []string) (*Config, error) {
	fs := flag.NewFlagSet("voxywatch-probe", flag.ContinueOnError)
	c := &Config{}
	fs.StringVar(&c.Iface, "i", "auto", "interfaz de red (auto = detecta la principal · any = todas)")
	fs.StringVar(&c.HEPServer, "hs", "127.0.0.1:9060", "destino HEP de VoxyWatch (host:port)")
	fs.StringVar(&c.Transport, "t", "udp", "transporte HEP: udp | tcp")
	fs.StringVar(&c.Mode, "m", "siprtp", "modo: sip | siprtcp | siprtp | all")
	sipPorts := fs.String("sip-ports", "5060,5061", "puertos SIP separados por coma")
	fs.StringVar(&c.BPF, "bpf", "", "filtro BPF adicional (avanzado)")
	capID := fs.Uint("capture-id", 2001, "capture/agent id")
	fs.IntVar(&c.Snaplen, "snaplen", 65535, "bytes máximos por paquete")
	fs.BoolVar(&c.Verbose, "v", false, "log detallado")
	fs.StringVar(&c.Profile, "profile", "auto", "encapsulación: auto | span | rspan | erspan | aws-vxlan")
	fs.StringVar(&c.MediaPolicy, "media-policy", "learned", "RTP: learned (SDP) | heuristic (avanzado)")
	trusted := fs.String("trusted-cidrs", "", "CIDR/IP de SBCs, separados por coma (recomendado)")
	fs.IntVar(&c.QueueSize, "queue-size", 8192, "cola HEP acotada")
	dedupeMs := fs.Int("dedupe-ms", 1500, "ventana de deduplicación del mirror")
	fs.StringVar(&c.StatusFile, "status-file", "/run/voxywatch-probe/status.json", "snapshot JSON de salud")
	fs.StringVar(&c.PCAPFile, "read-pcap", "", "reproducir un PCAP offline (validación)")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	c.CaptureID = uint32(*capID)
	if c.QueueSize < 256 || c.QueueSize > 262144 {
		return nil, fmt.Errorf("queue-size fuera de rango: %d", c.QueueSize)
	}
	if *dedupeMs < 0 || *dedupeMs > 10000 {
		return nil, fmt.Errorf("dedupe-ms fuera de rango: %d", *dedupeMs)
	}
	c.DedupeWindow = time.Duration(*dedupeMs) * time.Millisecond
	if !map[string]bool{"auto": true, "span": true, "rspan": true, "erspan": true, "aws-vxlan": true}[c.Profile] {
		return nil, fmt.Errorf("profile inválido: %q", c.Profile)
	}
	if c.MediaPolicy != "learned" && c.MediaPolicy != "heuristic" {
		return nil, fmt.Errorf("media-policy inválida: %q", c.MediaPolicy)
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
			return nil, fmt.Errorf("trusted-cidrs inválido: %q", raw)
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
			return nil, fmt.Errorf("puerto SIP inválido: %q", p)
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
		return nil, fmt.Errorf("modo inválido: %q (usa sip|siprtcp|siprtp|all)", c.Mode)
	}
	if c.Transport != "udp" && c.Transport != "tcp" {
		return nil, fmt.Errorf("transporte inválido: %q", c.Transport)
	}

	// Auto-configuración de la interfaz: el agente elige sola la principal.
	if c.PCAPFile == "" && (c.Iface == "" || c.Iface == "auto") {
		if d := detectDefaultIface(); d != "" {
			c.Iface = d
			c.IfaceAuto = true
		} else {
			return nil, fmt.Errorf("no se pudo detectar una interfaz; usa -i con la NIC espejo dedicada")
		}
	}
	return c, nil
}
