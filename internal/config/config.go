// Package config carga la configuración del probe desde flags de línea de comando.
// (Fase posterior: archivo YAML /etc/voxywatch-probe/probe.yml.)
package config

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
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
	Iface     string   // interfaz a capturar (resuelta; "any" = todas)
	IfaceAuto bool     // true si se autodetectó
	HEPServer string   // host:port destino HEP (VoxyWatch)
	Transport string   // "udp" o "tcp"
	Mode      string   // sip | siprtcp | siprtp | all
	SIPPorts  []uint16 // puertos considerados SIP
	BPF       string   // filtro BPF extra (opcional)
	CaptureID uint32   // id del agente/sitio
	Snaplen   int
	Verbose   bool
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
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	c.CaptureID = uint32(*capID)

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
	if c.Iface == "" || c.Iface == "auto" {
		if d := detectDefaultIface(); d != "" {
			c.Iface = d
			c.IfaceAuto = true
		} else {
			c.Iface = "any" // último recurso: capturar todas
		}
	}
	return c, nil
}
