// Package config carga la configuración del probe desde flags de línea de comando.
// (Fase posterior: archivo YAML /etc/voxywatch-probe/probe.yml.)
package config

import (
	"flag"
	"fmt"
	"strconv"
	"strings"
)

type Config struct {
	Iface     string   // interfaz a capturar ("any" = todas)
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
	fs.StringVar(&c.Iface, "i", "any", "interfaz de red a capturar (any = todas)")
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
	return c, nil
}
