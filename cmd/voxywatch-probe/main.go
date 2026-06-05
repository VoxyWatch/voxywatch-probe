// voxywatch-probe — agente de captura SIP/RTP/RTCP que reenvía a VoxyWatch por HEPv3.
// Licencia: FSL-1.1-Apache-2.0 (ver LICENSE.md).
package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/voxywatch/voxywatch-probe/internal/capture"
	"github.com/voxywatch/voxywatch-probe/internal/config"
	"github.com/voxywatch/voxywatch-probe/internal/sender"
)

var version = "0.1.0-mvp"

func main() {
	log.SetFlags(log.LstdFlags)
	cfg, err := config.Parse(os.Args[1:])
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	log.Printf("VoxyWatch Probe v%s — iniciando", version)
	if cfg.IfaceAuto {
		log.Printf("[auto] interfaz detectada automáticamente: %s", cfg.Iface)
	}

	snd := sender.New(cfg.Transport, cfg.HEPServer)
	cap, err := capture.New(cfg, snd)
	if err != nil {
		log.Fatalf("capture: %v", err)
	}
	defer cap.Close()

	// Stats periódicas
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for range t.C {
			sip, rtp, rtcp, other := cap.Counts()
			self, peer := cap.RtpDirs()
			sent, errs := snd.Stats()
			log.Printf("[stats] sip=%d rtp=%d (saliente=%d entrante=%d) rtcp=%d other=%d | enviados=%d errores=%d",
				sip, rtp, self, peer, rtcp, other, sent, errs)
		}
	}()

	// Señales para salida limpia
	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
		<-ch
		log.Printf("VoxyWatch Probe — deteniendo")
		cap.Close()
		os.Exit(0)
	}()

	if err := cap.Run(); err != nil {
		log.Fatalf("capture run: %v", err)
	}
}
