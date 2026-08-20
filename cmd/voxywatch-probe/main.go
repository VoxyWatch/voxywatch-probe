// voxywatch-probe — agente de captura SIP/RTP/RTCP que reenvía a VoxyWatch por HEPv3.
// Licencia: FSL-1.1-Apache-2.0 (ver LICENSE.md).
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/voxywatch/voxywatch-probe/internal/capture"
	"github.com/voxywatch/voxywatch-probe/internal/config"
	"github.com/voxywatch/voxywatch-probe/internal/sender"
)

var version = "0.2.0-beta"

func writeStatus(path string, value any) {
	if path == "" {
		return
	}
	b, err := json.Marshal(value)
	if err != nil {
		return
	}
	if err = os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return
	}
	tmp := path + ".tmp"
	if err = os.WriteFile(tmp, append(b, '\n'), 0640); err == nil {
		_ = os.Rename(tmp, path)
	}
}

func main() {
	log.SetFlags(log.LstdFlags)
	if len(os.Args) == 2 && (os.Args[1] == "--version" || os.Args[1] == "-version") {
		fmt.Printf("voxywatch-probe %s\n", version)
		return
	}
	cfg, err := config.Parse(os.Args[1:])
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	log.Printf("VoxyWatch Probe v%s — iniciando", version)
	if cfg.IfaceAuto {
		log.Printf("[auto] interfaz detectada automáticamente: %s", cfg.Iface)
	}

	snd := sender.New(cfg.Transport, cfg.HEPServer, cfg.QueueSize)
	defer snd.Close()
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
			sent, errs, senderDrop := snd.Stats()
			dup, untrusted, queueDrop, pci, recv, kernelDrop, ifaceDrop := cap.Health()
			log.Printf("[stats] sip=%d rtp=%d rtcp=%d other=%d sent=%d errors=%d drops(queue=%d kernel=%d iface=%d) dup=%d untrusted=%d",
				sip, rtp, rtcp, other, sent, errs, queueDrop+senderDrop, kernelDrop, ifaceDrop, dup, untrusted)
			writeStatus(cfg.StatusFile, map[string]any{"version": version, "updated_at": time.Now().UTC().Format(time.RFC3339), "interface": cfg.Iface, "profile": cfg.Profile, "mode": cfg.Mode, "media_policy": cfg.MediaPolicy, "capture_id": cfg.CaptureID, "packets_received": recv, "sip": sip, "rtp": rtp, "rtcp": rtcp, "other": other, "rtp_self": self, "rtp_peer": peer, "sent": sent, "send_errors": errs, "queue_dropped": queueDrop + senderDrop, "kernel_dropped": kernelDrop, "interface_dropped": ifaceDrop, "duplicates": dup, "untrusted": untrusted, "pci_suppressed": pci})
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
