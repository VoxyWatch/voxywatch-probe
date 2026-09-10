// Command voxywatch-probe passively captures observable SIP, RTP, and RTCP packets
// and forwards HEPv3 records to VoxyWatch. It does not alter PBX/SBC configuration.
// It is licensed under FSL-1.1-Apache-2.0; see LICENSE.md for the use restrictions.
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

var version = "0.2.1-beta"

// writeStatus atomically replaces the optional, best-effort runtime snapshot.
// A status-write failure must not interrupt capture or delivery.
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
	log.Printf("VoxyWatch Probe v%s — starting", version)
	if cfg.IfaceAuto {
		log.Printf("[auto] default-route interface detected: %s", cfg.Iface)
	}
	if err := run(cfg); err != nil {
		log.Printf("capture: %v", err)
		os.Exit(1)
	}
}

// run owns shutdown: stop capture, join its worker, drain/account sends, and write
// final counters. Returning through this path also covers offline EOF and errors.
func run(cfg *config.Config) error {
	snd := sender.New(cfg.Transport, cfg.HEPServer, cfg.QueueSize)
	defer snd.Close()
	cap, err := capture.New(cfg, snd)
	if err != nil {
		return err
	}
	defer cap.Close()

	// Publish aggregate counters every 10 seconds for operational observation only.
	status := func() {
		sip, rtp, rtcp, other := cap.Counts()
		self, peer := cap.RtpDirs()
		sent, errs, senderDrop := snd.Stats()
		dup, untrusted, _, pci, recv, kernelDrop, ifaceDrop := cap.Health()
		log.Printf("[stats] sip=%d rtp=%d rtcp=%d other=%d sent=%d errors=%d drops(queue=%d kernel=%d iface=%d) dup=%d untrusted=%d",
			sip, rtp, rtcp, other, sent, errs, senderDrop, kernelDrop, ifaceDrop, dup, untrusted)
		// Sender is the authoritative owner of admission and shutdown drops.
		writeStatus(cfg.StatusFile, map[string]any{"version": version, "updated_at": time.Now().UTC().Format(time.RFC3339), "interface": cfg.Iface, "profile": cfg.Profile, "mode": cfg.Mode, "media_policy": cfg.MediaPolicy, "capture_id": cfg.CaptureID, "packets_received": recv, "sip": sip, "rtp": rtp, "rtcp": rtcp, "other": other, "rtp_self": self, "rtp_peer": peer, "sent": sent, "send_errors": errs, "queue_dropped": senderDrop, "kernel_dropped": kernelDrop, "interface_dropped": ifaceDrop, "duplicates": dup, "untrusted": untrusted, "pci_suppressed": pci})
	}

	// Handle termination signals so the pcap handle is closed before process exit.
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(ch)
	done := make(chan error, 1)
	go func() { done <- cap.Run() }()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			status()
		case <-ch:
			log.Printf("VoxyWatch Probe — stopping")
			cap.Close()
			err = <-done
			snd.Close()
			status()
			return err
		case err = <-done:
			cap.Close()
			snd.Close()
			status()
			return err
		}
	}
}
