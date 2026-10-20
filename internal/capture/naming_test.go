package capture

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPCINamingCompatibility(t *testing.T) {
	t.Setenv("VOXYWATCH_PCI_FILE", "")
	t.Setenv("VW_PROBE_PCI_FILE", "")
	primary, fallback := pciPaths()
	if primary != "/etc/voxywatch-capture-agent/pci_suppress.json" || fallback != "/etc/voxywatch-probe/pci_suppress.json" {
		t.Fatalf("unexpected default paths: %q %q", primary, fallback)
	}
	t.Setenv("VW_PROBE_PCI_FILE", "/legacy-explicit")
	if p, f := pciPaths(); p != "/legacy-explicit" || f != "" {
		t.Fatal("legacy explicit override was not preserved")
	}
	t.Setenv("VOXYWATCH_PCI_FILE", "/canonical-explicit")
	if p, f := pciPaths(); p != "/canonical-explicit" || f != "" {
		t.Fatal("canonical explicit override must take precedence")
	}
}

func TestPCILegacyFileFallbackOnlyWhenCanonicalAbsent(t *testing.T) {
	dir := t.TempDir()
	primary, fallback := filepath.Join(dir, "new.json"), filepath.Join(dir, "old.json")
	if err := os.WriteFile(fallback, []byte(`{"calls":[{"flows":{"ssrc_caller":111}}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	c := &Capturer{pciPath: primary, pciFallback: fallback, pciSSRCs: map[uint32]bool{}}
	c.reloadPCI()
	if !c.pciSSRCs[111] {
		t.Fatal("active legacy suppression ignored")
	}
	if err := os.WriteFile(primary, []byte(`{"calls":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	c.pciLastCheck = 0
	c.reloadPCI()
	if len(c.pciSSRCs) != 0 {
		t.Fatal("canonical empty file must override legacy state")
	}
	if err := os.WriteFile(primary, []byte(`invalid`), 0600); err != nil {
		t.Fatal(err)
	}
	c.pciLastCheck = 0
	c.reloadPCI()
	if len(c.pciSSRCs) != 0 {
		t.Fatal("invalid primary must not fall back to a different control file")
	}
}
