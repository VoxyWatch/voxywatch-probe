package config

import "testing"

func TestCaptureIDDoesNotWrap(t *testing.T) {
	for _, value := range []string{"4294967296", "18446744073709551615", "-1"} {
		if _, err := Parse([]string{"-i", "any", "-capture-id", value}); err == nil {
			t.Fatalf("accepted unrepresentable capture-id %s", value)
		}
	}
	c, err := Parse([]string{"-i", "any", "-capture-id", "4294967295"})
	if err != nil || c.CaptureID != 4294967295 {
		t.Fatalf("maximum ID rejected: %v", err)
	}
}

func TestCaptureIDIsAlwaysDecimal(t *testing.T) {
	for value, want := range map[string]uint32{"010": 10, "08": 8, "000": 0, "0004294967295": 4294967295} {
		c, err := Parse([]string{"-i", "any", "-capture-id", value})
		if err != nil || c.CaptureID != want {
			t.Fatalf("%s parsed incorrectly: config=%v error=%v", value, c, err)
		}
	}
	for _, value := range []string{"0x10", "0b10", "0o10", "1_000", "+1", " 1", ""} {
		if _, err := Parse([]string{"-i", "any", "-capture-id", value}); err == nil {
			t.Fatalf("accepted non-decimal ID %q", value)
		}
	}
}
