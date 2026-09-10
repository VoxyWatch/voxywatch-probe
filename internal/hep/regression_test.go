package hep

import (
	"net"
	"testing"
)

func TestInvalidMetadataRejected(t *testing.T) {
	ip4, ip6 := net.ParseIP("192.0.2.1"), net.ParseIP("2001:db8::1")
	for _, p := range []*Packet{nil, {}, {SrcIP: ip4, DstIP: ip6}, {SrcIP: ip6, DstIP: ip4}, {SrcIP: ip4, DstIP: ip4, TsUsec: 1000000}} {
		if len(Encode(p)) != 0 {
			t.Fatal("invalid metadata emitted")
		}
	}
}
