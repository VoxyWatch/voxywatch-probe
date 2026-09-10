package capture

import (
 "encoding/binary"
 "net"
 "os"
 "path/filepath"
 "testing"
 "time"
 "github.com/google/gopacket"
 "github.com/google/gopacket/layers"
 "github.com/voxywatch/voxywatch-probe/internal/config"
 "github.com/voxywatch/voxywatch-probe/internal/sender"
)

func TestIndependentPCIPortalHexDoesNotLeaveSource(t *testing.T) {
 path := filepath.Join(t.TempDir(), "pci.json")
 if err:=os.WriteFile(path, []byte(`{"calls":[{"flows":{"ssrc_caller":"12345678"}}]}`),0600); err!=nil {t.Fatal(err)}
 ln,err:=net.ListenPacket("udp","127.0.0.1:0"); if err!=nil {t.Fatal(err)}; defer ln.Close()
 snd:=sender.New("udp",ln.LocalAddr().String(),16); defer snd.Close()
 c:=&Capturer{cfg:&config.Config{WantRTP:true, MediaPolicy:"heuristic"},snd:snd,pciPath:path,pciSSRCs:map[uint32]bool{},dedup:map[[32]byte]time.Time{}}
 payload:=make([]byte,32); payload[0]=0x80; binary.BigEndian.PutUint32(payload[8:12],0x12345678)
 frame:=ethernetUDP(t,"192.0.2.1","198.51.100.1",20000,30000,payload)
 c.handle_(gopacket.NewPacket(frame,layers.LayerTypeEthernet,gopacket.Default)); snd.Close()
 sent,errs,drops:=snd.Stats()
 if sent!=0 || c.counts.pciSuppressed!=1 {t.Fatalf("payment RTP escaped source: sent=%d errors=%d drops=%d suppressed=%d",sent,errs,drops,c.counts.pciSuppressed)}
}
