// Package hep construye paquetes HEPv3 (HEP3) — el formato que VoxyWatch (y Homer)
// ingieren. Portado de tools/send_test_calls.py del portal; layout de chunks idéntico
// para garantizar compatibilidad con el sniffer.
package hep

import (
	"bytes"
	"encoding/binary"
	"net"
)

// Protocol type (chunk 0x000b) — qué transporta el payload.
const (
	ProtoSIP   byte = 1
	ProtoRTP   byte = 4
	ProtoRTCP  byte = 5
	ProtoRTCPXR byte = 8
	ProtoLOG   byte = 100 // JSON de telemetría (métricas/host/eventos)
)

// IPFamily / IPProtocol
const (
	famINET  byte = 2  // AF_INET
	famINET6 byte = 10 // AF_INET6
)

// Packet describe un evento a encapsular en HEPv3.
type Packet struct {
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   uint16
	DstPort   uint16
	IPProto   byte   // 6=TCP, 17=UDP
	Proto     byte   // ProtoSIP / ProtoRTP / ...
	TsSec     uint32
	TsUsec    uint32
	CaptureID uint32
	Payload   []byte
}

func chunk(buf *bytes.Buffer, vendor, typeID uint16, payload []byte) {
	var hdr [6]byte
	binary.BigEndian.PutUint16(hdr[0:2], vendor)
	binary.BigEndian.PutUint16(hdr[2:4], typeID)
	binary.BigEndian.PutUint16(hdr[4:6], uint16(len(payload)+6))
	buf.Write(hdr[:])
	buf.Write(payload)
}

func chunkByte(buf *bytes.Buffer, vendor, typeID uint16, v byte)   { chunk(buf, vendor, typeID, []byte{v}) }
func chunkU16(buf *bytes.Buffer, vendor, typeID uint16, v uint16)  { b := make([]byte, 2); binary.BigEndian.PutUint16(b, v); chunk(buf, vendor, typeID, b) }
func chunkU32(buf *bytes.Buffer, vendor, typeID uint16, v uint32)  { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); chunk(buf, vendor, typeID, b) }

// Encode arma el datagrama HEPv3 completo listo para enviar por UDP/TCP.
func Encode(p *Packet) []byte {
	is6 := p.SrcIP.To4() == nil
	var chunks bytes.Buffer

	if is6 {
		chunkByte(&chunks, 0, 0x0001, famINET6)
	} else {
		chunkByte(&chunks, 0, 0x0001, famINET)
	}
	chunkByte(&chunks, 0, 0x0002, p.IPProto) // IP protocol id (UDP/TCP)

	if is6 {
		chunk(&chunks, 0, 0x0005, p.SrcIP.To16()) // IPv6 src
		chunk(&chunks, 0, 0x0006, p.DstIP.To16()) // IPv6 dst
	} else {
		chunk(&chunks, 0, 0x0003, p.SrcIP.To4()) // IPv4 src
		chunk(&chunks, 0, 0x0004, p.DstIP.To4()) // IPv4 dst
	}
	chunkU16(&chunks, 0, 0x0007, p.SrcPort)
	chunkU16(&chunks, 0, 0x0008, p.DstPort)
	chunkU32(&chunks, 0, 0x0009, p.TsSec)
	chunkU32(&chunks, 0, 0x000a, p.TsUsec)
	chunkByte(&chunks, 0, 0x000b, p.Proto)      // protocol type
	chunkU32(&chunks, 0, 0x000c, p.CaptureID)   // capture agent id
	chunk(&chunks, 0, 0x000f, p.Payload)        // payload

	var out bytes.Buffer
	out.WriteString("HEP3")
	var total [2]byte
	binary.BigEndian.PutUint16(total[:], uint16(chunks.Len()+6))
	out.Write(total[:])
	out.Write(chunks.Bytes())
	return out.Bytes()
}
