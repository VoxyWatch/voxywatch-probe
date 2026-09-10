// Package hep encodes HEPv3 records for VoxyWatch-compatible receivers.
// It owns the wire layout used by this probe; callers supply observed packet metadata.
package hep

import (
	"bytes"
	"encoding/binary"
	"net"
)

// HEP protocol-type values for chunk 0x000b identify the payload carried by a record.
const (
	ProtoSIP    byte = 1
	ProtoRTP    byte = 4
	ProtoRTCP   byte = 5
	ProtoRTCPXR byte = 8
	ProtoLOG    byte = 100 // JSON telemetry such as aggregate metrics or host events.
)

// HEP IP-family values; IPProto in Packet uses the IANA transport protocol number.
const (
	famINET  byte = 2  // AF_INET
	famINET6 byte = 10 // AF_INET6
)

// Packet is one observed transport payload and the metadata required to encode it.
// SrcIP and DstIP must belong to the same IP family; invalid inputs encode as nil.
type Packet struct {
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   uint16
	DstPort   uint16
	IPProto   byte // IANA protocol number: TCP is 6 and UDP is 17.
	Proto     byte // HEP payload type, for example ProtoSIP or ProtoRTP.
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

func chunkByte(buf *bytes.Buffer, vendor, typeID uint16, v byte) {
	chunk(buf, vendor, typeID, []byte{v})
}
func chunkU16(buf *bytes.Buffer, vendor, typeID uint16, v uint16) {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	chunk(buf, vendor, typeID, b)
}
func chunkU32(buf *bytes.Buffer, vendor, typeID uint16, v uint32) {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	chunk(buf, vendor, typeID, b)
}

// Encode returns one complete HEPv3 record. The same length-prefixed record is
// suitable for UDP or for sequential writing to a TCP stream; it adds no TLS,
// fragmentation handling, or transport retry policy.
func Encode(p *Packet) []byte {
	if p == nil || p.SrcIP.To16() == nil || p.DstIP.To16() == nil || p.TsUsec >= 1000000 {
		return nil
	}
	is6 := p.SrcIP.To4() == nil
	if is6 != (p.DstIP.To4() == nil) {
		return nil
	}
	// The fixed envelope is 99 bytes for IPv4 and 123 for IPv6. Check before
	// allocating or narrowing either the payload chunk or total length to uint16.
	overhead := 99
	if is6 {
		overhead = 123
	}
	if len(p.Payload) > 65535-overhead {
		return nil
	}
	var chunks bytes.Buffer

	if is6 {
		chunkByte(&chunks, 0, 0x0001, famINET6)
	} else {
		chunkByte(&chunks, 0, 0x0001, famINET)
	}
	chunkByte(&chunks, 0, 0x0002, p.IPProto) // IANA transport protocol number.

	if is6 {
		chunk(&chunks, 0, 0x0005, p.SrcIP.To16()) // IPv6 source address.
		chunk(&chunks, 0, 0x0006, p.DstIP.To16()) // IPv6 destination address.
	} else {
		chunk(&chunks, 0, 0x0003, p.SrcIP.To4()) // IPv4 source address.
		chunk(&chunks, 0, 0x0004, p.DstIP.To4()) // IPv4 destination address.
	}
	chunkU16(&chunks, 0, 0x0007, p.SrcPort)
	chunkU16(&chunks, 0, 0x0008, p.DstPort)
	chunkU32(&chunks, 0, 0x0009, p.TsSec)
	chunkU32(&chunks, 0, 0x000a, p.TsUsec)
	chunkByte(&chunks, 0, 0x000b, p.Proto)    // HEP payload type.
	chunkU32(&chunks, 0, 0x000c, p.CaptureID) // Capture-agent identifier.
	chunk(&chunks, 0, 0x000f, p.Payload)      // Observed transport payload.

	var out bytes.Buffer
	out.WriteString("HEP3")
	var total [2]byte
	binary.BigEndian.PutUint16(total[:], uint16(chunks.Len()+6))
	out.Write(total[:])
	out.Write(chunks.Bytes())
	return out.Bytes()
}
