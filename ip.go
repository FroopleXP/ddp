package main

import (
	"fmt"
	"strings"
	"io"
	"strconv"
)

const (
	IPPacketHeaderSize = 20
)

type IPAddress uint32

func (ip IPAddress) String() string {
	a, b, c, d :=
		uint8(ip>>24), uint8(ip>>16), uint8(ip>>8), uint8(ip)
	return fmt.Sprintf("%d.%d.%d.%d", a, b, c, d)
}

const NilIP = IPAddress(0)		

func ParseIP(value string) IPAddress {
	parts := strings.Split(value, ".")	
	if len(parts) < 4 {
		return NilIP
	}

	var err error
	var a, b, c, d int

	a, err = strconv.Atoi(parts[0])
	b, err = strconv.Atoi(parts[1])
	c, err = strconv.Atoi(parts[2])
	d, err = strconv.Atoi(parts[3])

	if err != nil {
		return NilIP
	}

	ip := uint32(a) << 24 | uint32(b) << 16 | uint32(c) << 8 | uint32(d)

	return IPAddress(ip)
}

type IPProtocol byte

const (
	IPProtocolICMP = IPProtocol(1)
	IPProtocolIGMP = IPProtocol(2)
	IPProtocolTCP  = IPProtocol(6)
	IPProtocolUDP  = IPProtocol(17)
)

type IPPacket struct {
	Version         byte
	IHL             byte
	DSCP            byte
	ECN             byte
	TotalLength     uint16
	Identification  uint16
	Flags           byte
	FragmentOffset  uint16
	TTL             byte
	Protocol        IPProtocol
	HeaderChecksum  uint16
	SourceAddr      IPAddress
	DestinationAddr IPAddress
	Payload         []byte
}

func (p *IPPacket) From(b []byte) error {
	if len(b) < IPPacketHeaderSize {
		return ErrPacketLen
	}

	*p = IPPacket{
		Version:         (b[0] & 0b11110000) >> 4,
		IHL:             (b[0] & 0b00001111),
		DSCP:            (b[1] & 0b11111100) >> 2,
		ECN:             b[1] & 0b00000011,
		TotalLength:     uint16(b[2])<<8 | uint16(b[3]),
		Identification:  uint16(b[4])<<8 | uint16(b[5]),
		Flags:           (b[6] & 0b11100000) >> 5,
		FragmentOffset:  uint16(b[6]&0b00011111)<<8 | uint16(b[7]),
		TTL:             b[8],
		Protocol:        IPProtocol(b[9]),
		HeaderChecksum:  uint16(b[10])<<8 | uint16(b[11]),
		SourceAddr:      IPAddress(uint32(b[12])<<24 | uint32(b[13])<<16 | uint32(b[14])<<8 | uint32(b[15])),
		DestinationAddr: IPAddress(uint32(b[16])<<24 | uint32(b[17])<<16 | uint32(b[18])<<8 | uint32(b[19])),
		Payload:         b[20:],
	}

	return nil
}

func (p *IPPacket) HeaderBytes() []byte {
	return []byte {
		p.Version << 4 | p.IHL,
		p.DSCP    << 2 | p.ECN,
		byte(p.TotalLength >> 8),    byte(p.TotalLength),
		byte(p.Identification >> 8), byte(p.Identification),
		p.Flags   << 5 | byte(p.FragmentOffset >> 8), byte(p.FragmentOffset),
		p.TTL,
		byte(p.Protocol),
		byte(p.HeaderChecksum >> 8), byte(p.HeaderChecksum),
		byte(p.SourceAddr >> 24), byte(p.SourceAddr >> 16), byte(p.SourceAddr >> 8), byte(p.SourceAddr),
		byte(p.DestinationAddr >> 24), byte(p.DestinationAddr >> 16), byte(p.DestinationAddr >> 8), byte(p.DestinationAddr),
	}
}

func (p *IPPacket) Bytes() []byte {
	return append(p.HeaderBytes(), p.Payload...)
}

// calculate the checksum
func (p *IPPacket) calculate() {
	// if we see 0x00 it means this is likely a new packet
	if p.HeaderChecksum == 0x00 {
		p.HeaderChecksum = checksum(p.HeaderBytes())
		return
	}
	p.HeaderChecksum = 0x00
	p.HeaderChecksum = checksum(p.HeaderBytes())
}

func (p *IPPacket) Valid() bool {
	p.calculate()
	return checksum(p.HeaderBytes()) == 0x00
}

func (p *IPPacket) Write(w io.Writer) (int, error) {
	p.calculate()
	return w.Write(p.Bytes())
}


