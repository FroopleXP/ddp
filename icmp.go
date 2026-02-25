package main

import (
	"errors"
	"io"
)

var (
	ErrPacketLen error = errors.New("invalid packet length")
)

type ICMPType byte

const (
	ICMPTypeEchoRequest            = ICMPType(0x08)
	ICMPTypeEchoReply              = ICMPType(0x00)
	ICMPTypeDestinationUnreachable = ICMPType(0x03)
	ICMPTypeTimeExceeded           = ICMPType(0x0B)
)

func (t ICMPType) String() string {
	switch t {
	case ICMPTypeEchoRequest:
		return "echo request"
	case ICMPTypeEchoReply:
		return "echo reply"
	case ICMPTypeDestinationUnreachable:
		return "destination unreachable"
	case ICMPTypeTimeExceeded:
		return "time exceeded"
	}
	return "unknown"
}

type ICMPPacket struct {
	Type       ICMPType
	Code       byte
	Checksum   uint16
	Identifier uint16
	Sequence   uint16
	Payload    []byte
}

func (p *ICMPPacket) Bytes() []byte {
	b := []byte{
		byte(p.Type),
		byte(p.Code),
		byte(p.Checksum >> 8), byte(p.Checksum),
		byte(p.Identifier >> 8), byte(p.Identifier),
		byte(p.Sequence >> 8), byte(p.Sequence),
	}

	return append(b, p.Payload...)
}

// calculate the checksum
func (p *ICMPPacket) calculate() {
	// if we see 0x00 it means this is likely a new packet
	if p.Checksum == 0x00 {
		p.Checksum = checksum(p.Bytes())
		return
	}
	p.Checksum = 0x00
	p.Checksum = checksum(p.Bytes())
}

func (p *ICMPPacket) Valid() bool {
	p.calculate()
	return checksum(p.Bytes()) == 0x00
}

func (p *ICMPPacket) Write(w io.Writer) (int, error) {
	p.calculate()
	return w.Write(p.Bytes())
}

func (p *ICMPPacket) From(b []byte) error {
	if len(b) < 8 {
		return ErrPacketLen
	}

	p.Type = ICMPType(b[0])
	p.Code = b[1]
	p.Checksum = uint16(b[2])<<8 | uint16(b[3])
	p.Identifier = uint16(b[4])<<8 | uint16(b[5])
	p.Sequence = uint16(b[6])<<8 | uint16(b[7])
	p.Payload = b[8:]

	return nil
}
