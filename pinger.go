package main

import (
	"log"
	"net"
	"io"
	"errors"
)

var (
	ErrPacketLen error = errors.New("invalid packet length")
)

type ICMPType byte

const (
	ICMPTypeEchoRequest = ICMPType(0x08)
	ICMPTypeEchoReply = ICMPType(0x00)
)

func (t ICMPType) String() string {
	switch t {
	case ICMPTypeEchoRequest:
		return "echo request"
	case ICMPTypeEchoReply:
		return "echo reply"
	}
	return "unknown"
}

type ICMPPacket struct {
	Type ICMPType
	Code byte
	Checksum uint16
	Identifier uint16
	Sequence uint16
	Payload []byte
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

func (p *ICMPPacket) Valid() bool {
	if p.Checksum == 0x00 {
		p.Checksum = checksum(p.Bytes())
	}
	return checksum(p.Bytes()) == 0x00
}

func (p *ICMPPacket) Write(w io.Writer) (int, error) {
	if p.Checksum == 0x00 {
		p.Checksum = checksum(p.Bytes())
	}
	return w.Write(p.Bytes())
}

func (p *ICMPPacket) From(b []byte) error {
	if len(b) < 8 {
		return ErrPacketLen
	}

	p.Type = ICMPType(b[0])
	p.Code = b[1]
	p.Identifier = uint16(b[4]) << 8 | uint16(b[5])
	p.Sequence = uint16(b[6]) << 8 | uint16(b[7])
	p.Payload = b[8:]
	
	p.Checksum = uint16(b[2]) << 8 | uint16(b[3])

	return nil
}

func checksum(data []byte) uint16 {
	if len(data) % 2 != 0 {
		data = append(data, 0x00)
	}
	var sum uint32
	for i := 0; i < len(data); i+=2 {
		sum += uint32(uint16(data[i]) << 8 | uint16(data[i+1]))
	}
	return ^(uint16(sum >> 16) + uint16(sum))
}

func listener(network string) {
	conn, err := net.ListenPacket("ip4:1", network)
	if err != nil {
		log.Fatalf("failed to start listener: %v", err)
	}
	defer conn.Close()

	b := make([]byte, 2048)

	for {
		n, addr, err := conn.ReadFrom(b)
		if err != nil {
			log.Printf("failed to read packet: %v", err)
			continue
		}

		var pkt ICMPPacket		
		if err := pkt.From(b[:n]); err != nil {
			log.Printf("failed to read packet: %v", err)
			continue
		}

		log.Printf("rx'd packet addr=%s, type=%s, code=%d, checksum=%04x, valid=%t", addr, pkt.Type, pkt.Code, checksum, pkt.Valid())
	}
}

func main() {
	go listener("10.20.0.248")

	conn, err := net.Dial("ip4:1", "86.14.108.21")
	if err != nil {
		log.Fatalf("failed to connect: %v", err)
	}

	var pkt ICMPPacket
	pkt.Type = ICMPTypeEchoRequest
	pkt.Code = 0x00
	pkt.Identifier = 0x5e1d
	pkt.Sequence = 0x0020
	pkt.Payload = []byte("I'm pinging you!\n")

	if _, err := pkt.Write(conn); err != nil {
		log.Fatalf("failed to write packet: %v", err)
	}

	if err := conn.Close(); err != nil {
		log.Fatalf("failed to close connection: %v", err)
	}

	<-make(chan interface{}, 0)
}
