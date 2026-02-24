package main

import (
	"log"
	"net"
	"io"
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
	Identifier uint16
	Sequence uint16
	Payload []byte
}

func (p *ICMPPacket) checksum(sum uint16) uint16 {
	var data = []byte{
		byte(p.Type),
		p.Code, 
		byte(sum >> 8), byte(sum),
		byte(p.Identifier >> 8), byte(p.Identifier),
		byte(p.Sequence >> 8), byte(p.Sequence),
	}
	data = append(data, p.Payload...)	
	return checksum(data)
}

func (p *ICMPPacket) Valid(checksum uint16) bool {
	return p.checksum(checksum) == 0x00
}

func (p *ICMPPacket) Write(w io.Writer) error {
	c := p.checksum(0x00)
	ch, cl := byte(c >> 8), byte(c)
	ih, il := byte(p.Identifier >> 8), byte(p.Identifier)
	sh, sl := byte(p.Sequence >> 8), byte(p.Sequence)

	payload := []byte{
		byte(p.Type),
		byte(p.Code),
		ch, cl, 	
		ih, il,
		sh, sl,
	}

	payload = append(payload, p.Payload...)

	if _, err := w.Write(payload); err != nil {
		return err
	}

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

		if n < 8 {
			log.Printf("invalid packet, len too short")
			continue
		}

		log.Printf("rx'd packet (%d) from %s", n, addr)

		var pkt ICMPPacket		
		pkt.Type = ICMPType(b[0])
		pkt.Code = b[1]
		pkt.Identifier = uint16(b[4]) << 8 | uint16(b[5])
		pkt.Sequence = uint16(b[6]) << 8 | uint16(b[7])
		pkt.Payload = b[8:n]
		
		checksum := uint16(b[2]) << 8 | uint16(b[3])

		log.Printf("rx'd packet type=%s, code=%d, checksum=%04x, valid=%t", pkt.Type, pkt.Code, checksum, pkt.Valid(checksum))
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

	if err := pkt.Write(conn); err != nil {
		log.Fatalf("failed to write packet: %v", err)
	}

	if err := conn.Close(); err != nil {
		log.Fatalf("failed to close connection: %v", err)
	}

	<-make(chan interface{}, 0)
}
