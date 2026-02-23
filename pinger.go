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

type ICMPPacket struct {
	Type ICMPType
	Code byte
	Identifier uint16
	Sequence uint16
	Payload []byte
}

func (p *ICMPPacket) Checksum() uint16 {
	var data = []byte{
		byte(p.Type),
		p.Code, 
		byte(p.Identifier >> 8), byte(p.Identifier),
		byte(p.Sequence >> 8), byte(p.Sequence),
	}
	data = append(data, p.Payload...)	
	return checksum(data)
}

func (p *ICMPPacket) Write(w io.Writer) error {
	c := p.Checksum()
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

	buf := make([]byte, 4096)

	for {
		n, _, err := conn.ReadFrom(buf)
		if n > 0 {
			log.Printf("data=%s", string(buf[:n]))
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Fatalf("error in rx: %v", err)
		}
	}
}

func main() {
	go listener("10.20.0.203")

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

	log.Printf("body=%s", pkt.Payload)

	if err := pkt.Write(conn); err != nil {
		log.Fatalf("failed to write packet: %v", err)
	}

	if err := conn.Close(); err != nil {
		log.Fatalf("failed to close connection: %v", err)
	}

	log.Printf("checksum=%04x", pkt.Checksum())

	<-make(chan interface{}, 0)
}
