package main

import (
	"log"
	"net"
	"time"
)

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

		if err := pkt.From(b[:n]); err != nil || !pkt.Valid() {
			log.Printf("received invalid packet")
			continue
		}

		if pkt.Type == ICMPTypeEchoReply {
			log.Printf("rx'd echo reply addr=%s, type=%d, code=%d", addr, pkt.Type, pkt.Code)
			continue
		}

		if pkt.Type == ICMPTypeDestinationUnreachable {
			var ipPkt IPPacket
			if err := ipPkt.From(pkt.Payload); err != nil {
				log.Printf("failed to read ip packet: %v", err)
				continue
			}

			if ipPkt.Protocol != IPProtocolICMP {
				continue
			}

			log.Printf("ip packet ver=%d, ihl=%d, src=%s, dst=%s", ipPkt.Version, ipPkt.IHL, ipPkt.SourceAddr, ipPkt.DestinationAddr)

			{
				var pkt ICMPPacket
				if err := pkt.From(ipPkt.Payload); err != nil {
					log.Printf("failed to read icmp packet from ip packet: %v", err)
					continue
				}

				log.Printf("icmp in ip addr=%s, type=%d, code=%d, valid=%t", addr, pkt.Type, pkt.Code, pkt.Valid())
			}
		}
	}
}

func main() {
	go listener("10.20.0.248")

	conn, err := net.Dial("ip4:1", "86.14.108.21")
	if err != nil {
		log.Fatalf("failed to connect: %v", err)
	}
	defer conn.Close()

	for i := range 10 {
		var pkt ICMPPacket
		pkt.Type = ICMPTypeEchoRequest
		pkt.Code = 0x00
		pkt.Identifier = 0x5e1d
		pkt.Sequence = uint16(i)
		pkt.Payload = []byte("I'm pinging you!\n")

		if _, err := pkt.Write(conn); err != nil {
			log.Fatalf("failed to write packet: %v", err)
			break
		}

		time.Sleep(1 * time.Second)
	}

	<-make(chan interface{}, 0)
}
