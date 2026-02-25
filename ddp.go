package main

import (
	"log"
	"net"
	"bytes"
	"os"
	"time"
	"errors"
	"sync"
	"context"
)

var (
	DuckIPStr = "4.21.3.11"
	DuckIP = ParseIP(DuckIPStr)
	DuckMagicIdentifier = uint16(0xC4AC)
)

const (
	PingDelay = time.Second * 5
	ListenDeadline = time.Second * 15
)

var MagicPacket = ICMPPacket{
	Type: ICMPTypeEchoRequest,
	Code: 0x00,
	Identifier: DuckMagicIdentifier,
	Sequence: uint16(0),
	Payload: []byte("quack"),
}

type DDP struct {
	Interface IPAddress
	Target IPAddress

	wg sync.WaitGroup
}

func (d *DDP) Wait() {
	d.wg.Wait()
}

func (d *DDP) Ping(conn net.Conn) (int, error) {
	return MagicPacket.Write(conn) 
}

// pinger periodically pings into the ether to a unrouteable
// ip address.
func (d *DDP) StartPinger(ctx context.Context) error {
	conn, err := net.Dial("ip4:1", DuckIP.String())
	if err != nil {
		return err
	}

	d.wg.Add(1)
	go func() {
		defer func () {
			conn.Close()
			d.wg.Done()
		}()

		ticker := time.NewTicker(PingDelay)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				n, err := d.Ping(conn)
				if err != nil {
					log.Printf("failed to write magic packet: %v", err)
					continue
				}
				log.Printf("magic packet sent size=%d byte(s)", n)
			}
		}
	}()

	return nil
}

func (d *DDP) StartListener(ctx context.Context, intface IPAddress) error {
	conn, err := net.ListenPacket("ip4:1", intface.String())
	if err != nil {
		return err
	}

	d.wg.Add(1)
	go func() {
		defer func () {
			conn.Close()
			d.wg.Done()
		}()

		var buf []byte = make([]byte, 2048)
		var packet ICMPPacket

		for {
			select {
			case <-ctx.Done():
				return
			default:
				if err := conn.SetDeadline(time.Now().Add(ListenDeadline)); err != nil {
					log.Printf("failed to extend connection deadline: %v", err)
					return
				}

				n, addr, err := conn.ReadFrom(buf)
				if err != nil {
					if errors.Is(err, os.ErrDeadlineExceeded) {
						continue // yield so the context can close
					}
					log.Printf("read error: %v", err)
					return
				}

				if err := packet.From(buf[:n]); err != nil {
					log.Printf("packet parse error: %v", err)
					continue
				}

				if !packet.Valid() || packet.Type != ICMPTypeTimeExceeded {
					log.Printf("received invalid icmp packet, skipping")
					continue
				}

				payload := packet.Payload
		
				// destination unreacable packets include the original ip packet
				// we can use this the get the remote ip of the caller.
				{
					var packet IPPacket
					if err := packet.From(payload); err != nil {
						log.Printf("ip packet read error: %v", err)
						continue
					}

					if packet.Protocol != IPProtocolICMP {
						continue
					}

					if packet.DestinationAddr != DuckIP {
						log.Printf("ip packet not destined for peer")
						continue
					}

					if packet.SourceAddr == d.Interface {
						//log.Printf("received icmp packet from ourselves, ignoring")
						continue
					}

					payload = packet.Payload
				}

				// reconstruct the contained icmp packet and see if it was sent
				// by a peer.
				{
					var packet ICMPPacket
					if err := packet.From(payload); err != nil {
						log.Printf("error parsing containing icmp packet: %v", err)
						continue
					}

					if packet.Identifier != DuckMagicIdentifier {
						log.Printf("icmp packet not sent by peer")
						continue
					}
				}

				log.Printf("peer found ip=%s", addr)
			}
		}
	}()

	return nil
}

// Quack sends the destination unreachable packet to the
// connection.
func (d *DDP) Quack(conn net.Conn) (int, error) {
	var payload = bytes.NewBuffer(make([]byte, 0))

	// write the inner icmp magic packet
	{
		if _, err := MagicPacket.Write(payload); err != nil {
			return 0, err
		}
	}
	
	// write the inner ip packet
	{
		var packet = IPPacket{
			Version: byte(4),
			IHL: byte(5),
			DSCP: byte(0),
			ECN: byte(0),
			TotalLength: uint16(payload.Len() + 20),
			Identification: uint16(23810),
			Flags: byte(2),
			FragmentOffset: uint16(0),
			TTL: byte(63),
			Protocol: IPProtocolICMP,
			HeaderChecksum: uint16(0),
			SourceAddr: d.Interface,
			DestinationAddr: d.Target,
			Payload: payload.Bytes(),
		}

		payload.Reset()
		if _, err := packet.Write(payload); err != nil {
			return 0, err
		}
	}

	// write the final, outer icmp packet
	var packet = ICMPPacket{
		Type: ICMPTypeTimeExceeded,
		Code: byte(0x01),
		Identifier: 0x4a4a,
		Sequence: uint16(0),
		Payload: payload.Bytes(),
	}

	return packet.Write(conn)
}

// StartQuacker perdiodically quacks at the target
func (d *DDP) StartQuacker(ctx context.Context, target IPAddress) error {
	conn, err := net.Dial("ip4:1", target.String())
	if err != nil {
		return err
	}

	d.wg.Add(1)
	go func() {
		defer func () {
			conn.Close()
			d.wg.Done()
		}()

		ticker := time.NewTicker(PingDelay)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := d.Quack(conn); err != nil {
					log.Printf("quack failed: %v", err)
					continue
				}
			}
		}
	}()

	return nil
}
