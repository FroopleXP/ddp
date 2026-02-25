package main

import (
	"log"
	"net"
	"bytes"
	"os"
	"fmt"
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

func (d *DDP) Start(ctx context.Context) error {
	log.Printf("ddp is starting duck-ip=%s, target=%s, interface=%s", DuckIP, d.Target, d.Interface)
	if err := d.pinger(ctx); err != nil {
		return err
	}

	if err := d.listener(ctx); err != nil {
		return err
	}

	if err := d.quacker(ctx); err != nil {
		return err
	}

	return nil
}

func (d *DDP) Wait() {
	d.wg.Wait()
}

// pinger periodically pings into the ether to a unrouteable
// ip address.
func (d *DDP) pinger(ctx context.Context) error {
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

		log.Printf("pinger started interval=%s", PingDelay)

		for {
			select {
			case <-ctx.Done():
				log.Printf("pinger closed, reason: %s", context.Cause(ctx))
				return
			case <-ticker.C:
				n, err := MagicPacket.Write(conn) 
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

func (d *DDP) listener(ctx context.Context) error {
	if d.Interface == NilIP {
		return fmt.Errorf("invalid or missing interface address")
	}

	conn, err := net.ListenPacket("ip4:1", d.Interface.String())
	if err != nil {
		log.Fatalf("failed to start listener: %v", err)
	}

	d.wg.Add(1)
	go func() {
		defer func () {
			conn.Close()
			d.wg.Done()
		}()

		var buf []byte = make([]byte, 2048)
		var packet ICMPPacket

		log.Printf("listener started")

		for {
			select {
			case <-ctx.Done():
				log.Printf("listener closed, reason: %s", context.Cause(ctx))
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

				if !packet.Valid() || packet.Type != ICMPTypeDestinationUnreachable {
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

func (d *DDP) quacker(ctx context.Context) error {
	if d.Target == NilIP {
		return fmt.Errorf("target ip is not defined")
	}

	conn, err := net.Dial("ip4:1", d.Target.String())
	if err != nil {
		return err
	}

	var payload = bytes.NewBuffer(make([]byte, 0))

	// write the inner icmp magic packet
	{
		if _, err := MagicPacket.Write(payload); err != nil {
			return err
		}
	}
	
	// build the inner ip packet
	{
		var packet = IPPacket{
			Version: byte(4),
			IHL: byte(5),
			DSCP: byte(0),
			ECN: byte(0),
			TotalLength: uint16(84),
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
			return err
		}
	}

	// write the outer icmp packet
	{
		var packet = ICMPPacket{
			Type: ICMPTypeDestinationUnreachable,
			Code: 0x00,
			Identifier: 0x4a4a,
			Sequence: uint16(0),
			Payload: payload.Bytes(),
		}

		payload.Reset()
		if _, err := packet.Write(payload); err != nil {
			return err
		}
	}

	d.wg.Add(1)
	go func() {
		defer func () {
			conn.Close()
			d.wg.Done()
		}()

		ticker := time.NewTicker(PingDelay)
		defer ticker.Stop()

		log.Printf("quacker started interval=%s", PingDelay)

		for {
			select {
			case <-ctx.Done():
				log.Printf("quacker closed, reason: %s", context.Cause(ctx))
				return
			case <-ticker.C:
				n, err := payload.WriteTo(conn) 
				if err != nil {
					log.Printf("failed to write icmp-ip-icmp packet: %v", err)
					continue
				}
				log.Printf("icmp-ip-icmp packet sent size=%d byte(s)", n)
			}
		}
	}()

	return nil
}
