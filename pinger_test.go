package main

import (
	"testing"
)

func TestChecksum(t *testing.T) {
	var pkt ICMPPacket
	pkt.Type = ICMPTypeEchoRequest
	pkt.Code = 0x00
	pkt.Identifier = 0x5e1d
	pkt.Sequence = 0x0020
	pkt.Payload = []byte("I'm pinging you!\n")

	checksum := pkt.Checksum()
	t.Logf("checksum=%04x", checksum)

	var expect uint16 = 0x3b8a
	if checksum != expect {
		t.Errorf("expected '%04x', got %04x", expect, checksum)
	}		
}
