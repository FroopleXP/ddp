package main

import (
	"log"
	"os"
	"net"
	"time"
	"os/signal"
	"context"
	"flag"
	"fmt"
)

var usage = func () {
	fmt.Printf("Usage of %s:\n", os.Args[0])
	fmt.Printf("  ddp [flags] <interface_ip> <target_ip>\n")
	fmt.Printf("Flags:\n")
	flag.PrintDefaults()
}

func main() {
	fDuckIP := flag.String("duck-ip", DuckIPStr, "the unrouteable ip")
	flag.Usage = usage
	flag.Parse()

	for flag.NArg() < 2 {
		fmt.Printf("invalid arguments\n")
		os.Exit(1)
	}

	intface := ParseIP(flag.Arg(0))
	target := ParseIP(flag.Arg(1))

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	context.AfterFunc(ctx, func() {
		log.Printf("shutting down, max wait time %s", ListenDeadline)
	})

	DuckIP = ParseIP(*fDuckIP)

	var ddp = DDP{ Target: target, Interface: intface }

	log.Print("starting listener")
	if err := ddp.StartListener(ctx, intface); err != nil {
		log.Fatalf("failed to start listener: %v", err)
	}

	log.Printf("dialing duck=%s", DuckIP.String())
	duckConn, err := net.Dial("ip4:1", DuckIP.String())
	if err != nil {
		log.Fatalf("failed to dial duck: %v", err)
	}

	log.Print("sending ping to duck=%s", DuckIP.String())
	n, err := ddp.Ping(duckConn)
	if err != nil {
		log.Printf("ping failed: %v", err)
	}
	log.Printf("-- sent %d byte(s) to duck", n)

	log.Printf("brief pause %s", PingDelay)
	time.Sleep(PingDelay)

	log.Printf("dialing target=%s", target.String())
	targetConn, err := net.Dial("ip4:1", target.String())
	if err != nil {
		log.Fatalf("failed to dial target: %v", err)
	}

	log.Printf("sending quack to target=%s", target.String())
	n, err = ddp.Quack(targetConn)
	if err != nil {
		log.Printf("quack failed: %v", err)
	}
	log.Printf("-- sent %d byte(s) to target", n)

	log.Printf("ddp started - ctrl+c to quit")

	ddp.Wait()
}
