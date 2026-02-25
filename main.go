package main

import (
	"log"
	"os"
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

	interfaceIp := flag.Arg(0)
	targetIp := flag.Arg(1)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	context.AfterFunc(ctx, func() {
		log.Printf("shutting down, max wait time %s", ListenDeadline)
	})

	DuckIP = ParseIP(*fDuckIP)

	var ddp = DDP{ Interface: ParseIP(interfaceIp), Target: ParseIP(targetIp) }
	if err := ddp.Start(ctx); err != nil {
		log.Fatalf("failed to start ddp: %v", err)
	}

	log.Printf("ddp started - ctrl+c to quit")

	ddp.Wait()
}
