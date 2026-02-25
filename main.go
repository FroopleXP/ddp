package main

import (
	"log"
	"os"
	"os/signal"
	"context"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	DuckIP = ParseIP("1.2.3.4")

	var ddp = DDP{ Interface: ParseIP("10.20.0.248"), Target: ParseIP("86.14.108.21") }
	if err := ddp.Start(ctx); err != nil {
		log.Fatalf("failed to start ddp: %v", err)
	}

	log.Printf("ddp started")

	ddp.Wait()
}
