package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Nando-suka/edr/internal/daemon"
)

func main() {
	socketPath := flag.String("socket", "/run/edr/control.sock", "control socket path")
	workerBin := flag.String("worker", "/usr/local/lib/edr/scanner-worker", "scanner worker binary")
	flag.Parse()

	d, err := daemon.New(*socketPath, *workerBin)
	if err != nil {
		log.Fatalf("daemon init: %v", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Printf("shutting down")
		_ = d.Shutdown()
	}()

	if err := d.Run(); err != nil {
		log.Fatalf("daemon run: %v", err)
	}
}
