package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/Nando-suka/edr/internal/protocol"
)

func main() {
	socketPath := flag.String("socket", "/run/edr/control.sock", "daemon control socket")
	flag.Parse()

	if flag.NArg() < 1 {
		usage()
	}
	switch flag.Arg(0) {
	case "scan":
		if flag.NArg() < 2 {
			usage()
		}
		doScan(*socketPath, flag.Arg(1))
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", flag.Arg(0))
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: edr-ctl [-socket path] scan <file>")
	os.Exit(2)
}

func doScan(socketPath, path string) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer conn.Close()

	req := protocol.Request{ID: 1, Kind: "scan", Path: path}
	if err := protocol.WriteFrame(conn, req); err != nil {
		log.Fatalf("write: %v", err)
	}
	var resp protocol.Response
	if err := protocol.ReadFrame(conn, &resp); err != nil {
		log.Fatalf("read: %v", err)
	}
	if resp.Err != "" {
		log.Fatalf("daemon: %s", resp.Err)
	}
	if resp.Malicious {
		fmt.Printf("MALICIOUS: %s (%v)\n", resp.ThreatName, resp.Engines)
		os.Exit(1)
	}
	fmt.Println("clean")
}
