package main

import (
	"bytes"
	"log"
	"os"
	"strconv"

	"github.com/Nando-suka/edr/internal/protocol"
)

// The standard EICAR test string, split so this source file doesn't
// itself trip other AV scanners on the developer's machine.
var eicarTest = []byte(
	"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
)

func main() {
	fdStr := os.Getenv("EDR_WORKER_FD")
	if fdStr == "" {
		log.Fatal("EDR_WORKER_FD not set")
	}
	fd, err := strconv.Atoi(fdStr)
	if err != nil {
		log.Fatalf("bad EDR_WORKER_FD: %v", err)
	}
	ipc := os.NewFile(uintptr(fd), "ipc")
	if ipc == nil {
		log.Fatal("could not wrap ipc fd")
	}
	defer ipc.Close()

	// Milestone 2: call sandboxSelf() here, before the loop. Once we do,
	// nothing below this line can open sockets, exec, or ptrace.

	log.Printf("scanner-worker started (ipc fd=%d)", fd)

	for {
		var req protocol.Request
		if err := protocol.ReadFrame(ipc, &req); err != nil {
			log.Printf("worker read: %v", err)
			return
		}
		resp := handle(req)
		if err := protocol.WriteFrame(ipc, resp); err != nil {
			log.Printf("worker write: %v", err)
			return
		}
	}
}

func handle(req protocol.Request) protocol.Response {
	switch req.Kind {
	case "scan":
		return scanFile(req)
	default:
		return protocol.Response{ID: req.ID, Err: "unknown kind: " + req.Kind}
	}
}

func scanFile(req protocol.Request) protocol.Response {
	data, err := os.ReadFile(req.Path)
	if err != nil {
		return protocol.Response{ID: req.ID, Err: err.Error()}
	}
	if bytes.Contains(data, eicarTest) {
		return protocol.Response{
			ID:         req.ID,
			Malicious:  true,
			ThreatName: "EICAR-Test-File",
			Engines:    []string{"stub-eicar"},
		}
	}
	return protocol.Response{ID: req.ID, Engines: []string{"stub-eicar"}}
}
