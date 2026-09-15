package dademon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/Nando-suka/edr/internal/protocol"
	"github.com/Nando-suka/edr/internal/worker"
)

type Daemon struct {
	socketPath string
	worker     *worker.Handle
	listener   net.Listener

	ctx    context.Context
	cancel context.CancelFunc
}

func New(socketPath, workerBin string) (*Daemon, error) {
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o755); err != nil {
		return nil, err
	}
	_ = os.Remove(socketPath) // clear a stale socket

	h, err := worker.Start(workerBin)
	if err != nil {
		return nil, fmt.Errorf("start worker: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &Daemon{
		socketPath: socketPath,
		worker:     h,
		ctx:        ctx,
		cancel:     cancel,
	}, nil
}

func (d *Daemon) Run() error {
	lis, err := net.Listen("unix", d.socketPath)
	if err != nil {
		return err
	}
	// Only root and the "edr" group can connect.
	if err := os.Chmod(d.socketPath, 0o660); err != nil {
		return err
	}
	d.listener = lis
	log.Printf("edr-daemon listening on %s", d.socketPath)

	for {
		conn, err := lis.Accept()
		if err != nil {
			select {
			case <-d.ctx.Done():
				return nil
			default:
				log.Printf("accept: %v", err)
				continue
			}
		}
		go d.handleConn(conn)
	}
}

func (d *Daemon) handleConn(conn net.Conn) {
	defer conn.Close()

	// Milestone 2: SO_PEERCRED check right here. Reject callers whose
	// UID/GID isn't allowed to talk to this socket.

	for {
		var req protocol.Request
		if err := protocol.ReadFrame(conn, &req); err != nil {
			if !errors.Is(err, io.EOF) {
				log.Printf("client read: %v", err)
			}
			return
		}
		resp := d.dispatch(req)
		if err := protocol.WriteFrame(conn, resp); err != nil {
			log.Printf("client write: %v", err)
			return
		}
	}
}

func (d *Daemon) dispatch(req protocol.Request) protocol.Response {
	switch req.Kind {
	case "scan":
		return d.handleScan(req)
	default:
		return protocol.Response{ID: req.ID, Err: "unknown request kind"}
	}
}

func (d *Daemon) handleScan(req protocol.Request) protocol.Response {
	ctx, cancel := context.WithTimeout(d.ctx, 30*time.Second)
	defer cancel()

	res, err := d.worker.Scan(ctx, req.Path)
	if err != nil {
		return protocol.Response{ID: req.ID, Err: err.Error()}
	}
	return protocol.Response{
		ID:         req.ID,
		Malicious:  res.Malicious,
		ThreatName: res.ThreatName,
		Engines:    res.Engines,
	}
}

func (d *Daemon) Shutdown() error {
	d.cancel()
	if d.listener != nil {
		_ = d.listener.Close()
	}
	_ = os.Remove(d.socketPath)
	return d.worker.Close()
}
