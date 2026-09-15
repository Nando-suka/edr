package worer

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/Nando-suka/edr/internal/protocol"
)

type Result struct {
	Malicious  bool
	ThreatName string
	Engines    []string
}

type Handle struct {
	cmd  *exec.Cmd
	conn net.Conn
	mu   sync.Mutex
	seq  uint64
}

// Start spawns the scanner worker. The child inherits one end of a
// socketpair as fd 3; we tell it via EDR_WORKER_FD=3.
func Start(bin string) (*Handle, error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
	}
	parentFile := os.NewFile(uintptr(fds[0]), "worker-parent")
	childFile := os.NewFile(uintptr(fds[1]), "worker-child")

	cmd := exec.Command(bin)
	cmd.ExtraFiles = []*os.File{childFile} // becomes fd 3 in the child
	cmd.Env = append(os.Environ(), "EDR_WORKER_FD=3")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Milestone 2 will populate SysProcAttr with clone flags, NoNewPrivs,
	// rlimits, etc. For now we start it plain so we can iterate.
	if err := cmd.Start(); err != nil {
		parentFile.Close()
		childFile.Close()
		return nil, err
	}
	childFile.Close() // parent doesn't need the child's end

	conn, err := net.FileConn(parentFile)
	if err != nil {
		parentFile.Close()
		_ = cmd.Process.Kill()
		return nil, err
	}
	parentFile.Close()

	return &Handle{cmd: cmd, conn: conn}, nil
}

func (h *Handle) Scan(ctx context.Context, path string) (*Result, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.seq++
	id := h.seq

	if deadline, ok := ctx.Deadline(); ok {
		_ = h.conn.SetDeadline(deadline)
	} else {
		_ = h.conn.SetDeadline(time.Time{})
	}

	req := protocol.Request{ID: id, Kind: "scan", Path: path}
	if err := protocol.WriteFrame(h.conn, req); err != nil {
		return nil, fmt.Errorf("write to worker: %w", err)
	}

	var resp protocol.Response
	if err := protocol.ReadFrame(h.conn, &resp); err != nil {
		// TODO(milestone 2): on any I/O error the worker may be mid-scan;
		// mark it broken, kill, and respawn rather than reusing the conn.
		return nil, fmt.Errorf("read from worker: %w", err)
	}
	if resp.ID != id {
		return nil, fmt.Errorf("worker id mismatch: got %d want %d", resp.ID, id)
	}
	if resp.Err != "" {
		return nil, fmt.Errorf("worker: %s", resp.Err)
	}
	return &Result{
		Malicious:  resp.Malicious,
		ThreatName: resp.ThreatName,
		Engines:    resp.Engines,
	}, nil
}

func (h *Handle) Close() error {
	_ = h.conn.Close()
	if h.cmd.Process != nil {
		_ = h.cmd.Process.Signal(syscall.SIGTERM)
		_, _ = h.cmd.Process.Wait()
	}
	return nil
}
