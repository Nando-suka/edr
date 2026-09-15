package protocol

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

const MaxFrameSize = 1 << 20

type Request struct {
	ID   uint64 `json:"id"`
	Kind string `json:"kind"`
	Path string `json:"path,omitempty"`
}

type Response struct {
	ID         uint64   `json:"id"`
	Err        string   `json:"err,omitempty"`
	Malicious  bool     `json:"malicious,omitempty"`
	ThreatName string   `json:"threat_name,omitempty"`
	Engines    []string `json:"engines,omitempty"`
}

// Write Frame
func WriteFrame(w io.Writer, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(data) > MaxFrameSize {
		return fmt.Errorf("frame too large: %d", len(data))
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(data)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// Read Frame
func ReadFrame(r io.Reader, v any) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxFrameSize {
		return fmt.Errorf("frame too large: %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	return json.Unmarshal(buf, v)
}
