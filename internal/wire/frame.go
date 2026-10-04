// Package wire defines the framed messages exchanged between keyroster
// clients and keyroster-signer over its Unix socket.
//
// A frame is a uint32 big-endian length followed by that many payload bytes.
// The payload starts with the protocol version byte and a message type byte;
// the rest is the message body, encoded with length-prefixed fields and
// decoded strictly (hard limits, no trailing bytes).
package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// MaxFrame is the largest payload a frame may carry. ReadFrame refuses a
// larger length before allocating anything.
const MaxFrame = 64 << 10

// Version is the protocol version byte at the start of every payload.
const Version = 1

// Message types.
const (
	TypeIssueRequest  byte = 0x01
	TypeIssueResponse byte = 0x81
	TypeError         byte = 0xFF
)

// Framing errors.
var (
	ErrFrameTooLarge = errors.New("wire: frame exceeds the maximum size")
	ErrEmptyFrame    = errors.New("wire: empty frame")
	ErrVersion       = errors.New("wire: unsupported protocol version")
)

// ReadFrame reads one frame from r and returns its payload.
func ReadFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("wire: read frame header: %w", err)
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 {
		return nil, ErrEmptyFrame
	}
	if n > MaxFrame {
		return nil, ErrFrameTooLarge
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("wire: read frame payload: %w", err)
	}
	return payload, nil
}

// WriteFrame writes payload to w as one frame.
func WriteFrame(w io.Writer, payload []byte) error {
	if len(payload) == 0 {
		return ErrEmptyFrame
	}
	if len(payload) > MaxFrame {
		return ErrFrameTooLarge
	}
	buf := make([]byte, 4, 4+len(payload))
	binary.BigEndian.PutUint32(buf, uint32(len(payload))) //nolint:gosec // G115: len(payload) <= MaxFrame, checked above
	buf = append(buf, payload...)
	_, err := w.Write(buf)
	return err
}

// WriteMessage writes one frame whose payload is the version byte, msgType
// and body.
func WriteMessage(w io.Writer, msgType byte, body []byte) error {
	payload := make([]byte, 0, 2+len(body))
	payload = append(payload, Version, msgType)
	payload = append(payload, body...)
	return WriteFrame(w, payload)
}

// ReadMessage reads one frame and splits its payload into the message type
// and body. A payload with another protocol version is refused.
func ReadMessage(r io.Reader) (msgType byte, body []byte, err error) {
	payload, err := ReadFrame(r)
	if err != nil {
		return 0, nil, err
	}
	if len(payload) < 2 {
		return 0, nil, fmt.Errorf("wire: payload too short")
	}
	if payload[0] != Version {
		return 0, nil, ErrVersion
	}
	return payload[1], payload[2:], nil
}
