// Package wire defines the framed messages exchanged between keyroster
// clients and keyroster-signer over its Unix socket.
//
// A frame is a uint32 big-endian length followed by that many bytes: the
// protocol version byte, a message type byte and the message body, encoded
// with length-prefixed fields and decoded strictly (hard limits, no
// trailing bytes). The length counts the two header bytes. Each message
// type has a cap on that length (maxBodyFor), checked before any byte is
// written. A reader passes the message types it accepts and their caps
// (Caps): a frame of another type, or above its cap, is refused after its
// length and header, before any body byte is allocated or read.
package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// MaxFrame is the largest frame length (header and body) of every message
// type except the two that carry a directory, the StatusResponse
// (MaxStatusFrame) and the GetKRLResponse (MaxKRLFrame).
const MaxFrame = 64 << 10

// MaxDirectoryFrame is the largest frame length of InstallDirectory and
// GetDirectoryResponse: a directory of MaxDirectory bytes, its signatures
// (at most MaxDirectorySigs, 64 KiB) and 64 bytes of header and field
// prefixes.
const MaxDirectoryFrame = MaxDirectory + 64<<10 + 64

// headerLen is the version byte and the message type byte that every
// frame length counts.
const headerLen = 2

// Version is the protocol version byte at the start of every payload.
const Version = 1

// Message types. A LoginIssueRequest is answered with an IssueResponse
// (0x81). GetDirectory, Status and GetKRL requests have an empty body.
const (
	TypeIssueRequest      byte = 0x01
	TypeInstallDirectory  byte = 0x02
	TypeGetDirectory      byte = 0x03
	TypeStatus            byte = 0x04
	TypeLoginIssueRequest byte = 0x05
	TypeRevokeRequest     byte = 0x06
	TypeGetKRL            byte = 0x07
	// The chain messages (03-07, chain.go): one installed trust bundle
	// or directory by version.
	TypeGetBundle           byte = 0x08
	TypeGetDirectoryVersion byte = 0x09
	// TypeForgetAgentRequest carries an admin-signed ForgetRequest
	// (03-08c), answered with a ForgetResponse (0x8D); both are capped at
	// MaxFrame. 0x0A to 0x0C are 03-09 to 03-11's.
	TypeForgetAgentRequest       byte = 0x0D
	TypeIssueResponse            byte = 0x81
	TypeInstallDirectoryResponse byte = 0x82
	TypeGetDirectoryResponse     byte = 0x83
	TypeStatusResponse           byte = 0x84
	TypeRevokeResponse           byte = 0x86
	TypeGetKRLResponse           byte = 0x87
	// TypeGetBundleResponse is capped like a StatusResponse
	// (MaxStatusFrame), TypeGetDirectoryVersionResponse like a
	// GetDirectoryResponse (MaxDirectoryFrame).
	TypeGetBundleResponse           byte = 0x88
	TypeGetDirectoryVersionResponse byte = 0x89
	TypeForgetAgentResponse         byte = 0x8D
	TypeError                       byte = 0xFF
)

// Framing errors.
var (
	ErrFrameTooLarge  = errors.New("wire: frame exceeds the maximum size for its message type")
	ErrEmptyFrame     = errors.New("wire: empty frame")
	ErrShortFrame     = errors.New("wire: frame shorter than its version and type header")
	ErrVersion        = errors.New("wire: unsupported protocol version")
	ErrUnexpectedType = errors.New("wire: unexpected message type")
)

// maxBodyFor returns the largest body a frame of msgType may carry: its
// frame length cap minus the header. Every type without its own cap,
// unknown types included, gets MaxFrame.
func maxBodyFor(msgType byte) int {
	switch msgType {
	case TypeInstallDirectory, TypeGetDirectoryResponse, TypeGetDirectoryVersionResponse:
		return MaxDirectoryFrame - headerLen
	case TypeStatusResponse, TypeGetBundleResponse:
		return MaxStatusFrame - headerLen
	case TypeGetKRLResponse:
		return MaxKRLFrame - headerLen
	default:
		return MaxFrame - headerLen
	}
}

// Caps is what a frame reader accepts: for a message type, whether it
// accepts frames of that type at all and the largest frame length (header
// included) it accepts for them.
type Caps func(msgType byte) (maxFrame int, ok bool)

// RequestCaps are the caps of the signer, which reads requests. Every
// message type is accepted: InstallDirectory up to MaxDirectoryFrame, and
// every other type, response and unknown types included, up to MaxFrame,
// so a frame of a type the signer does not serve is still read and then
// refused by it (unknown_message_type) instead of costing a directory-sized
// buffer.
func RequestCaps(msgType byte) (maxFrame int, ok bool) {
	if msgType == TypeInstallDirectory {
		return MaxDirectoryFrame, true
	}
	return MaxFrame, true
}

// ResponseCaps returns the caps of a client waiting for a response of type
// want: frames of type want up to that type's cap, and error responses up
// to MaxFrame. A frame of any other type is refused after its header
// (ErrUnexpectedType), before any body byte is allocated or read (T-02-12).
func ResponseCaps(want byte) Caps {
	return func(msgType byte) (int, bool) {
		if msgType != want && msgType != TypeError {
			return 0, false
		}
		return headerLen + maxBodyFor(msgType), true
	}
}

// WriteMessage writes one frame of msgType carrying body, with the length,
// header and body in one Write. A body above msgType's cap is refused
// before any byte is written.
func WriteMessage(w io.Writer, msgType byte, body []byte) error {
	if len(body) > maxBodyFor(msgType) {
		return ErrFrameTooLarge
	}
	buf := make([]byte, 4, 4+headerLen+len(body))
	binary.BigEndian.PutUint32(buf, uint32(headerLen+len(body))) //nolint:gosec // G115: at most MaxDirectoryFrame, checked above
	buf = append(buf, Version, msgType)
	buf = append(buf, body...)
	_, err := w.Write(buf)
	return err
}

// ReadMessage reads one frame and returns its message type and body. It
// reads the 4-byte length and refuses 0 (ErrEmptyFrame) and 1
// (ErrShortFrame) before reading anything after it, so a short frame
// never takes a header byte from the next one. It then reads the version
// and type bytes, and refuses another version (ErrVersion), a type caps
// does not accept (ErrUnexpectedType) and a length above the cap caps
// gives for the type (ErrFrameTooLarge) before allocating the body.
func ReadMessage(r io.Reader, caps Caps) (msgType byte, body []byte, err error) {
	var length [4]byte
	if _, err := io.ReadFull(r, length[:]); err != nil {
		return 0, nil, fmt.Errorf("wire: read frame length: %w", err)
	}
	n := binary.BigEndian.Uint32(length[:])
	switch n {
	case 0:
		return 0, nil, ErrEmptyFrame
	case 1:
		return 0, nil, ErrShortFrame
	}
	var hdr [headerLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, fmt.Errorf("wire: read frame header: %w", err)
	}
	if hdr[0] != Version {
		return 0, nil, ErrVersion
	}
	maxFrame, ok := caps(hdr[1])
	if !ok {
		return 0, nil, ErrUnexpectedType
	}
	if maxFrame < headerLen || uint64(n) > uint64(maxFrame) { //nolint:gosec // G115: maxFrame >= headerLen > 0 here
		return 0, nil, ErrFrameTooLarge
	}
	// n >= 2 here, so the subtraction cannot wrap.
	body = make([]byte, n-headerLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, fmt.Errorf("wire: read frame body: %w", err)
	}
	return hdr[1], body, nil
}
