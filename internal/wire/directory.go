package wire

import (
	"fmt"

	"golang.org/x/crypto/cryptobyte"
)

// Limits of an InstallDirectoryRequest. The frame cap (MaxFrame) is the
// tighter bound until plan 02-03 adds per-type caps.
const (
	MaxDirectory     = 1 << 20
	MaxDirectorySigs = 64 << 10
)

// InstallDirectoryRequest asks the signer to install a new directory
// version online: its canonical bytes and the admins' armored SSHSIG
// signatures under keyroster/directory/v1. Both fields are
// uint24-length-prefixed.
type InstallDirectoryRequest struct {
	Directory []byte
	Sigs      []byte
}

func (r *InstallDirectoryRequest) check() error {
	if len(r.Directory) == 0 || len(r.Directory) > MaxDirectory || len(r.Sigs) == 0 || len(r.Sigs) > MaxDirectorySigs {
		return fmt.Errorf("%w: directory or signature size", ErrMalformed)
	}
	return nil
}

// Marshal encodes the request body.
func (r *InstallDirectoryRequest) Marshal() ([]byte, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	var b cryptobyte.Builder
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(r.Directory) })
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(r.Sigs) })
	return b.Bytes()
}

// ParseInstallDirectoryRequest decodes a request body strictly.
func ParseInstallDirectoryRequest(body []byte) (*InstallDirectoryRequest, error) {
	s := cryptobyte.String(body)
	var doc, sigs cryptobyte.String
	if !s.ReadUint24LengthPrefixed(&doc) || !s.ReadUint24LengthPrefixed(&sigs) || !s.Empty() {
		return nil, ErrMalformed
	}
	r := &InstallDirectoryRequest{Directory: append([]byte(nil), doc...), Sigs: append([]byte(nil), sigs...)}
	if err := r.check(); err != nil {
		return nil, err
	}
	return r, nil
}

// InstallDirectoryResponse reports an installed directory: its version, the
// index of the directory_install log leaf that recorded it, and the
// SHA-256 of its canonical bytes (the next version's prev).
type InstallDirectoryResponse struct {
	Version   uint64
	LeafIndex uint64
	SHA256    [32]byte
}

// Marshal encodes the response body.
func (r *InstallDirectoryResponse) Marshal() ([]byte, error) {
	if r.Version == 0 {
		return nil, fmt.Errorf("%w: directory version 0", ErrMalformed)
	}
	var b cryptobyte.Builder
	b.AddUint64(r.Version)
	b.AddUint64(r.LeafIndex)
	b.AddBytes(r.SHA256[:])
	return b.Bytes()
}

// ParseInstallDirectoryResponse decodes a response body strictly.
func ParseInstallDirectoryResponse(body []byte) (*InstallDirectoryResponse, error) {
	s := cryptobyte.String(body)
	var (
		r   InstallDirectoryResponse
		sum []byte
	)
	if !s.ReadUint64(&r.Version) || !s.ReadUint64(&r.LeafIndex) || !s.ReadBytes(&sum, 32) || !s.Empty() || r.Version == 0 {
		return nil, ErrMalformed
	}
	copy(r.SHA256[:], sum)
	return &r, nil
}
