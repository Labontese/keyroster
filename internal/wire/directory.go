package wire

import (
	"fmt"

	"golang.org/x/crypto/cryptobyte"
)

// Limits of a directory and its signatures in an InstallDirectoryRequest
// and a GetDirectoryResponse. Both messages travel in frames of up to
// MaxDirectoryFrame. MaxDirectory equals tlog.MaxDocument, so every
// directory that installs fits its directory_install leaf.
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

// GetDirectoryResponse is what the signer holds as its installed
// directory: the version (0 when none is installed), the canonical bytes
// and the admins' signatures as installed, and whether the directory is
// authorized under the policy in force (logins are refused while it is
// not). The server mirrors exactly this. Version 0 has one encoding only:
// no directory bytes, no signatures, not authorized.
type GetDirectoryResponse struct {
	Version    uint64
	Directory  []byte
	Sigs       []byte
	Authorized bool
}

func (r *GetDirectoryResponse) check() error {
	if r.Version == 0 {
		if len(r.Directory) != 0 || len(r.Sigs) != 0 || r.Authorized {
			return fmt.Errorf("%w: a version 0 directory response carries a directory", ErrMalformed)
		}
		return nil
	}
	if len(r.Directory) == 0 || len(r.Directory) > MaxDirectory || len(r.Sigs) == 0 || len(r.Sigs) > MaxDirectorySigs {
		return fmt.Errorf("%w: directory or signature size", ErrMalformed)
	}
	return nil
}

// Marshal encodes the response body: the version as uint64, the directory
// and the signatures uint24-length-prefixed, and Authorized as one byte 0
// or 1.
func (r *GetDirectoryResponse) Marshal() ([]byte, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	var b cryptobyte.Builder
	b.AddUint64(r.Version)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(r.Directory) })
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(r.Sigs) })
	var auth uint8
	if r.Authorized {
		auth = 1
	}
	b.AddUint8(auth)
	return b.Bytes()
}

// ParseGetDirectoryResponse decodes a response body strictly: Authorized
// must be 0 or 1, nothing may follow it, and a version 0 response must
// carry no directory, no signatures and Authorized 0.
func ParseGetDirectoryResponse(body []byte) (*GetDirectoryResponse, error) {
	s := cryptobyte.String(body)
	var (
		r         GetDirectoryResponse
		doc, sigs cryptobyte.String
		auth      uint8
	)
	if !s.ReadUint64(&r.Version) || !s.ReadUint24LengthPrefixed(&doc) || !s.ReadUint24LengthPrefixed(&sigs) ||
		!s.ReadUint8(&auth) || !s.Empty() || auth > 1 {
		return nil, ErrMalformed
	}
	r.Authorized = auth == 1
	if len(doc) > 0 {
		r.Directory = append([]byte(nil), doc...)
	}
	if len(sigs) > 0 {
		r.Sigs = append([]byte(nil), sigs...)
	}
	if err := r.check(); err != nil {
		return nil, err
	}
	return &r, nil
}
