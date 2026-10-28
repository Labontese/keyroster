package wire

import (
	"fmt"

	"golang.org/x/crypto/cryptobyte"
)

// The chain messages (03-07): keyroster-server asks the signer for an
// installed trust bundle or directory by version, so that an agent behind
// the current version gets every version since its own, which it verifies
// one successor at a time. Each request body is one uint64 version from
// 1; an absent version is refused not_found.

// GetBundleRequest asks for the installed trust bundle of Version, with
// its policy and both signature files (TypeGetBundle).
type GetBundleRequest struct {
	Version uint64
}

// GetDirectoryVersionRequest asks for the installed directory of Version
// with its signatures (TypeGetDirectoryVersion).
type GetDirectoryVersionRequest struct {
	Version uint64
}

// marshalVersion encodes a version request body.
func marshalVersion(v uint64) ([]byte, error) {
	if v == 0 {
		return nil, fmt.Errorf("%w: version 0", ErrMalformed)
	}
	var b cryptobyte.Builder
	b.AddUint64(v)
	return b.Bytes()
}

// parseVersion decodes a version request body strictly.
func parseVersion(body []byte) (uint64, error) {
	s := cryptobyte.String(body)
	var v uint64
	if !s.ReadUint64(&v) || !s.Empty() || v == 0 {
		return 0, ErrMalformed
	}
	return v, nil
}

// Marshal encodes the request body.
func (r *GetBundleRequest) Marshal() ([]byte, error) { return marshalVersion(r.Version) }

// ParseGetBundleRequest decodes a request body strictly.
func ParseGetBundleRequest(body []byte) (*GetBundleRequest, error) {
	v, err := parseVersion(body)
	if err != nil {
		return nil, err
	}
	return &GetBundleRequest{Version: v}, nil
}

// Marshal encodes the request body.
func (r *GetDirectoryVersionRequest) Marshal() ([]byte, error) { return marshalVersion(r.Version) }

// ParseGetDirectoryVersionRequest decodes a request body strictly.
func ParseGetDirectoryVersionRequest(body []byte) (*GetDirectoryVersionRequest, error) {
	v, err := parseVersion(body)
	if err != nil {
		return nil, err
	}
	return &GetDirectoryVersionRequest{Version: v}, nil
}

// GetBundleResponse is one installed trust bundle version: the bundle and
// policy documents and their root signatures, exactly as installed. Its
// body is the version as uint64 and the four documents
// uint24-length-prefixed, each non-empty, within MaxStatusFrame (the
// signer installs no bundle and policy whose Status would not fit).
type GetBundleResponse struct {
	Version                                uint64
	Bundle, BundleSigs, Policy, PolicySigs []byte
}

func (r *GetBundleResponse) check() error {
	if r.Version == 0 || len(r.Bundle) == 0 || len(r.BundleSigs) == 0 || len(r.Policy) == 0 || len(r.PolicySigs) == 0 {
		return fmt.Errorf("%w: a bundle response without its version or documents", ErrMalformed)
	}
	return nil
}

// Marshal encodes the response body; one above MaxStatusFrame minus the
// header is ErrStatusTooLarge.
func (r *GetBundleResponse) Marshal() ([]byte, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	var b cryptobyte.Builder
	b.AddUint64(r.Version)
	for _, d := range [][]byte{r.Bundle, r.BundleSigs, r.Policy, r.PolicySigs} {
		if len(d) > 1<<24-1 {
			return nil, ErrStatusTooLarge
		}
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(d) })
	}
	out, err := b.Bytes()
	if err != nil {
		return nil, err
	}
	if len(out) > maxStatusBody {
		return nil, ErrStatusTooLarge
	}
	return out, nil
}

// ParseGetBundleResponse decodes a response body strictly.
func ParseGetBundleResponse(body []byte) (*GetBundleResponse, error) {
	if len(body) > maxStatusBody {
		return nil, ErrStatusTooLarge
	}
	s := cryptobyte.String(body)
	var r GetBundleResponse
	if !s.ReadUint64(&r.Version) {
		return nil, ErrMalformed
	}
	for _, d := range []*[]byte{&r.Bundle, &r.BundleSigs, &r.Policy, &r.PolicySigs} {
		var v cryptobyte.String
		if !s.ReadUint24LengthPrefixed(&v) {
			return nil, ErrMalformed
		}
		*d = append([]byte(nil), v...)
	}
	if !s.Empty() {
		return nil, ErrMalformed
	}
	if err := r.check(); err != nil {
		return nil, err
	}
	return &r, nil
}

// GetDirectoryVersionResponse is one installed directory version: its
// canonical bytes and the admins' signatures, exactly as installed. Its
// body is the version as uint64 and both fields uint24-length-prefixed,
// within the caps of a GetDirectoryResponse (MaxDirectoryFrame).
type GetDirectoryVersionResponse struct {
	Version   uint64
	Directory []byte
	Sigs      []byte
}

func (r *GetDirectoryVersionResponse) check() error {
	if r.Version == 0 || len(r.Directory) == 0 || len(r.Directory) > MaxDirectory || len(r.Sigs) == 0 || len(r.Sigs) > MaxDirectorySigs {
		return fmt.Errorf("%w: directory version response size", ErrMalformed)
	}
	return nil
}

// Marshal encodes the response body.
func (r *GetDirectoryVersionResponse) Marshal() ([]byte, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	var b cryptobyte.Builder
	b.AddUint64(r.Version)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(r.Directory) })
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(r.Sigs) })
	return b.Bytes()
}

// ParseGetDirectoryVersionResponse decodes a response body strictly.
func ParseGetDirectoryVersionResponse(body []byte) (*GetDirectoryVersionResponse, error) {
	s := cryptobyte.String(body)
	var (
		r         GetDirectoryVersionResponse
		doc, sigs cryptobyte.String
	)
	if !s.ReadUint64(&r.Version) || !s.ReadUint24LengthPrefixed(&doc) || !s.ReadUint24LengthPrefixed(&sigs) || !s.Empty() {
		return nil, ErrMalformed
	}
	r.Directory, r.Sigs = append([]byte(nil), doc...), append([]byte(nil), sigs...)
	if err := r.check(); err != nil {
		return nil, err
	}
	return &r, nil
}
