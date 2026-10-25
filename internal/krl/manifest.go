package krl

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
)

// Namespace is the SSHSIG namespace of the ops key's signature over a KRL
// manifest. A signature under any other namespace never verifies as one.
const Namespace = "keyroster/krl/v1"

// Size bounds of a published KRL version (F12).
const (
	// MaxManifest bounds a manifest; ParseManifest refuses a larger one
	// before decoding. A real manifest is about 250 bytes.
	MaxManifest = 4 << 10
	// MaxManifestSig bounds the manifest's armored SSHSIG; VerifyManifest
	// refuses a larger one before parsing. The armored form of sshsig's
	// largest blob (8 KiB) stays below 11.3 KiB.
	MaxManifestSig = 16 << 10
	// MaxKRLResponse bounds the JSON document that serves one KRL version
	// over HTTP (GET /api/v1/krl, serverclient.KRLDocument): each of its
	// three []byte fields is standard base64 with padding, which
	// encoding/json never escapes, so a field of n bytes takes
	// 4*((n+2)/3) bytes; 1 KiB covers the keys, the punctuation and the
	// encoder's newline. With MaxKRL, MaxManifest and MaxManifestSig that
	// is 5 592 408 + 5 464 + 21 848 + 1 024 = 5 620 744 bytes, above the
	// 4 MiB cap of every other route. 03-07 reuses it for the KRL item of
	// the agent state response.
	MaxKRLResponse = 4*((MaxKRL+2)/3) + 4*((MaxManifest+2)/3) + 4*((MaxManifestSig+2)/3) + 1<<10
)

// Manifest errors. Each refusal of VerifyManifest has its own sentinel.
var (
	ErrManifest     = errors.New("krl: malformed manifest")
	ErrSigner       = errors.New("krl: the manifest is not signed by the bundle's ops key")
	ErrSignature    = errors.New("krl: the manifest signature does not verify under keyroster/krl/v1")
	ErrInstallation = errors.New("krl: the manifest is for another installation")
	ErrVersion      = errors.New("krl: the KRL version is not above the stored version")
	ErrDigest       = errors.New("krl: the KRL bytes do not match the manifest's SHA-256")
)

// Manifest describes one published KRL version. It is canonical JSON
// (trust.CanonicalJSON, fields in this order) and is signed, detached, by
// the trust bundle's ops key under Namespace.
type Manifest struct {
	InstallationID string `json:"installation_id"`
	KRLVersion     uint64 `json:"krl_version"`
	KRLSHA256      string `json:"krl_sha256"`
	IssuedAt       string `json:"issued_at"`
	BundleVersion  uint64 `json:"bundle_version"`
	LogIndex       uint64 `json:"log_index"`
}

// Validate checks the manifest's structure: an installation ID of the
// bundle's form, a KRL version and a bundle version of at least 1, a
// SHA-256 of 64 lowercase hex digits and an issued_at in trust's timestamp
// format.
func (m *Manifest) Validate() error {
	switch {
	case !trust.IsInstallationID(m.InstallationID):
		return fmt.Errorf("%w: installation_id must be 32 lowercase hex digits", ErrManifest)
	case m.KRLVersion < 1:
		return fmt.Errorf("%w: krl_version must be >= 1", ErrManifest)
	case !isSHA256(m.KRLSHA256):
		return fmt.Errorf("%w: krl_sha256 must be 64 lowercase hex digits", ErrManifest)
	case m.BundleVersion < 1:
		return fmt.Errorf("%w: bundle_version must be >= 1", ErrManifest)
	}
	if err := trust.CheckTimestamp(m.IssuedAt); err != nil {
		return fmt.Errorf("%w: %w", ErrManifest, err)
	}
	return nil
}

// Canonical validates m and returns its canonical encoding, the bytes the
// ops key signs.
func (m *Manifest) Canonical() ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	out, err := trust.CanonicalJSON(m)
	if err != nil {
		return nil, err
	}
	if len(out) > MaxManifest {
		return nil, fmt.Errorf("%w: %d bytes", ErrManifest, len(out))
	}
	return out, nil
}

// ParseManifest decodes a canonical manifest strictly (trust.DecodeStrict)
// and validates it. A manifest above MaxManifest is refused before
// decoding.
func ParseManifest(data []byte) (*Manifest, error) {
	if len(data) > MaxManifest {
		return nil, fmt.Errorf("%w: %d bytes, above %d", ErrManifest, len(data), MaxManifest)
	}
	var m Manifest
	if err := trust.DecodeStrict(data, &m); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrManifest, err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// SHA256Hex returns the lowercase hex SHA-256 of a KRL, as krl_sha256
// records it.
func SHA256Hex(krl []byte) string {
	sum := sha256.Sum256(krl)
	return hex.EncodeToString(sum[:])
}

// VerifyManifest checks one published KRL version against the root-pinned
// bundle b and returns its manifest. It refuses, each with its own
// sentinel: a signature above MaxManifestSig before parsing it, KRL bytes
// above MaxKRL (ErrTooLarge), a manifest that does not parse (ErrManifest),
// a signature by any key but b's ops key (ErrSigner) or one that does not
// verify under Namespace (ErrSignature), an installation ID other than the
// pinned one, which must be non-empty (ErrInstallation), a krl_version not
// above storedVersion (ErrVersion), and KRL bytes whose SHA-256 is not
// krl_sha256 (ErrDigest).
func VerifyManifest(manifest, sig, krlBytes []byte, b *trust.Bundle, installationID string, storedVersion uint64) (*Manifest, error) {
	if b == nil {
		return nil, fmt.Errorf("%w: no trust bundle", ErrSigner)
	}
	if len(sig) > MaxManifestSig {
		return nil, fmt.Errorf("%w: signature of %d bytes, above %d", ErrSignature, len(sig), MaxManifestSig)
	}
	if len(krlBytes) > MaxKRL {
		return nil, fmt.Errorf("%w: %d bytes", ErrTooLarge, len(krlBytes))
	}
	m, err := ParseManifest(manifest)
	if err != nil {
		return nil, err
	}
	s, err := sshsig.Parse(sig)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSignature, err)
	}
	if trust.FormatKey(s.PublicKey()) != b.OpsKey.Key {
		return nil, ErrSigner
	}
	if err := s.Verify(Namespace, manifest); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSignature, err)
	}
	if installationID == "" || m.InstallationID != installationID {
		return nil, fmt.Errorf("%w: manifest %s, pinned %q", ErrInstallation, m.InstallationID, installationID)
	}
	if m.KRLVersion <= storedVersion {
		return nil, fmt.Errorf("%w: version %d, stored %d", ErrVersion, m.KRLVersion, storedVersion)
	}
	if SHA256Hex(krlBytes) != m.KRLSHA256 {
		return nil, ErrDigest
	}
	return m, nil
}

func isSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
