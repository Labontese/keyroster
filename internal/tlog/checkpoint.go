package tlog

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/mod/sumdb/note"
)

// OriginPrefix starts every keyroster log origin.
const OriginPrefix = "keyroster/log/"

// MaxCheckpoint bounds a signed checkpoint note.
const MaxCheckpoint = 16 << 10

// ErrMalformedCheckpoint reports a checkpoint body that is not exactly
// origin, size and root hash.
var ErrMalformedCheckpoint = errors.New("tlog: malformed checkpoint")

// Origin returns the log origin (and note key name) for a log key:
// "keyroster/log/" plus the first 16 hex digits of the SHA-256 of the key's
// SSH wire encoding. A different log key is a different log.
func Origin(logKey ssh.PublicKey) string {
	sum := sha256.Sum256(logKey.Marshal())
	return OriginPrefix + hex.EncodeToString(sum[:8])
}

// Checkpoint is a C2SP tlog-checkpoint body.
type Checkpoint struct {
	Origin string
	Size   uint64
	Root   []byte
}

// Text returns the note text: origin, decimal size and standard-base64
// root, one per line, with a trailing newline. keyroster writes no
// extension lines.
func (c Checkpoint) Text() string {
	return c.Origin + "\n" + strconv.FormatUint(c.Size, 10) + "\n" + base64.StdEncoding.EncodeToString(c.Root) + "\n"
}

// SignCheckpoint signs cp's text with s, whose name must be cp's origin.
func SignCheckpoint(cp Checkpoint, s note.Signer) ([]byte, error) {
	if s.Name() != cp.Origin {
		return nil, fmt.Errorf("tlog: signer %q does not sign origin %q", s.Name(), cp.Origin)
	}
	if _, err := ParseCheckpointText(cp.Text()); err != nil {
		return nil, err
	}
	return note.Sign(&note.Note{Text: cp.Text()}, s)
}

// OpenCheckpoint verifies msg with v (a signature by v is required; other
// signatures are ignored, per the signed-note spec) and parses the body
// strictly. The origin must equal v's key name.
func OpenCheckpoint(msg []byte, v note.Verifier) (Checkpoint, error) {
	if len(msg) > MaxCheckpoint {
		return Checkpoint{}, fmt.Errorf("%w: note too large", ErrMalformedCheckpoint)
	}
	n, err := note.Open(msg, note.VerifierList(v))
	if err != nil {
		var unverified *note.UnverifiedNoteError
		if errors.As(err, &unverified) {
			return Checkpoint{}, fmt.Errorf("tlog: checkpoint not signed by the log key %s", v.Name())
		}
		return Checkpoint{}, fmt.Errorf("tlog: checkpoint signature: %w", err)
	}
	cp, err := ParseCheckpointText(n.Text)
	if err != nil {
		return Checkpoint{}, err
	}
	if cp.Origin != v.Name() {
		return Checkpoint{}, fmt.Errorf("%w: origin %q, want %q", ErrMalformedCheckpoint, cp.Origin, v.Name())
	}
	return cp, nil
}

// ParseCheckpointText parses a checkpoint body: exactly three lines, a
// non-empty origin of at most 255 bytes, a decimal size without leading
// zeros and a canonical base64 32-byte root. Extension lines are refused.
func ParseCheckpointText(text string) (Checkpoint, error) {
	body, ok := strings.CutSuffix(text, "\n")
	if !ok {
		return Checkpoint{}, fmt.Errorf("%w: no trailing newline", ErrMalformedCheckpoint)
	}
	lines := strings.Split(body, "\n")
	if len(lines) != 3 {
		return Checkpoint{}, fmt.Errorf("%w: want 3 lines, got %d", ErrMalformedCheckpoint, len(lines))
	}
	origin, sizeStr, rootStr := lines[0], lines[1], lines[2]
	if origin == "" || len(origin) > 255 {
		return Checkpoint{}, fmt.Errorf("%w: origin", ErrMalformedCheckpoint)
	}
	size, err := strconv.ParseUint(sizeStr, 10, 64)
	if err != nil || strconv.FormatUint(size, 10) != sizeStr {
		return Checkpoint{}, fmt.Errorf("%w: size %q", ErrMalformedCheckpoint, sizeStr)
	}
	root, err := base64.StdEncoding.Strict().DecodeString(rootStr)
	if err != nil || len(root) != HashSize || base64.StdEncoding.EncodeToString(root) != rootStr {
		return Checkpoint{}, fmt.Errorf("%w: root hash", ErrMalformedCheckpoint)
	}
	return Checkpoint{Origin: origin, Size: size, Root: root}, nil
}
