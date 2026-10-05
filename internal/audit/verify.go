package audit

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/wire"
)

// maxLine bounds one export line (a bundle_install leaf carries up to four
// 1 MiB documents, base64 encoded, plus its decoded object).
const maxLine = 16 << 20

// Options configures Verify.
type Options struct {
	// LogKey is the operator-pinned log public key. It is never taken
	// from the export.
	LogKey ssh.PublicKey
	// Previous is an earlier signed checkpoint of the same log (optional).
	// The export must extend it: at least as many entries, and its first
	// entries must reproduce the earlier root.
	Previous []byte
}

// Report summarizes a verified export.
type Report struct {
	Size    uint64
	Root    []byte
	Counts  map[tlog.Kind]uint64
	Serials int // issued certificates (issue leaves), each re-verified
	// SummarizedRefusals is the total of all refusal_summary counts:
	// refusals that were counted but not logged individually.
	SummarizedRefusals uint64
}

// Verify checks an export read from r without trusting anything in it but
// the leaf bytes and the checkpoint:
//
//   - strict JSONL: leaf indices exactly 0..n-1, exactly one checkpoint
//     line and it is last; the informational "decoded" objects are ignored
//   - every leaf decodes, records its own index, and leaf times never
//     decrease
//   - every issue leaf holds a certificate whose CA signature verifies over
//     its signed bytes (expired certificates included), whose CA key is not
//     a certificate, whose serial equals the leaf's and the key ID's, and
//     serials strictly increase across the log
//   - the RFC 6962 root recomputed from the leaf bytes alone equals the
//     root of the checkpoint, the checkpoint covers exactly n entries, and
//     it is signed by opts.LogKey
//   - with opts.Previous, the log neither shrank nor rewrote the entries
//     that checkpoint covered
func Verify(r io.Reader, opts Options) (*Report, error) {
	if opts.LogKey == nil {
		return nil, errors.New("audit: no pinned log key")
	}
	verifier, err := tlog.NewNoteVerifier(tlog.Origin(opts.LogKey), opts.LogKey)
	if err != nil {
		return nil, fmt.Errorf("audit: log key: %w", err)
	}
	var prev *tlog.Checkpoint
	if opts.Previous != nil {
		p, err := tlog.OpenCheckpoint(opts.Previous, verifier)
		if err != nil {
			return nil, fmt.Errorf("audit: previous checkpoint: %w", err)
		}
		prev = &p
	}
	rep := &Report{Counts: map[tlog.Kind]uint64{}}
	tree := tlog.NewLog()
	var (
		hashes     [][]byte
		checkpoint []byte
		lineNo     int
		lastTime   uint64
		lastSerial uint64
	)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), maxLine)
	for sc.Scan() {
		lineNo++
		line, err := parseLine(sc.Bytes())
		if err != nil {
			return nil, fmt.Errorf("audit: line %d: %w", lineNo, err)
		}
		isCheckpoint := line.Checkpoint != ""
		if checkpoint != nil {
			if isCheckpoint {
				return nil, fmt.Errorf("audit: line %d: more than one checkpoint line", lineNo)
			}
			return nil, fmt.Errorf("audit: line %d: the checkpoint line is not last", lineNo)
		}
		if isCheckpoint {
			checkpoint = []byte(line.Checkpoint)
			continue
		}
		want := tree.Size()
		switch {
		case *line.Index < want:
			return nil, fmt.Errorf("audit: line %d: index %d repeated or out of order (want %d)", lineNo, *line.Index, want)
		case *line.Index > want:
			return nil, fmt.Errorf("audit: line %d: index %d out of order, or entries %d..%d missing", lineNo, *line.Index, want, *line.Index-1)
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(line.Leaf)
		if err != nil || base64.StdEncoding.EncodeToString(raw) != line.Leaf {
			return nil, fmt.Errorf("audit: line %d: leaf is not canonical base64", lineNo)
		}
		leaf, err := tlog.DecodeLeaf(raw)
		if err != nil {
			return nil, fmt.Errorf("audit: entry %d: %w", want, err)
		}
		if leaf.Index != want {
			return nil, fmt.Errorf("audit: entry %d: leaf records index %d", want, leaf.Index)
		}
		if leaf.TimeMicros < lastTime {
			return nil, fmt.Errorf("audit: entry %d: leaf time goes back (%d after %d)", want, leaf.TimeMicros, lastTime)
		}
		lastTime = leaf.TimeMicros
		switch leaf.Kind {
		case tlog.KindIssue:
			body, err := tlog.DecodeIssueBody(leaf.Body)
			if err != nil {
				return nil, fmt.Errorf("audit: entry %d: %w", want, err)
			}
			if err := checkIssue(body, lastSerial, rep.Serials > 0); err != nil {
				return nil, fmt.Errorf("audit: entry %d: %w", want, err)
			}
			lastSerial = body.Serial
			rep.Serials++
		case tlog.KindRefusalSummary:
			body, err := tlog.DecodeRefusalSummaryBody(leaf.Body)
			if err != nil {
				return nil, fmt.Errorf("audit: entry %d: %w", want, err)
			}
			rep.SummarizedRefusals += body.Total()
		}
		hash := tlog.HashLeaf(raw)
		if err := tree.Append(hash); err != nil {
			return nil, fmt.Errorf("audit: entry %d: %w", want, err)
		}
		hashes = append(hashes, hash)
		rep.Counts[leaf.Kind]++
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("audit: read export: %w", err)
	}
	if checkpoint == nil {
		return nil, errors.New("audit: empty log: the export has no checkpoint line")
	}
	if tree.Size() == 0 {
		return nil, errors.New("audit: empty log: the export has no entries")
	}
	cp, err := tlog.OpenCheckpoint(checkpoint, verifier)
	if err != nil {
		return nil, fmt.Errorf("audit: checkpoint: %w", err)
	}
	if cp.Size != tree.Size() {
		return nil, fmt.Errorf("audit: the checkpoint covers %d entries, the export has %d", cp.Size, tree.Size())
	}
	root, err := tree.Root()
	if err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	if !bytes.Equal(root, cp.Root) {
		return nil, errors.New("audit: root mismatch: the entries do not reproduce the signed checkpoint")
	}
	if prev != nil {
		if prev.Size > cp.Size {
			return nil, fmt.Errorf("audit: log shrank: the previous checkpoint covers %d entries, this log has %d", prev.Size, cp.Size)
		}
		old, err := tlog.FromHashes(hashes[:prev.Size])
		if err != nil {
			return nil, fmt.Errorf("audit: %w", err)
		}
		oldRoot, err := old.Root()
		if err != nil {
			return nil, fmt.Errorf("audit: %w", err)
		}
		if !bytes.Equal(oldRoot, prev.Root) {
			return nil, fmt.Errorf("audit: log rewritten: the first %d entries do not reproduce the previous checkpoint", prev.Size)
		}
	}
	rep.Size, rep.Root = cp.Size, root
	return rep, nil
}

// checkIssue re-verifies the certificate of one issue leaf. It does not use
// ssh.CertChecker, so certificates that have since expired still verify.
func checkIssue(b *tlog.IssueBody, prevSerial uint64, havePrev bool) error {
	pk, err := ssh.ParsePublicKey(b.Cert)
	if err != nil {
		return fmt.Errorf("certificate does not parse: %w", err)
	}
	c, ok := pk.(*ssh.Certificate)
	if !ok {
		return errors.New("the logged key is not a certificate")
	}
	if !bytes.Equal(c.Marshal(), b.Cert) {
		return errors.New("certificate encoding is not canonical")
	}
	if _, isCert := c.SignatureKey.(*ssh.Certificate); isCert {
		return errors.New("the CA key of the certificate is itself a certificate")
	}
	if err := cert.CheckCAKey(c.SignatureKey); err != nil {
		return fmt.Errorf("certificate signed by an unusable CA key: %w", err)
	}
	if c.Signature == nil {
		return errors.New("certificate has no CA signature")
	}
	if err := c.SignatureKey.Verify(signedBytes(c), c.Signature); err != nil {
		return fmt.Errorf("CA signature does not verify: %w", err)
	}
	if c.Serial != b.Serial {
		return fmt.Errorf("leaf serial %d differs from the certificate serial %d", b.Serial, c.Serial)
	}
	if havePrev && b.Serial <= prevSerial {
		return fmt.Errorf("serials not strictly increasing: %d after %d", b.Serial, prevSerial)
	}
	if b.KeyID != c.KeyId {
		return errors.New("leaf key ID differs from the certificate key ID")
	}
	kid, err := cert.ParseKeyID(c.KeyId)
	if err != nil {
		return fmt.Errorf("certificate key ID: %w", err)
	}
	if kid.Serial != c.Serial {
		return fmt.Errorf("key ID serial %d differs from the certificate serial %d", kid.Serial, c.Serial)
	}
	if role := wire.CARole(b.CARole).String(); kid.CA != role {
		return fmt.Errorf("key ID CA %q differs from the leaf's CA role %q", kid.CA, role)
	}
	return nil
}

// signedBytes returns the bytes the CA signed: the certificate encoding
// without its final signature field (PROTOCOL.certkeys).
func signedBytes(c *ssh.Certificate) []byte {
	c2 := *c
	c2.Signature = nil
	out := c2.Marshal()
	return out[:len(out)-4] // drop the empty signature's length prefix
}

// parseLine decodes one line strictly: unknown fields, trailing data and
// lines that are neither a leaf line nor a checkpoint line are refused.
func parseLine(b []byte) (*ExportLine, error) {
	if len(bytes.TrimSpace(b)) == 0 {
		return nil, errors.New("empty line")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var l ExportLine
	if err := dec.Decode(&l); err != nil {
		return nil, fmt.Errorf("not a valid export line: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data after the JSON object")
	}
	switch {
	case l.Checkpoint != "" && l.Index == nil && l.Leaf == "" && l.Decoded == nil:
	case l.Checkpoint == "" && l.Index != nil && l.Leaf != "":
	default:
		return nil, errors.New("neither a leaf line nor a checkpoint line")
	}
	return &l, nil
}
