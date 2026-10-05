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

	"github.com/Labontese/keyroster/internal/tlog"
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
	Previous []byte
}

// Report summarizes a verified export.
type Report struct {
	Size    uint64
	Root    []byte
	Counts  map[tlog.Kind]uint64
	Serials int // issued certificates (issue leaves)
}

// Verify checks an export read from r: strict JSONL, leaf indices exactly
// 0..n-1, exactly one checkpoint line and it is last, every leaf decodes,
// the RFC 6962 root recomputed from the leaf bytes alone equals the root of
// the checkpoint, the checkpoint covers exactly n leaves, and it is signed
// by opts.LogKey. The "decoded" objects are ignored.
func Verify(r io.Reader, opts Options) (*Report, error) {
	if opts.LogKey == nil {
		return nil, errors.New("audit: no pinned log key")
	}
	verifier, err := tlog.NewNoteVerifier(tlog.Origin(opts.LogKey), opts.LogKey)
	if err != nil {
		return nil, fmt.Errorf("audit: log key: %w", err)
	}
	rep := &Report{Counts: map[tlog.Kind]uint64{}}
	tree := tlog.NewLog()
	var (
		checkpoint []byte
		lineNo     int
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
			return nil, fmt.Errorf("audit: line %d: index %d, entries %d..%d missing", lineNo, *line.Index, want, *line.Index-1)
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
		if err := tree.Append(tlog.HashLeaf(raw)); err != nil {
			return nil, fmt.Errorf("audit: entry %d: %w", want, err)
		}
		rep.Counts[leaf.Kind]++
		if leaf.Kind == tlog.KindIssue {
			rep.Serials++
		}
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
	rep.Size, rep.Root = cp.Size, root
	return rep, nil
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
