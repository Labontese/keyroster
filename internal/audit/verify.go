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
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// maxLine bounds one export line (a bundle_install leaf carries up to four
// 1 MiB documents, base64 encoded, plus its decoded object).
const maxLine = 16 << 20

// Options configures Verify.
type Options struct {
	// Pins are the SHA256 fingerprints of the offline root keys, obtained
	// out of band. They are the only trust anchor: the log key and the CA
	// keys are taken from bundle_install entries that verify against them,
	// never from the export otherwise.
	Pins []string
	// Threshold is the number of pinned roots that must have signed the
	// genesis bundle; it must equal the bundle's own threshold.
	Threshold int
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
	// IssuedByCA counts the issue leaves per CA role (user, host, machine).
	IssuedByCA map[string]int
	// SummarizedRefusals is the total of all refusal_summary counts:
	// refusals that were counted but not logged individually.
	SummarizedRefusals uint64
	// BundleVersion and PolicyVersion are those of the last installed
	// trust bundle and policy; LogKey is the log key they name.
	BundleVersion uint64
	PolicyVersion uint64
	LogKey        ssh.PublicKey
}

// anchor is the trust state in force at a point of the log: the last
// bundle and policy that verified against the pins (genesis) or against
// their predecessor (successor), and the keys taken from them.
type anchor struct {
	bundle    *trust.Bundle
	canonical []byte
	policy    *trust.Policy
	logKey    ssh.PublicKey
	activeCA  map[string]ssh.PublicKey // role -> active CA key
}

// install verifies one bundle_install entry and makes its bundle the one in
// force. The first is a genesis bundle checked against opts' pins and
// threshold; every later one must be a valid successor of the bundle in
// force (TUF rule). In Phase 1 every bundle must name the same log key.
func (a *anchor) install(body *tlog.BundleInstallBody, opts Options) error {
	var (
		b   *trust.Bundle
		p   *trust.Policy
		err error
	)
	if a.bundle == nil {
		b, p, err = trust.VerifyGenesisBundle(body.Bundle, body.BundleSigs, body.Policy, body.PolicySigs, opts.Pins, opts.Threshold)
		if err != nil {
			return fmt.Errorf("bundle_install is not anchored in the pinned roots: %w", err)
		}
	} else {
		b, p, err = trust.VerifySuccessor(a.bundle, a.canonical, body.Bundle, body.BundleSigs, body.Policy, body.PolicySigs)
		if err != nil {
			return fmt.Errorf("bundle_install is not a valid successor of trust bundle v%d: %w", a.bundle.Version, err)
		}
	}
	if body.BundleVersion != b.Version {
		return fmt.Errorf("bundle_install records bundle version %d, but its bundle is version %d", body.BundleVersion, b.Version)
	}
	logKey, err := trust.ParseKey(b.Log.Key)
	if err != nil {
		return fmt.Errorf("bundle_install: log key: %w", err)
	}
	if a.logKey != nil && !bytes.Equal(a.logKey.Marshal(), logKey.Marshal()) {
		return fmt.Errorf("log key change unsupported: trust bundle v%d names log key %s, earlier bundles %s",
			b.Version, ssh.FingerprintSHA256(logKey), ssh.FingerprintSHA256(a.logKey))
	}
	active := map[string]ssh.PublicKey{}
	for _, ca := range b.CAs {
		if ca.State != "active" {
			continue
		}
		pub, err := trust.ParseKey(ca.Key)
		if err != nil {
			return fmt.Errorf("bundle_install: %s CA key: %w", ca.Role, err)
		}
		active[ca.Role] = pub
	}
	a.bundle, a.canonical, a.policy, a.logKey, a.activeCA = b, body.Bundle, p, logKey, active
	return nil
}

// checkIssue checks an issue leaf's certificate against the bundle and
// policy in force: it must be signed by the active CA of the leaf's role,
// be a host certificate exactly for the host role, and carry the policy
// version in force in its key ID and in the leaf.
func (a *anchor) checkIssue(b *tlog.IssueBody, c *ssh.Certificate, kid cert.KeyID) error {
	role := kid.CA
	if a.bundle == nil {
		return errors.New("issue entry before the first bundle_install: no root-signed CA key is in force")
	}
	want, ok := a.activeCA[role]
	if !ok {
		return fmt.Errorf("trust bundle v%d has no active %s CA", a.bundle.Version, role)
	}
	if !bytes.Equal(c.SignatureKey.Marshal(), want.Marshal()) {
		return fmt.Errorf("certificate for CA role %s signed by %s, not by the role's active CA %s in trust bundle v%d",
			role, ssh.FingerprintSHA256(c.SignatureKey), ssh.FingerprintSHA256(want), a.bundle.Version)
	}
	wantType := uint32(ssh.UserCert)
	if role == trust.RoleHost {
		wantType = ssh.HostCert
	}
	if c.CertType != wantType {
		return fmt.Errorf("certificate type %s for CA role %s, want %s", certTypeName(c.CertType), role, certTypeName(wantType))
	}
	if kid.Policy != a.policy.Version {
		return fmt.Errorf("key ID pol=%d, but the policy in force is version %d", kid.Policy, a.policy.Version)
	}
	if b.PolicyVersion != a.policy.Version {
		return fmt.Errorf("leaf records policy version %d, but the policy in force is version %d", b.PolicyVersion, a.policy.Version)
	}
	return nil
}

func certTypeName(t uint32) string {
	switch t {
	case ssh.UserCert:
		return "user"
	case ssh.HostCert:
		return "host"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}

// Verify checks an export read from r. Its only trust anchors are the
// pinned root fingerprints in opts; it trusts nothing in the export but
// the leaf bytes and the checkpoint, and only after checking them:
//
//   - strict JSONL: leaf indices exactly 0..n-1, exactly one checkpoint
//     line and it is last; the informational "decoded" objects are ignored
//   - every leaf decodes, records its own index, and leaf times never
//     decrease
//   - the first bundle_install entry holds a genesis bundle and policy
//     signed by opts.Threshold of the pinned roots, whose root set is
//     exactly the pinned set; every later one is a root-signed successor of
//     the bundle in force; each records its bundle's version, and all of
//     them name the same log key (Phase 1)
//   - every issue leaf comes after the first bundle_install and holds a
//     certificate whose CA signature verifies over its signed bytes
//     (expired certificates included), signed by the active CA of the
//     leaf's role in the bundle in force, of the role's type (host
//     certificates for the host CA only), whose key ID and leaf carry the
//     policy version in force, whose serial equals the leaf's and the key
//     ID's, and serials strictly increase across the log
//   - the RFC 6962 root recomputed from the leaf bytes alone equals the
//     root of the checkpoint, the checkpoint covers exactly n entries, and
//     it is signed by the log key of the root-signed bundle
//   - with opts.Previous, the log neither shrank nor rewrote the entries
//     that checkpoint covered
func Verify(r io.Reader, opts Options) (*Report, error) {
	if len(opts.Pins) == 0 {
		return nil, errors.New("audit: no pinned root fingerprints")
	}
	rep := &Report{Counts: map[tlog.Kind]uint64{}, IssuedByCA: map[string]int{}}
	tree := tlog.NewLog()
	var (
		trustState anchor
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
		case tlog.KindBundleInstall:
			body, err := tlog.DecodeBundleInstallBody(leaf.Body)
			if err != nil {
				return nil, fmt.Errorf("audit: entry %d: %w", want, err)
			}
			if err := trustState.install(body, opts); err != nil {
				return nil, fmt.Errorf("audit: entry %d: %w", want, err)
			}
		case tlog.KindIssue:
			body, err := tlog.DecodeIssueBody(leaf.Body)
			if err != nil {
				return nil, fmt.Errorf("audit: entry %d: %w", want, err)
			}
			c, kid, err := checkIssue(body, lastSerial, rep.Serials > 0)
			if err != nil {
				return nil, fmt.Errorf("audit: entry %d: %w", want, err)
			}
			if err := trustState.checkIssue(body, c, kid); err != nil {
				return nil, fmt.Errorf("audit: entry %d: %w", want, err)
			}
			lastSerial = body.Serial
			rep.Serials++
			rep.IssuedByCA[kid.CA]++
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
	if trustState.logKey == nil {
		return nil, errors.New("audit: the export has no bundle_install entry, so no root-signed log key")
	}
	verifier, err := tlog.NewNoteVerifier(tlog.Origin(trustState.logKey), trustState.logKey)
	if err != nil {
		return nil, fmt.Errorf("audit: log key: %w", err)
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
	if opts.Previous != nil {
		prev, err := tlog.OpenCheckpoint(opts.Previous, verifier)
		if err != nil {
			return nil, fmt.Errorf("audit: previous checkpoint: %w", err)
		}
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
	rep.BundleVersion, rep.PolicyVersion, rep.LogKey = trustState.bundle.Version, trustState.policy.Version, trustState.logKey
	return rep, nil
}

// checkIssue re-verifies the certificate of one issue leaf and returns it
// with its parsed key ID. It does not use ssh.CertChecker, so certificates
// that have since expired still verify.
func checkIssue(b *tlog.IssueBody, prevSerial uint64, havePrev bool) (*ssh.Certificate, cert.KeyID, error) {
	var none cert.KeyID
	pk, err := ssh.ParsePublicKey(b.Cert)
	if err != nil {
		return nil, none, fmt.Errorf("certificate does not parse: %w", err)
	}
	c, ok := pk.(*ssh.Certificate)
	if !ok {
		return nil, none, errors.New("the logged key is not a certificate")
	}
	if !bytes.Equal(c.Marshal(), b.Cert) {
		return nil, none, errors.New("certificate encoding is not canonical")
	}
	if _, isCert := c.SignatureKey.(*ssh.Certificate); isCert {
		return nil, none, errors.New("the CA key of the certificate is itself a certificate")
	}
	if err := cert.CheckCAKey(c.SignatureKey); err != nil {
		return nil, none, fmt.Errorf("certificate signed by an unusable CA key: %w", err)
	}
	if c.Signature == nil {
		return nil, none, errors.New("certificate has no CA signature")
	}
	if err := c.SignatureKey.Verify(signedBytes(c), c.Signature); err != nil {
		return nil, none, fmt.Errorf("CA signature does not verify: %w", err)
	}
	if c.Serial != b.Serial {
		return nil, none, fmt.Errorf("leaf serial %d differs from the certificate serial %d", b.Serial, c.Serial)
	}
	if havePrev && b.Serial <= prevSerial {
		return nil, none, fmt.Errorf("serials not strictly increasing: %d after %d", b.Serial, prevSerial)
	}
	if b.KeyID != c.KeyId {
		return nil, none, errors.New("leaf key ID differs from the certificate key ID")
	}
	kid, err := cert.ParseKeyID(c.KeyId)
	if err != nil {
		return nil, none, fmt.Errorf("certificate key ID: %w", err)
	}
	if kid.Serial != c.Serial {
		return nil, none, fmt.Errorf("key ID serial %d differs from the certificate serial %d", kid.Serial, c.Serial)
	}
	if role := wire.CARole(b.CARole).String(); kid.CA != role {
		return nil, none, fmt.Errorf("key ID CA %q differs from the leaf's CA role %q", kid.CA, role)
	}
	return c, kid, nil
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
