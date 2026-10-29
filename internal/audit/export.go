// Package audit exports the signer's Merkle log as JSONL and verifies such
// an export end to end without trusting the signer (VIS-03).
//
// Export format: one JSON object per line. Leaf lines come first, in index
// order 0..n-1:
//
//	{"index":N,"leaf":"<std base64 of the canonical leaf bytes>","decoded":{...}}
//
// and one final line carries the signed checkpoint note for size n:
//
//	{"checkpoint":"<signed note text>"}
//
// "decoded" is informational: Verify does not interpret it, except for
// the fields a restore reads from the line's text with grep to count, list
// and replay lost installs (03-02, signer-install.md). "kind" on every
// leaf line, "bundle_version" on every bundle_install line, and "version",
// "directory" and "sigs" on a directory_install line that carries them
// must each occur once, with the leaf's own value, and on no line of
// another kind (checkGrepFields, checkReplayFields). Exports written
// before 02-12 have no "version", and those before 03-02 no "directory"
// or "sigs"; their lines still verify.
package audit

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"slices"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/wire"
)

// ExportLine is one line of an export: a leaf line (Index, Leaf, Decoded)
// or the checkpoint line (Checkpoint only).
type ExportLine struct {
	Index      *uint64         `json:"index,omitempty"`
	Leaf       string          `json:"leaf,omitempty"`
	Decoded    json.RawMessage `json:"decoded,omitempty"`
	Checkpoint string          `json:"checkpoint,omitempty"`
}

// LogSource reads a consistent snapshot of a log: fn is called for every
// leaf below the latest checkpoint's size, in index order, and the signed
// checkpoint is returned (signerdb.DB implements it).
type LogSource interface {
	ReadLog(ctx context.Context, fn func(idx uint64, leaf []byte) error) (note []byte, size uint64, err error)
}

// Export writes src as JSONL to w and returns the number of leaves.
func Export(ctx context.Context, w io.Writer, src LogSource) (uint64, error) {
	bw := bufio.NewWriter(w)
	enc := json.NewEncoder(bw)
	enc.SetEscapeHTML(false)
	var n uint64
	note, _, err := src.ReadLog(ctx, func(idx uint64, leaf []byte) error {
		i := idx
		n++
		return enc.Encode(ExportLine{Index: &i, Leaf: base64.StdEncoding.EncodeToString(leaf), Decoded: Decode(leaf)})
	})
	if err != nil {
		return 0, err
	}
	if err := enc.Encode(ExportLine{Checkpoint: string(note)}); err != nil {
		return 0, err
	}
	return n, bw.Flush()
}

// Decode renders leaf bytes as an informational JSON object. A leaf that
// does not decode yields {"error": ...}.
func Decode(leaf []byte) json.RawMessage {
	out, err := json.Marshal(decodeLeaf(leaf))
	if err != nil {
		return json.RawMessage(`{"error":"unrenderable"}`)
	}
	return out
}

func decodeLeaf(data []byte) map[string]any {
	l, err := tlog.DecodeLeaf(data)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	m := map[string]any{"kind": l.Kind.String(), "index": l.Index, "time_micros": l.TimeMicros}
	switch l.Kind {
	case tlog.KindIssue:
		b, err := tlog.DecodeIssueBody(l.Body)
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		types := make([]string, 0, len(b.Evidence))
		for _, e := range b.Evidence {
			types = append(types, e.Type)
		}
		m["ca_role"] = wire.CARole(b.CARole).String()
		m["serial"] = b.Serial
		m["policy_version"] = b.PolicyVersion
		m["request_digest"] = hex.EncodeToString(b.RequestDigest[:])
		m["evidence_types"] = types
		m["key_id"] = b.KeyID
		if pk, err := ssh.ParsePublicKey(b.Cert); err == nil {
			if c, ok := pk.(*ssh.Certificate); ok {
				m["principals"] = c.ValidPrincipals
				m["valid_after"] = c.ValidAfter
				m["valid_before"] = c.ValidBefore
				m["ca_fingerprint"] = ssh.FingerprintSHA256(c.SignatureKey)
				m["ca_algorithm"] = c.SignatureKey.Type()
			}
		}
	case tlog.KindRefusal:
		b, err := tlog.DecodeRefusalBody(l.Body)
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		m["reason"] = tlog.ReasonName(b.Reason)
		m["detail"] = b.Detail
		m["peer_uid"] = b.PeerUID
		m["request_digest"] = hex.EncodeToString(b.RequestDigest[:])
	case tlog.KindRefusalSummary:
		b, err := tlog.DecodeRefusalSummaryBody(l.Body)
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		counts := map[string]uint64{}
		for _, c := range b.Counts {
			counts[tlog.ReasonName(c.Reason)] = c.Count
		}
		m["window_start_micros"] = b.WindowStartMicros
		m["window_end_micros"] = b.WindowEndMicros
		m["counts"] = counts
		m["total"] = b.Total()
	case tlog.KindClockRegression:
		b, err := tlog.DecodeClockRegressionBody(l.Body)
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		m["now_micros"] = b.NowMicros
		m["high_water_micros"] = b.HighWaterMicros
	case tlog.KindCAInit:
		b, err := tlog.DecodeCAInitBody(l.Body)
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		keys := make([]map[string]string, 0, len(b.Keys))
		for _, k := range b.Keys {
			e := map[string]string{"role": k.Role, "alg": k.Alg, "custody": k.Custody}
			if pk, err := ssh.ParsePublicKey(k.PublicKey); err == nil {
				e["fingerprint"] = ssh.FingerprintSHA256(pk)
			}
			keys = append(keys, e)
		}
		m["keys"] = keys
	case tlog.KindBundleInstall:
		b, err := tlog.DecodeBundleInstallBody(l.Body)
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		m["bundle_version"] = b.BundleVersion
	case tlog.KindDirectoryInstall:
		b, err := tlog.DecodeDirectoryInstallBody(l.Body)
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		m["version"] = b.Version
		m["policy_version"] = b.PolicyVersion
		// The installed document and its signatures, as standard base64,
		// so a restore can write them back as a proposal (directory.json
		// and directory.json.sigs) and replay them with keyroster directory
		// install (03-02). Verify requires them to be the leaf's own
		// bytes (checkReplayFields), and the signer checks them again at
		// the replay.
		m["directory"] = b.Directory
		m["sigs"] = b.Sigs
	case tlog.KindLoginIssue:
		b, err := tlog.DecodeLoginIssueBody(l.Body)
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		decodeLoginIssue(m, b)
	case tlog.KindRevoke:
		b, err := tlog.DecodeRevokeBody(l.Body)
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		decodeRevoke(m, b)
	case tlog.KindRevocationRecovery:
		b, err := tlog.DecodeRecoveryBody(l.Body)
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		decodeRecovery(m, b)
	case tlog.KindHostForget:
		b, err := tlog.DecodeHostForgetBody(l.Body)
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		decodeHostForget(m, b)
	case tlog.KindKRLPublish:
		b, err := tlog.DecodeKRLPublishBody(l.Body)
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		// No "bundle_version" or "version" key: Verify binds those names
		// to bundle_install and directory_install lines (checkGrepFields).
		m["krl_version"] = b.KRLVersion
		m["krl_sha256"] = hex.EncodeToString(b.SHA256[:])
		m["issued_at"] = b.IssuedAtSeconds
		m["krl_bundle_version"] = b.BundleVersion
	}
	return m
}

// decodeRevoke renders a revoke body into m (03-03): the target its
// logged request names, the resolution time, the fingerprints of the keys
// that signed its evidence and its entries. An entry's kind is rendered
// as "entry_kind", never "kind", and no field is named "version",
// "bundle_version", "directory" or "sigs": Verify binds each of those
// names, at any depth of the line, to the leaf kind the restore runbook
// greps for (checkGrepFields, checkReplayFields).
func decodeRevoke(m map[string]any, b *tlog.RevokeBody) {
	m["policy_version"] = b.PolicyVersion
	m["resolved_at"] = b.ResolvedAtSeconds
	if req, err := wire.ParseRevokeSigningBytes(b.Request); err != nil {
		m["request_error"] = err.Error()
	} else {
		m["request_id"] = hex.EncodeToString(req.RequestID[:])
		m["created_at"] = req.CreatedAt
		m["reason"] = req.Reason
		switch req.Target {
		case wire.TargetSerial:
			m["target"] = "serial"
			m["ca_role"] = req.CARole.String()
			m["serial"] = req.Serial
		case wire.TargetKeyID:
			m["target"] = "key_id"
			m["ca_role"] = req.CARole.String()
			m["key_id"] = req.KeyID
		case wire.TargetKey:
			m["target"] = "key"
			m["key_fingerprint"] = fingerprint(req.Key)
		case wire.TargetSubject:
			m["target"] = "subject"
			m["subject_kind"] = req.SubjectKind.String()
			m["subject"] = req.Subject
		}
	}
	admins := make([]string, 0, len(b.Evidence))
	for _, e := range b.Evidence {
		if e.Type != wire.EvidenceAdminSSHSIG {
			continue
		}
		if sig, err := sshsig.Parse(e.Blob); err == nil {
			admins = append(admins, ssh.FingerprintSHA256(sig.PublicKey()))
		}
	}
	m["admins"] = admins
	entries := make([]map[string]any, 0, len(b.Entries))
	for _, e := range b.Entries {
		r := map[string]any{}
		switch e.Kind {
		case tlog.RevokedSerial:
			r["entry_kind"] = "serial"
			r["serial"] = e.Serial
			r["ca_fingerprint"] = fingerprint(e.CAKey)
			r["valid_before"] = e.ValidBeforeSeconds
		case tlog.RevokedKeyID:
			r["entry_kind"] = "key_id"
			r["key_id"] = e.KeyID
			r["ca_fingerprint"] = fingerprint(e.CAKey)
			r["valid_before"] = e.ValidBeforeSeconds
		case tlog.RevokedKey:
			r["entry_kind"] = "key"
			r["key_fingerprint"] = fingerprint(e.Key)
		}
		entries = append(entries, r)
	}
	m["entries"] = entries
}

// decodeRecovery renders a revocation_recovery body into m (03-06b) as
// counts only: the restored log size its request names, the number of
// imported KRL versions and their versions, the number of carried
// certificates and of those revoked, the number of entries, and the
// fingerprints of the keys that signed its evidence. It renders no KRL or
// certificate bytes, and no key named "kind" (beyond the line's own),
// "bundle_version", "version", "directory" or "sigs" (checkGrepFields,
// checkReplayFields).
func decodeRecovery(m map[string]any, b *tlog.RecoveryBody) {
	m["policy_version"] = b.PolicyVersion
	m["resolved_at"] = b.ResolvedAtSeconds
	if req, err := wire.ParseRecoverySigningBytes(b.Request); err != nil {
		m["request_error"] = err.Error()
	} else {
		m["request_id"] = hex.EncodeToString(req.RequestID[:])
		m["restored_size"] = req.RestoredSize
		m["imports"] = len(req.Imports)
		versions := make([]uint64, 0, len(req.Imports))
		for _, im := range req.Imports {
			if man, err := krl.ParseManifest(im.Manifest); err == nil {
				versions = append(versions, man.KRLVersion)
			}
		}
		m["import_krl_versions"] = versions
		revoked := 0
		for _, c := range req.Certificates {
			if c.Revoke {
				revoked++
			}
		}
		m["certificates"] = len(req.Certificates)
		m["certificates_revoked"] = revoked
	}
	m["entries"] = len(b.Entries)
	admins := make([]string, 0, len(b.Evidence))
	for _, e := range b.Evidence {
		if e.Type != wire.EvidenceAdminSSHSIG {
			continue
		}
		if sig, err := sshsig.Parse(e.Blob); err == nil {
			admins = append(admins, ssh.FingerprintSHA256(sig.PublicKey()))
		}
	}
	m["admins"] = admins
}

// decodeHostForget renders a host_forget body into m (03-08c): the agent
// its logged request names (its identity fingerprint, expected name,
// enrollment time and the SHA256 fingerprints of its host keys), the facts
// the admins signed (approved_once, host_gone, removal_version, and
// confirmed_version with confirmed_sha256 for a confirmation, neither
// without one), the request ID and times, the policy and directory
// versions in force, the evidence types and the sorted SHA256
// fingerprints of the keys that signed (admin_fingerprints), so the entry
// names who forgot. It renders no key named "kind" (beyond the line's
// own), "bundle_version", "version", "directory" or "sigs"
// (checkGrepFields, checkReplayFields), and Verify binds the rendered
// approved_once and host_gone to the leaf (checkForgetFields).
func decodeHostForget(m map[string]any, b *tlog.HostForgetBody) {
	m["policy_version"] = b.PolicyVersion
	m["directory_version"] = b.DirectoryVersion
	m["resolved_at"] = b.ResolvedAtSeconds
	if req, err := wire.ParseForgetSigningBytes(b.Request); err != nil {
		m["request_error"] = err.Error()
	} else {
		m["identity"] = "SHA256:" + base64.RawStdEncoding.EncodeToString(req.AgentIdentity[:])
		m["expected_name"] = req.ExpectedName
		m["enrolled_at_us"] = req.EnrolledAtMicros
		fps := make([]string, 0, len(req.HostKeyFingerprints))
		for _, d := range req.HostKeyFingerprints {
			fps = append(fps, "SHA256:"+base64.RawStdEncoding.EncodeToString(d[:]))
		}
		m["host_key_fingerprints"] = fps
		m["approved_once"] = req.ApprovedOnce
		m["host_gone"] = req.HostGone
		m["removal_version"] = req.RemovalVersion
		if req.ConfirmedVersion != 0 {
			m["confirmed_version"] = req.ConfirmedVersion
			m["confirmed_sha256"] = hex.EncodeToString(req.ConfirmedSHA256[:])
		}
		m["request_id"] = hex.EncodeToString(req.RequestID[:])
		m["created_at"] = req.CreatedAt
	}
	types := make([]string, 0, len(b.Evidence))
	admins := make([]string, 0, len(b.Evidence))
	for _, e := range b.Evidence {
		types = append(types, e.Type)
		if e.Type != wire.EvidenceAdminSSHSIG {
			continue
		}
		if sig, err := sshsig.Parse(e.Blob); err == nil {
			admins = append(admins, ssh.FingerprintSHA256(sig.PublicKey()))
		}
	}
	slices.Sort(admins)
	m["evidence_types"] = types
	m["admin_fingerprints"] = admins
}

// fingerprint is the SHA256 fingerprint of an SSH wire-format key, or ""
// when it does not parse.
func fingerprint(blob []byte) string {
	pub, err := ssh.ParsePublicKey(blob)
	if err != nil {
		return ""
	}
	return ssh.FingerprintSHA256(pub)
}

// decodeLoginIssue renders a login_issue body into m (02-12). Each part
// degrades on its own: a certificate or an evidence blob that does not
// parse adds cert_error or authenticator_error and keeps the body's other
// fields, so the serial and key ID of every login issuance stay readable.
// authenticator_data_len and authenticator_flags (the flags byte in hex)
// record what each real authenticator sent (02-01-F5).
func decodeLoginIssue(m map[string]any, b *tlog.LoginIssueBody) {
	types := make([]string, 0, len(b.Evidence))
	for _, e := range b.Evidence {
		types = append(types, e.Type)
	}
	m["serial"] = b.Serial
	m["policy_version"] = b.PolicyVersion
	m["directory_version"] = b.DirectoryVersion
	m["key_id"] = b.KeyID
	m["evidence_types"] = types
	if c, err := parseCert(b.Cert); err != nil {
		m["cert_error"] = err.Error()
	} else {
		m["principals"] = c.ValidPrincipals
		m["valid_after"] = c.ValidAfter
		m["valid_before"] = c.ValidBefore
		m["ca_fingerprint"] = ssh.FingerprintSHA256(c.SignatureKey)
		m["ca_algorithm"] = c.SignatureKey.Type()
		m["key_fingerprint"] = ssh.FingerprintSHA256(c.Key)
	}
	for _, e := range b.Evidence {
		if e.Type != wire.EvidenceWebAuthnAssertion {
			continue
		}
		a, err := wire.ParseWebAuthnAssertion(e.Blob)
		if err != nil {
			m["authenticator_error"] = err.Error()
			continue
		}
		m["authenticator_data_len"] = len(a.AuthenticatorData)
		if len(a.AuthenticatorData) > 32 {
			m["authenticator_flags"] = hex.EncodeToString(a.AuthenticatorData[32:33])
		}
	}
}

// parseCert parses certificate wire bytes.
func parseCert(raw []byte) (*ssh.Certificate, error) {
	pk, err := ssh.ParsePublicKey(raw)
	if err != nil {
		return nil, err
	}
	c, ok := pk.(*ssh.Certificate)
	if !ok {
		return nil, errNotCertificate
	}
	return c, nil
}

// errNotCertificate is a log leaf's certificate field holding a plain key.
var errNotCertificate = errors.New("not a certificate")
