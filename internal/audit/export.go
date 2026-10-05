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
// "decoded" is informational only: Verify never reads it.
package audit

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"

	"golang.org/x/crypto/ssh"

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
	}
	return m
}
