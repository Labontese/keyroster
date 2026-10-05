package signer

import (
	"errors"
	"slices"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// verifyAdminEvidence authorizes req under the installed policy (D-13).
// Every evidence item must be of type admin-sshsig/v1: an armored SSHSIG
// under the namespace keyroster/issue-request/v1 over req.SigningBytes(),
// made by a key the root-signed policy lists as an admin. Any other type,
// a signature that does not parse or verify, a wrong namespace and a
// non-admin signer each refuse the whole request (default deny). At least
// the policy's admin quorum of distinct admins must have signed; an admin
// who signed twice counts once. It returns the sorted names of the admins
// who signed.
func verifyAdminEvidence(req *wire.IssueRequest, pol *trust.Policy) ([]string, error) {
	if pol == nil || pol.AdminQuorum < 1 {
		return nil, refusalErr(wire.CodeRefused, "no_policy", nil)
	}
	admins := map[string]trust.AdminKey{} // SHA256 fingerprint -> admin
	for _, a := range pol.Admins {
		pub, err := trust.ParseKey(a.Key)
		if err != nil {
			return nil, refusalErr(wire.CodeInternal, "bad_policy", err)
		}
		admins[ssh.FingerprintSHA256(pub)] = a
	}
	if len(req.Evidence) == 0 {
		return nil, refusalErr(wire.CodeRefused, "missing_evidence", nil)
	}
	msg := req.SigningBytes()
	signed := map[string]string{} // fingerprint -> admin name
	for _, ev := range req.Evidence {
		if ev.Type != wire.EvidenceAdminSSHSIG {
			return nil, refusalErr(wire.CodeRefused, "unknown_evidence_type", nil)
		}
		sig, err := sshsig.Parse(ev.Blob)
		if err != nil {
			return nil, refusalErr(wire.CodeRefused, "bad_evidence", err)
		}
		fp := ssh.FingerprintSHA256(sig.PublicKey())
		admin, ok := admins[fp]
		if !ok || admin.Key != trust.FormatKey(sig.PublicKey()) {
			return nil, refusalErr(wire.CodeRefused, "evidence_not_admin", nil)
		}
		if err := sig.Verify(wire.AdminSSHSIGNamespace, msg); err != nil {
			if errors.Is(err, sshsig.ErrNamespace) {
				return nil, refusalErr(wire.CodeRefused, "evidence_wrong_namespace", err)
			}
			return nil, refusalErr(wire.CodeRefused, "evidence_digest_mismatch", err)
		}
		signed[fp] = admin.Name
	}
	if len(signed) < int(pol.AdminQuorum) {
		return nil, refusalErr(wire.CodeRefused, "admin_quorum_not_met", nil)
	}
	names := make([]string, 0, len(signed))
	for _, n := range signed {
		names = append(names, n)
	}
	slices.Sort(names)
	return names, nil
}
