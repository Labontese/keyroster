package audit

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math"

	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// verifyForget checks one host_forget entry (kind 16, 03-08c) at index,
// with leaf time leafMicros, against the trust state and the directory in
// force and the log before it, with the signer's rules (ForgetAgent):
//
//   - its logged request parses strictly (wire.ParseForgetSigningBytes)
//     and names the installation of the bundle in force, which has one;
//   - its evidence is admin-sshsig/v1 under keyroster/host-forget-request/v1
//     over exactly those bytes, every item by an admin of the policy in
//     force, from at least one distinct admin for an agent never approved
//     and the policy's admin_quorum for every other (owner decision Q3);
//     the entry records that policy's version and the version of the
//     directory in force;
//   - its resolution time × 10^6 is not after the leaf time, and it is
//     within 300 s of the request's CreatedAt;
//   - its request ID was used by no earlier revoke, recovery or forget
//     entry;
//   - no host entry of the directory in force, active or disabled, holds
//     one of the host keys the request names;
//   - a confirmation lies at or below the directory version in force (at
//     or above the removal version, which the parse checks) and has the
//     SHA-256 of the document the directory_install entry of that version
//     logged (the document without signatures, the basis of the heartbeat
//     and of 03-08b's recording).
//
// It checks that the number of signatures matches the signed
// approved_once; it cannot tell a false approved_once, because the log
// records no approvals (T-03-293). What a confirmation says about the host
// is keyroster-server's rule (03-08b), recorded as attested by the admins
// who signed.
func verifyForget(index uint64, body *tlog.HostForgetBody, leafMicros uint64, a *anchor, ds *directoryInForce, rs *revocations) error {
	req, err := wire.ParseForgetSigningBytes(body.Request)
	if err != nil {
		return fmt.Errorf("logged forget request: %w", err)
	}
	if a.bundle == nil || a.policy == nil {
		return errors.New("host_forget entry before the first bundle_install: no root-signed policy is in force")
	}
	if a.bundle.InstallationID == "" {
		return fmt.Errorf("trust bundle v%d in force has no installation ID, and the signer forgets nothing without one (forget_no_installation_id)", a.bundle.Version)
	}
	if req.InstallationID != a.bundle.InstallationID {
		return fmt.Errorf("the forget is for installation %s, but trust bundle v%d in force is for %s (forget_installation_mismatch)",
			req.InstallationID, a.bundle.Version, a.bundle.InstallationID)
	}
	if body.PolicyVersion != a.policy.Version {
		return fmt.Errorf("entry records policy version %d, but the policy in force is version %d", body.PolicyVersion, a.policy.Version)
	}
	if body.DirectoryVersion != ds.version {
		return fmt.Errorf("entry records directory version %d, but the directory in force is version %d", body.DirectoryVersion, ds.version)
	}
	need := 1
	if req.ApprovedOnce {
		need = int(a.policy.AdminQuorum)
	}
	if err := verifyRevokeAdmins(body.Evidence, body.Request, wire.ForgetSSHSIGNamespace, need, a.policy); err != nil {
		return err
	}
	if body.ResolvedAtSeconds > math.MaxUint64/1_000_000 || body.ResolvedAtSeconds*1_000_000 > leafMicros {
		return fmt.Errorf("resolution time %d s is after the leaf time %d µs: the signer decides a forget at the clock reading the leaf time is taken from, and only ever raises the leaf time",
			body.ResolvedAtSeconds, leafMicros)
	}
	if d := absDiff(body.ResolvedAtSeconds, req.CreatedAt); d > maxRevokeSkewSeconds {
		return fmt.Errorf("resolution time %d s is %d s from the request's CreatedAt %d; the signer accepts at most %d s",
			body.ResolvedAtSeconds, d, req.CreatedAt, maxRevokeSkewSeconds)
	}
	if first, used := rs.requests[req.RequestID]; used {
		return fmt.Errorf("request ID %s replayed: entry %d already used it", hex.EncodeToString(req.RequestID[:]), first)
	}
	if ds.dir != nil {
		named := map[[32]byte]bool{}
		for _, d := range req.HostKeyFingerprints {
			named[d] = true
		}
		for _, h := range ds.dir.Hosts {
			for _, k := range h.Keys {
				pub, err := trust.ParseKey(k)
				if err != nil {
					return fmt.Errorf("directory v%d: host %s: %w", ds.version, h.Name, err)
				}
				if named[wire.HostKeyDigest(pub)] {
					return fmt.Errorf("forgets an agent whose host key is on host %s of directory v%d in force (forget_host_in_directory)", h.Name, ds.version)
				}
			}
		}
	}
	if v := req.ConfirmedVersion; v != 0 {
		if v > ds.version {
			return fmt.Errorf("confirmation at directory v%d is above the directory in force, v%d (forget_confirmation_invalid)", v, ds.version)
		}
		if sum, ok := ds.shas[v]; !ok || sum != req.ConfirmedSHA256 {
			return fmt.Errorf("confirmation SHA-256 %s is not that of the directory v%d the log installed (forget_confirmation_invalid)",
				hex.EncodeToString(req.ConfirmedSHA256[:]), v)
		}
	}
	rs.requests[req.RequestID] = index
	return nil
}
