package signer

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"maps"
	"slices"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// hostLatest is the latest host certificate for one host key (03-09): the
// certificate and its bytes, its serial, the leaf that logged it (0 for one
// a recovery carried), its issuance second (ValidAfter + 300), its
// principals, the host cap recorded at its issuance (CapSeconds, which is
// also its lifetime), the directory version it was issued under, the
// SHA-256 of its request's signing bytes (zero for a carried one), and
// whether it was revoked, at which directory version.
type hostLatest struct {
	cert           *ssh.Certificate
	certBytes      []byte
	serial         uint64
	leaf           uint64
	issued         uint64
	principals     []string
	capSeconds     uint64
	issuedUnderDir uint64
	reqSHA256      [32]byte
	revoked        bool
	revokedAtDir   uint64
}

// prev is the latest certificate as cert.HostCertRecent takes it.
func (h hostLatest) prev() cert.HostPrev {
	return cert.HostPrev{Cert: h.cert, CapSeconds: h.capSeconds, IssuedUnderDir: h.issuedUnderDir, Revoked: h.revoked, RevokedAtDir: h.revokedAtDir}
}

// hostIndex is the signer's in-memory view of host issuance (03-09,
// critic-recent-lookup-scan): per host key (trust.FormatKey), its latest
// host certificate; the serial and key ID of each latest certificate; the
// explicitly revoked keys; and the directory version in force. It is a
// field of loggedInstalls, rebuilt from the log by rebuildLogFrom (one
// apply per leaf, in order), so every loadLog refreshes it, and a
// transaction's change is staged in pendingHosts and installed only after
// COMMIT, as pendingRevoked is. HostIssue, Revoke and RecoverRevocations
// read it under s.mu and never update it themselves; no request scans a
// table for it.
type hostIndex struct {
	latest      map[string]hostLatest
	bySerial    map[uint64]string
	byKeyID     map[string]string
	revokedKeys map[string]bool
	curDir      uint64
}

// clone is a deep copy of h (the certificates themselves are never
// modified).
func (h *hostIndex) clone() hostIndex {
	c := hostIndex{latest: maps.Clone(h.latest), bySerial: maps.Clone(h.bySerial), byKeyID: maps.Clone(h.byKeyID),
		revokedKeys: maps.Clone(h.revokedKeys), curDir: h.curDir}
	if c.latest == nil {
		c.latest = map[string]hostLatest{}
	}
	if c.bySerial == nil {
		c.bySerial = map[uint64]string{}
	}
	if c.byKeyID == nil {
		c.byKeyID = map[string]string{}
	}
	if c.revokedKeys == nil {
		c.revokedKeys = map[string]bool{}
	}
	for k, v := range c.latest {
		v.principals = slices.Clone(v.principals)
		c.latest[k] = v
	}
	return c
}

// init makes h's maps, for an index never applied to.
func (h *hostIndex) init() {
	if h.latest == nil {
		h.latest = map[string]hostLatest{}
	}
	if h.bySerial == nil {
		h.bySerial = map[uint64]string{}
	}
	if h.byKeyID == nil {
		h.byKeyID = map[string]string{}
	}
	if h.revokedKeys == nil {
		h.revokedKeys = map[string]bool{}
	}
}

// hostRelevant reports whether apply changes the index for a leaf of kind
// k.
func hostRelevant(k tlog.Kind) bool {
	switch k {
	case tlog.KindDirectoryInstall, tlog.KindHostIssue, tlog.KindRevoke, tlog.KindRevocationRecovery:
		return true
	}
	return false
}

// apply applies one leaf to h: a directory_install sets the directory
// version in force; a host_issue makes its certificate the latest for its
// key; a revoke or revocation_recovery entry marks a matching latest
// certificate revoked at the directory version in force (by serial under
// its CA key, or by key ID under its CA key) and records explicit keys. A
// revocation_recovery's carried kr3 ca=host certificates are recorded
// first, as the latest for their key when their serial is above the
// indexed one, and its entries are applied after, so a carried
// certificate its Revoke flag or an entry names is marked revoked
// (close-issuance-index-restore-gap). Audit verify applies the same rule
// in the same order. Other kinds change nothing.
func (h *hostIndex) apply(l tlog.Leaf) error {
	h.init()
	switch l.Kind {
	case tlog.KindDirectoryInstall:
		b, err := tlog.DecodeDirectoryInstallBody(l.Body)
		if err != nil {
			return fmt.Errorf("%w: leaf %d: directory_install body does not decode", errLogMismatch, l.Index)
		}
		h.curDir = b.Version
	case tlog.KindHostIssue:
		b, err := tlog.DecodeHostIssueBody(l.Body)
		if err != nil {
			return fmt.Errorf("%w: leaf %d: host_issue body does not decode", errLogMismatch, l.Index)
		}
		c, err := parseLoggedCert(b.Cert)
		if err != nil {
			return fmt.Errorf("%w: leaf %d: %w", errLogMismatch, l.Index, err)
		}
		h.setLatest(c, b.Cert, hostLatest{leaf: l.Index, capSeconds: b.CapSeconds, issuedUnderDir: b.DirectoryVersion, reqSHA256: sha256.Sum256(b.Request)})
	case tlog.KindRevoke:
		b, err := tlog.DecodeRevokeBody(l.Body)
		if err != nil {
			return fmt.Errorf("%w: leaf %d: revoke body does not decode", errLogMismatch, l.Index)
		}
		h.revokeEntries(b.Entries)
	case tlog.KindRevocationRecovery:
		b, err := tlog.DecodeRecoveryBody(l.Body)
		if err != nil {
			return fmt.Errorf("%w: leaf %d: revocation_recovery body does not decode", errLogMismatch, l.Index)
		}
		req, err := wire.ParseRecoverySigningBytes(b.Request)
		if err != nil {
			return fmt.Errorf("%w: leaf %d: revocation_recovery request does not parse", errLogMismatch, l.Index)
		}
		for _, rc := range req.Certificates {
			c, err := parseLoggedCert(rc.Cert)
			if err != nil || c.CertType != ssh.HostCert {
				continue
			}
			kid, err := cert.ParseKeyID(c.KeyId)
			if err != nil || !kid.V3 || kid.CA != wire.CARoleHost.String() {
				continue
			}
			k := trust.FormatKey(c.Key)
			if cur, ok := h.latest[k]; ok && cur.serial >= c.Serial {
				continue
			}
			life := uint64(0)
			if c.ValidBefore > c.ValidAfter+300 {
				life = c.ValidBefore - c.ValidAfter - 300
			}
			h.setLatest(c, rc.Cert, hostLatest{capSeconds: life, issuedUnderDir: kid.Directory})
			if rc.Revoke {
				h.markRevoked(k)
			}
		}
		h.revokeEntries(b.Entries)
	}
	return nil
}

// setLatest makes c, with the fields of base, the latest certificate of
// its key, replacing the previous one in the serial and key ID maps.
func (h *hostIndex) setLatest(c *ssh.Certificate, raw []byte, base hostLatest) {
	k := trust.FormatKey(c.Key)
	if old, ok := h.latest[k]; ok {
		delete(h.bySerial, old.serial)
		delete(h.byKeyID, old.cert.KeyId)
	}
	base.cert, base.certBytes, base.serial = c, slices.Clone(raw), c.Serial
	base.issued = c.ValidAfter + 300
	base.principals = slices.Clone(c.ValidPrincipals)
	h.latest[k] = base
	h.bySerial[c.Serial] = k
	h.byKeyID[c.KeyId] = k
}

// revokeEntries applies revoked entries: a serial or key ID that names a
// latest host certificate under its CA key marks it revoked; an explicit
// key is recorded.
func (h *hostIndex) revokeEntries(entries []tlog.RevokedEntry) {
	for _, e := range entries {
		switch e.Kind {
		case tlog.RevokedSerial:
			if k, ok := h.bySerial[e.Serial]; ok && bytes.Equal(h.latest[k].cert.SignatureKey.Marshal(), e.CAKey) {
				h.markRevoked(k)
			}
		case tlog.RevokedKeyID:
			if k, ok := h.byKeyID[e.KeyID]; ok && bytes.Equal(h.latest[k].cert.SignatureKey.Marshal(), e.CAKey) {
				h.markRevoked(k)
			}
		case tlog.RevokedKey:
			if pub, err := ssh.ParsePublicKey(e.Key); err == nil {
				h.revokedKeys[trust.FormatKey(pub)] = true
			}
		}
	}
}

// markRevoked marks key k's latest certificate revoked at the directory
// version in force; a certificate already revoked keeps its version.
func (h *hostIndex) markRevoked(k string) {
	l, ok := h.latest[k]
	if !ok || l.revoked {
		return
	}
	l.revoked, l.revokedAtDir = true, h.curDir
	h.latest[k] = l
}

// parseLoggedCert parses a logged certificate.
func parseLoggedCert(b []byte) (*ssh.Certificate, error) {
	pub, err := ssh.ParsePublicKey(b)
	if err != nil {
		return nil, err
	}
	c, ok := pub.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("the logged key is not a certificate")
	}
	return c, nil
}
