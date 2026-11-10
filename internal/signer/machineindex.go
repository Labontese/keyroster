package signer

import (
	"fmt"
	"maps"
	"slices"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
)

// machineLatest is the latest machine certificate for one machine key
// (03-11): the certificate and its bytes, its serial, the leaf that logged
// it (0 for one a recovery carried), its issuance second (ValidAfter +
// 300), its principals, its lifetime (the machine_issue leaf's
// CapSeconds) and the directory version it was issued under.
type machineLatest struct {
	cert           *ssh.Certificate
	certBytes      []byte
	serial         uint64
	leaf           uint64
	issued         uint64
	principals     []string
	capSeconds     uint64
	issuedUnderDir uint64
}

// machineIndex is the signer's in-memory view of machine issuance (03-11,
// PD2), on the pattern of hostIndex: per machine key (trust.FormatKey), its
// latest machine certificate and the issuance seconds of its last hour
// (cert.MachineRecentAdd); the serial and key ID of each latest
// certificate; and the directory version in force. It is a field of
// loggedInstalls, rebuilt from the log by rebuildLogFrom (one apply per
// leaf, in order), and a transaction's change is staged in
// pendingMachines and installed only after COMMIT. MachineIssue reads it
// under s.mu and never updates it itself; no request scans a table for
// it. The explicitly revoked keys are the host index's revokedKeys, which
// records every RevokedKey entry of any CA.
type machineIndex struct {
	latest   map[string]machineLatest
	recent   map[string][]uint64
	bySerial map[uint64]string
	byKeyID  map[string]string
	curDir   uint64
}

// clone is a deep copy of m (the certificates themselves are never
// modified, and the recent slices are cloned, not aliased).
func (m *machineIndex) clone() machineIndex {
	c := machineIndex{latest: maps.Clone(m.latest), recent: maps.Clone(m.recent), bySerial: maps.Clone(m.bySerial),
		byKeyID: maps.Clone(m.byKeyID), curDir: m.curDir}
	c.init()
	for k, v := range c.latest {
		v.principals = slices.Clone(v.principals)
		c.latest[k] = v
	}
	for k, v := range c.recent {
		c.recent[k] = slices.Clone(v)
	}
	return c
}

// init makes m's maps, for an index never applied to.
func (m *machineIndex) init() {
	if m.latest == nil {
		m.latest = map[string]machineLatest{}
	}
	if m.recent == nil {
		m.recent = map[string][]uint64{}
	}
	if m.bySerial == nil {
		m.bySerial = map[uint64]string{}
	}
	if m.byKeyID == nil {
		m.byKeyID = map[string]string{}
	}
}

// machineRelevant reports whether apply changes the index for a leaf of
// kind k.
func machineRelevant(k tlog.Kind) bool {
	switch k {
	case tlog.KindDirectoryInstall, tlog.KindMachineIssue:
		return true
	}
	return false
}

// apply applies one leaf to m: a directory_install sets the directory
// version in force; a machine_issue makes its certificate the latest for
// its key and adds its issuance second (ValidAfter + 300) to the key's
// recent list through cert.MachineRecentAdd (PD4). Other kinds change
// nothing.
func (m *machineIndex) apply(l tlog.Leaf) error {
	m.init()
	switch l.Kind {
	case tlog.KindDirectoryInstall:
		b, err := tlog.DecodeDirectoryInstallBody(l.Body)
		if err != nil {
			return fmt.Errorf("%w: leaf %d: directory_install body does not decode", errLogMismatch, l.Index)
		}
		m.curDir = b.Version
	case tlog.KindMachineIssue:
		b, err := tlog.DecodeMachineIssueBody(l.Body)
		if err != nil {
			return fmt.Errorf("%w: leaf %d: machine_issue body does not decode", errLogMismatch, l.Index)
		}
		c, err := parseLoggedCert(b.Cert)
		if err != nil {
			return fmt.Errorf("%w: leaf %d: %w", errLogMismatch, l.Index, err)
		}
		k := m.setLatest(c, b.Cert, machineLatest{leaf: l.Index, capSeconds: b.CapSeconds, issuedUnderDir: b.DirectoryVersion})
		m.recent[k] = cert.MachineRecentAdd(m.recent[k], c.ValidAfter+300)
	}
	return nil
}

// setLatest makes c, with the fields of base, the latest certificate of
// its key, replacing the previous one in the serial and key ID maps, and
// returns the key.
func (m *machineIndex) setLatest(c *ssh.Certificate, raw []byte, base machineLatest) string {
	k := trust.FormatKey(c.Key)
	if old, ok := m.latest[k]; ok {
		delete(m.bySerial, old.serial)
		delete(m.byKeyID, old.cert.KeyId)
	}
	base.cert, base.certBytes, base.serial = c, slices.Clone(raw), c.Serial
	base.issued = c.ValidAfter + 300
	base.principals = slices.Clone(c.ValidPrincipals)
	m.latest[k] = base
	m.bySerial[c.Serial] = k
	m.byKeyID[c.KeyId] = k
	return k
}
