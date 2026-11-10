//go:build linux

package signer

import (
	"context"
	"crypto/rand"
	"maps"
	"slices"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// revokeMachineSubject revokes every live certificate of machine name and
// returns the signer's answer (03-11, REVOKE-01's machine subject).
func (e *machineEnv) revokeMachineSubject(t *testing.T, name string) *wire.RevokeResponse {
	t.Helper()
	e.clock.set(e.clock.Now().Add(time.Millisecond))
	return e.revokeAny(t, &wire.RevokeRequest{Target: wire.TargetSubject, SubjectKind: wire.SubjectMachine, Subject: name})
}

// signedRevoke completes req (installation, clock, request ID, reason) and
// signs it with signer under the revoke namespace.
func (e *machineEnv) signedRevoke(t *testing.T, req *wire.RevokeRequest, signer ssh.Signer) *wire.RevokeRequest {
	t.Helper()
	req.InstallationID, req.CreatedAt, req.Reason = testInstallationID, uint64(e.clock.Now().Unix()), "test" //nolint:gosec // G115: after 1970
	if _, err := rand.Read(req.RequestID[:]); err != nil {
		t.Fatal(err)
	}
	sig, err := sshsig.Sign(rand.Reader, signer, wire.RevokeSSHSIGNamespace, req.SigningBytes())
	if err != nil {
		t.Fatal(err)
	}
	req.Evidence = []wire.Evidence{{Type: wire.EvidenceAdminSSHSIG, Blob: sig}}
	return req
}

// lastRevoke is the body of the log's last revoke leaf.
func (e *machineEnv) lastRevoke(t *testing.T) *tlog.RevokeBody {
	t.Helper()
	var last *tlog.RevokeBody
	for _, l := range e.leavesOf() {
		if l.Kind != tlog.KindRevoke {
			continue
		}
		b, err := tlog.DecodeRevokeBody(l.Body)
		if err != nil {
			t.Fatal(err)
		}
		last = b
	}
	if last == nil {
		t.Fatal("no revoke leaf")
	}
	return last
}

// idleMachine is a machineEnv whose ci was issued once and whose
// certificate has expired past the live margin, so a sweep of ci lists
// nothing.
func idleMachine(t *testing.T) *machineEnv {
	t.Helper()
	e := newMachineEnv(t)
	c, _ := e.mustMachine(t, e.machineReq(e.k1, "ci"))
	e.tickTo(c.ValidBefore + 300)
	return e
}

// TestRevokeMachine (03-11, REVOKE-01, D-09): a subject revocation of a
// machine resolves the live kr1 and kr3 certificates of that exact subject
// under the machine CA, serial entries only, never a probe certificate,
// and its logged request holds the machine's name until a newer directory
// version is installed (default 2 amended, PD11).
func TestRevokeMachine(t *testing.T) {
	ctx := context.Background()
	t.Run("subject_reserved_probe", func(t *testing.T) {
		e := newMachineEnv(t)
		before, rows := e.leafCount(tlog.KindRevoke), len(e.revocationRows(t))
		req := e.signedRevoke(t, &wire.RevokeRequest{Target: wire.TargetSubject, SubjectKind: wire.SubjectMachine, Subject: "probe.web1"}, e.fx.Admins[0])
		_, er := e.s.revokeOrRefuse(ctx, Peer{UID: 1000}, req)
		if er == nil || er.Message != "subject_reserved" || er.Code != wire.CodeMalformed {
			t.Fatalf("revoke machine probe.web1: %+v, want subject_reserved (malformed)", er)
		}
		if e.leafCount(tlog.KindRevoke) != before || len(e.revocationRows(t)) != rows {
			t.Fatal("the refused subject revoke wrote a revoke leaf or a revocation row")
		}
	})
	t.Run("prefix_exact", func(t *testing.T) {
		e := newMachineEnv(t)
		kOld := newEd25519(t)
		e.machines = append(e.machines, directory.Machine{Name: "ci-old", Key: trust.FormatKey(kOld.PublicKey()), Roles: []string{"deploy"},
			MaxTTLSeconds: 3600, Status: directory.StatusActive})
		e.publishMachines(t)
		c, _ := e.mustMachine(t, e.machineReq(e.k1, "ci"))
		e.mustMachine(t, e.machineReq(kOld, "ci-old"))
		if resp := e.revokeMachineSubject(t, "ci"); !slices.Equal(resp.Serials, []uint64{c.Serial}) {
			t.Fatalf("revoke machine ci listed %v, want only %d", resp.Serials, c.Serial)
		}
		if resp := e.revokeMachineSubject(t, "c"); len(resp.Serials) != 0 {
			t.Fatalf("revoke machine c listed %v, want nothing", resp.Serials)
		}
	})
	t.Run("kr1_admin_cert_included", func(t *testing.T) {
		e := newMachineEnv(t)
		k1 := e.issueKR1(t, wire.CARoleMachine, "ci", 600)
		if resp := e.revokeMachineSubject(t, "ci"); !slices.Equal(resp.Serials, []uint64{k1.Serial}) {
			t.Fatalf("revoke machine ci listed %v, want the kr1 certificate %d", resp.Serials, k1.Serial)
		}
	})
	t.Run("kr3_pop_cert_included", func(t *testing.T) {
		e := newMachineEnv(t)
		c, _ := e.mustMachine(t, e.machineReq(e.k1, "ci"))
		if resp := e.revokeMachineSubject(t, "ci"); !slices.Equal(resp.Serials, []uint64{c.Serial}) {
			t.Fatalf("revoke machine ci listed %v, want the kr3 certificate %d", resp.Serials, c.Serial)
		}
	})
	t.Run("no_issue_time_cutoff", func(t *testing.T) {
		e := newMachineEnv(t)
		c, _ := e.mustMachine(t, e.machineReq(e.k1, "ci"))
		e.setMachineCap(t, 600, func(p *trust.Policy) { p.PoP = &trust.PoPPolicy{Hosts: true, Machines: true} })
		if resp := e.revokeMachineSubject(t, "ci"); !slices.Equal(resp.Serials, []uint64{c.Serial}) {
			t.Fatalf("after a shorter machine cap revoke machine ci listed %v, want %d", resp.Serials, c.Serial)
		}
	})
	t.Run("live_boundary", func(t *testing.T) {
		e := newMachineEnv(t)
		c, _ := e.mustMachine(t, e.machineReq(e.k1, "ci"))
		e.tickTo(c.ValidBefore + 299)
		if resp := e.revokeMachineSubject(t, "ci"); !slices.Equal(resp.Serials, []uint64{c.Serial}) {
			t.Fatalf("at ValidBefore + 299 s revoke machine ci listed %v, want %d", resp.Serials, c.Serial)
		}
		e.tickTo(c.ValidBefore + 300)
		if resp := e.revokeMachineSubject(t, "ci"); len(resp.Serials) != 0 {
			t.Fatalf("at ValidBefore + 300 s revoke machine ci listed %v, want nothing", resp.Serials)
		}
	})
	t.Run("removed_machine_serials_revoked", func(t *testing.T) {
		e := newMachineEnv(t)
		c, _ := e.mustMachine(t, e.machineReq(e.k1, "ci"))
		e.machines = e.machines[1:]
		e.publishMachines(t)
		if resp := e.revokeMachineSubject(t, "ci"); !slices.Equal(resp.Serials, []uint64{c.Serial}) {
			t.Fatalf("revoke of the removed machine ci listed %v, want %d", resp.Serials, c.Serial)
		}
	})
	t.Run("serial_count_is_serials", func(t *testing.T) {
		e := newMachineEnv(t)
		c1, _ := e.mustMachine(t, e.machineReq(e.k1, "ci"))
		k1 := e.issueKR1(t, wire.CARoleMachine, "ci", 600)
		c2, _ := e.mustMachine(t, e.machineReq(e.k1, "ci"))
		want := []uint64{c1.Serial, k1.Serial, c2.Serial}
		slices.Sort(want)
		resp := e.revokeMachineSubject(t, "ci")
		if !slices.Equal(resp.Serials, want) || len(e.lastRevoke(t).Entries) != len(want) {
			t.Fatalf("revoke machine ci listed %v (%d entries), want %v", resp.Serials, len(e.lastRevoke(t).Entries), want)
		}
	})
	t.Run("no_key_entry", func(t *testing.T) {
		e := newMachineEnv(t)
		e.mustMachine(t, e.machineReq(e.k1, "ci"))
		e.issueKR1(t, wire.CARoleMachine, "ci", 600)
		e.s.mu.Lock()
		keysBefore := maps.Clone(e.s.loaded.hosts.revokedKeys)
		e.s.mu.Unlock()
		e.revokeMachineSubject(t, "ci")
		for _, en := range e.lastRevoke(t).Entries {
			if en.Kind != tlog.RevokedSerial {
				t.Fatalf("the machine subject revoke carries an entry of kind %d, want serial entries only", en.Kind)
			}
		}
		e.s.mu.Lock()
		keysAfter := maps.Clone(e.s.loaded.hosts.revokedKeys)
		e.s.mu.Unlock()
		if !maps.Equal(keysBefore, keysAfter) {
			t.Fatal("the machine subject revoke changed the explicitly revoked keys")
		}
	})
	t.Run("probe_certificates_untouched", func(t *testing.T) {
		// A host named ci gets a probe certificate with subject probe.ci; a
		// revoke of machine ci does not list it.
		e := newMachineEnv(t)
		_, hk := NewEd25519Key(t)
		e.hosts = append(e.hosts, directory.Host{Name: "ci", HostGroup: "lab", Keys: []string{trust.FormatKey(hk.PublicKey())}, Principals: []string{"ci"},
			Status: directory.StatusActive})
		e.publishMachines(t)
		e.clock.set(e.clock.Now().Add(time.Millisecond))
		preq, _ := e.probeReq(hk, "ci", false)
		presp, er := e.s.probeIssueOrRefuse(ctx, Peer{UID: 1000}, preq)
		if er != nil {
			t.Fatalf("probe issue for host ci: %s", er.Message)
		}
		c, _ := e.mustMachine(t, e.machineReq(e.k1, "ci"))
		resp := e.revokeMachineSubject(t, "ci")
		if slices.Contains(resp.Serials, presp.Serial) || !slices.Equal(resp.Serials, []uint64{c.Serial}) {
			t.Fatalf("revoke machine ci listed %v; the probe certificate is %d, the machine certificate %d", resp.Serials, presp.Serial, c.Serial)
		}
	})
	t.Run("user_and_host_subjects_unchanged", func(t *testing.T) {
		e := newMachineEnv(t)
		h, _ := e.mustHost(e.hostReq(e.ed, "web1"))
		if resp := e.revokeHostSubject(t, "web1"); !slices.Equal(resp.Serials, []uint64{h.Serial}) {
			t.Fatalf("revoke host web1 listed %v, want %d", resp.Serials, h.Serial)
		}
		u := e.issueKR1(t, wire.CARoleUser, "u:alice", 600)
		resp := e.revokeAny(t, &wire.RevokeRequest{Target: wire.TargetSubject, SubjectKind: wire.SubjectUser, Subject: "u:alice"})
		if !slices.Equal(resp.Serials, []uint64{u.Serial}) {
			t.Fatalf("revoke user u:alice listed %v, want %d", resp.Serials, u.Serial)
		}
	})
	t.Run("full_revoke_quorum1_then_renew_is_disabled", func(t *testing.T) {
		// Default 2, keep-first: the sweep at V marks the latest
		// certificate, the disable installs V+1, the second sweep re-lists
		// it at V+1 (and moves the name hold there); the renewal is
		// machine_disabled, never cert_revoked.
		e := newMachineEnv(t)
		c, _ := e.mustMachine(t, e.machineReq(e.k1, "ci"))
		e.revokeMachineSubject(t, "ci")
		e.machines[0].Status = directory.StatusDisabled
		e.publishMachines(t)
		if resp := e.revokeMachineSubject(t, "ci"); !slices.Equal(resp.Serials, []uint64{c.Serial}) {
			t.Fatalf("the second sweep listed %v, want %d again", resp.Serials, c.Serial)
		}
		e.refusedMachine(t, e.machineReq(e.k1, "ci"), "machine_disabled", wire.CodeRefused)
	})
	t.Run("pending_disable_renew_is_cert_revoked", func(t *testing.T) {
		e := newMachineEnv(t)
		e.mustMachine(t, e.machineReq(e.k1, "ci"))
		e.revokeMachineSubject(t, "ci")
		e.refusedMachine(t, e.machineReq(e.k1, "ci"), "cert_revoked", wire.CodeRefused)
		e.publishMachines(t)
		e.mustMachine(t, e.machineReq(e.k1, "ci"))
	})
	t.Run("idle_machine_revoke_holds_name", func(t *testing.T) {
		e := idleMachine(t)
		before := e.leafCount(tlog.KindRevoke)
		if resp := e.revokeMachineSubject(t, "ci"); len(resp.Serials) != 0 || e.leafCount(tlog.KindRevoke) != before+1 {
			t.Fatalf("the idle sweep listed %v and wrote %d revoke leaves; want nothing and one leaf", resp.Serials, e.leafCount(tlog.KindRevoke)-before)
		}
		e.refusedMachine(t, e.machineReq(e.k1, "ci"), "cert_revoked", wire.CodeRefused)
		e.publishMachines(t)
		e.mustMachine(t, e.machineReq(e.k1, "ci"))
	})
	t.Run("name_hold_released_active_issues", func(t *testing.T) {
		e := idleMachine(t)
		e.revokeMachineSubject(t, "ci")
		e.publishMachines(t)
		e.mustMachine(t, e.machineReq(e.k1, "ci"))
		e.verifyExport()
	})
	t.Run("name_hold_released_disabled_is_machine_disabled", func(t *testing.T) {
		e := idleMachine(t)
		e.revokeMachineSubject(t, "ci")
		e.machines[0].Status = directory.StatusDisabled
		e.publishMachines(t)
		e.refusedMachine(t, e.machineReq(e.k1, "ci"), "machine_disabled", wire.CodeRefused)
	})
	t.Run("kr1_only_revoke_holds_name", func(t *testing.T) {
		// Only a kr1 certificate of ci is live and no kr3 certificate of
		// the key is indexed, so only the name hold can refuse.
		e := newMachineEnv(t)
		k1 := e.issueKR1(t, wire.CARoleMachine, "ci", 600)
		if resp := e.revokeMachineSubject(t, "ci"); !slices.Equal(resp.Serials, []uint64{k1.Serial}) {
			t.Fatalf("the sweep listed %v, want the kr1 certificate %d", resp.Serials, k1.Serial)
		}
		e.refusedMachine(t, e.machineReq(e.k1, "ci"), "cert_revoked", wire.CodeRefused)
	})
	t.Run("name_hold_bad_pop_is_pop_invalid", func(t *testing.T) {
		e := newMachineEnv(t)
		e.revokeMachineSubject(t, "ci")
		e.refusedMachine(t, e.badPoP(e.machineReq(e.k1, "ci"), e.k1), "machine_pop_invalid", wire.CodeRefused)
	})
	t.Run("name_hold_survives_restart", func(t *testing.T) {
		e := idleMachine(t)
		e.revokeMachineSubject(t, "ci")
		e.restart(t)
		e.refusedMachine(t, e.machineReq(e.k1, "ci"), "cert_revoked", wire.CodeRefused)
		e.verifyExport()
	})
	t.Run("name_hold_is_per_name", func(t *testing.T) {
		// ci2 is disabled in the env, so the other active machine is ci3.
		e := newMachineEnv(t)
		k3 := e.addCI3(t)
		e.revokeMachineSubject(t, "ci")
		e.mustMachine(t, e.machineReq(k3, "ci3"))
		e.refusedMachine(t, e.machineReq(e.k1, "ci"), "cert_revoked", wire.CodeRefused)
		e.verifyExport()
	})
	t.Run("host_subject_revoke_holds_no_machine_name", func(t *testing.T) {
		e := newMachineEnv(t)
		e.revokeHostSubject(t, "ci")
		e.mustMachine(t, e.machineReq(e.k1, "ci"))
	})
	t.Run("renamed_key_old_name_not_swept", func(t *testing.T) {
		// T-03-72's residual: a sweep of the new name does not list the
		// certificate the key obtained under the old one.
		e := newMachineEnv(t)
		c, _ := e.mustMachine(t, e.machineReq(e.k1, "ci"))
		e.machines[0].Name = "ci-renamed"
		e.publishMachines(t)
		c2, _ := e.mustMachine(t, e.machineReq(e.k1, "ci-renamed"))
		if resp := e.revokeMachineSubject(t, "ci-renamed"); slices.Contains(resp.Serials, c.Serial) || !slices.Equal(resp.Serials, []uint64{c2.Serial}) {
			t.Fatalf("revoke machine ci-renamed listed %v; the sub=ci certificate is %d", resp.Serials, c.Serial)
		}
	})
	t.Run("name_hold_rearmed_by_later_sweep", func(t *testing.T) {
		// The move rule: a later sweep at V+1 holds the name again, at V+1.
		e := idleMachine(t)
		e.revokeMachineSubject(t, "ci")
		e.publishMachines(t)
		c, _ := e.mustMachine(t, e.machineReq(e.k1, "ci"))
		e.tickTo(c.ValidBefore + 300) // so the second sweep lists nothing and only the name hold can refuse
		if resp := e.revokeMachineSubject(t, "ci"); len(resp.Serials) != 0 {
			t.Fatalf("the second sweep listed %v, want nothing", resp.Serials)
		}
		e.refusedMachine(t, e.machineReq(e.k1, "ci"), "cert_revoked", wire.CodeRefused)
		e.publishMachines(t)
		e.mustMachine(t, e.machineReq(e.k1, "ci"))
		e.verifyExport()
	})
	t.Run("refused_revoke_arms_nothing", func(t *testing.T) {
		e := newMachineEnv(t)
		before := e.leafCount(tlog.KindRevoke)
		req := e.signedRevoke(t, &wire.RevokeRequest{Target: wire.TargetSubject, SubjectKind: wire.SubjectMachine, Subject: "ci"}, newEd25519(t))
		if _, er := e.s.revokeOrRefuse(ctx, Peer{UID: 1000}, req); er == nil {
			t.Fatal("a machine subject revoke signed by no admin was accepted")
		}
		if e.leafCount(tlog.KindRevoke) != before {
			t.Fatal("the refused revoke wrote a revoke leaf")
		}
		e.mustMachine(t, e.machineReq(e.k1, "ci"))
		e.verifyExport()
	})
}
