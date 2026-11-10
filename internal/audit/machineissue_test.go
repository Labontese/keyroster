package audit

import (
	"crypto/rand"
	"encoding/hex"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/webauthn"
	"github.com/Labontese/keyroster/internal/webauthn/webauthntest"
	"github.com/Labontese/keyroster/internal/wire"
)

// machineFixture is a probeFixture for machine certificates (03-11): a
// genesis policy with pop.hosts and pop.machines (or pop.hosts only), and
// a directory with the machine-only roles deploy (app, deploy; 7200 s;
// permit-pty) and build (build, deploy; 5400 s) and the machines ci
// (mkey, both roles, 3600 s, active), ci2 (mkey2, deploy, disabled) and
// ci3 (mec, an ECDSA key, deploy, active).
type machineFixture struct {
	*probeFixture
	mkey, mkey2, mec ssh.Signer
	roles            []directory.Role
}

func newMachineFixture(t testing.TB) *machineFixture { return newMachineFixtureWith(t, true, nil) }

// newMachineFixtureWith is newMachineFixture with pop.machines as given and
// root as the genesis root (nil: a new one).
func newMachineFixtureWith(t testing.TB, popMachines bool, root ssh.Signer) *machineFixture {
	t.Helper()
	f := newBareFixtureAt(t, "ed25519", time.Now().Truncate(time.Second))
	if root != nil {
		f.root = root
	}
	pol := f.loginPolicy(false)
	pol.PoP = &trust.PoPPolicy{Hosts: true, Machines: popMachines}
	pol.CAProfiles[1].MaxTTLSeconds = 90
	g := f.genesis()
	g.InstallationID = auditInstallationID
	lf := &loginFixture{fixture: f, pol: pol}
	lf.docs = f.signDocs(g, pol, f.root)
	f.addBundle(lf.docs)
	var err error
	if lf.alice, err = webauthntest.New(webauthn.AlgEdDSA); err != nil {
		t.Fatal(err)
	}
	if lf.bob, err = webauthntest.New(webauthn.AlgES256); err != nil {
		t.Fatal(err)
	}
	hf := &hostFixture{loginFixture: lf, key: newSigner(t, "ed25519"), key2: newSigner(t, "p256"), off: newSigner(t, "ed25519")}
	hf.hosts = []directory.Host{
		{Name: "web1", HostGroup: "lab", Keys: []string{trust.FormatKey(hf.key.PublicKey()), trust.FormatKey(hf.key2.PublicKey())}, Principals: []string{"web1"}, Status: directory.StatusActive},
	}
	mf := &machineFixture{probeFixture: &probeFixture{hostFixture: hf, key3: newSigner(t, "ed25519")},
		mkey: newSigner(t, "ed25519"), mkey2: newSigner(t, "ed25519"), mec: newSigner(t, "p256")}
	hf.hosts = append(hf.hosts, directory.Host{Name: "web3", HostGroup: "lab", Keys: []string{trust.FormatKey(mf.key3.PublicKey())},
		Principals: []string{"web3"}, Status: directory.StatusActive})
	mf.rev = hf.rf()
	mf.roles = []directory.Role{
		{Name: "deploy", Principals: []string{"app", "deploy"}, MaxTTLSeconds: 7200, Extensions: []string{"permit-pty"}},
		{Name: "build", Principals: []string{"build", "deploy"}, MaxTTLSeconds: 5400},
	}
	hf.machines = []directory.Machine{
		{Name: "ci", Key: trust.FormatKey(mf.mkey.PublicKey()), Roles: []string{"build", "deploy"}, MaxTTLSeconds: 3600, Status: directory.StatusActive},
		{Name: "ci2", Key: trust.FormatKey(mf.mkey2.PublicKey()), Roles: []string{"deploy"}, MaxTTLSeconds: 3600, Status: directory.StatusDisabled},
		{Name: "ci3", Key: trust.FormatKey(mf.mec.PublicKey()), Roles: []string{"deploy"}, MaxTTLSeconds: 3600, Status: directory.StatusActive},
	}
	mf.publish()
	return mf
}

// publish logs the next directory version with the hosts, the machines
// and the machine roles of mf.
func (mf *machineFixture) publish() {
	mf.t.Helper()
	hosts := slices.Clone(mf.hosts)
	for i := range hosts {
		hosts[i].Keys = slices.Sorted(slices.Values(hosts[i].Keys))
	}
	mf.addDirectory(mf.directory(func(d *directory.Directory) {
		d.InstallationID = auditInstallationID
		d.HostGroups = []directory.HostGroup{{Name: "lab", Accounts: []directory.AccountMap{{Account: "root", Roles: []string{"ops"}}}}}
		d.Hosts = hosts
		d.Machines = slices.Clone(mf.machines)
		for _, r := range mf.roles {
			r.Principals = slices.Clone(r.Principals)
			d.Roles = append(d.Roles, r)
		}
	}), nil)
}

// machineIssue is one machine issuance as the fixture builds it, in the
// order of the signer's steps; pre changes the request before the proof of
// possession is signed, tamper after, post the certificate and body.
type machineIssue struct {
	req        *wire.MachineIssueRequest
	popKey     ssh.Signer
	ns         string
	evidence   []wire.Evidence
	ca         ssh.Signer
	principals []string
	extensions map[string]string
	options    map[string]string
	lifetime   uint64
	capSeconds uint64
	keyID      cert.KeyID
	serial     uint64
	issued     time.Time // cert.Build's Now; zero: issuedAt(serial)
	dirVersion uint64
	polVersion uint64
	cert       *ssh.Certificate
}

// grantOf is the sorted union of the principals of the roles that the
// fixture machine name holds (ci's for a name the directory lacks).
func (mf *machineFixture) grantOf(name string) []string {
	roles := []string{"build", "deploy"}
	for _, m := range mf.machines {
		if m.Name == name {
			roles = m.Roles
		}
	}
	set := map[string]bool{}
	for _, r := range mf.roles {
		if slices.Contains(roles, r.Name) {
			for _, p := range r.Principals {
				set[p] = true
			}
		}
	}
	return slices.Sorted(maps.Keys(set))
}

// addMachine logs a machine_issue entry: by default key's request for the
// machine that lists key ("ci" for an unlisted key), valid_for 0, created
// at the entry time, signed by key under the machine namespace, and the
// certificate cert.Build gives the machine CA for it with the grant's
// principals, permit-pty and the lifetime 3600 s, with the next serial.
func (mf *machineFixture) addMachine(key ssh.Signer, pre, tamper, post func(*machineIssue)) *machineIssue {
	mf.t.Helper()
	name := "ci"
	for _, m := range mf.machines {
		if m.Key == trust.FormatKey(key.PublicKey()) {
			name = m.Name
		}
	}
	m := &machineIssue{
		req:    &wire.MachineIssueRequest{InstallationID: auditInstallationID, MachineName: name, MachineKey: key.PublicKey().Marshal(), CreatedAt: mf.leafSecs()},
		popKey: key, ns: wire.MachinePoPNamespace, ca: mf.machineCA, extensions: map[string]string{"permit-pty": ""},
		lifetime: 3600, capSeconds: 3600, serial: mf.serial + 1, dirVersion: mf.dirVersion, polVersion: mf.pol.Version,
	}
	if _, err := rand.Read(m.req.RequestID[:]); err != nil {
		mf.t.Fatal(err)
	}
	if pre != nil {
		pre(m)
	}
	m.principals = mf.grantOf(m.req.MachineName)
	sig, err := sshsig.Sign(rand.Reader, m.popKey, m.ns, m.req.SigningBytes())
	if err != nil {
		mf.t.Fatal(err)
	}
	m.evidence = []wire.Evidence{{Type: wire.EvidenceMachinePoP, Blob: sig}}
	if tamper != nil {
		tamper(m)
	}
	m.keyID = cert.KeyID{V3: true, CA: "machine", Subject: m.req.MachineName, Request: hex.EncodeToString(m.req.RequestID[:]),
		Policy: m.polVersion, Directory: m.dirVersion}
	if post != nil {
		post(m)
	}
	m.keyID.Serial = m.serial
	issued := m.issued
	if issued.IsZero() {
		issued = issuedAt(m.serial)
	}
	pub, err := ssh.ParsePublicKey(m.req.MachineKey)
	if err != nil {
		mf.t.Fatal(err)
	}
	prof := cert.Profile{CertType: ssh.UserCert, MaxTTL: 30 * 24 * time.Hour, DefaultExtensions: m.extensions,
		AllowedCriticalOptions: slices.Sorted(maps.Keys(m.options))}
	c, err := cert.Build(cert.Request{Profile: prof, Subject: pub, Principals: m.principals, Now: issued,
		ValidFor: time.Duration(m.lifetime) * time.Second, KeyID: m.keyID, Serial: m.serial, CriticalOptions: m.options}, m.ca, rand.Reader) //nolint:gosec // G115: test lifetimes
	if err != nil {
		mf.t.Fatal(err)
	}
	m.cert = c
	body, err := (&tlog.MachineIssueBody{Serial: m.serial, PolicyVersion: m.polVersion, DirectoryVersion: m.dirVersion, CapSeconds: m.capSeconds,
		Request: m.req.SigningBytes(), Evidence: m.evidence, Cert: c.Marshal(), KeyID: c.KeyId}).Encode()
	if err != nil {
		mf.t.Fatal(err)
	}
	mf.add(tlog.KindMachineIssue, body)
	mf.serial = max(mf.serial, m.serial)
	return m
}

// revokeKey logs an explicit-key revoke of key and the krl_publish the
// signer writes with it.
func (mf *machineFixture) revokeKey(key ssh.PublicKey) {
	mf.t.Helper()
	k := key.Marshal()
	mf.rev.revoke(&wire.RevokeRequest{Target: wire.TargetKey, Key: k}, []tlog.RevokedEntry{{Kind: tlog.RevokedKey, Key: k}}, nil)
	mf.rev.publish(nil)
}

// TestVerifyMachineIssue: audit verify re-proves every machine_issue
// entry from the log alone, with the signer's rules (03-11).
func TestVerifyMachineIssue(t *testing.T) {
	t.Run("valid_passes", func(t *testing.T) {
		mf := newMachineFixture(t)
		mf.addMachine(mf.mkey, nil, nil, nil)
		mf.advance(time.Minute)
		mf.addMachine(mf.mkey, nil, nil, nil)
		mf.addMachine(mf.mec, nil, nil, nil)
		rep := mf.wantPass(t)
		if rep.Counts[tlog.KindMachineIssue] != 3 {
			t.Fatalf("Counts[machine_issue] = %d, want 3", rep.Counts[tlog.KindMachineIssue])
		}
	})
	t.Run("sshsig_by_other_key_fails", func(t *testing.T) {
		mf := newMachineFixture(t)
		mf.addMachine(mf.mkey, func(m *machineIssue) { m.popKey = mf.mkey2 }, nil, nil)
		mf.wantFail(t, "machine proof of possession is by")
	})
	t.Run("namespace_host_fails", func(t *testing.T) {
		mf := newMachineFixture(t)
		mf.addMachine(mf.mkey, func(m *machineIssue) { m.ns = wire.HostPoPNamespace }, nil, nil)
		mf.wantFail(t, "machine proof of possession does not verify")
	})
	t.Run("namespace_probe_fails", func(t *testing.T) {
		mf := newMachineFixture(t)
		mf.addMachine(mf.mkey, func(m *machineIssue) { m.ns = wire.ProbePoPNamespace }, nil, nil)
		mf.wantFail(t, "machine proof of possession does not verify")
	})
	t.Run("installation_mismatch_fails", func(t *testing.T) {
		mf := newMachineFixture(t)
		mf.addMachine(mf.mkey, func(m *machineIssue) { m.req.InstallationID = strings.Repeat("ab", 16) }, nil, nil)
		mf.wantFail(t, "but the bundle in force is installation")
	})
	t.Run("pop_machines_off_fails", func(t *testing.T) {
		mf := newMachineFixtureWith(t, false, nil)
		mf.addMachine(mf.mkey, nil, nil, nil)
		mf.wantFail(t, "does not set pop.machines")
	})
	t.Run("key_not_listed_fails", func(t *testing.T) {
		// An SSHSIG by the listed key over a request that names an
		// unlisted key: only the entry-key rule can catch it.
		mf := newMachineFixture(t)
		other := newSigner(t, "ed25519")
		mf.addMachine(other, func(m *machineIssue) { m.popKey = mf.mkey }, nil, nil)
		mf.wantFail(t, "does not list key")
	})
	t.Run("key_mismatch_request_vs_entry_fails", func(t *testing.T) {
		// ci's name with ci3's key, signed by ci3's key.
		mf := newMachineFixture(t)
		mf.addMachine(mf.mec, func(m *machineIssue) { m.req.MachineName = "ci" }, nil, nil)
		mf.wantFail(t, "does not list key")
	})
	t.Run("unknown_machine_fails", func(t *testing.T) {
		mf := newMachineFixture(t)
		mf.addMachine(mf.mkey, func(m *machineIssue) { m.req.MachineName = "nope" }, nil, nil)
		mf.wantFail(t, `has no machine "nope"`)
	})
	t.Run("disabled_fails", func(t *testing.T) {
		mf := newMachineFixture(t)
		mf.addMachine(mf.mkey2, nil, nil, nil)
		mf.wantFail(t, "is disabled, not active")
	})
	t.Run("key_revoked_fails", func(t *testing.T) {
		mf := newMachineFixture(t)
		mf.revokeKey(mf.mkey.PublicKey())
		mf.addMachine(mf.mkey, nil, nil, nil)
		mf.wantFail(t, "machine_key_revoked")
	})
	t.Run("valid_for_fails", func(t *testing.T) {
		mf := newMachineFixture(t)
		mf.addMachine(mf.mkey, func(m *machineIssue) { m.req.ValidForSeconds = 3600 }, nil, nil)
		mf.wantFail(t, "asks for valid_for")
	})
	t.Run("created_at_fails", func(t *testing.T) {
		mf := newMachineFixture(t)
		mf.addMachine(mf.mkey, func(m *machineIssue) { m.req.CreatedAt -= 301 }, nil, nil)
		mf.wantFail(t, "request CreatedAt is")
	})
	t.Run("policy_version_fails", func(t *testing.T) {
		mf := newMachineFixture(t)
		mf.addMachine(mf.mkey, nil, nil, func(m *machineIssue) { m.polVersion++; m.keyID.Policy = m.polVersion })
		mf.wantFail(t, "entry records policy version")
	})
	t.Run("directory_version_fails", func(t *testing.T) {
		mf := newMachineFixture(t)
		mf.addMachine(mf.mkey, nil, nil, func(m *machineIssue) { m.dirVersion--; m.keyID.Directory = m.dirVersion })
		mf.wantFail(t, "entry records directory version")
	})
	t.Run("lifetime_fails", func(t *testing.T) {
		mf := newMachineFixture(t)
		mf.addMachine(mf.mkey, nil, nil, func(m *machineIssue) { m.lifetime-- })
		mf.wantFail(t, "certificate lives")
	})
	t.Run("cap_seconds_fails", func(t *testing.T) {
		mf := newMachineFixture(t)
		mf.addMachine(mf.mkey, nil, nil, func(m *machineIssue) { m.capSeconds-- })
		mf.wantFail(t, "entry records CapSeconds")
	})
	t.Run("principals_fails", func(t *testing.T) {
		for name, edit := range map[string]func(*machineIssue){
			"missing": func(m *machineIssue) { m.principals = []string{"app", "deploy"} },
			"extra":   func(m *machineIssue) { m.principals = []string{"app", "build", "deploy", "root"} },
		} {
			t.Run(name, func(t *testing.T) {
				mf := newMachineFixture(t)
				mf.addMachine(mf.mkey, nil, nil, edit)
				mf.wantFail(t, "certificate principals")
			})
		}
	})
	t.Run("extensions_fails", func(t *testing.T) {
		mf := newMachineFixture(t)
		mf.addMachine(mf.mkey, nil, nil, func(m *machineIssue) { m.extensions = map[string]string{} })
		mf.wantFail(t, "certificate extensions")
	})
	t.Run("critical_option_fails", func(t *testing.T) {
		mf := newMachineFixture(t)
		mf.addMachine(mf.mkey, nil, nil, func(m *machineIssue) { m.options = map[string]string{"force-command": "/bin/true"} })
		mf.wantFail(t, "carries critical options")
	})
	t.Run("key_id_fields_fails", func(t *testing.T) {
		for name, tc := range map[string]struct {
			edit func(*machineIssue)
			want string
		}{
			"subject":   {func(m *machineIssue) { m.keyID.Subject = "ci3" }, "key ID sub="},
			"request":   {func(m *machineIssue) { m.keyID.Request = strings.Repeat("0", 32) }, "key ID req="},
			"directory": {func(m *machineIssue) { m.keyID.Directory++ }, "key ID dir="},
		} {
			t.Run(name, func(t *testing.T) {
				mf := newMachineFixture(t)
				mf.addMachine(mf.mkey, nil, nil, tc.edit)
				mf.wantFail(t, tc.want)
			})
		}
	})
	t.Run("wrong_ca_fails", func(t *testing.T) {
		mf := newMachineFixture(t)
		mf.addMachine(mf.mkey, nil, nil, func(m *machineIssue) { m.ca = mf.ca })
		mf.wantFail(t, "not by the role's active CA")
	})
	t.Run("probe_name_fails", func(t *testing.T) {
		mf := newMachineFixture(t)
		pk := newSigner(t, "ed25519")
		mf.machines = append(mf.machines, directory.Machine{Name: "probe.x", Key: trust.FormatKey(pk.PublicKey()), Roles: []string{"deploy"},
			MaxTTLSeconds: 3600, Status: directory.StatusActive})
		mf.publish()
		mf.addMachine(pk, nil, nil, nil)
		mf.wantFail(t, "machine_name_reserved")
	})
	t.Run("request_id_reused_from_other_kind_fails", func(t *testing.T) {
		withID := func(id [16]byte) func(*machineIssue) { return func(m *machineIssue) { m.req.RequestID = id } }
		t.Run("issue", func(t *testing.T) {
			mf := newMachineFixture(t)
			id := [16]byte{9, 8, 7}
			mf.addIssueWithRequest(hex.EncodeToString(id[:]))
			mf.addMachine(mf.mkey, withID(id), nil, nil)
			mf.wantFail(t, "issue entry")
		})
		t.Run("login_issue", func(t *testing.T) {
			mf := newMachineFixture(t)
			mf.installPolicy(func(p *trust.Policy) { p.WebAuthn = &trust.WebAuthnRP{RPID: auditRPID, Origins: []string{auditOrigin}} })
			mf.publish()
			l := mf.addLogin(nil, nil)
			mf.addMachine(mf.mkey, withID(l.req.RequestID), nil, nil)
			mf.wantFail(t, "login_issue entry")
		})
		t.Run("host_issue", func(t *testing.T) {
			mf := newMachineFixture(t)
			h := mf.addHost(mf.key, nil, nil, nil)
			mf.addMachine(mf.mkey, withID(h.req.RequestID), nil, nil)
			mf.wantFail(t, "host_issue entry")
		})
		t.Run("probe_issue", func(t *testing.T) {
			mf := newMachineFixture(t)
			p := mf.addProbe(mf.key, false, nil, nil, nil)
			mf.addMachine(mf.mkey, withID(p.req.RequestID), nil, nil)
			mf.wantFail(t, "probe_issue entry")
		})
	})
	machineHoldBoundAuditCases(t)
}

// revokeSerial logs a serial revoke of m's certificate under the machine
// CA and the krl_publish the signer writes with it.
func (mf *machineFixture) revokeSerial(m *machineIssue) {
	mf.t.Helper()
	mf.rev.revoke(&wire.RevokeRequest{Target: wire.TargetSerial, CARole: wire.CARoleMachine, Serial: m.serial}, []tlog.RevokedEntry{serialEntry(m.cert)}, nil)
	mf.rev.publish(nil)
}

// lostMachine is a kr3 machine certificate of key for ci with the next
// serial, as a lost log would have issued it, not logged.
func (mf *machineFixture) lostMachine(key ssh.Signer) *ssh.Certificate {
	mf.t.Helper()
	mf.serial++
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		mf.t.Fatal(err)
	}
	kid := cert.KeyID{V3: true, CA: "machine", Subject: "ci", Request: hex.EncodeToString(id[:]), Policy: mf.pol.Version, Directory: mf.dirVersion, Serial: mf.serial}
	prof := cert.Profile{CertType: ssh.UserCert, MaxTTL: 30 * 24 * time.Hour, DefaultExtensions: map[string]string{"permit-pty": ""}}
	c, err := cert.Build(cert.Request{Profile: prof, Subject: key.PublicKey(), Principals: mf.grantOf("ci"), Now: issuedAt(mf.serial),
		ValidFor: time.Hour, KeyID: kid, Serial: mf.serial}, mf.machineCA, rand.Reader)
	if err != nil {
		mf.t.Fatal(err)
	}
	return c
}

// carry logs a recovery that carries c, revoked or not, and its
// krl_publish.
func (mf *machineFixture) carry(c *ssh.Certificate, revoke bool) {
	mf.t.Helper()
	mf.rev.recover(nil, []wire.RecoveredCertificate{{Cert: c.Marshal(), Revoke: revoke}}, nil)
	mf.rev.publish(nil)
}

// machineHoldBoundAuditCases are TestVerifyMachineIssue's hold, bound,
// unusable key and request-ID parity cases (03-11 Task 2).
func machineHoldBoundAuditCases(t *testing.T) {
	const keyHold = "its latest certificate, serial"
	t.Run("hold_fails", func(t *testing.T) {
		mf := newMachineFixture(t)
		mf.revokeSerial(mf.addMachine(mf.mkey, nil, nil, nil))
		mf.addMachine(mf.mkey, nil, nil, nil)
		mf.wantFail(t, keyHold)
	})
	t.Run("hold_released_by_newer_directory_passes", func(t *testing.T) {
		mf := newMachineFixture(t)
		mf.revokeSerial(mf.addMachine(mf.mkey, nil, nil, nil))
		mf.publish()
		mf.addMachine(mf.mkey, nil, nil, nil)
		mf.wantPass(t)
	})
	t.Run("bound_fails", func(t *testing.T) {
		mf := newMachineFixture(t)
		for range 13 {
			mf.addMachine(mf.mkey, nil, nil, nil)
		}
		mf.wantFail(t, "machine_renew_too_often")
	})
	t.Run("bound_window_passes", func(t *testing.T) {
		// One at S, eleven at S + 10, then one at S + 3601: the first is out
		// of the window, so eleven count.
		mf := newMachineFixture(t)
		mf.addMachine(mf.mkey, nil, nil, nil)
		mf.advance(10 * time.Second)
		for range 11 {
			mf.addMachine(mf.mkey, nil, nil, nil)
		}
		mf.advance(3591 * time.Second)
		mf.addMachine(mf.mkey, nil, nil, nil)
		mf.wantPass(t)
	})
	t.Run("installation_key_fails", func(t *testing.T) {
		mf := newMachineFixture(t)
		mf.machines = append(mf.machines, directory.Machine{Name: "opsm", Key: trust.FormatKey(mf.ops.PublicKey()), Roles: []string{"deploy"},
			MaxTTLSeconds: 3600, Status: directory.StatusActive})
		mf.publish()
		mf.addMachine(mf.ops, nil, nil, nil)
		mf.wantFail(t, "machine_key_unusable")
	})
	t.Run("recovery_carried_hold_fails", func(t *testing.T) {
		mf := newMachineFixture(t)
		mf.addMachine(mf.mkey, nil, nil, nil)
		mf.carry(mf.lostMachine(mf.mkey), true)
		mf.addMachine(mf.mkey, nil, nil, nil)
		mf.wantFail(t, keyHold)
	})
	t.Run("recovery_carried_not_counted_toward_bound_passes", func(t *testing.T) {
		mf := newMachineFixture(t)
		mf.carry(mf.lostMachine(mf.mkey), false)
		for range 12 {
			mf.addMachine(mf.mkey, nil, nil, nil)
		}
		mf.wantPass(t)
		mf.addMachine(mf.mkey, nil, nil, nil)
		mf.wantFail(t, "machine_renew_too_often")
	})
	t.Run("relisting_keeps_first_passes", func(t *testing.T) {
		mf := newMachineFixture(t)
		m := mf.addMachine(mf.mkey, nil, nil, nil)
		mf.revokeSerial(m)
		mf.publish()
		mf.revokeSerial(m)
		mf.addMachine(mf.mkey, nil, nil, nil)
		mf.wantPass(t)
	})
	const reused = "machine_issue entry"
	t.Run("host_reuses_machine_request_id_fails", func(t *testing.T) {
		mf := newMachineFixture(t)
		m := mf.addMachine(mf.mkey, nil, nil, nil)
		mf.addHost(mf.key, func(h *hostIssue) { h.req.RequestID = m.req.RequestID }, nil, nil)
		mf.wantFail(t, reused)
	})
	t.Run("login_reuses_machine_request_id_fails", func(t *testing.T) {
		mf := newMachineFixture(t)
		mf.installPolicy(func(p *trust.Policy) { p.WebAuthn = &trust.WebAuthnRP{RPID: auditRPID, Origins: []string{auditOrigin}} })
		mf.publish()
		m := mf.addMachine(mf.mkey, nil, nil, nil)
		mf.addLogin(func(l *login) { l.req.RequestID = m.req.RequestID }, nil)
		mf.wantFail(t, reused)
	})
	t.Run("issue_reuses_machine_request_id_fails", func(t *testing.T) {
		mf := newMachineFixture(t)
		m := mf.addMachine(mf.mkey, nil, nil, nil)
		mf.addIssueWithRequest(hex.EncodeToString(m.req.RequestID[:]))
		mf.wantFail(t, reused)
	})
	t.Run("probe_reuses_machine_request_id_fails", func(t *testing.T) {
		mf := newMachineFixture(t)
		m := mf.addMachine(mf.mkey, nil, nil, nil)
		mf.addProbe(mf.key, false, func(p *probeIssue) { p.req.RequestID = m.req.RequestID }, nil, nil)
		mf.wantFail(t, reused)
	})
	t.Run("machine_reuses_machine_request_id_fails", func(t *testing.T) {
		mf := newMachineFixture(t)
		m := mf.addMachine(mf.mkey, nil, nil, nil)
		mf.addMachine(mf.mec, func(n *machineIssue) { n.req.RequestID = m.req.RequestID }, nil, nil)
		mf.wantFail(t, reused)
	})
}

// TestExportMachineIssue: the machine_issue line carries the decoded
// fields, and Verify binds it to the leaf (03-11).
func TestExportMachineIssue(t *testing.T) {
	t.Run("line_carries_decoded_fields", func(t *testing.T) {
		mf := newMachineFixture(t)
		m := mf.addMachine(mf.mkey, nil, nil, nil)
		line := decoded(t, mf.leaves[len(mf.leaves)-1])
		for _, k := range []string{"kind", "serial", "policy_version", "directory_version", "cap_seconds", "key_id", "evidence_types",
			"machine_name", "request_id", "created_at", "machine_key_fingerprint", "principals", "valid_after", "valid_before",
			"ca_fingerprint", "ca_algorithm"} {
			if _, ok := line[k]; !ok {
				t.Errorf("the machine_issue line has no %q: %v", k, line)
			}
		}
		for _, k := range []string{"version", "bundle_version", "directory", "sigs", "host_name", "host_key_fingerprint"} {
			if _, ok := line[k]; ok {
				t.Errorf("the machine_issue line carries %q", k)
			}
		}
		if line["kind"] != "machine_issue" || line["machine_name"] != "ci" || line["key_id"] != m.cert.KeyId ||
			line["machine_key_fingerprint"] != ssh.FingerprintSHA256(mf.mkey.PublicKey()) ||
			line["request_id"] != hex.EncodeToString(m.req.RequestID[:]) {
			t.Fatalf("the machine_issue line: %v", line)
		}
		mf.wantPass(t)
	})
	t.Run("tampered_decoded_field_refused", func(t *testing.T) {
		mf := newMachineFixture(t)
		mf.addMachine(mf.mkey, nil, nil, nil)
		in := join(mf.lines())
		for _, mut := range [][2]string{
			{`"machine_name":"ci"`, `"machine_name":"ci3"`},
			{`"machine_key_fingerprint":"`, `"machine_key_fingerprint":"x`},
			{`"cap_seconds":3600`, `"cap_seconds":3599`},
			{`"kind":"machine_issue",`, `"kind":"machine_issue","note":"x",`},
		} {
			if !strings.Contains(in, mut[0]) {
				t.Fatalf("the export holds no %s", mut[0])
			}
			if _, err := mf.verify(strings.Replace(in, mut[0], mut[1], 1), nil); err == nil || !strings.Contains(err.Error(), "machine_issue leaf") {
				t.Errorf("a machine_issue line with %s: %v, want it refused", mut[1], err)
			}
		}
	})
}
