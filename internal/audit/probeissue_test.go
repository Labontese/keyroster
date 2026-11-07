package audit

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/certprofile"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/webauthn"
	"github.com/Labontese/keyroster/internal/webauthn/webauthntest"
	"github.com/Labontese/keyroster/internal/wire"
)

// probeFixture is a hostFixture for probe certificates (03-10): the same
// bundle and policy (pop.hosts, the machine cap 86400 s of the genesis
// policy), with web3 (active, key3) added to directory version 2, so a
// request can name one host and carry another host's listed key.
type probeFixture struct {
	*hostFixture
	key3 ssh.Signer
	rev  *revokeFixture
}

func newProbeFixture(t testing.TB) *probeFixture {
	t.Helper()
	return probeFixtureFrom(t, newHostFixture(t, 90))
}

// newProbeFixtureNoPoP is newProbeFixture under a genesis policy that never
// set pop.hosts (a successor may not clear it, so installPolicy cannot).
func newProbeFixtureNoPoP(t testing.TB) *probeFixture {
	t.Helper()
	f := newBareFixtureAt(t, "ed25519", time.Now().Truncate(time.Second))
	pol := f.loginPolicy(false)
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
	hf.publish()
	return probeFixtureFrom(t, hf)
}

func probeFixtureFrom(t testing.TB, hf *hostFixture) *probeFixture {
	t.Helper()
	pf := &probeFixture{hostFixture: hf, key3: newSigner(t, "ed25519")}
	hf.hosts = append(hf.hosts, directory.Host{Name: "web3", HostGroup: "lab", Keys: []string{trust.FormatKey(pf.key3.PublicKey())},
		Principals: []string{"web3"}, Status: directory.StatusActive})
	hf.publish()
	pf.rev = hf.rf()
	return pf
}

// probeIssue is one probe issuance as the fixture builds it, in the order
// of the signer's steps; pre changes the request before the evidence is
// signed, tamper after, post the certificate and body.
type probeIssue struct {
	req             *wire.ProbeIssueRequest
	probe           ssh.Signer
	hostPoPKey      ssh.Signer
	probePoPKey     ssh.Signer
	hostNS, probeNS string
	evidence        []wire.Evidence
	ca              ssh.Signer
	principals      []string
	lifetime        uint64
	capSeconds      uint64
	keyID           cert.KeyID
	serial          uint64
	dirVersion      uint64
	polVersion      uint64
	options         map[string]string
	extensions      map[string]string
	bodyNegative    bool
	cert            *ssh.Certificate
	body            *tlog.ProbeIssueBody
	overrideRequest []byte
}

// probeCap is min(604800, the policy in force's machine cap).
func (pf *probeFixture) probeCap() uint64 {
	return min(certprofile.MaxProbeLifetimeSeconds, pf.pol.CAProfiles[2].MaxTTLSeconds)
}

// addProbe logs a probe_issue entry: by default host key key's request for
// web1 with a fresh probe key, valid_for 0, created at the entry time,
// both evidence items signed under the probe namespace, and the
// certificate cert.Build gives the machine CA for it under the probe
// restrictions, with the next serial.
func (pf *probeFixture) addProbe(key ssh.Signer, negative bool, pre, tamper, post func(*probeIssue)) *probeIssue {
	pf.t.Helper()
	probe := newSigner(pf.t, "ed25519")
	p := &probeIssue{
		req: &wire.ProbeIssueRequest{InstallationID: auditInstallationID, HostName: "web1", HostKey: key.PublicKey().Marshal(),
			ProbeKey: probe.PublicKey().Marshal(), Negative: negative, CreatedAt: pf.leafSecs()},
		probe: probe, hostPoPKey: key, probePoPKey: probe, hostNS: wire.ProbePoPNamespace, probeNS: wire.ProbePoPNamespace,
		ca: pf.machineCA, lifetime: pf.probeCap(), capSeconds: pf.probeCap(),
		serial: pf.serial + 1, dirVersion: pf.dirVersion, polVersion: pf.pol.Version,
		options: certprofile.ProbeCriticalOptions(), extensions: map[string]string{},
	}
	if _, err := rand.Read(p.req.RequestID[:]); err != nil {
		pf.t.Fatal(err)
	}
	if pre != nil {
		pre(p)
	}
	p.principals = []string{"keyroster-probe:" + p.req.HostName}
	p.bodyNegative = p.req.Negative
	hs, err := sshsig.Sign(rand.Reader, p.hostPoPKey, p.hostNS, p.req.SigningBytes())
	if err != nil {
		pf.t.Fatal(err)
	}
	ps, err := sshsig.Sign(rand.Reader, p.probePoPKey, p.probeNS, p.req.SigningBytes())
	if err != nil {
		pf.t.Fatal(err)
	}
	p.evidence = []wire.Evidence{{Type: wire.EvidenceHostPoP, Blob: hs}, {Type: wire.EvidenceProbePoP, Blob: ps}}
	if tamper != nil {
		tamper(p)
	}
	p.keyID = cert.KeyID{V3: true, CA: "machine", Subject: "probe." + p.req.HostName, Request: hex.EncodeToString(p.req.RequestID[:]),
		Policy: p.polVersion, Directory: p.dirVersion}
	if post != nil {
		post(p)
	}
	p.keyID.Serial = p.serial
	subject, err := ssh.ParsePublicKey(p.req.ProbeKey)
	if err != nil {
		pf.t.Fatal(err)
	}
	prof := cert.Profile{CertType: ssh.UserCert, MaxTTL: 30 * 24 * time.Hour, DefaultExtensions: map[string]string{},
		AllowedExtensions: slices.Sorted(maps.Keys(p.extensions)), AllowedCriticalOptions: slices.Sorted(maps.Keys(p.options))}
	c, err := cert.Build(cert.Request{Profile: prof, Subject: subject, Principals: p.principals, Now: issuedAt(p.serial),
		ValidFor: time.Duration(p.lifetime) * time.Second, KeyID: p.keyID, Serial: p.serial, //nolint:gosec // G115: test lifetimes
		ExtraExtensions: p.extensions, CriticalOptions: p.options}, p.ca, rand.Reader)
	if err != nil {
		pf.t.Fatal(err)
	}
	p.cert = c
	request := p.req.SigningBytes()
	if p.overrideRequest != nil {
		request = p.overrideRequest
	}
	neg := p.bodyNegative
	p.body = &tlog.ProbeIssueBody{Serial: p.serial, Negative: neg, PolicyVersion: p.polVersion, DirectoryVersion: p.dirVersion,
		CapSeconds: p.capSeconds, Request: request, Evidence: p.evidence, Cert: c.Marshal(), KeyID: c.KeyId}
	enc, err := p.body.Encode()
	if err != nil {
		pf.t.Fatal(err)
	}
	pf.add(tlog.KindProbeIssue, enc)
	pf.serial = max(pf.serial, p.serial)
	return p
}

// publishWith logs a krl_publish entry that lists every entry so far plus
// the negative probe entries given (the signer's publish).
func (pf *probeFixture) publishWith(probes ...*probeIssue) {
	pf.t.Helper()
	for _, p := range probes {
		entries, err := p.body.RevokedEntries()
		if err != nil {
			pf.t.Fatal(err)
		}
		for _, e := range entries {
			pf.rev.entries = append(pf.rev.entries, krl.Entry{Kind: krl.EntrySerial, CAKey: e.CAKey, Serial: e.Serial, ValidBefore: e.ValidBeforeSeconds})
		}
	}
	pf.rev.publish(nil)
}

// TestVerifyProbeIssue: audit verify re-proves every probe_issue entry
// from the log alone, with the signer's rules (03-10). Every fail case
// isolates one rule through wantFail's rule-naming message.
func TestVerifyProbeIssue(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		pf := newProbeFixture(t)
		neg := pf.addProbe(pf.key, true, nil, nil, nil)
		pf.addProbe(pf.key2, false, nil, nil, nil)
		pf.publishWith(neg)
		if rep := pf.wantPass(t); rep.Counts[tlog.KindProbeIssue] != 2 {
			t.Fatalf("counts %v", rep.Counts)
		}
	})
	t.Run("negative_listed_by_next_publish", func(t *testing.T) {
		pf := newProbeFixture(t)
		neg := pf.addProbe(pf.key, true, nil, nil, nil)
		pf.publishWith(neg)
		pf.wantPass(t)
	})
	t.Run("negative_missing_from_next_publish_fails", func(t *testing.T) {
		pf := newProbeFixture(t)
		pf.addProbe(pf.key, true, nil, nil, nil)
		pf.publishWith()
		pf.wantFail(t, "re-derived from the log's revocations")
	})
	t.Run("malformed_logged_request_fails", func(t *testing.T) {
		pf := newProbeFixture(t)
		pf.addProbe(pf.key, false, nil, nil, func(p *probeIssue) { p.overrideRequest = []byte("not a probe request") })
		pf.wantFail(t, "logged request")
	})
	t.Run("installation_mismatch_fails", func(t *testing.T) {
		pf := newProbeFixture(t)
		pf.addProbe(pf.key, false, func(p *probeIssue) { p.req.InstallationID = "fedcba9876543210fedcba9876543210" }, nil, nil)
		pf.wantFail(t, "request names installation")
	})
	t.Run("pop_hosts_off_fails", func(t *testing.T) {
		pf := newProbeFixtureNoPoP(t)
		pf.addProbe(pf.key, false, nil, nil, nil)
		pf.wantFail(t, "does not set pop.hosts")
	})
	t.Run("policy_version_mismatch_fails", func(t *testing.T) {
		pf := newProbeFixture(t)
		pf.addProbe(pf.key, false, nil, nil, func(p *probeIssue) { p.polVersion++ })
		pf.wantFail(t, "entry records policy version")
	})
	t.Run("directory_version_mismatch_fails", func(t *testing.T) {
		pf := newProbeFixture(t)
		pf.addProbe(pf.key, false, nil, nil, func(p *probeIssue) { p.dirVersion--; p.keyID.Directory = p.dirVersion })
		pf.wantFail(t, "entry records directory version")
	})
	t.Run("directory_not_authorized_fails", func(t *testing.T) {
		pf := newProbeFixture(t)
		pf.installPolicy(func(p *trust.Policy) {
			p.Admins = append(p.Admins, trust.AdminKey{Name: "bob", Key: trust.FormatKey(newSigner(t, "ed25519").PublicKey())})
			p.AdminQuorum = 2
		})
		pf.addProbe(pf.key, false, nil, nil, nil)
		pf.wantFail(t, "not authorized")
	})
	t.Run("unknown_host_fails", func(t *testing.T) {
		pf := newProbeFixture(t)
		pf.addProbe(pf.key, false, func(p *probeIssue) { p.req.HostName = "web9" }, nil, nil)
		pf.wantFail(t, "has no host")
	})
	t.Run("key_not_listed_fails", func(t *testing.T) {
		// The cross-host form: host B (web3) with host A's listed key and a
		// valid host-pop by that key.
		pf := newProbeFixture(t)
		pf.addProbe(pf.key, false, func(p *probeIssue) { p.req.HostName = "web3" }, nil, nil)
		pf.wantFail(t, "does not list key")
	})
	t.Run("host_disabled_fails", func(t *testing.T) {
		pf := newProbeFixture(t)
		pf.addProbe(pf.off, false, func(p *probeIssue) { p.req.HostName = "web2" }, nil, nil)
		pf.wantFail(t, "not active")
	})
	t.Run("revoked_key_fails", func(t *testing.T) {
		pf := newProbeFixture(t)
		pf.rev.revoke(&wire.RevokeRequest{Target: wire.TargetKey, Key: pf.key.PublicKey().Marshal()},
			[]tlog.RevokedEntry{{Kind: tlog.RevokedKey, Key: pf.key.PublicKey().Marshal()}}, nil)
		pf.rev.publish(nil)
		pf.addProbe(pf.key, false, nil, nil, nil)
		pf.wantFail(t, "explicitly revoked")
	})
	t.Run("host_pop_wrong_namespace_fails", func(t *testing.T) {
		pf := newProbeFixture(t)
		pf.addProbe(pf.key, false, func(p *probeIssue) { p.hostNS = wire.HostPoPNamespace }, nil, nil)
		pf.wantFail(t, "host-pop/v1 does not verify under the probe namespace")
	})
	t.Run("host_pop_by_other_key_fails", func(t *testing.T) {
		pf := newProbeFixture(t)
		pf.addProbe(pf.key, false, func(p *probeIssue) { p.hostPoPKey = pf.key2 }, nil, nil)
		pf.wantFail(t, "host-pop/v1 is not by the request's host key")
	})
	t.Run("probe_pop_by_other_key_fails", func(t *testing.T) {
		pf := newProbeFixture(t)
		pf.addProbe(pf.key, false, func(p *probeIssue) { p.probePoPKey = newSigner(t, "ed25519") }, nil, nil)
		pf.wantFail(t, "probe-pop/v1 is not by the request's probe key")
	})
	t.Run("evidence_order_fails", func(t *testing.T) {
		pf := newProbeFixture(t)
		pf.addProbe(pf.key, false, nil, func(p *probeIssue) { p.evidence[0], p.evidence[1] = p.evidence[1], p.evidence[0] }, nil)
		pf.wantFail(t, "evidence order")
	})
	t.Run("probe_key_is_host_key_fails", func(t *testing.T) {
		pf := newProbeFixture(t)
		pf.addProbe(pf.key, false, func(p *probeIssue) { p.req.ProbeKey, p.probePoPKey = pf.key.PublicKey().Marshal(), pf.key }, nil, nil)
		pf.wantFail(t, "probe key is the request's host key")
	})
	t.Run("probe_key_installation_key_fails", func(t *testing.T) {
		pf := newProbeFixture(t)
		pf.addProbe(pf.key, false, func(p *probeIssue) { p.req.ProbeKey, p.probePoPKey = pf.ca.PublicKey().Marshal(), pf.ca }, nil, nil)
		pf.wantFail(t, "probe key is a key of trust bundle")
	})
	t.Run("probe_key_directory_key_fails", func(t *testing.T) {
		pf := newProbeFixture(t)
		pf.addProbe(pf.key, false, func(p *probeIssue) { p.req.ProbeKey, p.probePoPKey = pf.key3.PublicKey().Marshal(), pf.key3 }, nil, nil)
		pf.wantFail(t, "probe key is listed by directory")
	})
	t.Run("nonzero_valid_for_fails", func(t *testing.T) {
		pf := newProbeFixture(t)
		pf.addProbe(pf.key, false, func(p *probeIssue) { p.req.ValidForSeconds = 60 }, nil, nil)
		pf.wantFail(t, "valid_for")
	})
	t.Run("issued_long_after_created_fails", func(t *testing.T) {
		pf := newProbeFixture(t)
		pf.addProbe(pf.key, false, func(p *probeIssue) { p.req.CreatedAt -= 400 }, nil, nil)
		pf.wantFail(t, "CreatedAt")
	})
	t.Run("lifetime_not_cap_fails", func(t *testing.T) {
		pf := newProbeFixture(t)
		pf.addProbe(pf.key, false, nil, nil, func(p *probeIssue) { p.lifetime-- })
		pf.wantFail(t, "certificate lives")
	})
	t.Run("wrong_ca_fails", func(t *testing.T) {
		t.Run("signed_by_another_key", func(t *testing.T) {
			pf := newProbeFixture(t)
			pf.addProbe(pf.key, false, nil, nil, func(p *probeIssue) { p.ca = pf.hostCA })
			pf.wantFail(t, "not by the active machine CA")
		})
		t.Run("key_id_names_another_ca", func(t *testing.T) {
			pf := newProbeFixture(t)
			pf.addProbe(pf.key, false, nil, nil, func(p *probeIssue) { p.keyID.CA = "host" })
			pf.wantFail(t, `key ID CA "host" differs`)
		})
	})
	t.Run("wrong_principal_fails", func(t *testing.T) {
		pf := newProbeFixture(t)
		pf.addProbe(pf.key, false, nil, nil, func(p *probeIssue) { p.principals = []string{"keyroster-probe:web3"} })
		pf.wantFail(t, "certificate principals")
	})
	t.Run("extension_fails", func(t *testing.T) {
		pf := newProbeFixture(t)
		pf.addProbe(pf.key, false, nil, nil, func(p *probeIssue) { p.extensions = map[string]string{"permit-pty": ""} })
		pf.wantFail(t, "extension")
	})
	t.Run("no_source_address_fails", func(t *testing.T) {
		pf := newProbeFixture(t)
		pf.addProbe(pf.key, false, nil, nil, func(p *probeIssue) { delete(p.options, "source-address") })
		pf.wantFail(t, "critical options")
	})
	t.Run("wrong_source_address_fails", func(t *testing.T) {
		pf := newProbeFixture(t)
		pf.addProbe(pf.key, false, nil, nil, func(p *probeIssue) { p.options["source-address"] = "127.0.0.0/8,::/0" })
		pf.wantFail(t, "critical options")
	})
	t.Run("wrong_force_command_fails", func(t *testing.T) {
		pf := newProbeFixture(t)
		pf.addProbe(pf.key, false, nil, nil, func(p *probeIssue) { p.options["force-command"] = "/bin/sh" })
		pf.wantFail(t, "critical options")
	})
	t.Run("extra_critical_option_fails", func(t *testing.T) {
		pf := newProbeFixture(t)
		pf.addProbe(pf.key, false, nil, nil, func(p *probeIssue) { p.options["verify-required"] = "" })
		pf.wantFail(t, "critical option")
	})
	t.Run("key_id_subject_fails", func(t *testing.T) {
		pf := newProbeFixture(t)
		pf.addProbe(pf.key, false, nil, nil, func(p *probeIssue) { p.keyID.Subject = "probe.web3" })
		pf.wantFail(t, "key ID sub=")
	})
	t.Run("key_id_request_fails", func(t *testing.T) {
		pf := newProbeFixture(t)
		pf.addProbe(pf.key, false, nil, nil, func(p *probeIssue) { p.keyID.Request = strings.Repeat("ab", 16) })
		pf.wantFail(t, "key ID req=")
	})
	t.Run("key_id_directory_fails", func(t *testing.T) {
		pf := newProbeFixture(t)
		pf.addProbe(pf.key, false, nil, nil, func(p *probeIssue) { p.keyID.Directory++ })
		pf.wantFail(t, "key ID dir=")
	})
	t.Run("serial_not_increasing_fails", func(t *testing.T) {
		pf := newProbeFixture(t)
		first := pf.addProbe(pf.key, false, nil, nil, nil)
		pf.addProbe(pf.key2, false, nil, nil, func(p *probeIssue) { p.serial = first.serial })
		pf.wantFail(t, "serials not strictly increasing")
	})
	t.Run("negative_flag_mismatch_fails", func(t *testing.T) {
		pf := newProbeFixture(t)
		pf.addProbe(pf.key, false, nil, nil, func(p *probeIssue) { p.bodyNegative = true })
		pf.wantFail(t, "negative flag")
	})
	probeBoundsCases(t)
}

// probeBoundsCases are TestVerifyProbeIssue's window, request-ID, recovery
// and pending cases (03-10, Task 2).
func probeBoundsCases(t *testing.T) {
	t.Run("no_adjacency_needed", func(t *testing.T) {
		pf := newProbeFixture(t)
		neg := pf.addProbe(pf.key, true, nil, nil, nil)
		pf.advance(time.Minute)
		pf.addProbe(pf.key, false, nil, nil, nil)
		pf.advance(time.Hour)
		pf.publishWith(neg)
		pf.wantPass(t)
	})
	t.Run("revoke_without_publish_still_fails", func(t *testing.T) {
		pf := newProbeFixture(t)
		c := pf.rev.issue()
		pf.rev.revoke(&wire.RevokeRequest{Target: wire.TargetSerial, CARole: wire.CARoleUser, Serial: c.Serial}, []tlog.RevokedEntry{serialEntry(c)}, nil)
		pf.addProbe(pf.key, true, nil, nil, nil)
		pf.wantFail(t, "is not followed by the krl_publish entry")
	})
	t.Run("recent_rederived", func(t *testing.T) {
		pf := newProbeFixture(t)
		pf.addProbe(pf.key, true, nil, nil, nil)
		pf.advance(time.Second)
		pf.addProbe(pf.key2, true, nil, nil, nil)
		pf.wantFail(t, "probe_cert_recent")
	})
	t.Run("recent_cap_change_both_ways", func(t *testing.T) {
		setCap := func(pf *probeFixture, secs uint64) {
			pf.installPolicy(func(p *trust.Policy) { p.CAProfiles[2].MaxTTLSeconds = secs })
		}
		pf := newProbeFixture(t)
		pf.addProbe(pf.key, false, nil, nil, nil)
		setCap(pf, 90)
		pf.advance(31 * time.Second)
		pf.addProbe(pf.key, false, nil, nil, nil)
		pf.wantPass(t)
		pf = newProbeFixture(t)
		setCap(pf, 90)
		pf.addProbe(pf.key, false, nil, nil, nil)
		setCap(pf, 86400)
		pf.advance(31 * time.Second)
		pf.addProbe(pf.key, false, nil, nil, nil)
		pf.wantFail(t, "probe_cert_recent")
	})
	t.Run("cap_seconds_rederived", func(t *testing.T) {
		pf := newProbeFixture(t)
		pf.addProbe(pf.key, false, nil, nil, func(p *probeIssue) { p.capSeconds-- })
		pf.wantFail(t, "entry records CapSeconds")
	})
	t.Run("request_id_replayed_across_kinds", func(t *testing.T) {
		withID := func(id [16]byte) func(*probeIssue) { return func(p *probeIssue) { p.req.RequestID = id } }
		hexID := func(id [16]byte) string { return hex.EncodeToString(id[:]) }
		t.Run("probe_reuses_issue", func(t *testing.T) {
			pf := newProbeFixture(t)
			id := [16]byte{1, 2, 3}
			pf.addIssueWithRequest(hexID(id))
			pf.addProbe(pf.key, false, withID(id), nil, nil)
			pf.wantFail(t, "replayed")
		})
		withRP := func(pf *probeFixture) {
			pf.installPolicy(func(p *trust.Policy) { p.WebAuthn = &trust.WebAuthnRP{RPID: auditRPID, Origins: []string{auditOrigin}} })
			pf.publish()
		}
		t.Run("probe_reuses_login", func(t *testing.T) {
			pf := newProbeFixture(t)
			withRP(pf)
			l := pf.addLogin(nil, nil)
			pf.addProbe(pf.key, false, withID(l.req.RequestID), nil, nil)
			pf.wantFail(t, "replayed")
		})
		t.Run("probe_reuses_host", func(t *testing.T) {
			pf := newProbeFixture(t)
			h := pf.addHost(pf.key, nil, nil, nil)
			pf.addProbe(pf.key, false, withID(h.req.RequestID), nil, nil)
			pf.wantFail(t, "replayed")
		})
		t.Run("probe_reuses_probe", func(t *testing.T) {
			pf := newProbeFixture(t)
			p := pf.addProbe(pf.key, false, nil, nil, nil)
			pf.addProbe(pf.key, true, withID(p.req.RequestID), nil, nil)
			pf.wantFail(t, "replayed")
		})
		t.Run("issue_reuses_probe", func(t *testing.T) {
			pf := newProbeFixture(t)
			p := pf.addProbe(pf.key, false, nil, nil, nil)
			pf.addIssueWithRequest(hexID(p.req.RequestID))
			pf.wantFail(t, "replayed")
		})
		t.Run("login_reuses_probe", func(t *testing.T) {
			pf := newProbeFixture(t)
			withRP(pf)
			p := pf.addProbe(pf.key, false, nil, nil, nil)
			pf.addLogin(func(l *login) { l.req.RequestID = p.req.RequestID }, nil)
			pf.wantFail(t, "replayed")
		})
		t.Run("host_reuses_probe", func(t *testing.T) {
			pf := newProbeFixture(t)
			p := pf.addProbe(pf.key, false, nil, nil, nil)
			pf.addHost(pf.key, func(h *hostIssue) { h.req.RequestID = p.req.RequestID }, nil, nil)
			pf.wantFail(t, "replayed")
		})
	})
	t.Run("recovery_lookup_sees_probe_certificate", func(t *testing.T) {
		pf := newProbeFixture(t)
		p := pf.addProbe(pf.key, false, nil, nil, nil)
		pf.advance(time.Minute)
		ca := p.cert.SignatureKey.Marshal()
		im := pf.rev.importKRL([]krl.Entry{{Kind: krl.EntrySerial, CAKey: ca, Serial: p.cert.Serial, ValidBefore: p.cert.ValidBefore}}, 1, pf.ops, auditInstallationID)
		pf.rev.recover([]wire.RecoveryImport{im}, nil, func(o *recoveryOpts) {
			o.entries = func(es []tlog.RevokedEntry) []tlog.RevokedEntry {
				for i := range es {
					if es[i].Serial == p.cert.Serial {
						es[i].ValidBeforeSeconds = p.cert.ValidBefore // what the log's probe leaf gives
					}
				}
				return es
			}
		})
		pf.rev.publish(nil)
		pf.wantPass(t)
	})
	t.Run("recovery_collects_probe_certificate", func(t *testing.T) {
		pf := newProbeFixture(t)
		p := pf.addProbe(pf.key, false, nil, nil, nil)
		from := uint64(0)
		rep, err := Verify(strings.NewReader(join(pf.lines())), Options{Pins: pf.pins(), Threshold: 1, CertificatesFrom: &from})
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, c := range rep.Certificates {
			found = found || (c.Kind == tlog.KindProbeIssue && bytes.Equal(c.Cert, p.cert.Marshal()))
		}
		if !found {
			t.Fatalf("Report.Certificates (%d) does not list the probe certificate", len(rep.Certificates))
		}
	})
	t.Run("pending_negatives_counted", func(t *testing.T) {
		pf := newProbeFixture(t)
		neg := pf.addProbe(pf.key, true, nil, nil, nil)
		pf.addProbe(pf.key, false, nil, nil, nil)
		if rep := pf.wantPass(t); rep.PendingNegativeProbes != 1 {
			t.Fatalf("PendingNegativeProbes = %d, want 1", rep.PendingNegativeProbes)
		}
		pf.publishWith(neg)
		if rep := pf.wantPass(t); rep.PendingNegativeProbes != 0 {
			t.Fatalf("PendingNegativeProbes after a publish = %d, want 0", rep.PendingNegativeProbes)
		}
	})
}

// TestExportProbeIssue: a probe_issue line names the certificate and the
// request, and every decoded field is bound to its leaf (03-10).
func TestExportProbeIssue(t *testing.T) {
	t.Run("export_fields_bound", func(t *testing.T) {
		pf := newProbeFixture(t)
		p := pf.addProbe(pf.key, true, nil, nil, nil)
		m := decoded(t, pf.leaves[len(pf.leaves)-1])
		for _, k := range []string{"kind", "serial", "negative", "policy_version", "directory_version", "cap_seconds", "key_id", "evidence_types",
			"host_name", "request_id", "created_at", "host_key_fingerprint", "probe_key_fingerprint", "principals", "valid_after", "valid_before",
			"ca_fingerprint", "ca_algorithm"} {
			if _, ok := m[k]; !ok {
				t.Errorf("the probe_issue line has no %q: %v", k, m)
			}
		}
		for _, k := range []string{"version", "bundle_version", "directory", "sigs"} {
			if _, ok := m[k]; ok {
				t.Errorf("the probe_issue line carries %q", k)
			}
		}
		if m["kind"] != "probe_issue" || m["negative"] != true || m["host_name"] != "web1" || m["key_id"] != p.cert.KeyId ||
			m["probe_key_fingerprint"] != ssh.FingerprintSHA256(p.probe.PublicKey()) || m["host_key_fingerprint"] != ssh.FingerprintSHA256(pf.key.PublicKey()) {
			t.Fatalf("the probe_issue line: %v", m)
		}
		pf.wantPass(t)
	})
	t.Run("tampered_field_fails_verify", func(t *testing.T) {
		pf := newProbeFixture(t)
		pf.addProbe(pf.key, true, nil, nil, nil)
		in := join(pf.lines())
		for _, mut := range [][2]string{
			{`"negative":true`, `"negative":false`},
			{`"host_name":"web1"`, `"host_name":"web3"`},
			{`"probe_key_fingerprint":"`, `"probe_key_fingerprint":"x`},
			{`"kind":"probe_issue",`, `"kind":"probe_issue","note":"x",`},
		} {
			if !strings.Contains(in, mut[0]) {
				t.Fatalf("the export holds no %s", mut[0])
			}
			if _, err := pf.verify(strings.Replace(in, mut[0], mut[1], 1), nil); err == nil || !strings.Contains(err.Error(), "probe_issue leaf") {
				t.Errorf("a probe_issue line with %s: %v, want it refused", mut[1], err)
			}
		}
	})
}
