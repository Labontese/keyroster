//go:build linux

package signer

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/certprofile"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/keystore"
	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/signerclient"
	"github.com/Labontese/keyroster/internal/signerdb"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// setMachineCap installs a successor policy with the machine cap
// capSeconds (and edit, when set) and restarts the signer on it, as
// setHostCap does for the host cap (03-10). The host cap stays 90 s.
func (e *hostEnv) setMachineCap(t *testing.T, capSeconds uint64, edit func(*trust.Policy)) {
	t.Helper()
	e.setHostCap(t, 90, func(p *trust.Policy) {
		for i := range p.CAProfiles {
			if p.CAProfiles[i].Role == trust.RoleMachine {
				p.CAProfiles[i].MaxTTLSeconds = capSeconds
			}
		}
		if edit != nil {
			edit(p)
		}
	})
}

// probeReq is a probe request for host name by host key key, with a fresh
// Ed25519 probe key, valid_for 0, a fresh request ID and created now on the
// env's clock, both evidence items signed under the probe namespace. It
// returns the probe key's signer too.
func (e *hostEnv) probeReq(key ssh.Signer, name string, negative bool) (*wire.ProbeIssueRequest, ssh.Signer) {
	e.t.Helper()
	_, probe := NewEd25519Key(e.t)
	install := e.fx.InstallationID
	if install == "" {
		install = testInstallationID
	}
	req := &wire.ProbeIssueRequest{InstallationID: install, HostName: name, HostKey: key.PublicKey().Marshal(),
		ProbeKey: probe.PublicKey().Marshal(), Negative: negative,
		CreatedAt: uint64(e.clock.Now().Unix())} //nolint:gosec // G115: after 1970
	if _, err := rand.Read(req.RequestID[:]); err != nil {
		e.t.Fatal(err)
	}
	return e.probeSign(req, key, probe, wire.ProbePoPNamespace, wire.ProbePoPNamespace), probe
}

// probeSign replaces req's evidence with host-pop/v1 by host under hostNS
// and probe-pop/v1 by probe under probeNS, over its signing bytes.
func (e *hostEnv) probeSign(req *wire.ProbeIssueRequest, host, probe ssh.Signer, hostNS, probeNS string) *wire.ProbeIssueRequest {
	e.t.Helper()
	hs, err := sshsig.Sign(rand.Reader, host, hostNS, req.SigningBytes())
	if err != nil {
		e.t.Fatal(err)
	}
	ps, err := sshsig.Sign(rand.Reader, probe, probeNS, req.SigningBytes())
	if err != nil {
		e.t.Fatal(err)
	}
	req.Evidence = []wire.Evidence{{Type: wire.EvidenceHostPoP, Blob: hs}, {Type: wire.EvidenceProbePoP, Blob: ps}}
	return req
}

// mustProbe requires req to be answered with a certificate and returns it.
// The clock moves on a millisecond first, so serials never wait for it.
func (e *hostEnv) mustProbe(req *wire.ProbeIssueRequest) (*ssh.Certificate, *wire.IssueResponse) {
	e.t.Helper()
	e.clock.set(e.clock.Now().Add(time.Millisecond))
	resp, er := e.s.probeIssueOrRefuse(context.Background(), Peer{UID: 1000}, req)
	if er != nil {
		e.t.Fatalf("ProbeIssue refused: %s", er.Message)
	}
	return parseIssued(e.t, resp.Cert), resp
}

// refusedProbe requires req to be refused with detail and wire code code.
func (e *hostEnv) refusedProbe(t *testing.T, req *wire.ProbeIssueRequest, detail string, code wire.ErrorCode) {
	t.Helper()
	e.clock.set(e.clock.Now().Add(time.Millisecond))
	resp, er := e.s.probeIssueOrRefuse(context.Background(), Peer{UID: 1000}, req)
	if er == nil {
		t.Fatalf("issued serial %d, want the refusal %s", resp.Serial, detail)
	}
	if er.Message != detail || er.Code != code {
		t.Fatalf("refused %s (%s), want %s (%s)", er.Message, er.Code, detail, code)
	}
}

// probeLeaves are the probe_issue leaves of the log with their indexes.
func (e *hostEnv) probeLeaves() ([]*tlog.ProbeIssueBody, []uint64) {
	e.t.Helper()
	var (
		out []*tlog.ProbeIssueBody
		idx []uint64
	)
	for _, l := range e.leavesOf() {
		if l.Kind != tlog.KindProbeIssue {
			continue
		}
		b, err := tlog.DecodeProbeIssueBody(l.Body)
		if err != nil {
			e.t.Fatal(err)
		}
		out, idx = append(out, b), append(idx, l.Index)
	}
	return out, idx
}

// revocationRows reads every revocation row.
func (e *hostEnv) revocationRows(t *testing.T) []signerdb.Revocation {
	t.Helper()
	var rows []signerdb.Revocation
	if err := e.db.WithTx(context.Background(), func(tx *sql.Tx) error {
		var err error
		rows, err = e.db.RevocationsTx(context.Background(), tx)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return rows
}

// permissiveMachine grants the machine profile everything a policy can:
// default and allowed extensions and both probe option names plus another.
func permissiveMachine(p *trust.Policy) {
	for i := range p.CAProfiles {
		if p.CAProfiles[i].Role == trust.RoleMachine {
			p.CAProfiles[i].DefaultExtensions = []string{"permit-X11-forwarding", "permit-pty", "permit-user-rc"}
			p.CAProfiles[i].AllowedExtensions = []string{"permit-agent-forwarding", "permit-port-forwarding"}
			p.CAProfiles[i].AllowedCriticalOptions = []string{"force-command", "source-address", "verify-required"}
		}
	}
}

func TestProbeProfile(t *testing.T) {
	pol := func(t *testing.T, edit func(*trust.Policy)) *trust.Policy {
		t.Helper()
		e := newHostEnv(t, 90)
		if edit != nil {
			e.setMachineCap(t, 86400, edit)
		}
		e.s.mu.Lock()
		defer e.s.mu.Unlock()
		return e.s.policy
	}
	t.Run("exact_fields", func(t *testing.T) {
		p := pol(t, nil)
		got, err := certprofile.ProbeProfile(p)
		if err != nil {
			t.Fatal(err)
		}
		m, err := certprofile.ForRole(trust.RoleMachine, p)
		if err != nil {
			t.Fatal(err)
		}
		if got.CertType != ssh.UserCert || got.MaxTTL != m.MaxTTL || len(got.DefaultExtensions) != 0 || len(got.AllowedExtensions) != 0 ||
			!slices.Equal(got.AllowedCriticalOptions, []string{"force-command", "source-address"}) {
			t.Fatalf("ProbeProfile = %+v (machine MaxTTL %s)", got, m.MaxTTL)
		}
		if certprofile.ProbeForceCommand != "/bin/false" || certprofile.ProbeSourceAddress != "127.0.0.0/8,::1/128" ||
			certprofile.MaxProbeLifetimeSeconds != 604800 {
			t.Fatal("the probe constants changed")
		}
		if !maps.Equal(certprofile.ProbeCriticalOptions(), map[string]string{"force-command": "/bin/false", "source-address": "127.0.0.0/8,::1/128"}) {
			t.Fatalf("ProbeCriticalOptions = %v", certprofile.ProbeCriticalOptions())
		}
	})
	t.Run("permissive_machine_profile_ignored", func(t *testing.T) {
		plain, err := certprofile.ProbeProfile(pol(t, func(*trust.Policy) {}))
		if err != nil {
			t.Fatal(err)
		}
		wide, err := certprofile.ProbeProfile(pol(t, permissiveMachine))
		if err != nil {
			t.Fatal(err)
		}
		m, err := certprofile.ForRole(trust.RoleMachine, pol(t, permissiveMachine))
		if err != nil {
			t.Fatal(err)
		}
		if len(m.DefaultExtensions) == 0 || len(m.AllowedExtensions) == 0 {
			t.Fatal("the permissive machine profile grants nothing; the test tests nothing")
		}
		if wide.CertType != plain.CertType || wide.MaxTTL != plain.MaxTTL || !maps.Equal(wide.DefaultExtensions, plain.DefaultExtensions) ||
			!slices.Equal(wide.AllowedExtensions, plain.AllowedExtensions) || !slices.Equal(wide.AllowedCriticalOptions, plain.AllowedCriticalOptions) {
			t.Fatalf("a permissive machine profile changed the probe profile: %+v, want %+v", wide, plain)
		}
	})
	t.Run("probe_lifetime", func(t *testing.T) {
		for _, c := range []struct{ cap, want uint64 }{{90, 90}, {172800, 172800}, {2592000, 604800}, {604800, 604800}} {
			p := cert.Profile{CertType: ssh.UserCert, MaxTTL: time.Duration(c.cap) * time.Second} //nolint:gosec // G115: test values
			if got := certprofile.ProbeLifetime(p); got != c.want {
				t.Errorf("ProbeLifetime(cap %d s) = %d, want %d", c.cap, got, c.want)
			}
		}
	})
}

func TestProbeIssue(t *testing.T) {
	refused := func(t *testing.T, edit func(e *hostEnv) *wire.ProbeIssueRequest, detail string, code wire.ErrorCode) {
		t.Helper()
		e := newHostEnv(t, 90)
		e.refusedProbe(t, edit(e), detail, code)
	}
	t.Run("issues_negative_and_positive_for_listed_key", func(t *testing.T) {
		e := newHostEnv(t, 90)
		negReq, _ := e.probeReq(e.ed, "web1", true)
		neg, _ := e.mustProbe(negReq)
		posReq, _ := e.probeReq(e.ec, "web1", false)
		pos, _ := e.mustProbe(posReq)
		for _, c := range []*ssh.Certificate{neg, pos} {
			if c.CertType != ssh.UserCert || !slices.Equal(c.ValidPrincipals, []string{"keyroster-probe:web1"}) ||
				!bytes.Equal(c.SignatureKey.Marshal(), e.fx.Roles[keystore.RoleMachine].PublicKey().Marshal()) {
				t.Fatalf("certificate %d: type %d, principals %v, not the machine CA's", c.Serial, c.CertType, c.ValidPrincipals)
			}
		}
		p := e.parsedKRL(t)
		if !p.RevokesSerial(neg.SignatureKey.Marshal(), neg.Serial) || p.RevokesSerial(pos.SignatureKey.Marshal(), pos.Serial) {
			t.Fatal("the published KRL does not revoke exactly the negative serial")
		}
		if rep := e.verifyExport(); rep.Counts[tlog.KindProbeIssue] != 2 {
			t.Fatalf("audit verify counts %d probe_issue entries, want 2", rep.Counts[tlog.KindProbeIssue])
		}
	})
	t.Run("over_socket_round_trip", func(t *testing.T) {
		e := newHostEnv(t, 90)
		req, _ := e.probeReq(e.ed, "web1", true)
		sock, _ := serveHostSigner(t, e)
		resp, err := signerclient.ProbeIssue(context.Background(), sock, req)
		if err != nil {
			t.Fatal(err)
		}
		c := parseIssued(t, resp.Cert)
		if c.Serial != resp.Serial || !slices.Equal(c.ValidPrincipals, []string{"keyroster-probe:web1"}) {
			t.Fatalf("over the socket: serial %d (answer %d), principals %v", c.Serial, resp.Serial, c.ValidPrincipals)
		}
		k, err := signerclient.GetKRL(context.Background(), sock)
		if err != nil {
			t.Fatal(err)
		}
		p, err := krl.Parse(k.KRL)
		if err != nil || !p.RevokesSerial(c.SignatureKey.Marshal(), c.Serial) {
			t.Fatalf("the served KRL does not list the negative serial (%v)", err)
		}
	})
	t.Run("no_installation_id", func(t *testing.T) {
		e := newHostEnvOpts(t, 90, "", true)
		r, _ := e.probeReq(e.ed, "web1", false)
		e.refusedProbe(t, r, "probe_issue_no_installation_id", wire.CodeRefused)
	})
	t.Run("installation_mismatch", func(t *testing.T) {
		e := newHostEnv(t, 90)
		r, probe := e.probeReq(e.ed, "web1", false)
		r.InstallationID = "fedcba9876543210fedcba9876543210"
		e.refusedProbe(t, e.probeSign(r, e.ed, probe, wire.ProbePoPNamespace, wire.ProbePoPNamespace), "probe_issue_installation_mismatch", wire.CodeRefused)
	})
	t.Run("pop_hosts_off", func(t *testing.T) {
		e := newHostEnvOpts(t, 90, testInstallationID, false)
		r, _ := e.probeReq(e.ed, "web1", false)
		e.refusedProbe(t, r, "host_pop_not_enabled", wire.CodeRefused)
	})
	t.Run("directory_not_installed", func(t *testing.T) {
		e := newHostEnvBare(t, 90)
		r, _ := e.probeReq(e.ed, "web1", false)
		e.refusedProbe(t, r, "directory_not_installed", wire.CodeRefused)
	})
	t.Run("directory_not_authorized", func(t *testing.T) {
		e := newHostEnv(t, 90)
		e.setMachineCap(t, 86400, func(p *trust.Policy) { p.AdminQuorum = 2 })
		r, _ := e.probeReq(e.ed, "web1", false)
		e.refusedProbe(t, r, "directory_not_authorized", wire.CodeRefused)
	})
	t.Run("unknown_host", func(t *testing.T) {
		refused(t, func(e *hostEnv) *wire.ProbeIssueRequest { r, _ := e.probeReq(e.ed, "web9", false); return r }, "unknown_host", wire.CodeRefused)
	})
	t.Run("host_key_not_listed", func(t *testing.T) {
		// The cross-host form: host B's name (web3, active, lists only
		// "other") with host A's listed key ed and a valid host-pop by ed.
		e := newHostEnv(t, 90)
		r, _ := e.probeReq(e.ed, "web3", true)
		e.refusedProbe(t, r, "host_key_not_listed", wire.CodeRefused)
		if rows := e.revocationRows(t); len(rows) != 0 {
			t.Fatalf("a refused negative wrote %d revocation rows", len(rows))
		}
	})
	t.Run("host_key_revoked", func(t *testing.T) {
		e := newHostEnv(t, 90)
		e.revokeHost(t, &wire.RevokeRequest{Target: wire.TargetKey, Key: e.off.PublicKey().Marshal()})
		r, _ := e.probeReq(e.off, "web2", false)
		e.refusedProbe(t, r, "host_key_revoked", wire.CodeRefused)
	})
	t.Run("host_disabled", func(t *testing.T) {
		refused(t, func(e *hostEnv) *wire.ProbeIssueRequest { r, _ := e.probeReq(e.off, "web2", false); return r }, "host_disabled", wire.CodeRefused)
	})
	t.Run("host_pop_invalid", func(t *testing.T) {
		for name, edit := range map[string]func(e *hostEnv, r *wire.ProbeIssueRequest, probe ssh.Signer) *wire.ProbeIssueRequest{
			"another_listed_key": func(e *hostEnv, r *wire.ProbeIssueRequest, probe ssh.Signer) *wire.ProbeIssueRequest {
				return e.probeSign(r, e.ec, probe, wire.ProbePoPNamespace, wire.ProbePoPNamespace)
			},
			"other_bytes": func(e *hostEnv, r *wire.ProbeIssueRequest, _ ssh.Signer) *wire.ProbeIssueRequest {
				sig, err := sshsigSign(e.ed, wire.ProbePoPNamespace, []byte("other bytes"))
				if err != nil {
					t.Fatal(err)
				}
				r.Evidence[0].Blob = sig
				return r
			},
		} {
			t.Run(name, func(t *testing.T) {
				refused(t, func(e *hostEnv) *wire.ProbeIssueRequest {
					r, probe := e.probeReq(e.ed, "web1", false)
					return edit(e, r, probe)
				}, "host_pop_invalid", wire.CodeRefused)
			})
		}
	})
	t.Run("host_pop_host_issue_namespace", func(t *testing.T) {
		refused(t, func(e *hostEnv) *wire.ProbeIssueRequest {
			r, probe := e.probeReq(e.ed, "web1", false)
			return e.probeSign(r, e.ed, probe, wire.HostPoPNamespace, wire.ProbePoPNamespace)
		}, "host_pop_invalid", wire.CodeRefused)
	})
	t.Run("probe_pop_invalid", func(t *testing.T) {
		for name, edit := range map[string]func(e *hostEnv, r *wire.ProbeIssueRequest, probe ssh.Signer) *wire.ProbeIssueRequest{
			"other_key": func(e *hostEnv, r *wire.ProbeIssueRequest, _ ssh.Signer) *wire.ProbeIssueRequest {
				_, other := NewEd25519Key(t)
				return e.probeSign(r, e.ed, other, wire.ProbePoPNamespace, wire.ProbePoPNamespace)
			},
			"other_bytes": func(_ *hostEnv, r *wire.ProbeIssueRequest, probe ssh.Signer) *wire.ProbeIssueRequest {
				sig, err := sshsigSign(probe, wire.ProbePoPNamespace, []byte("other bytes"))
				if err != nil {
					t.Fatal(err)
				}
				r.Evidence[1].Blob = sig
				return r
			},
			"host_issue_namespace": func(e *hostEnv, r *wire.ProbeIssueRequest, probe ssh.Signer) *wire.ProbeIssueRequest {
				return e.probeSign(r, e.ed, probe, wire.ProbePoPNamespace, wire.HostPoPNamespace)
			},
		} {
			t.Run(name, func(t *testing.T) {
				refused(t, func(e *hostEnv) *wire.ProbeIssueRequest {
					r, probe := e.probeReq(e.ed, "web1", false)
					return edit(e, r, probe)
				}, "probe_pop_invalid", wire.CodeRefused)
			})
		}
	})
	t.Run("evidence_order_and_types", func(t *testing.T) {
		for name, c := range map[string]struct {
			edit   func(r *wire.ProbeIssueRequest)
			detail string
		}{
			"swapped":         {func(r *wire.ProbeIssueRequest) { r.Evidence[0], r.Evidence[1] = r.Evidence[1], r.Evidence[0] }, "host_pop_invalid"},
			"both_host_pop":   {func(r *wire.ProbeIssueRequest) { r.Evidence[1].Type = wire.EvidenceHostPoP }, "probe_pop_invalid"},
			"both_probe_pop":  {func(r *wire.ProbeIssueRequest) { r.Evidence[0].Type = wire.EvidenceProbePoP }, "host_pop_invalid"},
			"admin_type":      {func(r *wire.ProbeIssueRequest) { r.Evidence[0].Type = wire.EvidenceAdminSSHSIG }, "host_pop_invalid"},
			"unknown_type_p2": {func(r *wire.ProbeIssueRequest) { r.Evidence[1].Type = "probe-pop/v2" }, "probe_pop_invalid"},
		} {
			t.Run(name, func(t *testing.T) {
				refused(t, func(e *hostEnv) *wire.ProbeIssueRequest {
					r, _ := e.probeReq(e.ed, "web1", false)
					c.edit(r)
					return r
				}, c.detail, wire.CodeRefused)
			})
		}
	})
	probeKeyRefused := func(t *testing.T, e *hostEnv, probe ssh.Signer) {
		t.Helper()
		r, _ := e.probeReq(e.ed, "web1", true)
		r.ProbeKey = probe.PublicKey().Marshal()
		e.refusedProbe(t, e.probeSign(r, e.ed, probe, wire.ProbePoPNamespace, wire.ProbePoPNamespace), "probe_key_unusable", wire.CodeRefused)
	}
	t.Run("probe_key_is_host_key", func(t *testing.T) {
		e := newHostEnv(t, 90)
		probeKeyRefused(t, e, e.ed)
	})
	t.Run("probe_key_installation_key", func(t *testing.T) {
		for _, role := range []keystore.Role{keystore.RoleMachine, keystore.RoleUser, keystore.RoleOps} {
			t.Run(string(role), func(t *testing.T) {
				e := newHostEnv(t, 90)
				probeKeyRefused(t, e, e.fx.Roles[role])
			})
		}
	})
	t.Run("probe_key_directory_key", func(t *testing.T) {
		t.Run("host_key_of_another_entry", func(t *testing.T) {
			e := newHostEnv(t, 90)
			probeKeyRefused(t, e, e.other)
		})
		t.Run("machine_key", func(t *testing.T) {
			e := newHostEnv(t, 90)
			_, m := NewEd25519Key(t)
			e.publishWithMachine(t, directory.Machine{Name: "ci", Key: trust.FormatKey(m.PublicKey()), Roles: []string{"ops"}, MaxTTLSeconds: 3600, Status: directory.StatusActive})
			probeKeyRefused(t, e, m)
		})
	})
	t.Run("valid_for_not_zero", func(t *testing.T) {
		for _, v := range []uint32{1, 90, 604800} {
			refused(t, func(e *hostEnv) *wire.ProbeIssueRequest {
				r, probe := e.probeReq(e.ed, "web1", false)
				r.ValidForSeconds = v
				return e.probeSign(r, e.ed, probe, wire.ProbePoPNamespace, wire.ProbePoPNamespace)
			}, "probe_issue_valid_for_not_zero", wire.CodeRefused)
		}
	})
	t.Run("request_time_skew", func(t *testing.T) {
		for _, d := range []int64{301, -301} {
			refused(t, func(e *hostEnv) *wire.ProbeIssueRequest {
				r, probe := e.probeReq(e.ed, "web1", false)
				r.CreatedAt = uint64(e.clock.Now().Unix() + d) //nolint:gosec // G115: after 1970
				return e.probeSign(r, e.ed, probe, wire.ProbePoPNamespace, wire.ProbePoPNamespace)
			}, "request_time_skew", wire.CodeRefused)
		}
	})
	t.Run("malformed_probe_key", func(t *testing.T) {
		for name, key := range map[string]func(e *hostEnv) []byte{
			"ecdsa":       func(*hostEnv) []byte { return newECDSAKey(t).PublicKey().Marshal() },
			"garbage":     func(*hostEnv) []byte { return []byte("garbage") },
			"certificate": func(e *hostEnv) []byte { return e.issueKR1(t, wire.CARoleMachine, "ci", 60).Marshal() },
		} {
			t.Run(name, func(t *testing.T) {
				e := newHostEnv(t, 90)
				r, _ := e.probeReq(e.ed, "web1", false)
				r.ProbeKey = key(e)
				e.refusedProbe(t, r, "malformed_request", wire.CodeMalformed)
			})
		}
	})
	t.Run("lifetime_min_cap_and_7d", func(t *testing.T) {
		for _, c := range []struct{ cap, want uint64 }{{90, 90}, {172800, 172800}, {2592000, 604800}} {
			e := newHostEnv(t, 90)
			e.setMachineCap(t, c.cap, nil)
			r, _ := e.probeReq(e.ed, "web1", false)
			got, _ := e.mustProbe(r)
			if life := got.ValidBefore - got.ValidAfter - 300; life != c.want {
				t.Errorf("cap %d s: lifetime %d s, want %d", c.cap, life, c.want)
			}
			bodies, _ := e.probeLeaves()
			if len(bodies) != 1 || bodies[0].CapSeconds != c.want {
				t.Errorf("cap %d s: the leaf's CapSeconds is not %d", c.cap, c.want)
			}
		}
	})
	t.Run("cert_exact_restrictions_under_permissive_machine_profile", func(t *testing.T) {
		e := newHostEnv(t, 90)
		e.setMachineCap(t, 86400, permissiveMachine)
		r, _ := e.probeReq(e.ed, "web1", true)
		c, resp := e.mustProbe(r)
		if len(c.Extensions) != 0 {
			t.Fatalf("extensions %v, want none", c.Extensions)
		}
		if !maps.Equal(c.CriticalOptions, map[string]string{"force-command": "/bin/false", "source-address": "127.0.0.0/8,::1/128"}) {
			t.Fatalf("critical options %v", c.CriticalOptions)
		}
		if !slices.Equal(c.ValidPrincipals, []string{"keyroster-probe:web1"}) {
			t.Fatalf("principals %v", c.ValidPrincipals)
		}
		kid, err := cert.ParseKeyID(c.KeyId)
		if err != nil {
			t.Fatal(err)
		}
		if !kid.V3 || kid.CA != "machine" || kid.Subject != "probe.web1" || kid.Serial != resp.Serial || kid.Request != hexID(r.RequestID) ||
			kid.Directory != 1 || kid.Policy == 0 || strings.Contains(c.KeyId, "neg") {
			t.Fatalf("key ID %q", c.KeyId)
		}
	})
	t.Run("negative_row_matches_entry", func(t *testing.T) {
		e := newHostEnv(t, 90)
		r, _ := e.probeReq(e.ed, "web1", true)
		c, resp := e.mustProbe(r)
		bodies, idx := e.probeLeaves()
		if len(bodies) != 1 {
			t.Fatalf("%d probe leaves", len(bodies))
		}
		entries, err := bodies[0].RevokedEntries()
		if err != nil || len(entries) != 1 {
			t.Fatalf("RevokedEntries = %v, %v", entries, err)
		}
		rows := e.revocationRows(t)
		if len(rows) != 1 {
			t.Fatalf("%d revocation rows, want 1", len(rows))
		}
		row, en := rows[0], entries[0]
		if row.Kind != signerdb.RevocationSerial || !bytes.Equal(row.CAKey, en.CAKey) || row.Serial != en.Serial ||
			row.ValidBeforeMicros != en.ValidBeforeSeconds*1_000_000 || row.RequestID != r.RequestID || row.LeafIndex != idx[0] ||
			row.LeafIndex != resp.LeafIndex || row.KeyID != "" || len(row.Key) != 0 {
			t.Fatalf("row %+v does not match the entry %+v (leaf %d)", row, en, idx[0])
		}
		if !bytes.Equal(en.CAKey, e.fx.Roles[keystore.RoleMachine].PublicKey().Marshal()) || en.Serial != c.Serial || en.ValidBeforeSeconds != c.ValidBefore {
			t.Fatalf("the entry is not the certificate's own serial under the machine CA: %+v", en)
		}
	})
	t.Run("positive_writes_no_row", func(t *testing.T) {
		e := newHostEnv(t, 90)
		before := e.leafCount(tlog.KindKRLPublish)
		r, _ := e.probeReq(e.ed, "web1", false)
		e.mustProbe(r)
		if rows := e.revocationRows(t); len(rows) != 0 {
			t.Fatalf("a positive probe wrote %d revocation rows", len(rows))
		}
		if e.leafCount(tlog.KindKRLPublish) != before {
			t.Fatal("a positive probe published a KRL")
		}
	})
	t.Run("negative_publishes_at_once", func(t *testing.T) {
		e := newHostEnv(t, 90)
		r, _ := e.probeReq(e.ed, "web1", true)
		c, resp := e.mustProbe(r)
		leaves := e.leavesOf()
		if resp.LeafIndex+1 >= uint64(len(leaves)) || leaves[resp.LeafIndex+1].Kind != tlog.KindKRLPublish {
			t.Fatal("no krl_publish leaf follows the negative probe_issue leaf")
		}
		if !e.parsedKRL(t).RevokesSerial(c.SignatureKey.Marshal(), c.Serial) {
			t.Fatal("the published KRL does not list the negative serial")
		}
	})
	t.Run("leaf_fields", func(t *testing.T) {
		e := newHostEnv(t, 90)
		reqs := []*wire.ProbeIssueRequest{}
		for _, neg := range []bool{true, false} {
			r, _ := e.probeReq(e.ed, "web1", neg)
			e.mustProbe(r)
			reqs = append(reqs, r)
		}
		bodies, _ := e.probeLeaves()
		if len(bodies) != 2 {
			t.Fatalf("%d probe leaves", len(bodies))
		}
		for i, b := range bodies {
			r := reqs[i]
			if b.Negative != r.Negative || b.CapSeconds != 86400 || !bytes.Equal(b.Request, r.SigningBytes()) ||
				len(b.Evidence) != 2 || b.Evidence[0].Type != wire.EvidenceHostPoP || b.Evidence[1].Type != wire.EvidenceProbePoP ||
				!bytes.Equal(b.Evidence[0].Blob, r.Evidence[0].Blob) || !bytes.Equal(b.Evidence[1].Blob, r.Evidence[1].Blob) ||
				b.DirectoryVersion != 1 {
				t.Fatalf("leaf %d: negative %t (want %t), cap %d, evidence %d", i, b.Negative, r.Negative, b.CapSeconds, len(b.Evidence))
			}
		}
	})
}

// publishWithMachine installs the next directory version with e.hosts and
// machine m (03-10).
func (e *hostEnv) publishWithMachine(t *testing.T, m directory.Machine) {
	t.Helper()
	prev := trust.SHA256Hex(e.docs[len(e.docs)-1])
	hosts := slices.Clone(e.hosts)
	for i := range hosts {
		hosts[i].Keys = slices.Sorted(slices.Values(hosts[i].Keys))
	}
	d := &directory.Directory{
		Version: uint64(len(e.docs) + 1), Prev: prev, InstallationID: e.fx.InstallationID,
		Roles:      []directory.Role{{Name: "ops", Principals: loginPrincipals, MaxTTLSeconds: 3600}},
		HostGroups: []directory.HostGroup{{Name: "lab", Accounts: []directory.AccountMap{{Account: "root", Roles: []string{"ops"}}}}},
		Hosts:      hosts,
		Machines:   []directory.Machine{m},
	}
	d.Sort()
	doc, sigs := signDirectory(t, d, e.fx.Admins[0])
	e.installDirectory(t, doc, sigs)
	e.docs = append(e.docs, doc)
}

// hexID is a request ID in the key ID's form.
func hexID(id [16]byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 32)
	for _, b := range id {
		out = append(out, digits[b>>4], digits[b&15])
	}
	return string(out)
}

func TestProbeLog(t *testing.T) {
	t.Run("restart_after_negative_ok", func(t *testing.T) {
		e := newHostEnv(t, 90)
		r, _ := e.probeReq(e.ed, "web1", true)
		e.mustProbe(r)
		e.restart(t)
		rows := e.revocationRows(t)
		e.s.mu.Lock()
		err := e.s.loaded.revoked.check(rows)
		e.s.mu.Unlock()
		if err != nil || len(rows) != 1 {
			t.Fatalf("after the restart the logged set does not hold the %d negative rows: %v", len(rows), err)
		}
		// A second negative after the restart publishes against the rebuilt set.
		r2, _ := e.probeReq(e.ec, "web1", true)
		e.mustProbe(r2)
	})
	t.Run("doctor_after_negative_ok", func(t *testing.T) {
		e := newHostEnv(t, 90)
		r, _ := e.probeReq(e.ed, "web1", true)
		e.mustProbe(r)
		ctx := context.Background()
		if err := CheckTrust(ctx, e.db); err != nil {
			t.Fatalf("CheckTrust: %v", err)
		}
		if err := CheckLog(ctx, e.db, e.fx.Roles[keystore.RoleLog].PublicKey()); err != nil {
			t.Fatalf("CheckLog: %v", err)
		}
	})
	t.Run("issued_counts_probe_leaf", func(t *testing.T) {
		e := newHostEnv(t, 90)
		var last uint64
		for _, neg := range []bool{false, true} {
			r, _ := e.probeReq(e.ed, "web1", neg)
			c, _ := e.mustProbe(r)
			last = c.Serial
		}
		_, issued, high := e.counts()
		if issued != 2 || high != last {
			t.Fatalf("%d issuance rows, serial high-water mark %d; want 2 and %d", issued, high, last)
		}
		e.s.mu.Lock()
		v := e.s.cpVerifier
		e.s.mu.Unlock()
		if _, _, _, err := rebuildLogFrom(context.Background(), e.db, v); err != nil {
			t.Fatalf("the log rebuild refuses the probe leaves: %v", err)
		}
	})
}
