//go:build linux

package signer

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
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
	probeIssueBoundsCases(t)
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
		// A second negative after the restart, for another host, publishes
		// against the rebuilt set.
		r2, _ := e.probeReq(e.other, "web3", true)
		e.mustProbe(r2)
	})
	t.Run("restart_keeps_window", func(t *testing.T) {
		e := newHostEnv(t, 90)
		r, _ := e.probeReq(e.ed, "web1", true)
		e.mustProbe(r)
		e.restart(t)
		e.tick(time.Second)
		again, _ := e.probeReq(e.ed, "web1", true)
		e.refusedProbe(t, again, "probe_cert_recent", wire.CodeRefused)
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

// addActiveHosts appends n active hosts h01.. to e.hosts, each with a fresh
// Ed25519 key, installs the directory and returns the keys by name (03-10).
func (e *hostEnv) addActiveHosts(t *testing.T, n int) map[string]ssh.Signer {
	t.Helper()
	keys := map[string]ssh.Signer{}
	for i := 1; i <= n; i++ {
		name := fmt.Sprintf("h%02d", i)
		_, k := NewEd25519Key(t)
		keys[name] = k
		e.hosts = append(e.hosts, directory.Host{Name: name, HostGroup: "lab", Keys: []string{trust.FormatKey(k.PublicKey())},
			Principals: []string{name}, Status: directory.StatusActive})
	}
	e.publish(t)
	return keys
}

// liveProbes is a copy of the signer's committed probe index.
func liveProbes(e *hostEnv) probeIndex {
	e.s.mu.Lock()
	defer e.s.mu.Unlock()
	return e.s.loaded.probes.clone()
}

// promptState is the signer's prompt flag and last probe-caused publish.
func promptState(e *hostEnv) (bool, time.Time) {
	e.s.mu.Lock()
	defer e.s.mu.Unlock()
	return e.s.probePrompt, e.s.lastProbePublish
}

// publishedAfter reports whether the leaf right after idx is a krl_publish
// leaf.
func (e *hostEnv) publishedAfter(t *testing.T, idx uint64) bool {
	t.Helper()
	leaves := e.leavesOf()
	return idx+1 < uint64(len(leaves)) && leaves[idx+1].Kind == tlog.KindKRLPublish
}

// probeTimes are the leaf times (µs) of the krl_publish leaves after the
// first probe_issue leaf: the probe-caused and later publishes.
func (e *hostEnv) publishTimesAfterFirstProbe(t *testing.T) []uint64 {
	t.Helper()
	var out []uint64
	seen := false
	for _, l := range e.leavesOf() {
		seen = seen || l.Kind == tlog.KindProbeIssue
		if seen && l.Kind == tlog.KindKRLPublish {
			out = append(out, l.TimeMicros)
		}
	}
	return out
}

func sameProbeIndex(a, b probeIndex) bool {
	if a.lastPublish != b.lastPublish || a.havePublish != b.havePublish || len(a.byHost) != len(b.byHost) {
		return false
	}
	for k, x := range a.byHost {
		y, ok := b.byHost[k]
		if !ok || x.serial != y.serial || x.leaf != y.leaf || x.issued != y.issued || x.capSeconds != y.capSeconds ||
			x.reqSHA256 != y.reqSHA256 || x.negative != y.negative || !bytes.Equal(x.certBytes, y.certBytes) {
			return false
		}
	}
	return true
}

func rebuiltProbes(t *testing.T, e *hostEnv) probeIndex {
	t.Helper()
	e.s.mu.Lock()
	v := e.s.cpVerifier
	e.s.mu.Unlock()
	_, _, installs, err := rebuildLogFrom(context.Background(), e.db, v)
	if err != nil {
		t.Fatal(err)
	}
	return installs.probes.clone()
}

func TestProbeCertRecent(t *testing.T) {
	t.Run("boundary", func(t *testing.T) {
		for _, c := range []struct {
			lifetime, at uint64
			want         string
		}{{90, 29, "probe_cert_recent"}, {90, 30, ""}, {86400, 3599, "probe_cert_recent"}, {86400, 3600, ""}} {
			if got := certprofile.ProbeCertRecent(1_000_000, c.lifetime, 1_000_000+c.at); got != c.want {
				t.Errorf("lifetime %d, +%d s: %q, want %q", c.lifetime, c.at, got, c.want)
			}
		}
	})
	t.Run("window_table", func(t *testing.T) {
		for _, l := range []uint64{1, 2, 3, 89, 90, 91, 3600, 10799, 10800, 10801, 86400, 604800, 2592000} {
			w := min(3600, l/3)
			if w > 0 && certprofile.ProbeCertRecent(500, l, 500+w-1) != "probe_cert_recent" {
				t.Errorf("lifetime %d: +%d s is not inside the window %d", l, w-1, w)
			}
			if certprofile.ProbeCertRecent(500, l, 500+w) != "" {
				t.Errorf("lifetime %d: +%d s is inside the window %d", l, w, w)
			}
		}
	})
}

func TestProbeIndex(t *testing.T) {
	t.Run("rebuild_matches_incremental", func(t *testing.T) {
		e := newHostEnv(t, 90)
		for _, c := range []struct {
			key  ssh.Signer
			host string
			neg  bool
		}{{e.ed, "web1", true}, {e.ed, "web1", false}, {e.other, "web3", true}} {
			r, _ := e.probeReq(c.key, c.host, c.neg)
			e.mustProbe(r)
		}
		e.tick(61 * time.Second)
		e.s.republishIfDue(context.Background())
		if live, rebuilt := liveProbes(e), rebuiltProbes(t, e); !sameProbeIndex(live, rebuilt) || len(live.byHost) != 3 {
			t.Fatalf("the incremental index (%d entries) differs from the rebuilt one (%d)", len(live.byHost), len(rebuilt.byHost))
		}
	})
	t.Run("published_flag_follows_krl_publish_leaf", func(t *testing.T) {
		e := newHostEnv(t, 90)
		r1, _ := e.probeReq(e.ed, "web1", true)
		_, a := e.mustProbe(r1)
		e.tick(10 * time.Second)
		r3, _ := e.probeReq(e.other, "web3", true)
		_, b := e.mustProbe(r3) // coalesced: no publish follows it
		p := liveProbes(e)
		if !p.published(a.LeafIndex) || p.published(b.LeafIndex) || !p.hasUnpublishedNegative() {
			t.Fatalf("published(%d) = %t (want true), published(%d) = %t (want false)", a.LeafIndex, p.published(a.LeafIndex), b.LeafIndex, p.published(b.LeafIndex))
		}
		e.tick(51 * time.Second)
		if !e.s.republishIfDue(context.Background()) {
			t.Fatal("the flagged tick did not publish")
		}
		if p := liveProbes(e); !p.published(b.LeafIndex) || p.hasUnpublishedNegative() {
			t.Fatal("the krl_publish leaf after it does not mark web3's negative published")
		}
	})
	t.Run("pending_copy_discarded_on_failed_commit", func(t *testing.T) {
		e := newHostEnv(t, 90)
		before := liveProbes(e)
		if err := e.db.WithTx(context.Background(), func(tx *sql.Tx) error {
			_, err := tx.Exec(`CREATE TRIGGER fail_revocation BEFORE INSERT ON revocation BEGIN SELECT RAISE(ABORT, 'injected'); END`)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		r, _ := e.probeReq(e.ed, "web1", true)
		e.clock.set(e.clock.Now().Add(time.Millisecond))
		if _, er := e.s.probeIssueOrRefuse(context.Background(), Peer{UID: 1000}, r); er == nil {
			t.Fatal("the negative issuance committed despite the failing revocation insert")
		}
		if after := liveProbes(e); !sameProbeIndex(before, after) {
			t.Fatal("a failed transaction changed the probe index")
		}
		e.s.mu.Lock()
		pending := e.s.pendingProbes
		e.s.mu.Unlock()
		if pending != nil {
			t.Fatal("the pending probe index survived the failed transaction")
		}
	})
}

// probeIssueBoundsCases are TestProbeIssue's issuance bounds, re-delivery
// and publish rule cases (03-10, Task 2).
func probeIssueBoundsCases(t *testing.T) {
	ctx := context.Background()
	t.Run("cert_recent_per_polarity", func(t *testing.T) {
		e := newHostEnv(t, 90)
		r, _ := e.probeReq(e.ed, "web1", true)
		e.mustProbe(r)
		e.tick(time.Second)
		again, _ := e.probeReq(e.ed, "web1", true)
		e.refusedProbe(t, again, "probe_cert_recent", wire.CodeRefused)
		pos, _ := e.probeReq(e.ed, "web1", false)
		e.mustProbe(pos)
		other, _ := e.probeReq(e.other, "web3", true)
		e.mustProbe(other)
	})
	t.Run("cert_recent_window_from_new_lifetime", func(t *testing.T) {
		// A first certificate under a 1 d cap, the cap lowered to 90 s: the
		// window is 30 s, so +31 s is allowed (the old certificate's 3600 s
		// window would refuse it).
		e := newHostEnv(t, 90)
		r, _ := e.probeReq(e.ed, "web1", false)
		c1, _ := e.mustProbe(r)
		e.setMachineCap(t, 90, nil)
		e.tickTo(issuedSecs(c1) + 31)
		r2, _ := e.probeReq(e.ed, "web1", false)
		if c2, _ := e.mustProbe(r2); c2.ValidBefore-c2.ValidAfter-300 != 90 {
			t.Fatal("the renewal after the lowering is not a 90 s certificate")
		}
		// A first under 90 s, the cap raised to 1 d: the window is 3600 s,
		// so +31 s is refused (the old 30 s window would allow it).
		e = newHostEnv(t, 90)
		e.setMachineCap(t, 90, nil)
		r, _ = e.probeReq(e.ed, "web1", false)
		c1, _ = e.mustProbe(r)
		e.setMachineCap(t, 86400, nil)
		e.tickTo(issuedSecs(c1) + 31)
		r2, _ = e.probeReq(e.ed, "web1", false)
		e.refusedProbe(t, r2, "probe_cert_recent", wire.CodeRefused)
		// No change: 90 s gives a 30 s window, 1 d gives 3600 s.
		for _, c := range []struct {
			cap, inside, outside uint64
		}{{90, 29, 31}, {86400, 3599, 3600}} {
			e = newHostEnv(t, 90)
			e.setMachineCap(t, c.cap, nil)
			r, _ = e.probeReq(e.ed, "web1", false)
			c1, _ = e.mustProbe(r)
			e.tickTo(issuedSecs(c1) + c.inside)
			r2, _ = e.probeReq(e.ed, "web1", false)
			e.refusedProbe(t, r2, "probe_cert_recent", wire.CodeRefused)
			e.tickTo(issuedSecs(c1) + c.outside)
			r3, _ := e.probeReq(e.ed, "web1", false)
			e.mustProbe(r3)
		}
	})
	t.Run("exact_retry_redelivers_no_leaf", func(t *testing.T) {
		e := newHostEnv(t, 90)
		r, _ := e.probeReq(e.ed, "web1", true)
		c1, resp1 := e.mustProbe(r)
		leaves, issued, last := e.counts()
		rows, before := len(e.revocationRows(t)), liveProbes(e)
		c2, resp2 := e.mustProbe(r)
		l2, i2, last2 := e.counts()
		if !bytes.Equal(c1.Marshal(), c2.Marshal()) || resp1.LeafIndex != resp2.LeafIndex || l2 != leaves || i2 != issued || last2 != last ||
			len(e.revocationRows(t)) != rows || !sameProbeIndex(before, liveProbes(e)) {
			t.Fatalf("the exact retry: same certificate %t, leaves %d -> %d, issued %d -> %d, serial %d -> %d", bytes.Equal(c1.Marshal(), c2.Marshal()), leaves, l2, issued, i2, last, last2)
		}
	})
	t.Run("retry_with_other_bytes_is_duplicate", func(t *testing.T) {
		e := newHostEnv(t, 90)
		r, probe := e.probeReq(e.ed, "web1", false)
		e.mustProbe(r)
		r2 := *r
		r2.CreatedAt++
		e.refusedProbe(t, e.probeSign(&r2, e.ed, probe, wire.ProbePoPNamespace, wire.ProbePoPNamespace), "duplicate_request", wire.CodeRefused)
	})
	t.Run("older_request_after_newer_is_duplicate", func(t *testing.T) {
		e := newHostEnv(t, 90)
		e.setMachineCap(t, 90, nil)
		r1, _ := e.probeReq(e.ed, "web1", false)
		c1, _ := e.mustProbe(r1)
		e.tickTo(issuedSecs(c1) + 31)
		r2, _ := e.probeReq(e.ed, "web1", false)
		e.mustProbe(r2)
		e.refusedProbe(t, r1, "duplicate_request", wire.CodeRefused)
	})
	t.Run("expired_latest_not_redelivered", func(t *testing.T) {
		e := newHostEnv(t, 90)
		e.setMachineCap(t, 90, nil)
		r, _ := e.probeReq(e.ed, "web1", false)
		c, _ := e.mustProbe(r)
		e.tickTo(c.ValidBefore)
		e.refusedProbe(t, r, "duplicate_request", wire.CodeRefused)
	})
	t.Run("first_negative_publishes_at_once", func(t *testing.T) {
		e := newHostEnv(t, 90)
		r, _ := e.probeReq(e.ed, "web1", true)
		c, resp := e.mustProbe(r)
		if !e.publishedAfter(t, resp.LeafIndex) || !e.parsedKRL(t).RevokesSerial(c.SignatureKey.Marshal(), c.Serial) {
			t.Fatal("the first negative of a host was not published at once")
		}
	})
	renewal := func(t *testing.T) (*hostEnv, *ssh.Certificate) {
		t.Helper()
		e := newHostEnv(t, 90)
		r, _ := e.probeReq(e.ed, "web1", true)
		c1, _ := e.mustProbe(r)
		e.tickTo(issuedSecs(c1) + 16*3600)
		r2, _ := e.probeReq(e.ed, "web1", true)
		c2, resp := e.mustProbe(r2)
		if e.publishedAfter(t, resp.LeafIndex) {
			t.Fatal("a renewal whose published predecessor lives 8 h more published at once")
		}
		return e, c2
	}
	t.Run("renewal_rides_scheduled_publish", func(t *testing.T) {
		e, c2 := renewal(t)
		if e.parsedKRL(t).RevokesSerial(c2.SignatureKey.Marshal(), c2.Serial) {
			t.Fatal("the served KRL lists the riding serial before any publish")
		}
		if prompt, _ := promptState(e); prompt {
			t.Fatal("a riding row set the prompt flag")
		}
	})
	t.Run("scheduled_publish_lists_negative", func(t *testing.T) {
		e, c2 := renewal(t)
		e.tick(time.Hour)
		if !e.s.republishIfDue(ctx) || !e.parsedKRL(t).RevokesSerial(c2.SignatureKey.Marshal(), c2.Serial) {
			t.Fatal("the hourly republish does not list the riding negative serial")
		}
	})
	t.Run("unpublished_predecessor_publishes_now", func(t *testing.T) {
		e := newHostEnv(t, 90)
		r1, _ := e.probeReq(e.ed, "web1", true)
		e.mustProbe(r1)
		e.tick(10 * time.Second)
		r3, _ := e.probeReq(e.other, "web3", true)
		c3, resp3 := e.mustProbe(r3) // coalesced, unpublished
		if e.publishedAfter(t, resp3.LeafIndex) {
			t.Fatal("setup: web3's first negative published although the last probe publish is 10 s old")
		}
		e.tickTo(issuedSecs(c3) + 3601)
		r4, _ := e.probeReq(e.other, "web3", true)
		c4, resp4 := e.mustProbe(r4)
		if !e.publishedAfter(t, resp4.LeafIndex) || !e.parsedKRL(t).RevokesSerial(c4.SignatureKey.Marshal(), c4.Serial) {
			t.Fatal("a renewal whose predecessor is unpublished did not publish at once")
		}
	})
	t.Run("predecessor_expiring_publishes_now", func(t *testing.T) {
		e := newHostEnv(t, 90)
		r, _ := e.probeReq(e.ed, "web1", true)
		c1, _ := e.mustProbe(r)
		e.tickTo(c1.ValidBefore - (2*3600 - 60)) // published, 1 h 59 min left
		r2, _ := e.probeReq(e.ed, "web1", true)
		if _, resp := e.mustProbe(r2); !e.publishedAfter(t, resp.LeafIndex) {
			t.Fatal("a renewal whose predecessor has 1 h 59 min left did not publish at once")
		}
	})
	t.Run("short_cap_publishes_each_renewal_once_per_minute", func(t *testing.T) {
		e := newHostEnv(t, 90)
		e.setMachineCap(t, 3*3600, nil)
		r, _ := e.probeReq(e.ed, "web1", true)
		c1, _ := e.mustProbe(r)
		e.tickTo(issuedSecs(c1) + 2*3600) // after the window; 1 h left
		r2, _ := e.probeReq(e.ed, "web1", true)
		if _, resp := e.mustProbe(r2); !e.publishedAfter(t, resp.LeafIndex) {
			t.Fatal("the renewal under a 3 h cap with 1 h left did not publish at once")
		}
		e.tick(20 * time.Second)
		r3, _ := e.probeReq(e.other, "web3", true)
		if _, resp := e.mustProbe(r3); e.publishedAfter(t, resp.LeafIndex) {
			t.Fatal("a second negative inside the minute published at once")
		}
		if prompt, _ := promptState(e); !prompt {
			t.Fatal("the second negative inside the minute did not set the prompt flag")
		}
	})
	t.Run("coalesced_publishes_at_most_one_per_minute", func(t *testing.T) {
		e := newHostEnv(t, 90)
		keys := e.addActiveHosts(t, 10)
		e.setMachineCap(t, 3*3600, nil)
		r, _ := e.probeReq(e.ed, "web1", true)
		_, resp := e.mustProbe(r)
		if !e.publishedAfter(t, resp.LeafIndex) {
			t.Fatal("setup: the first negative did not publish")
		}
		t0 := e.clock.Now()
		e.clock.set(t0.Add(10 * time.Second))
		r3, _ := e.probeReq(e.other, "web3", true)
		if _, resp := e.mustProbe(r3); e.publishedAfter(t, resp.LeafIndex) {
			t.Fatal("a negative 10 s after an immediate publish published at once")
		}
		e.clock.set(t0.Add(50 * time.Second))
		if e.s.republishIfDue(ctx) {
			t.Fatal("the tick 50 s after the immediate publish published")
		}
		if prompt, _ := promptState(e); !prompt {
			t.Fatal("the early tick cleared the prompt flag")
		}
		e.clock.set(t0.Add(61 * time.Second))
		if !e.s.republishIfDue(ctx) {
			t.Fatal("the tick 61 s after the immediate publish did not publish")
		}
		if prompt, _ := promptState(e); prompt {
			t.Fatal("the flagged publish did not clear the prompt flag")
		}
		// Ten negatives 5 s apart, each for its own host, with a tick every
		// minute.
		start := t0.Add(130 * time.Second)
		lastTick := start
		for i := 0; i < 10; i++ {
			now := start.Add(time.Duration(5*i) * time.Second)
			if now.Sub(lastTick) >= time.Minute {
				e.clock.set(now)
				e.s.republishIfDue(ctx)
				lastTick = now
			}
			e.clock.set(now)
			name := fmt.Sprintf("h%02d", i+1)
			rq, _ := e.probeReq(keys[name], name, true)
			e.mustProbe(rq)
		}
		for m := 1; m <= 2; m++ {
			e.clock.set(lastTick.Add(time.Duration(m) * time.Minute))
			e.s.republishIfDue(ctx)
		}
		times := e.publishTimesAfterFirstProbe(t)
		for i := 1; i < len(times); i++ {
			if d := times[i] - times[i-1]; d < 60_000_000 {
				t.Fatalf("two probe-caused KRL versions %d µs apart (leaf times %v)", d, times)
			}
		}
		if len(times) < 4 {
			t.Fatalf("only %d publishes after the first probe; the test exercised nothing", len(times))
		}
	})
	t.Run("flag_published_at_next_tick", func(t *testing.T) {
		e := newHostEnv(t, 90)
		r, _ := e.probeReq(e.ed, "web1", true)
		e.mustProbe(r)
		t0 := e.clock.Now()
		e.clock.set(t0.Add(10 * time.Second))
		r3, _ := e.probeReq(e.other, "web3", true)
		c3, _ := e.mustProbe(r3)
		e.clock.set(t0.Add(61 * time.Second))
		if !e.s.republishIfDue(ctx) || !e.parsedKRL(t).RevokesSerial(c3.SignatureKey.Marshal(), c3.Serial) {
			t.Fatal("the flagged tick a minute later did not publish the waiting negative serial")
		}
	})
	t.Run("flag_moot_after_other_publish", func(t *testing.T) {
		e := newHostEnv(t, 90)
		r, _ := e.probeReq(e.ed, "web1", true)
		e.mustProbe(r)
		t0 := e.clock.Now()
		e.clock.set(t0.Add(10 * time.Second))
		r3, _ := e.probeReq(e.other, "web3", true)
		e.mustProbe(r3)
		e.clock.set(t0.Add(20 * time.Second))
		e.revokeHost(t, &wire.RevokeRequest{Target: wire.TargetKey, Key: e.off.PublicKey().Marshal()})
		e.clock.set(t0.Add(70 * time.Second))
		if e.s.republishIfDue(ctx) {
			t.Fatal("the tick after an admin publish published again for a moot prompt flag")
		}
	})
	// Pre-merge review of PR #90: a publish the flag did not cause still
	// carries every waiting negative row (each publish encodes the whole
	// table), so it clears the flag. A stale flag would publish the next
	// riding row before the hourly republish.
	t.Run("flag_cleared_by_carrying_publish", func(t *testing.T) {
		// The carrying publish is at t0+3671 s, a minute after the last
		// probe publish, or at t0+7202 s (over an hour after it) for the hourly
		// republish.
		for _, via := range []string{"admin_revoke", "probe_issuance", "recovery", "hourly"} {
			t.Run(via, func(t *testing.T) {
				e := newHostEnv(t, 90)
				keys := e.addActiveHosts(t, 2)
				r1, _ := e.probeReq(e.ed, "web1", true)
				e.mustProbe(r1)
				t0 := e.clock.Now()
				e.clock.set(t0.Add(3601 * time.Second))
				r3, _ := e.probeReq(e.other, "web3", true)
				if _, resp := e.mustProbe(r3); !e.publishedAfter(t, resp.LeafIndex) {
					t.Fatal("setup: web3's first negative did not publish at once")
				}
				e.clock.set(t0.Add(3611 * time.Second))
				rh, _ := e.probeReq(keys["h01"], "h01", true)
				if _, resp := e.mustProbe(rh); e.publishedAfter(t, resp.LeafIndex) {
					t.Fatal("setup: a negative 10 s after a probe publish published at once")
				}
				if prompt, _ := promptState(e); !prompt {
					t.Fatal("setup: the coalesced negative did not set the prompt flag")
				}
				at := t0.Add(3671 * time.Second)
				if via == "hourly" {
					at = t0.Add(7202 * time.Second)
				}
				e.clock.set(at)
				switch via {
				case "admin_revoke":
					e.revokeHost(t, &wire.RevokeRequest{Target: wire.TargetKey, Key: e.off.PublicKey().Marshal()})
				case "probe_issuance":
					r, _ := e.probeReq(keys["h02"], "h02", true)
					if _, resp := e.mustProbe(r); !e.publishedAfter(t, resp.LeafIndex) {
						t.Fatal("setup: a first negative a minute after the last probe publish did not publish at once")
					}
				case "recovery":
					e.recover(t, e.recoveryRequest(t, []wire.RecoveryImport{e.served(t)}, nil, nil))
				case "hourly":
					if !e.s.republishIfDue(ctx) {
						t.Fatal("setup: the tick an hour after the last publish did not publish")
					}
				}
				if prompt, _ := promptState(e); prompt {
					t.Errorf("the %s publish carried the waiting negative but left the prompt flag set", via)
				}
				e.clock.set(at.Add(10 * time.Second))
				r1b, _ := e.probeReq(e.ed, "web1", true)
				if _, resp := e.mustProbe(r1b); e.publishedAfter(t, resp.LeafIndex) {
					t.Fatal("setup: web1's renewal did not ride")
				}
				e.clock.set(at.Add(70 * time.Second))
				if e.s.republishIfDue(ctx) {
					t.Fatal("a stale prompt flag published the riding negative before the hourly republish")
				}
			})
		}
	})
	t.Run("negative_pruned_after_valid_before_plus_300", func(t *testing.T) {
		e := newHostEnv(t, 90)
		e.setMachineCap(t, 90, nil)
		r, _ := e.probeReq(e.ed, "web1", true)
		c, _ := e.mustProbe(r)
		for _, x := range []struct {
			at   uint64
			want bool
		}{{c.ValidBefore + 299, true}, {c.ValidBefore + 300, false}} {
			e.tickTo(x.at)
			e.revokeHost(t, &wire.RevokeRequest{Target: wire.TargetKey, Key: newEd25519(t).PublicKey().Marshal()})
			if got := e.parsedKRL(t).RevokesSerial(c.SignatureKey.Marshal(), c.Serial); got != x.want {
				t.Fatalf("a publish at valid_before + %d s lists the serial: %t, want %t", x.at-c.ValidBefore, got, x.want)
			}
		}
	})
	t.Run("krl_too_large_refuses_issuance", func(t *testing.T) {
		if testing.Short() {
			t.Skip("fills the KRL to krl.MaxKRL")
		}
		for _, mode := range []string{"immediate", "ride", "coalesced"} {
			t.Run(mode, func(t *testing.T) { probeTooLarge(t, mode) })
		}
		t.Run("edge_exact_fits", func(t *testing.T) { probeEdgeFits(t) })
	})
	t.Run("classify_wire_codes", func(t *testing.T) {
		for d, want := range map[string]struct {
			class uint8
			code  wire.ErrorCode
		}{
			"probe_issue_no_installation_id":    {tlog.ReasonUnauthorized, wire.CodeRefused},
			"probe_issue_installation_mismatch": {tlog.ReasonUnauthorized, wire.CodeRefused},
			"probe_pop_invalid":                 {tlog.ReasonUnauthorized, wire.CodeRefused},
			"probe_key_unusable":                {tlog.ReasonBadSubjectKey, wire.CodeRefused},
			"probe_issue_valid_for_not_zero":    {tlog.ReasonTTLExceeded, wire.CodeRefused},
			"probe_cert_recent":                 {tlog.ReasonDuplicateRequest, wire.CodeRefused},
			"malformed_request":                 {tlog.ReasonMalformed, wire.CodeMalformed},
			"request_time_skew":                 {tlog.ReasonStaleRequest, wire.CodeRefused},
			"host_pop_not_enabled":              {tlog.ReasonUnauthorized, wire.CodeRefused},
			"host_pop_invalid":                  {tlog.ReasonUnauthorized, wire.CodeRefused},
			"duplicate_request":                 {tlog.ReasonDuplicateRequest, wire.CodeRefused},
			"krl_too_large":                     {tlog.ReasonUnavailable, wire.CodeUnavailable},
			"revocations_not_logged":            {tlog.ReasonUnavailable, wire.CodeUnavailable},
			"bad_principal":                     {tlog.ReasonBadPrincipal, wire.CodeRefused},
			"principal_reserved":                {tlog.ReasonUnauthorized, wire.CodeRefused},
			"account_reserved":                  {tlog.ReasonUnauthorized, wire.CodeRefused},
		} {
			if got := classify(d); got != want.class || codeFor(got) != want.code {
				t.Errorf("%s: class %d (%s), want %d (%s)", d, got, codeFor(got), want.class, want.code)
			}
		}
	})
}

// tooLargeSeed stages n key_id rows under caKey in a table bulk, each key
// ID about 1000 bytes and distinct, by a recursive CTE.
func tooLargeSeed(t *testing.T, e *hostEnv, caKey []byte, n int) {
	t.Helper()
	if err := e.db.WithTx(context.Background(), func(tx *sql.Tx) error {
		if _, err := tx.Exec(`CREATE TABLE bulk (x INTEGER PRIMARY KEY, ca BLOB, key_id TEXT)`); err != nil {
			return err
		}
		_, err := tx.Exec(`WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < ?)
			INSERT INTO bulk (x, ca, key_id) SELECT x, ?, printf('%06d', x) || substr(replace(hex(zeroblob(600)), '0', 'k'), 1, 994) FROM c`, n, caKey)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// setTuning sets the key ID of bulk row 1 to length n.
func setTuning(t *testing.T, e *hostEnv, n int) {
	t.Helper()
	if err := e.db.WithTx(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE bulk SET key_id = printf('%06d', 1) || substr(replace(hex(zeroblob(8000)), '0', 't'), 1, ?) WHERE x = 1`, n-6)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// seededKRLSize is the size of the KRL of the revocation rows, the bulk
// rows and extra at at, or -1 when it is krl.ErrTooLarge.
func seededKRLSize(t *testing.T, e *hostEnv, extra krl.Entry, at time.Time) int {
	t.Helper()
	entries := revocationEntries(e.revocationRows(t))
	if err := e.db.WithTx(context.Background(), func(tx *sql.Tx) error {
		rows, err := tx.Query(`SELECT ca, key_id FROM bulk`)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var en krl.Entry
			if err := rows.Scan(&en.CAKey, &en.KeyID); err != nil {
				return err
			}
			en.Kind = krl.EntryKeyID
			entries = append(entries, en)
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	entries = append(entries, extra)
	secs := uint64(at.Unix()) //nolint:gosec // G115: after 1970
	set, err := krl.PublishSet(entries, secs)
	if err != nil {
		t.Fatal(err)
	}
	data, err := krl.Encode(set, secs, at)
	if errors.Is(err, krl.ErrTooLarge) {
		return -1
	}
	if err != nil {
		t.Fatal(err)
	}
	return len(data)
}

// tuneToEdge sets the tuning row so that the seeded KRL with extra is
// exactly krl.MaxKRL bytes, and checks that one byte more is too large.
func tuneToEdge(t *testing.T, e *hostEnv, extra krl.Entry, at time.Time) int {
	t.Helper()
	const base = 1000
	setTuning(t, e, base)
	size := seededKRLSize(t, e, extra, at)
	if size < 0 {
		t.Fatal("the seed is already above krl.MaxKRL")
	}
	n := base + (krl.MaxKRL - size) // a key ID is length-prefixed: the size is linear in its length
	if n < 7 || n > 8000 {
		t.Fatalf("the tuning row would need %d bytes", n)
	}
	setTuning(t, e, n)
	if got := seededKRLSize(t, e, extra, at); got != krl.MaxKRL {
		t.Fatalf("the tuned seed encodes to %d bytes, want krl.MaxKRL %d", got, krl.MaxKRL)
	}
	setTuning(t, e, n+1)
	if seededKRLSize(t, e, extra, at) != -1 {
		t.Fatal("one byte above the edge is not krl.ErrTooLarge")
	}
	return n
}

// probeTooLarge (T-03-366): a Negative issuance whose row would publish
// (immediate), ride or wait for the flag (coalesced) is refused
// krl_too_large, with the seed one byte over the edge inside its own
// transaction, and nothing probe-related is written.
func probeTooLarge(t *testing.T, mode string) {
	e := newHostEnv(t, 90)
	ctx := context.Background()
	machine := e.fx.Roles[keystore.RoleMachine].PublicKey().Marshal()
	key, host := e.ed, "web1"
	switch mode {
	case "ride":
		r, _ := e.probeReq(e.ed, "web1", true)
		c1, _ := e.mustProbe(r)
		e.tickTo(issuedSecs(c1) + 16*3600)
	case "coalesced":
		r, _ := e.probeReq(e.ed, "web1", true)
		e.mustProbe(r)
		e.tick(10 * time.Second)
		key, host = e.other, "web3"
	}
	at := e.clock.Now().Add(time.Millisecond)
	_, _, lastBefore := e.counts()
	next := max(uint64(at.UnixMicro()), lastBefore+1)                                                               //nolint:gosec // G115: after 1970
	extra := krl.Entry{Kind: krl.EntrySerial, CAKey: machine, Serial: next, ValidBefore: uint64(at.Unix()) + 86400} //nolint:gosec // G115: after 1970
	tooLargeSeed(t, e, machine, 4176)
	n := tuneToEdge(t, e, extra, at)
	setTuning(t, e, n+1)
	if err := e.db.WithTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.Exec(`CREATE TRIGGER bulk_probe AFTER INSERT ON issuance BEGIN
			INSERT INTO revocation (kind, ca_key, key_id, request_id, leaf_index, revoked_at_us)
			SELECT 'key_id', ca, key_id, NEW.request_id, 0, 1 FROM bulk; END`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	leaves, issued, last := e.counts()
	rows, probes, krlBefore := len(e.revocationRows(t)), liveProbes(e), e.s.GetKRL()
	kinds := func() (p, k, r int) {
		return e.leafCount(tlog.KindProbeIssue), e.leafCount(tlog.KindKRLPublish), e.leafCount(tlog.KindRefusal)
	}
	p0, k0, r0 := kinds()
	e.clock.set(at)
	req, _ := e.probeReq(key, host, true)
	resp, er := e.s.probeIssueOrRefuse(ctx, Peer{UID: 1000}, req)
	if er == nil || er.Message != "krl_too_large" || er.Code != wire.CodeUnavailable {
		t.Fatalf("%s: answer %+v, refusal %+v; want krl_too_large (unavailable)", mode, resp, er)
	}
	l2, i2, last2 := e.counts()
	p1, k1, r1 := kinds()
	if i2 != issued || last2 != last || len(e.revocationRows(t)) != rows || !sameProbeIndex(probes, liveProbes(e)) ||
		!bytes.Equal(e.s.GetKRL().KRL, krlBefore.KRL) || p1 != p0 || k1 != k0 || r1 != r0+1 || l2 != leaves+1 {
		t.Fatalf("%s: the refusal wrote: issued %d -> %d, serial %d -> %d, probe leaves %d -> %d, publishes %d -> %d, refusals %d -> %d", mode,
			issued, i2, last, last2, p0, p1, k0, k1, r0, r1)
	}
	if err := e.db.WithTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.Exec(`DROP TRIGGER bulk_probe`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	e.clock.set(at)
	again, _ := e.probeReq(key, host, true)
	resp2, er2 := e.s.probeIssueOrRefuse(ctx, Peer{UID: 1000}, again)
	if er2 != nil || resp2.Serial != next {
		t.Fatalf("%s: the next issuance: %+v, %+v; want serial %d", mode, resp2, er2, next)
	}
}

// probeEdgeFits: inside one transaction that is rolled back, the tuned
// seed plus the new certificate's entry is exactly krl.MaxKRL bytes and
// checkKRLFitsLocked accepts it; one byte more is krl_too_large.
func probeEdgeFits(t *testing.T) {
	e := newHostEnv(t, 90)
	ctx := context.Background()
	machine := e.fx.Roles[keystore.RoleMachine].PublicKey().Marshal()
	at := e.clock.Now().Add(time.Millisecond)
	_, _, last := e.counts()
	extra := krl.Entry{Kind: krl.EntrySerial, CAKey: machine, Serial: max(uint64(at.UnixMicro()), last+1), ValidBefore: uint64(at.Unix()) + 86400} //nolint:gosec // G115: after 1970
	tooLargeSeed(t, e, machine, 4176)
	n := tuneToEdge(t, e, extra, at)
	setTuning(t, e, n)
	errRollback := errors.New("roll back")
	e.s.mu.Lock()
	defer e.s.mu.Unlock()
	err := e.db.WithTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO revocation (kind, ca_key, key_id, request_id, leaf_index, revoked_at_us)
			SELECT 'key_id', ca, key_id, zeroblob(16), 0, 1 FROM bulk`); err != nil {
			return err
		}
		if err := e.db.InsertRevocation(tx, signerdb.Revocation{Kind: signerdb.RevocationSerial, CAKey: machine, Serial: extra.Serial,
			ValidBeforeMicros: extra.ValidBefore * 1_000_000, LeafIndex: 0, RevokedAt: at}); err != nil {
			return err
		}
		if err := e.s.checkKRLFitsLocked(ctx, tx, at); err != nil {
			return fmt.Errorf("at the edge: %w", err)
		}
		if _, err := tx.Exec(`UPDATE revocation SET key_id = key_id || 'x' WHERE key_id LIKE '000001%'`); err != nil {
			return err
		}
		var r *refusal
		if err := e.s.checkKRLFitsLocked(ctx, tx, at); !errors.As(err, &r) || r.reason != "krl_too_large" {
			return fmt.Errorf("one byte above the edge: %w, want krl_too_large", err)
		}
		return errRollback
	})
	if !errors.Is(err, errRollback) {
		t.Fatal(err)
	}
}

// nextDirectory is the next directory version after e.docs with e.hosts,
// changed by edit, signed by the fixture's first admin (03-10).
func (e *hostEnv) nextDirectory(t *testing.T, edit func(*directory.Directory)) (doc, sigs []byte) {
	t.Helper()
	hosts := slices.Clone(e.hosts)
	for i := range hosts {
		hosts[i].Keys = slices.Sorted(slices.Values(hosts[i].Keys))
	}
	d := &directory.Directory{
		Version: uint64(len(e.docs) + 1), Prev: trust.SHA256Hex(e.docs[len(e.docs)-1]), InstallationID: e.fx.InstallationID,
		Roles:      []directory.Role{{Name: "ops", Principals: slices.Clone(loginPrincipals), MaxTTLSeconds: 3600}},
		HostGroups: []directory.HostGroup{{Name: "lab", Accounts: []directory.AccountMap{{Account: "root", Roles: []string{"ops"}}}}},
		Hosts:      hosts,
	}
	edit(d)
	d.Sort()
	return signDirectory(t, d, e.fx.Admins[0])
}

// TestInstallDirectoryReserved (03-10, Q4): a new directory may not grant
// the probe principal prefix to a role or map the probe account; a
// directory already stored with one still loads and verifies.
func TestInstallDirectoryReserved(t *testing.T) {
	withPrincipal := func(p string) func(*directory.Directory) {
		return func(d *directory.Directory) {
			d.Roles[0].Principals = slices.Sorted(slices.Values(append(d.Roles[0].Principals, p)))
		}
	}
	t.Run("principal_prefix_refused", func(t *testing.T) {
		e := newHostEnv(t, 90)
		doc, sigs := e.nextDirectory(t, withPrincipal("keyroster-probe:x"))
		e.refuseInstall(t, &wire.InstallDirectoryRequest{Directory: doc, Sigs: sigs}, "principal_reserved")
		if c := classify("principal_reserved"); c != tlog.ReasonUnauthorized || codeFor(c) != wire.CodeRefused {
			t.Fatalf("principal_reserved: class %d, code %s", c, codeFor(c))
		}
	})
	t.Run("account_name_refused", func(t *testing.T) {
		e := newHostEnv(t, 90)
		doc, sigs := e.nextDirectory(t, func(d *directory.Directory) {
			d.HostGroups[0].Accounts = append([]directory.AccountMap{{Account: "keyroster-probe", Roles: []string{"ops"}}}, d.HostGroups[0].Accounts...)
		})
		e.refuseInstall(t, &wire.InstallDirectoryRequest{Directory: doc, Sigs: sigs}, "account_reserved")
		if c := classify("account_reserved"); c != tlog.ReasonUnauthorized || codeFor(c) != wire.CodeRefused {
			t.Fatalf("account_reserved: class %d, code %s", c, codeFor(c))
		}
	})
	t.Run("other_names_fine", func(t *testing.T) {
		e := newHostEnv(t, 90)
		doc, sigs := e.nextDirectory(t, func(d *directory.Directory) {
			withPrincipal("keyroster-probe")(d)
			withPrincipal("keyroster-probex:a")(d)
			d.HostGroups[0].Accounts = append([]directory.AccountMap{{Account: "keyroster-probes", Roles: []string{"ops"}}}, d.HostGroups[0].Accounts...)
		})
		e.installDirectory(t, doc, sigs)
	})
	t.Run("stored_directory_still_loads", func(t *testing.T) {
		e := newHostEnv(t, 90)
		doc, sigs := e.nextDirectory(t, withPrincipal("keyroster-probe:x"))
		e.seedDirectory(t, doc, sigs) // stores it as an earlier signer would have, and reopens the signer on it
		e.restart(t)
		if got := e.s.GetDirectory(); got.Version != 2 || !got.Authorized {
			t.Fatalf("the stored directory: version %d, authorized %t; want 2, true", got.Version, got.Authorized)
		}
		if rep := e.verifyExport(); rep.Counts[tlog.KindDirectoryInstall] != 2 {
			t.Fatalf("audit verify counts %d directory_install entries, want 2", rep.Counts[tlog.KindDirectoryInstall])
		}
	})
}

// TestIssueReserved (03-10, Q4, T-03-367): the prefix is refused at the
// one signing funnel on every issuing path but the probe's.
func TestIssueReserved(t *testing.T) {
	t.Run("admin_issue_refused", func(t *testing.T) {
		e := newHostEnv(t, 90)
		req := e.request()
		req.Principals = []string{"keyroster-probe:web1"}
		req.Evidence = SignRequest(t, req, e.fx.Admins...)
		_, er := e.s.issueOrRefuse(context.Background(), Peer{UID: 1000}, req)
		if er == nil || er.Message != "bad_principal" || classify(er.Message) != tlog.ReasonBadPrincipal {
			t.Fatalf("admin issue of the reserved prefix: %+v, want bad_principal", er)
		}
	})
	t.Run("login_refused", func(t *testing.T) {
		pk := newPasskeys(t)
		e := newLoginEnv(t, pk, NewFixture(t, 1, 1), true, false)
		d := loginDirectory(pk, 1, trust.GenesisPrev)
		for i := range d.Roles {
			if d.Roles[i].Name == "ops" {
				d.Roles[i].Principals = slices.Sorted(slices.Values(append(slices.Clone(d.Roles[i].Principals), "keyroster-probe:x")))
			}
		}
		d.Sort()
		doc, sigs := signDirectory(t, d, e.fx.Admins...)
		e.seedDirectory(t, doc, sigs) // a stored directory: InstallDirectory would refuse it
		req := e.loginReq(t, "alice")
		req.Principals = slices.Sorted(slices.Values(append(slices.Clone(loginPrincipals), "keyroster-probe:x")))
		e.refuseLogin(t, approve(t, pk.eddsa, req, nil), "bad_principal")
	})
	t.Run("host_issue_refused_for_prefix_principal", func(t *testing.T) {
		// A host entry cannot name the prefix: host principals are DNS names
		// or IP addresses, and the colon is neither. Should the host
		// issuance tail ever get one, the signing funnel refuses it under
		// the host profile in force, as bad_principal.
		if err := directory.CheckHostPrincipal("keyroster-probe:web1"); err == nil {
			t.Fatal("a host entry may name the reserved prefix; this case must then go through HostIssue")
		}
		e := newHostEnv(t, 90)
		e.s.mu.Lock()
		caKey, okCA := e.s.ca[wire.CARoleHost]
		profile, okProfile := e.s.profiles[wire.CARoleHost]
		e.s.mu.Unlock()
		if !okCA || !okProfile {
			t.Fatal("no host CA or profile")
		}
		kid := cert.KeyID{V3: true, CA: "host", Subject: "web1", Request: "000102030405060708090a0b0c0d0e0f", Policy: 1, Directory: 1, Serial: 1}
		_, err := cert.Build(cert.Request{Profile: profile, Subject: e.ed.PublicKey(), Principals: []string{"keyroster-probe:web1", "web1"},
			Now: e.clock.Now(), ValidFor: time.Minute, KeyID: kid, Serial: 1}, caKey, rand.Reader)
		var r *refusal
		if !errors.Is(err, cert.ErrReservedPrincipal) || !errors.As(buildRefusal(err), &r) || r.reason != "bad_principal" {
			t.Fatalf("the host profile signs the reserved prefix: %v", err)
		}
	})
	t.Run("probe_issue_still_works", func(t *testing.T) {
		e := newHostEnv(t, 90)
		r, _ := e.probeReq(e.ed, "web1", true)
		if c, _ := e.mustProbe(r); !slices.Equal(c.ValidPrincipals, []string{cert.ReservedPrincipalPrefix + "web1"}) {
			t.Fatalf("probe principals %v", c.ValidPrincipals)
		}
	})
}
