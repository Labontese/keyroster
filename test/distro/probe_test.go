//go:build e2edistro && linux

package distro

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/agent/apply"
)

// The probe matrix (03-10c, owner answer P1, 2026-11-07): the runbook's
// account script, the positive and negative probe certificates against
// each image's own sshd, the account findings of the agent's preflight,
// the `!` cells and the penalty facts. Every account change is undone by
// snapshotAccounts, every sshd change by newHost's pristine /etc/ssh.

// nologinFor is the nologin path each family's arm of probe-account.sh
// gives the account.
var nologinFor = map[string]string{"debian": "/usr/sbin/nologin", "rhel": "/sbin/nologin", "alpine": "/sbin/nologin", "arch": "/usr/bin/nologin"}

// packagedUsePAM is the usepam line of the image's packaged sshd -T, and
// whether sshd prints the keyword at all (a build without PAM does not,
// UNVERIFIED until TestDistroProbeFacts' usepam= FACT on each image).
func packagedUsePAM(t *testing.T) (string, bool) {
	t.Helper()
	_ = newHost(t, true, hostEdit{noStart: true})
	d := sshdT(t, "")
	v, ok := d["usepam"]
	if !ok || len(v) == 0 {
		return "", false
	}
	return v[0], true
}

// setUsePAM is the edit that puts UsePAM v in force: prepended, since the
// first value sshd reads wins and the images set UsePAM further down.
func setUsePAM(v string) hostEdit {
	return hostEdit{config: prepend("UsePAM " + v + "\n")}
}

// requireUsePAM fails unless sshd -T -C for the probe account reports
// usepam v: an edit that is not in force must not pass as a cell.
func requireUsePAM(t *testing.T, v string) {
	t.Helper()
	if got := sshdT(t, probeSpec).One("usepam"); got != v {
		t.Fatalf("sshd -T -C usepam = %q, want %q", got, v)
	}
}

// shadowLine is the probe account's line of /etc/shadow, split.
func shadowLine(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile("/etc/shadow")
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(string(b), "\n") {
		if f := strings.Split(l, ":"); f[0] == probeName {
			return f
		}
	}
	t.Fatalf("no /etc/shadow line for %s", probeName)
	return nil
}

func usermod(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("usermod", append(args, probeName)...).CombinedOutput(); err != nil { //nolint:gosec // G204: the image's usermod
		t.Fatalf("usermod %s: %v: %s", strings.Join(args, " "), err, out)
	}
}

// probeFinding runs the agent's preflight for the probe account and
// returns its probe_account finding, or nil. Preflight must exit 0: a
// probe-account finding is report only (Contracts frozen by 03-10c).
func probeFinding(t *testing.T) *apply.Finding {
	t.Helper()
	code, out, _ := agent(t, append(preflightArgs(true), "--probe-account", probeName)...)
	r := decode[apply.PreflightReport](t, out)
	if code != 0 {
		t.Fatalf("preflight exit %d, want 0 (a probe-account finding is report only): %+v", code, r.Findings)
	}
	f := findingOf(r, apply.CodeProbeAccount)
	if f != nil && f.Refusal {
		t.Fatalf("a probe_account finding is a refusal: %+v", f)
	}
	return f
}

// editFile replaces a file for the rest of a cause and returns the
// function that puts the old bytes back.
func editFile(t *testing.T, p string, edit func(string) string) func() {
	t.Helper()
	b, err := os.ReadFile(p) //nolint:gosec // G304: the container's own files
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(edit(string(b))), 0o600); err != nil { // an existing file keeps its mode
		t.Fatal(err)
	}
	return func() {
		if err := os.WriteFile(p, b, 0o600); err != nil { //nolint:gosec // G703: the test's own fixed paths
			t.Fatal(err)
		}
	}
}

// TestDistroProbe: on each image, for the packaged UsePAM and UsePAM no,
// the runbook's script creates an account that the agent finds healthy,
// whose problems the agent's preflight names, whose positive probe
// certificate sshd accepts and whose negative one a KRL makes it refuse,
// and whose login runs no command.
func TestDistroProbe(t *testing.T) {
	_, hasUsePAM := packagedUsePAM(t)
	for _, variant := range []struct {
		name string
		edit hostEdit
	}{
		{"usepam_packaged", hostEdit{}},
		{"usepam_no", setUsePAM("no")},
	} {
		t.Run(variant.name, func(t *testing.T) {
			if variant.name == "usepam_no" && !hasUsePAM {
				t.Skipf("%s: sshd -T prints no usepam keyword, so the packaged variant already is the no-PAM case", distro)
			}
			start := func(t *testing.T) *host {
				h := probeHost(t, variant.edit)
				if variant.name == "usepam_no" {
					requireUsePAM(t, "no")
				}
				return h
			}
			t.Run("account_created", func(t *testing.T) {
				_ = start(t)
				family := os.Getenv("KEYROSTER_FAMILY")
				line := passwdLine(t)
				if f := strings.Split(line, ":"); len(f) != 7 || f[6] != nologinFor[family] {
					t.Fatalf("passwd line %q, want the shell %s of family %s", line, nologinFor[family], family)
				}
			})
			t.Run("shadow_line", func(t *testing.T) {
				_ = start(t)
				if f := shadowLine(t); len(f) != 9 || f[1] != "*" {
					t.Fatalf("the shadow line has %d fields and the field is %q, want %s:*: and the aging fields", len(f), shadowClass(f), probeName)
				}
			})
			t.Run("account_findings", func(t *testing.T) {
				_ = start(t)
				if f := probeFinding(t); f != nil {
					t.Fatalf("a healthy probe account after the first install: %+v", f)
				}
				for _, c := range []struct {
					reason string
					cause  func(t *testing.T) func()
				}{
					{"account_missing", func(t *testing.T) func() {
						return editFile(t, "/etc/passwd", func(s string) string {
							var out []string
							for _, l := range strings.Split(s, "\n") {
								if !strings.HasPrefix(l, probeName+":") {
									out = append(out, l)
								}
							}
							return strings.Join(out, "\n")
						})
					}},
					{"password_set", func(t *testing.T) func() {
						restore := editFile(t, "/etc/shadow", func(s string) string { return s })
						usermod(t, "-p", "$6$distrosalt$distrohashvalue")
						if c := shadowClass(shadowLine(t)); c != "hash" {
							t.Fatalf("usermod -p left a %s field", c)
						}
						return restore
					}},
					{"account_excluded", func(t *testing.T) func() {
						restore := editFile(t, sshdConfig, prepend("DenyUsers "+probeName+"\n"))
						if got := sshdT(t, probeSpec)["denyusers"]; len(got) != 1 || got[0] != probeName {
							t.Fatalf("sshd -T -C denyusers = %q, want %s", got, probeName)
						}
						return restore
					}},
					{"sshd_override", func(t *testing.T) func() {
						restore := editFile(t, sshdConfig, func(s string) string {
							return s + "\nMatch User " + probeName + "\n    PubkeyAuthentication no\n"
						})
						if got := sshdT(t, probeSpec).One("pubkeyauthentication"); got != "no" {
							t.Fatalf("sshd -T -C pubkeyauthentication = %q, want no", got)
						}
						return restore
					}},
				} {
					restore := c.cause(t)
					f := probeFinding(t)
					restore()
					if f == nil || f.Account != probeName || !strings.HasPrefix(f.Message, c.reason) {
						t.Fatalf("%s: the probe_account finding is %+v, want a Message that starts %s", c.reason, f, c.reason)
					}
				}
				if f := probeFinding(t); f != nil {
					t.Fatalf("after every cause was removed: %+v", f)
				}
			})
			t.Run("positive_accepted_negative_refused", func(t *testing.T) {
				h := start(t)
				pos, neg := h.w.mintProbe(), h.w.mintProbe()
				h.w.writeProbeKRL(t, neg.cert.Serial)
				if r, err := h.probe(apply.ProbeSource, pos.cert); r != apply.ProbeAccepted {
					t.Fatalf("the positive from %s: %s (%v), want accepted", apply.ProbeSource, r, err)
				}
				if r, err := h.probe(apply.ProbeSource, neg.cert); r != apply.ProbeRefused {
					t.Fatalf("the negative, serial %d in the KRL, from %s: %s (%v), want refused", neg.cert.Serial, apply.ProbeSource, r, err)
				}
			})
			t.Run("positive_has_no_session", func(t *testing.T) {
				h := start(t)
				pos := h.w.mintProbe()
				noCommand := func(t *testing.T) {
					out, status, err := h.runAs(apply.ProbeSource, pos.signer, "id")
					t.Logf("the login's output %q, exit status %d", out, status)
					if err != nil {
						t.Fatalf("a login with the positive certificate from %s: %v", apply.ProbeSource, err)
					}
					if strings.Contains(out, "uid=") || status == 0 {
						t.Fatalf("the requested command ran: exit status %d, output %q", status, out)
					}
				}
				t.Run("nologin_shell", noCommand)
				t.Run("sh_shell", func(t *testing.T) {
					snapshotAccounts(t)
					usermod(t, "-s", "/bin/sh")
					noCommand(t)
				})
			})
		})
	}
}

// passwdLine is the probe account's line of /etc/passwd through getent
// where the image has it.
func passwdLine(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("getent"); err == nil {
		out, err := exec.Command("getent", "passwd", probeName).Output()
		if err != nil {
			t.Fatalf("getent passwd %s: %v", probeName, err)
		}
		return strings.TrimSpace(string(out))
	}
	t.Logf("%s has no getent: reading /etc/passwd", distro)
	b, err := os.ReadFile("/etc/passwd")
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, probeName+":") {
			return l
		}
	}
	t.Fatalf("no /etc/passwd line for %s", probeName)
	return ""
}

// shadowClass names a shadow line's field the way the agent classes it,
// so that no field is ever logged.
func shadowClass(f []string) string {
	switch {
	case len(f) < 2:
		return "malformed"
	case f[1] == "":
		return "empty"
	case f[1] == "*":
		return "star"
	case strings.HasPrefix(f[1], "!"):
		return "locked"
	}
	return "hash"
}

// TestDistroProbeAccountBang: the shadow field `*` or `!` under UsePAM yes
// and no, as far as the image's sshd supports them (a build without the
// keyword runs the no-PAM column only). `*` must be accepted in every
// cell; `!` under UsePAM no must be refused, the premise of the agent's
// sshd_override rule for a `!` field (03-10c, D4); `!` under UsePAM yes is
// a fact only.
func TestDistroProbeAccountBang(t *testing.T) {
	_, hasUsePAM := packagedUsePAM(t)
	columns := []string{"no"}
	if hasUsePAM {
		columns = []string{"yes", "no"}
	}
	for _, usepam := range columns {
		for _, field := range []struct{ name, value string }{{"star", "*"}, {"bang", "!"}} {
			t.Run("usepam_"+usepam+"/"+field.name, func(t *testing.T) {
				edit := hostEdit{}
				if hasUsePAM {
					edit = setUsePAM(usepam)
				}
				h := probeHost(t, edit)
				if hasUsePAM {
					requireUsePAM(t, usepam)
				}
				usermod(t, "-p", field.value)
				if f := shadowLine(t); len(f) < 2 || f[1] != field.value {
					t.Fatalf("usermod -p left a %s field", shadowClass(f))
				}
				r, err := h.probe(apply.ProbeSource, h.w.mintProbe().cert)
				t.Logf("FACT probe_bang image=%s usepam=%s field=%s outcome=%s", distro, usepam, field.name, r)
				switch {
				case field.name == "star" && r != apply.ProbeAccepted:
					t.Fatalf("the field * under UsePAM %s: %s (%v), want accepted", usepam, r, err)
				case field.name == "bang" && usepam == "no" && r != apply.ProbeRefused:
					t.Fatalf("the field ! under UsePAM no: %s (%v), want refused: the premise of the sshd_override rule for a ! field does not hold on %s", r, err, distro)
				}
			})
		}
	}
}

// TestDistroProbeFacts records the probe facts of each image (owner answer
// P1): the sshd version, PerSourcePenalties and its netblock size, UsePAM,
// the shadow file's mode and the CA signature algorithms; on an image with
// PerSourcePenalties a control (refused queries from 127.0.0.3 until the
// source is dropped, at most 8) and three probe pairs from 127.0.0.2 at
// the production spacing, each followed by a listener-style handshake from
// 127.0.0.1, none of which may be dropped.
func TestDistroProbeFacts(t *testing.T) {
	h := probeHost(t, hostEdit{})
	out, _ := exec.Command(sshdBin, "-V").CombinedOutput()
	version := strings.Fields(strings.TrimSpace(string(out)) + " unknown")[0]
	d := sshdT(t, "")
	_, penalties := d["persourcepenalties"]
	value := func(k, absent string) string {
		if v := strings.Join(d[k], ","); v != "" {
			return strings.ReplaceAll(v, " ", ",")
		}
		return absent
	}
	fi, err := os.Stat("/etc/shadow")
	if err != nil {
		t.Fatal(err)
	}
	pos, neg := h.w.mintProbe(), h.w.mintProbe()
	h.w.writeProbeKRL(t, neg.cert.Serial)
	control, spacing, mechanism := "none", "not_exercised", "not_exercised"
	var odd []string
	if penalties {
		restartSSHD(t)
		for i := 0; i < 8; i++ {
			if r, err := h.probe(apply.ProbeSourceAlt, neg.cert); r != apply.ProbeRefused {
				control = strconv.Itoa(i)
				t.Logf("the control's query %d from %s: %s (%v)", i+1, apply.ProbeSourceAlt, r, err)
				mechanism = "exercised"
				break
			}
		}
		restartSSHD(t)
		const pairs = 3
		for i := 0; i < pairs; i++ {
			if i > 0 {
				time.Sleep(apply.ProbePairSpacing)
			}
			if r, err := h.probe(apply.ProbeSource, pos.cert); r != apply.ProbeAccepted {
				odd = append(odd, fmt.Sprintf("pair %d positive: %s (%v)", i+1, r, err))
			}
			if r, err := h.probe(apply.ProbeSource, neg.cert); r != apply.ProbeRefused {
				odd = append(odd, fmt.Sprintf("pair %d negative: %s (%v)", i+1, r, err))
			}
			if err := listenerHandshake(hostKeys(t)); err != nil {
				odd = append(odd, fmt.Sprintf("pair %d listener source 127.0.0.1: %v", i+1, err))
			}
		}
		dropped := "none"
		if len(odd) > 0 {
			dropped = strconv.Itoa(len(odd))
		}
		spacing = fmt.Sprintf("%ds,pairs=%d,dropped=%s", int(apply.ProbePairSpacing/time.Second), pairs, dropped)
	}
	t.Logf("FACT probe image=%s sshd=%s persourcepenalties=%s persourcenetblocksize=%s usepam=%s shadow_mode=%04o casignaturealgorithms=%s control_dropped_after=%s mechanism=%s spacing=%s",
		distro, version, yesNo(penalties), value("persourcenetblocksize", "default"), value("usepam", "absent"),
		fi.Mode().Perm(), value("casignaturealgorithms", "absent"), control, mechanism, spacing)
	if penalties {
		t.Run("pairs_at_production_spacing_never_dropped", func(t *testing.T) {
			if len(odd) != 0 {
				t.Fatalf("at the production spacing: %v", odd)
			}
		})
	}
}

// listenerHandshake is the listener test's connection from 127.0.0.1: a
// key exchange that sees one of sshd's host keys and stops before any
// authentication.
func listenerHandshake(keys []ssh.PublicKey) error {
	seen := false
	errStop := errors.New("stop after the host key")
	cfg := &ssh.ClientConfig{User: "nobody", Timeout: 5 * time.Second,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			for _, k := range keys {
				seen = seen || bytes.Equal(k.Marshal(), key.Marshal())
			}
			return errStop
		}}
	if _, err := ssh.Dial("tcp", "127.0.0.1:22", cfg); !seen {
		return fmt.Errorf("no host key of sshd seen: %w", err)
	}
	return nil
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
