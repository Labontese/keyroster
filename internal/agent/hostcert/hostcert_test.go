package hostcert

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/trust"
)

const t0 = 1_800_000_000

func newKey(t testing.TB) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// env is a host key, a host CA and web1's entry.
type env struct {
	host, ca ssh.Signer
	entry    *directory.Host
	serial   uint64
}

func newEnv(t testing.TB) *env {
	t.Helper()
	e := &env{host: newKey(t), ca: newKey(t), serial: 100}
	e.entry = &directory.Host{Name: "web1", HostGroup: "lab", Keys: []string{trust.FormatKey(e.host.PublicKey())}, Principals: []string{"web1"}, Status: directory.StatusActive}
	return e
}

// issue builds a host certificate for e's key issued at issued for v
// seconds, with principals, from ca.
func (e *env) issue(t testing.TB, issued, v uint64, ca ssh.Signer, principals ...string) *ssh.Certificate {
	t.Helper()
	if len(principals) == 0 {
		principals = []string{"web1"}
	}
	e.serial++
	c, err := cert.Build(cert.Request{Profile: cert.Profile{CertType: ssh.HostCert, MaxTTL: 40 * 24 * time.Hour}, Subject: e.host.PublicKey(), Principals: principals,
		Now: time.Unix(int64(issued), 0), ValidFor: time.Duration(v) * time.Second, Serial: e.serial, //nolint:gosec // G115: test times
		KeyID: cert.KeyID{V3: true, CA: "host", Subject: "web1", Request: strings.Repeat("ab", 16), Policy: 1, Directory: 1, Serial: e.serial}}, ca, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (e *env) entryFor(t testing.TB, c *ssh.Certificate) Entry {
	t.Helper()
	en, err := NewEntry(e.host.PublicKey(), c, c.Marshal(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return en
}

// input is Decide's input with c installed (nil: none) at now.
func (e *env) input(now uint64, c *ssh.Certificate, a *Attempts) Input {
	in := Input{Now: time.Unix(int64(now), 0), Served: []ssh.PublicKey{e.host.PublicKey()}, Entry: e.entry, Authorized: true, //nolint:gosec // G115: test times
		Attempts: a, Bundle: 1, Policy: 1, Directory: 1, CAKeys: []ssh.PublicKey{e.ca.PublicKey()}, Installed: map[string]*ssh.Certificate{}}
	if c != nil {
		k := KeySHA256(e.host.PublicKey())
		en, _ := NewEntry(e.host.PublicKey(), c, c.Marshal(), zeroReader{})
		in.Committed = []Entry{en}
		in.Installed[k] = c
	}
	return in
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func only(t *testing.T, acts []Action) Action {
	t.Helper()
	if len(acts) != 1 {
		t.Fatalf("actions %+v, want one", acts)
	}
	return acts[0]
}

func TestDecide(t *testing.T) {
	e := newEnv(t)
	k := KeySHA256(e.host.PublicKey())
	t.Run("renew_before_and_after_renew_at", func(t *testing.T) {
		c := e.issue(t, t0, 90, e.ca)
		renew := uint64(t0 + 60) // zeroReader: no jitter
		if a := only(t, Decide(e.input(renew-1, c, nil))); a.Kind != Keep {
			t.Fatalf("before RenewAt: %+v", a)
		}
		if a := only(t, Decide(e.input(renew, c, nil))); a.Kind != Request || a.Code != "renew" {
			t.Fatalf("at RenewAt: %+v", a)
		}
	})
	t.Run("missing_margin_is_min_60_or_sixth", func(t *testing.T) {
		for _, v := range []uint64{90, 2592000} {
			c := e.issue(t, t0, v, e.ca)
			margin := min(60, v/6)
			in := e.input(t0+v-margin, c, nil)
			in.Committed[0].RenewAt = t0 + v - 1
			if a := only(t, Decide(in)); a.Kind != Request || a.Code != "missing" {
				t.Fatalf("V %d at ValidBefore - margin: %+v", v, a)
			}
			in = e.input(t0+v-margin-1, c, nil)
			in.Committed[0].RenewAt = t0 + v - 1
			if a := only(t, Decide(in)); a.Kind != Keep {
				t.Fatalf("V %d before the margin: %+v", v, a)
			}
		}
	})
	t.Run("principals_differ_due", func(t *testing.T) {
		c := e.issue(t, t0, 2592000, e.ca, "web1", "old")
		if a := only(t, Decide(e.input(t0+1, c, nil))); a.Kind != Request || a.Code != "principals_differ" {
			t.Fatalf("%+v", a)
		}
	})
	t.Run("revoked_installed_cert_due", func(t *testing.T) {
		c := e.issue(t, t0, 2592000, e.ca)
		data, err := krl.Encode(krl.Set{Certs: []krl.CertSection{{CAKey: e.ca.PublicKey(), Serials: []uint64{c.Serial}}}}, 1, time.Unix(t0, 0))
		if err != nil {
			t.Fatal(err)
		}
		p, err := krl.Parse(data)
		if err != nil {
			t.Fatal(err)
		}
		in := e.input(t0+1, c, nil)
		in.KRL = p
		if a := only(t, Decide(in)); a.Kind != Request || a.Code != "revoked" {
			t.Fatalf("%+v", a)
		}
	})
	t.Run("timing_from_cert_lifetime", func(t *testing.T) {
		for _, v := range []uint64{90, 2592000} {
			c := e.issue(t, t0, v, e.ca)
			en := e.entryFor(t, c)
			lo, hi := t0+2*v/3-min(3600, v/10), t0+2*v/3
			if en.RenewAt < lo || en.RenewAt > hi {
				t.Fatalf("V %d: RenewAt %d outside [%d, %d]", v, en.RenewAt, lo, hi)
			}
			nextAt, n := NextBackoff(c.ValidBefore-min(3600, v/10), 5, c)
			if nextAt != c.ValidBefore-min(3600, v/10)+60 || n != 0 {
				t.Fatalf("V %d: near expiry back-off %d, %d", v, nextAt, n)
			}
		}
	})
	t.Run("lazy_across_ca_rotation", func(t *testing.T) {
		old := newKey(t)
		c := e.issue(t, t0, 2592000, old)
		in := e.input(t0+1, c, nil)
		in.CAKeys = []ssh.PublicKey{old.PublicKey(), e.ca.PublicKey()}
		if a := only(t, Decide(in)); a.Kind != Keep {
			t.Fatalf("a certificate of a still-trusted older CA key: %+v, want kept until due", a)
		}
	})
	for _, h := range []struct {
		name string
		edit func(*Input)
		want string
		none bool
	}{
		{"hold_directory_unauthorized", func(in *Input) { in.Authorized = false }, HoldDirectoryUnauthorized, false},
		{"hold_host_disabled", func(in *Input) { in.Entry = &directory.Host{Name: "web1", Status: directory.StatusDisabled} }, HoldHostDisabled, false},
		{"hold_host_removed", func(in *Input) { in.Entry = nil }, HoldHostRemoved, false},
		{"hold_host_keys_rotated", func(in *Input) { in.HostStatus = HoldHostKeysRotated }, HoldHostKeysRotated, false},
		{"hold_host_keys_disagree", func(in *Input) { in.HostStatus = HoldHostKeysDisagree }, HoldHostKeysDisagree, false},
		{"hold_no_generation", func(in *Input) { in.NoGeneration = true }, HoldNoGeneration, true},
		{"hold_apply_unfinished", func(in *Input) { in.ApplyUnfinished = true }, HoldApplyUnfinished, true},
		{"hold_foreign_host_certificate", func(in *Input) { in.Foreign = true }, HoldForeignHostCertificate, false},
		{"hold_hostcert_in_match", func(in *Input) { in.InMatch = true }, HoldInMatch, false},
	} {
		t.Run(h.name, func(t *testing.T) {
			in := e.input(t0+1, e.issue(t, t0, 90, e.ca), nil)
			h.edit(&in)
			a := only(t, Decide(in))
			if a.Kind != Hold || a.Code != h.want || a.WriteNothing != h.none {
				t.Fatalf("%+v, want Hold %s (write nothing %t), the installed certificate kept", a, h.want, h.none)
			}
		})
	}
	t.Run("hold_host_cert_algorithm_disabled", func(t *testing.T) {
		ec := newKey(t)
		in := e.input(t0+1, nil, nil)
		in.Served = append(in.Served, ec.PublicKey())
		in.Entry = &directory.Host{Name: "web1", Keys: []string{trust.FormatKey(e.host.PublicKey()), trust.FormatKey(ec.PublicKey())}, Principals: []string{"web1"}, Status: directory.StatusActive}
		in.HostKeyAlgorithms = []string{ssh.KeyAlgoED25519}
		for _, a := range Decide(in) {
			if a.Kind != Defer || a.Code != DeferAlgorithmDisabled {
				t.Fatalf("%+v, want every Ed25519 key deferred", a)
			}
		}
	})
	t.Run("key_not_in_entry_removed", func(t *testing.T) {
		in := e.input(t0+1, e.issue(t, t0, 90, e.ca), nil)
		in.Entry = &directory.Host{Name: "web1", Keys: []string{trust.FormatKey(newKey(t).PublicKey())}, Principals: []string{"web1"}, Status: directory.StatusActive}
		if a := only(t, Decide(in)); a.Kind != Remove || a.Key != k {
			t.Fatalf("%+v", a)
		}
	})
	t.Run("key_not_served_removed", func(t *testing.T) {
		in := e.input(t0+1, e.issue(t, t0, 90, e.ca), nil)
		in.Served = nil
		if a := only(t, Decide(in)); a.Kind != Remove || a.Key != k {
			t.Fatalf("%+v", a)
		}
	})
	t.Run("backoff_schedule", func(t *testing.T) {
		c := e.issue(t, t0, 2592000, e.ca)
		for n, want := range map[uint64]uint64{1: 60, 2: 120, 3: 240, 4: 480, 5: 960, 7: 3600} {
			if next, got := NextBackoff(t0+1, n, c); next != t0+1+want || got != n {
				t.Errorf("n %d: next %d (n %d), want +%d", n, next-t0-1, got, want)
			}
		}
		// Within min(3600, V/10) of ValidBefore (and past it): 60 s, n reset.
		for _, d := range []int64{-3599, -1, 1} {
			now := uint64(int64(c.ValidBefore) + d) //nolint:gosec // G115: test times
			if next, n := NextBackoff(now, 10, c); next != now+60 || n != 0 {
				t.Errorf("ValidBefore%+d with n 10: next +%d, n %d, want +60 and n reset", d, next-now, n)
			}
		}
		if now := c.ValidBefore - 3601; true {
			if next, n := NextBackoff(now, 10, c); next != now+3600 || n != 10 {
				t.Errorf("ValidBefore-3601 with n 10: next +%d, n %d, want the 3600 s maximum", next-now, n)
			}
		}
		if next, n := NextBackoff(t0, 4, nil); next != t0+60 || n != 0 {
			t.Errorf("no certificate: +%d, n %d", next-t0, n)
		}
	})
	sticky := func(code string, at uint64) *Attempts {
		return &Attempts{Version: 1, Keys: []Attempt{{KeySHA256: k, Requests: []PendingRequest{}, Sticky: &StickyHold{Code: code, Bundle: 1, Policy: 1, Directory: 1, At: at}}}}
	}
	held := func(in Input) bool {
		a := only(t, Decide(in))
		return a.Kind == Defer && strings.HasPrefix(a.Code, DeferRefusedPrefix)
	}
	t.Run("sticky_list_is_closed", func(t *testing.T) {
		for _, d := range []string{"cert_revoked", "host_key_revoked", "unknown_host", "host_key_not_listed", "host_disabled", "host_pop_not_enabled",
			"host_issue_no_installation_id", "host_issue_installation_mismatch", "host_key_not_enrolled", "host_name_mismatch", "signer_too_old",
			"malformed_request", "ttl_exceeds_host_cap", "host_issue_valid_for_not_zero", "http_400", "http_404"} {
			if !IsSticky(d) {
				t.Errorf("%s is not sticky", d)
			}
		}
		for _, d := range []string{"host_pop_invalid", "directory_not_authorized", "something_new", "http_429", "http_503"} {
			if IsSticky(d) {
				t.Errorf("%s is sticky", d)
			}
		}
	})
	t.Run("skew_refusal_is_transient", func(t *testing.T) {
		for _, d := range []string{"request_time_skew", "directory_changed", "host_cert_recent"} {
			if IsSticky(d) {
				t.Errorf("%s is sticky", d)
			}
		}
	})
	t.Run("sticky_released_by_bundle", func(t *testing.T) {
		in := e.input(t0, nil, sticky("cert_revoked", t0))
		in.Bundle = 2
		if held(in) {
			t.Fatal("a new bundle version did not release the hold")
		}
	})
	t.Run("sticky_released_by_policy", func(t *testing.T) {
		in := e.input(t0, nil, sticky("cert_revoked", t0))
		in.Policy = 2
		if held(in) {
			t.Fatal("a new policy version did not release the hold")
		}
	})
	t.Run("sticky_released_by_directory", func(t *testing.T) {
		in := e.input(t0, nil, sticky("cert_revoked", t0))
		in.Directory = 2
		if held(in) {
			t.Fatal("a new directory version did not release the hold")
		}
	})
	t.Run("sticky_not_released_by_unrelated_change", func(t *testing.T) {
		in := e.input(t0+10, nil, sticky("cert_revoked", t0))
		in.KRL = &krl.Parsed{}
		in.Attempts.Keys = append(in.Attempts.Keys, Attempt{KeySHA256: strings.Repeat("f", 64)})
		if !held(in) {
			t.Fatal("a new KRL or another key's state released the hold")
		}
	})
	t.Run("sticky_refusal_retries_after_24h", func(t *testing.T) {
		if held(e.input(t0+StickyRelease, nil, sticky("cert_revoked", t0))) {
			t.Fatal("24 hours did not release the hold")
		}
		if !held(e.input(t0+StickyRelease-1, nil, sticky("cert_revoked", t0))) {
			t.Fatal("the hold was released before 24 hours")
		}
	})
	t.Run("sticky_at_in_future_released", func(t *testing.T) {
		if held(e.input(t0, nil, sticky("cert_revoked", t0+3601))) {
			t.Fatal("a StickyHold.At at now + 3601 s held the key")
		}
		if !held(e.input(t0, nil, sticky("cert_revoked", t0+3600))) {
			t.Fatal("a StickyHold.At at now + 3600 s released the key")
		}
		next := func(at uint64) Action {
			return only(t, Decide(e.input(t0, nil, &Attempts{Version: 1, Keys: []Attempt{{KeySHA256: k, NextAt: at}}})))
		}
		if a := next(t0 + 3601); a.Kind != Request {
			t.Fatalf("a NextAt at now + 3601 s: %+v", a)
		}
		if a := next(t0 + 3600); a.Kind != Defer || a.Code != DeferBackoff {
			t.Fatalf("a NextAt at now + 3600 s: %+v", a)
		}
	})
}

func TestVerifyAnswer(t *testing.T) {
	e := newEnv(t)
	check := func(now uint64) AnswerCheck {
		return AnswerCheck{Key: e.host.PublicKey(), HostName: "web1", Principals: []string{"web1"}, CAKeys: []ssh.PublicKey{e.ca.PublicKey()}, Now: time.Unix(int64(now), 0)} //nolint:gosec // G115
	}
	good := e.issue(t, t0, 90, e.ca)
	if err := VerifyAnswer(good, check(t0)); err != nil {
		t.Fatalf("a valid answer: %v", err)
	}
	other := newEnv(t)
	for name, tc := range map[string]struct {
		c    *ssh.Certificate
		in   AnswerCheck
		want error
	}{
		"malformed":        {&ssh.Certificate{CertType: ssh.UserCert}, check(t0), ErrAnswerMalformed},
		"other_key":        {other.issue(t, t0, 90, e.ca), check(t0), ErrAnswerOtherKey},
		"principals":       {e.issue(t, t0, 90, e.ca, "web9"), check(t0), ErrAnswerPrincipalsDiffer},
		"unpinned_ca":      {e.issue(t, t0, 90, newKey(t)), check(t0), ErrAnswerUnpinnedCA},
		"expired":          {good, check(t0 + 90 - 15), ErrAnswerExpired},
		"too_long":         {e.issue(t, t0, 2592001, e.ca), check(t0), ErrAnswerTooLong},
		"not_newer":        {good, func() AnswerCheck { c := check(t0); c.Committed = good.Serial; return c }(), ErrAnswerNotNewer},
		"revoked_by_krl":   {good, func() AnswerCheck { c := check(t0); c.KRL = revokedKRL(t, e.ca, good.Serial); return c }(), ErrAnswerRevoked},
		"wrong_entry_name": {good, func() AnswerCheck { c := check(t0); c.HostName = "web2"; return c }(), ErrAnswerMalformed},
	} {
		if err := VerifyAnswer(tc.c, tc.in); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
	t.Run("redelivered_req_field_accepted", func(t *testing.T) {
		// The key ID's req names an earlier request: a re-delivery.
		if err := VerifyAnswer(e.issue(t, t0, 90, e.ca), check(t0)); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("stale_agent_cap_not_stranded", func(t *testing.T) {
		if err := VerifyAnswer(e.issue(t, t0, 2592000, e.ca), check(t0)); err != nil {
			t.Fatalf("a 30-day certificate: %v", err)
		}
		if err := VerifyAnswer(e.issue(t, t0, 2592001, e.ca), check(t0)); !errors.Is(err, ErrAnswerTooLong) {
			t.Fatalf("a 2592001-second certificate: %v", err)
		}
	})
}

func revokedKRL(t *testing.T, ca ssh.Signer, serial uint64) *krl.Parsed {
	t.Helper()
	data, err := krl.Encode(krl.Set{Certs: []krl.CertSection{{CAKey: ca.PublicKey(), Serials: []uint64{serial}}}}, 1, time.Unix(t0, 0))
	if err != nil {
		t.Fatal(err)
	}
	p, err := krl.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func validRecord(t testing.TB) *Record {
	t.Helper()
	e := newEnv(t)
	en := e.entryFor(t, e.issue(t, t0, 90, e.ca))
	return &Record{Version: 1, Committed: []Entry{en}, Candidate: []Entry{}}
}

func TestRecord(t *testing.T) {
	r := validRecord(t)
	b, err := r.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseRecord(b)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := got.Encode(); err != nil || !bytes.Equal(again, b) {
		t.Fatalf("round trip differs (%v)", err)
	}
	two := func() []Entry {
		x, y := validRecord(t).Committed[0], validRecord(t).Committed[0]
		if x.KeySHA256 > y.KeySHA256 {
			x, y = y, x
		}
		return []Entry{y, x}
	}
	for name, edit := range map[string]func(*Record){
		"version_2":         func(r *Record) { r.Version = 2 },
		"unsorted":          func(r *Record) { r.Committed = two() },
		"duplicate":         func(r *Record) { r.Committed = append(r.Committed, r.Committed[0]) },
		"nine_entries":      func(r *Record) { r.Committed = make([]Entry, 9) },
		"key_sha_not_hash":  func(r *Record) { r.Committed[0].KeySHA256 = strings.Repeat("0", 64) },
		"file_not_name":     func(r *Record) { r.Committed[0].File = "x-cert.pub" },
		"renew_outside":     func(r *Record) { r.Committed[0].RenewAt = r.Committed[0].ValidBefore },
		"candidate_without": func(r *Record) { r.Candidate = r.Committed },
	} {
		x := validRecord(t)
		edit(x)
		if err := x.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ParseRecord([]byte(`{"version":1,"committed":[],"in_progress":false,"candidate":[],"extra":1}` + "\n")); err == nil {
		t.Error("an unknown field was accepted")
	}
	if _, err := ParseRecord(bytes.Repeat([]byte(" "), MaxRecord+1)); err == nil {
		t.Error("a record above 16 KiB was accepted")
	}
	t.Run("in_progress_empty_candidate_allowed", func(t *testing.T) {
		x := validRecord(t)
		x.InProgress = true
		if err := x.Validate(); err != nil {
			t.Fatalf("removing the last line: %v", err)
		}
	})
}

func FuzzParseRecord(f *testing.F) {
	b, err := validRecord(f).Encode()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	f.Add([]byte(`{"version":1,"committed":[],"in_progress":true,"candidate":[]}` + "\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := ParseRecord(data)
		if err != nil {
			return
		}
		enc, err := r.Encode()
		if err != nil {
			t.Fatalf("a parsed record does not encode: %v", err)
		}
		again, err := ParseRecord(enc)
		if err != nil {
			t.Fatal(err)
		}
		if enc2, _ := again.Encode(); !bytes.Equal(enc, enc2) {
			t.Fatal("parse, encode, parse is not the identity")
		}
	})
}

func TestAttempts(t *testing.T) {
	a := &Attempt{KeySHA256: strings.Repeat("a", 64)}
	for i := range 6 {
		a.AddRequest(strings.Repeat(string(rune('a'+i)), 32), t0+uint64(i)) //nolint:gosec // G115: small
	}
	if len(a.Requests) != MaxPending || a.Requests[0].CreatedAt != t0+2 {
		t.Fatalf("requests %+v, want the 4 newest", a.Requests)
	}
	if a.Pending(t0+5+RequestTTL-1) == nil || a.Pending(t0+5+RequestTTL) != nil {
		t.Fatal("a request does not expire after 330 s")
	}
	at := &Attempts{Version: 1, Keys: []Attempt{*a}}
	if err := at.Validate(); err != nil {
		t.Fatal(err)
	}
	at.Keys[0].Requests = append(at.Keys[0].Requests, PendingRequest{ID: strings.Repeat("9", 32)})
	if err := at.Validate(); err == nil {
		t.Fatal("five requests were accepted")
	}
}

func TestJitter(t *testing.T) {
	e := newEnv(t)
	for _, v := range []uint64{90, 2592000} {
		c := e.issue(t, t0, v, e.ca)
		for range 50 {
			r, err := RenewAt(c, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			lo, hi := t0+2*v/3-min(3600, v/10), t0+2*v/3
			if r < lo || r > hi {
				t.Fatalf("V %d: RenewAt %d outside [%d, %d]", v, r, lo, hi)
			}
		}
	}
}
