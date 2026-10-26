//go:build linux

package apply

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/agent/state"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/trust"
)

// prng is splitmix64: a fixed-seed generator for the model's pairs (the
// repository bans math/rand everywhere).
type prng struct{ s uint64 }

func (p *prng) next() uint64 {
	p.s += 0x9e3779b97f4a7c15
	z := p.s
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

func (p *prng) bit() bool    { return p.next()&1 == 1 }
func (p *prng) n(k int) int  { return int(p.next() % uint64(k)) } //nolint:gosec // G115: k is small
func (p *prng) chance() bool { return p.n(4) == 0 }

// The model's universe (Task 3 of 03-05): three CA keys, eight serials,
// two key IDs, two explicit keys, three accounts and four principals.
const (
	modelCAs        = 3
	modelSerials    = 8
	modelAccounts   = 3
	modelPrincipals = 4
	modelLGT        = 120 * time.Second // sshd's LoginGraceTime in the model
	// Serials 7 and 8 belong to certificates past ValidBefore + 300 s at
	// the model's clock: 03-03's pruning may drop them from a KRL.
	firstExpiredSerial = 7
)

var (
	modelKeyIDs   = []string{"kid-0", "kid-1"}
	modelAccNames = []string{"acc0", "acc1", "acc2"}
)

// universe holds the model's keys.
type universe struct {
	cas      []ssh.PublicKey // CA keys
	explicit []ssh.PublicKey // explicitly revocable keys: a user key and CA key 1
	userKeys []ssh.PublicKey // keys certificates are issued for: explicit[0] and a key no KRL names
	host     ssh.PublicKey
}

func newUniverse(t testing.TB) *universe {
	u := &universe{}
	for i := range modelCAs {
		u.cas = append(u.cas, seedKey(t, byte(40+i)).PublicKey())
	}
	u.userKeys = []ssh.PublicKey{seedKey(t, 50).PublicKey(), seedKey(t, 51).PublicKey()}
	u.explicit = []ssh.PublicKey{u.userKeys[0], u.cas[1]}
	u.host = seedKey(t, 52).PublicKey()
	return u
}

// spec is one generation's content in the universe.
type spec struct {
	cas     [modelCAs]bool
	princ   [modelAccounts][modelPrincipals]bool
	serials [modelCAs][modelSerials + 1]bool
	keyIDs  [modelCAs][2]bool
	keys    [2]bool
}

func randomSpec(r *prng) spec {
	var s spec
	for i := range s.cas {
		s.cas[i] = r.bit()
	}
	for a := range s.princ {
		for p := range s.princ[a] {
			s.princ[a][p] = r.bit()
		}
	}
	for c := range s.serials {
		for n := 1; n <= modelSerials; n++ {
			s.serials[c][n] = r.chance()
		}
		for k := range s.keyIDs[c] {
			s.keyIDs[c][k] = r.chance()
		}
	}
	for k := range s.keys {
		s.keys[k] = r.chance()
	}
	return s
}

// derive is B from A by 03-03's rules: CA keys and principal lines added
// or removed freely; serials, key IDs and explicit keys only added; a
// serial dropped only when its certificate is past ValidBefore + 300 s.
func derive(r *prng, a spec) spec {
	b := a
	for i := range b.cas {
		if r.chance() {
			b.cas[i] = !b.cas[i]
		}
	}
	for x := range b.princ {
		for p := range b.princ[x] {
			if r.chance() {
				b.princ[x][p] = !b.princ[x][p]
			}
		}
	}
	for c := range b.serials {
		for n := 1; n <= modelSerials; n++ {
			switch {
			case !b.serials[c][n] && r.chance():
				b.serials[c][n] = true
			case b.serials[c][n] && n >= firstExpiredSerial && r.chance():
				b.serials[c][n] = false
			}
		}
		for k := range b.keyIDs[c] {
			b.keyIDs[c][k] = b.keyIDs[c][k] || r.chance()
		}
	}
	for k := range b.keys {
		b.keys[k] = b.keys[k] || r.chance()
	}
	return b
}

// verified is the state.Verified that Render turns into s: a bundle whose
// active and next CA entries are the spec's CA keys, a directory naming
// the model's host with one role per account, and the encoded KRL.
func (u *universe) verified(t testing.TB, s spec) *state.Verified {
	t.Helper()
	b := &trust.Bundle{}
	roles := []string{trust.RoleUser, trust.RoleUser, trust.RoleMachine}
	statesFor := []string{"active", "next", "active"}
	for i, on := range s.cas {
		if on {
			b.CAs = append(b.CAs, trust.CAEntry{Role: roles[i], Key: trust.FormatKey(u.cas[i]), State: statesFor[i], Generation: uint32(i + 1)}) //nolint:gosec // G115: i < 3
		}
	}
	d := &directory.Directory{Version: 1, Prev: trust.GenesisPrev, Users: []directory.User{}, Groups: []directory.Group{}, Roles: []directory.Role{}, InstallationID: testInstallation}
	var accounts []directory.AccountMap
	for a, ps := range s.princ {
		var principals []string
		for p, on := range ps {
			if on {
				principals = append(principals, fmt.Sprintf("p%d", p))
			}
		}
		if len(principals) == 0 {
			continue
		}
		role := "r" + modelAccNames[a]
		d.Roles = append(d.Roles, directory.Role{Name: role, Principals: principals, MaxTTLSeconds: 3600, Extensions: []string{}, Users: []string{}, Groups: []string{}})
		accounts = append(accounts, directory.AccountMap{Account: modelAccNames[a], Roles: []string{role}})
	}
	d.HostGroups = []directory.HostGroup{{Name: "lab", Accounts: accounts}}
	d.Hosts = []directory.Host{{Name: "web1", HostGroup: "lab", Keys: []string{trust.FormatKey(u.host)}, Principals: []string{"web1"}, Status: directory.StatusActive}}
	d.Sort()
	var set krl.Set
	for c := range s.serials {
		sec := krl.CertSection{CAKey: u.cas[c]}
		for n := 1; n <= modelSerials; n++ {
			if s.serials[c][n] {
				sec.Serials = append(sec.Serials, uint64(n)) //nolint:gosec // G115: n is positive
			}
		}
		for k, on := range s.keyIDs[c] {
			if on {
				sec.KeyIDs = append(sec.KeyIDs, modelKeyIDs[k])
			}
		}
		if len(sec.Serials) > 0 || len(sec.KeyIDs) > 0 {
			set.Certs = append(set.Certs, sec)
		}
	}
	for k, on := range s.keys {
		if on {
			set.Keys = append(set.Keys, u.explicit[k])
		}
	}
	kb, err := krl.Encode(set, 1, time.Unix(1793000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	return &state.Verified{Bundle: b, Directory: d, Next: state.Stored{KRL: kb}}
}

// cert is one certificate of the model.
type cert struct {
	ca         int
	serial     uint64
	keyID      string
	key        ssh.PublicKey
	principals []string
	account    int
	valid      bool // within ValidBefore at the model's clock
}

func (u *universe) certs() []cert {
	var out []cert
	for c := range modelCAs {
		for n := uint64(1); n <= modelSerials; n++ {
			out = append(out, cert{
				ca: c, serial: n, keyID: modelKeyIDs[n%2], key: u.userKeys[n%2],
				principals: []string{fmt.Sprintf("p%d", n%modelPrincipals)}, account: int(n % modelAccounts),
				valid: n < firstExpiredSerial,
			})
		}
		out = append(out, cert{ca: c, serial: 3, keyID: "kid-other", key: u.userKeys[1], principals: []string{"p1", "p2"}, account: 2, valid: true})
	}
	return out
}

// modelGen is a generation as sshd reads it: parsed from the files on disk.
type modelGen struct {
	n     uint64
	krl   *krl.Parsed
	cas   map[string]bool
	princ map[string]map[string]bool
}

func loadModel(t testing.TB, g *Generation) modelGen {
	t.Helper()
	m := modelGen{n: g.N, cas: map[string]bool{}, princ: map[string]map[string]bool{}}
	if b := g.Files[KRLFile]; len(b) > 0 {
		p, err := krl.Parse(b)
		if err != nil {
			t.Fatal(err)
		}
		m.krl = p
	}
	for _, l := range lines(g.Files[CAFile]) {
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(l))
		if err == nil {
			m.cas[string(pub.Marshal())] = true
		}
	}
	for name, b := range g.Files {
		acc, ok := strings.CutPrefix(name, PrincipalsDir+"/")
		if !ok {
			continue
		}
		m.princ[acc] = map[string]bool{}
		for _, l := range lines(b) {
			if k, ok := principalLine(l); ok {
				m.princ[acc][k] = true
			}
		}
	}
	return m
}

// The four reads of one authentication, in sshd's order (see
// TestSwapInterleaving).
func (m modelGen) krlRevokesCert(u *universe, c cert) bool {
	if m.krl == nil {
		return false
	}
	ca := u.cas[c.ca].Marshal()
	return m.krl.RevokesSerial(ca, c.serial) || m.krl.RevokesKeyID(ca, c.keyID) || m.krl.RevokesKey(c.key.Marshal())
}

func (m modelGen) krlRevokesCA(u *universe, c cert) bool {
	return m.krl != nil && m.krl.RevokesKey(u.cas[c.ca].Marshal())
}

func (m modelGen) caListed(u *universe, c cert) bool { return m.cas[string(u.cas[c.ca].Marshal())] }

func (m modelGen) principalOK(c cert) bool {
	f := m.princ[modelAccNames[c.account]]
	return slices.ContainsFunc(c.principals, func(p string) bool { return f[p] })
}

func accepts(u *universe, r [4]modelGen, c cert) bool {
	return c.valid && !r[0].krlRevokesCert(u, c) && !r[1].krlRevokesCA(u, c) && r[2].caListed(u, c) && r[3].principalOK(c)
}

// schedule is the sequence of generations current named, and when each
// became current (at[0] is when the first did, long before).
type schedule struct {
	gens []modelGen
	at   []time.Duration
}

// check enumerates every non-decreasing assignment of the four reads to
// the schedule's generations whose reads fit inside a window shorter
// than LoginGraceTime: reads from generation a to d need an
// authentication longer than at[d] - at[a+1]. Each accepting read set
// must be accepted by one generation current during that window, or it
// is a violation. It returns the read sets checked and the violations.
func check(u *universe, s schedule, certs []cert) (int, []string) {
	n := len(s.gens)
	checked := 0
	var bad []string
	for a := range n {
		for b := a; b < n; b++ {
			for c := b; c < n; c++ {
				for d := c; d < n; d++ {
					if d > a && s.at[d]-s.at[a+1] >= modelLGT {
						continue
					}
					checked++
					r := [4]modelGen{s.gens[a], s.gens[b], s.gens[c], s.gens[d]}
					for _, ct := range certs {
						if !accepts(u, r, ct) {
							continue
						}
						ok := false
						for g := a; g <= d && !ok; g++ {
							ok = accepts(u, [4]modelGen{s.gens[g], s.gens[g], s.gens[g], s.gens[g]}, ct)
						}
						if !ok {
							bad = append(bad, fmt.Sprintf("reads from generations %d,%d,%d,%d accept the certificate of CA %d serial %d (key ID %s, principals %v, account %s), which none of generations %d..%d accepts",
								s.gens[a].n, s.gens[b].n, s.gens[c].n, s.gens[d].n, ct.ca, ct.serial, ct.keyID, ct.principals, modelAccNames[ct.account], s.gens[a].n, s.gens[d].n))
						}
					}
				}
			}
		}
	}
	return checked, bad
}

// modelHost runs the shipped engine on a layout without sshd: Render's
// generations written by installGeneration, moved by Transition and
// swapCurrent under the fake clock, every swap recorded.
type modelHost struct {
	t     *testing.T
	h     *testHost
	e     *engine
	u     *universe
	sched schedule
	gens  map[uint64]*Generation
}

func newModelHost(t *testing.T, u *universe) *modelHost {
	t.Helper()
	// The model runs thousands of moves; on tmpfs (/dev/shm) fsync costs
	// nothing, and rename(2), symlinks and directory reads behave as on
	// any Linux file system. The crash-recovery properties that need
	// durability are TestApply's, on the ordinary temporary directory.
	base := t.TempDir()
	if fi, err := os.Stat("/dev/shm"); err == nil && fi.IsDir() {
		if d, err := os.MkdirTemp("/dev/shm", "keyroster-model-"); err == nil {
			t.Cleanup(func() { _ = os.RemoveAll(d) })
			base = d
		}
	}
	h := newTestHostIn(t, newFixture(t), base)
	m := &modelHost{t: t, h: h, u: u, gens: map[uint64]*Generation{}}
	m.e = m.newEngine(false)
	return m
}

// newEngine is a fresh engine, as after a restart: pending makes it
// treat the last swap as just made.
func (m *modelHost) newEngine(pending bool) *engine {
	e := m.h.engine()
	e.cfg.Fault = m.onFault
	e.loadLastSwap(pending, true)
	return e
}

// onFault records each swap: the generation the marker says it installs.
func (m *modelHost) onFault(point string) error {
	if point != "swap" {
		return nil
	}
	mk := readMarker(m.t, m.h)
	if mk == nil {
		return nil
	}
	n := mk.To
	if mk.Step == "intermediate" {
		n = mk.Intermediate
	}
	m.record(n)
	return nil
}

func (m *modelHost) record(n uint64) {
	g, err := readGeneration(m.h.l.Gen(n))
	if err != nil {
		m.t.Fatal(err)
	}
	g.N = n
	m.sched.gens = append(m.sched.gens, loadModel(m.t, g))
	m.sched.at = append(m.sched.at, m.h.clock.Monotonic())
}

// render writes the generation for s.
func (m *modelHost) render(s spec) *Generation {
	m.t.Helper()
	g, err := Render(m.u.verified(m.t, s), []ssh.PublicKey{m.u.host})
	if err != nil {
		m.t.Fatal(err)
	}
	g.N = m.e.allocGeneration()
	if err := m.e.installGeneration(g); err != nil {
		m.t.Fatal(err)
	}
	m.gens[g.N] = g
	return g
}

// start makes g current directly (the first install) a long time ago.
func (m *modelHost) start(g *Generation) {
	m.t.Helper()
	if err := m.e.replaceLink(m.h.l.Current(), "gen/"+fmt.Sprint(g.N)); err != nil {
		m.t.Fatal(err)
	}
	m.h.clock.advance(time.Hour)
	m.record(g.N)
	m.sched.at[0] = -time.Hour
}

// to moves current to g through Transition, as Apply does.
func (m *modelHost) to(g *Generation) error {
	m.t.Helper()
	cur, _, err := m.e.readCurrent()
	if err != nil {
		m.t.Fatal(err)
	}
	_, err = m.e.Transition(context.Background(), cur, g, swapPolled)
	return err
}

func (m *modelHost) mustTo(g *Generation) {
	m.t.Helper()
	if err := m.to(g); err != nil {
		m.t.Fatal(err)
	}
}

// crashAt makes the k-th fault point of the next move crash.
func (m *modelHost) crashAt(k int) {
	n := 0
	m.e.cfg.Fault = func(point string) error {
		if err := m.onFault(point); err != nil {
			return err
		}
		n++
		if n == k {
			return &crash{point: point}
		}
		return nil
	}
}

func (m *modelHost) verify(t *testing.T, certs []cert, total *atomic.Int64) {
	t.Helper()
	n, bad := check(m.u, m.sched, certs)
	total.Add(int64(n))
	if len(bad) > 0 {
		t.Fatalf("%d violations, first: %s", len(bad), bad[0])
	}
}

// TestSwapInterleaving (F1, REVIEWS L1361, L1475@e7b3b32) models the
// reads sshd makes for one authentication, in sshd's order, as OpenSSH's
// auth2-pubkey.c does at both CI versions
// (github.com/openssh/openssh-portable/blob/V_9_5_P1/auth2-pubkey.c and
// .../V_10_5_P1/auth2-pubkey.c, verified in REVIEWS L1397@e7b3b32):
// user_key_allowed() first checks the revocation of the key and of its
// signing CA key against RevokedKeys, then user_cert_trusted_ca() reads
// TrustedUserCAKeys and the AuthorizedPrincipalsFile. Each read takes
// the generation current names at that moment. Generations are rendered
// by Render from seeded pairs built by 03-03's KRL rules, written to a
// temporary layout and moved by the shipped Transition under a fake
// clock; every accepting read set inside a window shorter than
// LoginGraceTime must be accepted by a generation current during it.
func TestSwapInterleaving(t *testing.T) {
	u := newUniverse(t)
	certs := u.certs()
	var total atomic.Int64
	t.Cleanup(func() { t.Logf("%d read sets checked against %d certificates", total.Load(), len(certs)) })

	pairs := func(seed uint64, n int, keep func(a, b spec) bool) [][2]spec {
		r := &prng{s: seed}
		var out [][2]spec
		for len(out) < n {
			a := randomSpec(r)
			b := derive(r, a)
			if keep == nil || keep(a, b) {
				out = append(out, [2]spec{a, b})
			}
		}
		return out
	}
	// One layout runs many pairs: each pair starts from a fresh current.
	runPairs := func(t *testing.T, ps [][2]spec, move func(m *modelHost, a, b *Generation)) {
		m := newModelHost(t, u)
		for _, p := range ps {
			m.sched = schedule{}
			a := m.render(p[0])
			m.start(a)
			b := m.render(p[1])
			move(m, a, b)
			m.verify(t, certs, &total)
			m.e.cleanup()
		}
	}

	t.Run("direct_swap_control_finds_violation", func(t *testing.T) {
		t.Parallel()
		// The Codex example (REVIEWS L1399-1403@e7b3b32): B revokes X and
		// adds X's principal. Swapped directly, a read set takes A's KRL
		// and B's CA file and principals and accepts X.
		var a spec
		a.cas[0] = true
		a.princ[1][0] = true // acc1 has p0; X (serial 1) carries p1 for acc1
		b := a
		b.serials[0][1] = true
		b.princ[1][1] = true
		m := newModelHost(t, u)
		ga, gb := m.render(a), m.render(b)
		m.start(ga)
		if err := m.e.replaceLink(m.h.l.Current(), "gen/"+fmt.Sprint(gb.N)); err != nil {
			t.Fatal(err)
		}
		m.record(gb.N)
		n, bad := check(u, m.sched, certs)
		total.Add(int64(n))
		if len(bad) == 0 {
			t.Fatal("the direct swap shows no violation: the model cannot fail")
		}
		t.Logf("control: %s", bad[0])
	})
	t.Run("back_to_back_revoke_then_add", func(t *testing.T) {
		t.Parallel()
		var a spec
		a.cas[0] = true
		a.princ[1][0] = true
		revoked := a
		revoked.serials[0][1] = true
		added := revoked
		added.princ[1][1] = true
		run := func(timing bool) int {
			m := newModelHost(t, u)
			ga, gr, gd := m.render(a), m.render(revoked), m.render(added)
			m.start(ga)
			m.mustTo(gr)
			m.h.clock.advance(60 * time.Second)
			if timing {
				m.mustTo(gd)
			} else {
				if err := m.e.replaceLink(m.h.l.Current(), "gen/"+fmt.Sprint(gd.N)); err != nil {
					t.Fatal(err)
				}
				m.record(gd.N)
			}
			n, bad := check(u, m.sched, certs)
			total.Add(int64(n))
			return len(bad)
		}
		if run(false) == 0 {
			t.Fatal("a revoke-only and an add-only apply 60 s apart without the timing rule show no violation")
		}
		if v := run(true); v != 0 {
			t.Fatalf("with the timing rule: %d violations", v)
		}
	})
	t.Run("forward_A_M_B", func(t *testing.T) {
		t.Parallel()
		runPairs(t, pairs(1, 2000, nil), func(m *modelHost, _, b *Generation) { m.mustTo(b) })
	})
	t.Run("rollback_B_M_L", func(t *testing.T) {
		t.Parallel()
		runPairs(t, pairs(2, 300, nil), func(m *modelHost, a, b *Generation) {
			m.mustTo(b)
			m.mustTo(a)
		})
	})
	t.Run("rollback_keeps_newest_krl", func(t *testing.T) {
		t.Parallel()
		// Owner decision 2026-10-26 (PR #67): the rollback goes to
		// RollbackTarget(B, A), A's CA keys and principals with the newer
		// KRL; every mix of the move from B is accepted by a generation
		// current during it.
		runPairs(t, pairs(11, 300, nil), func(m *modelHost, a, b *Generation) {
			m.mustTo(b)
			r := RollbackTarget(b, a)
			if r.N == 0 {
				r.N = m.e.allocGeneration()
				if err := m.e.installGeneration(r); err != nil {
					m.t.Fatal(err)
				}
			}
			if newerKRL(b.Files[KRLFile], a.Files[KRLFile]) && string(r.Files[KRLFile]) != string(b.Files[KRLFile]) {
				m.t.Fatal("the rollback target does not carry the newer KRL")
			}
			m.mustTo(r)
		})
	})
	t.Run("collapsed_single_swap", func(t *testing.T) {
		t.Parallel()
		collapses := func(a, b spec) bool {
			m, err := Render(u.verified(t, a), []ssh.PublicKey{u.host})
			if err != nil {
				t.Fatal(err)
			}
			n, err := Render(u.verified(t, b), []ssh.PublicKey{u.host})
			if err != nil {
				t.Fatal(err)
			}
			_, c := Intermediate(m, n)
			return c
		}
		runPairs(t, pairs(3, 300, collapses), func(m *modelHost, _, b *Generation) {
			before := len(m.sched.gens)
			m.mustTo(b)
			if len(m.sched.gens) != before+1 {
				t.Fatal("a collapsing pair took more than one swap")
			}
		})
	})
	t.Run("pruned_expired_serial", func(t *testing.T) {
		t.Parallel()
		prunes := func(a, b spec) bool {
			for c := range a.serials {
				for n := firstExpiredSerial; n <= modelSerials; n++ {
					if a.serials[c][n] && !b.serials[c][n] {
						return true
					}
				}
			}
			return false
		}
		runPairs(t, pairs(4, 300, prunes), func(m *modelHost, _, b *Generation) { m.mustTo(b) })
	})
	t.Run("apply_schedules", func(t *testing.T) {
		t.Parallel()
		r := &prng{s: 5}
		m := newModelHost(t, u)
		for range 150 {
			m.sched = schedule{}
			s := randomSpec(r)
			m.start(m.render(s))
			for range 2 + r.n(2) {
				m.h.clock.advance(time.Duration(r.n(201)) * time.Second)
				s = derive(r, s)
				m.mustTo(m.render(s))
			}
			m.verify(t, certs, &total)
			m.e.cleanup()
		}
	})
	t.Run("superseded_during_wait", func(t *testing.T) {
		t.Parallel()
		r := &prng{s: 6}
		m := newModelHost(t, u)
		for range 100 {
			m.sched = schedule{}
			a := randomSpec(r)
			b := derive(r, a)
			b2 := derive(r, b)
			m.start(m.render(a))
			m.mustTo(m.render(a)) // a swap just now: the next widening move waits
			gb, gb2 := m.render(b), m.render(b2)
			polls := 0
			m.e.poll = func(context.Context) (*Generation, *state.Verified, error) {
				polls++
				if polls == 1 {
					return gb2, nil, nil
				}
				return nil, nil, nil
			}
			err := m.to(gb)
			var s *superseded
			if errors.As(err, &s) {
				err = m.to(s.gen)
			}
			if err != nil {
				t.Fatal(err)
			}
			m.e.poll = nil
			m.verify(t, certs, &total)
			m.e.cleanup()
		}
	})
	// Crash recovery: a move stopped at a fault point, a restart after a
	// delay from 0 to 200 s (a fresh engine that starts with the pending
	// marker), then Transition(current, last-good) as recovery runs it.
	recovery := func(t *testing.T, seed uint64, setup func(m *modelHost, a, b *Generation) bool) {
		r := &prng{s: seed}
		m := newModelHost(t, u)
		for range 150 {
			m.sched = schedule{}
			a := randomSpec(r)
			b := derive(r, a)
			ga := m.render(a)
			m.start(ga)
			gb := m.render(b)
			if !setup(m, ga, gb) {
				m.e.cfg.Fault = m.onFault
				continue
			}
			m.h.clock.advance(time.Duration(r.n(201)) * time.Second)
			m.e = m.newEngine(true)
			m.mustTo(ga)
			m.verify(t, certs, &total)
			m.e.cleanup()
			if err := m.e.clearMarker(); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Run("recovery_M_to_L", func(t *testing.T) {
		t.Parallel()
		recovery(t, 7, func(m *modelHost, _, b *Generation) bool {
			m.crashAt(4) // marker, swap (to M), marker, swap <- crash
			err := m.to(b)
			return isCrash(err) && m.h.current() != b.N
		})
	})
	t.Run("recovery_after_final_swap", func(t *testing.T) {
		t.Parallel()
		recovery(t, 8, func(m *modelHost, _, b *Generation) bool {
			m.mustTo(b) // stopped at B before the commit
			return true
		})
	})
	t.Run("crash_in_rollback", func(t *testing.T) {
		t.Parallel()
		recovery(t, 9, func(m *modelHost, a, b *Generation) bool {
			m.mustTo(b)
			m.crashAt(3) // rollback: marker, swap (to M'), marker <- crash
			err := m.to(a)
			return isCrash(err)
		})
	})
	t.Run("crash_during_recovery_transition", func(t *testing.T) {
		t.Parallel()
		recovery(t, 10, func(m *modelHost, a, b *Generation) bool {
			m.crashAt(4)
			if err := m.to(b); !isCrash(err) {
				return false
			}
			m.h.clock.advance(30 * time.Second)
			m.e = m.newEngine(true)
			m.crashAt(3) // recovery: marker, swap (to M_r), marker <- crash
			return isCrash(m.to(a))
		})
	})
}

// TestIntermediate covers Intermediate's per-class rules and the class
// registry.
func TestIntermediate(t *testing.T) {
	u := newUniverse(t)
	key := func(i int) string { return trust.FormatKey(u.cas[i]) + "\n" }
	gen := func(ca string, krlBytes string, princ map[string]string) *Generation {
		g := &Generation{Files: map[string][]byte{CAFile: []byte(ca), KRLFile: []byte(krlBytes)}}
		for acc, p := range princ {
			g.Files[PrincipalsDir+"/"+acc] = []byte(p)
		}
		return g
	}
	t.Run("ca_intersection_by_key", func(t *testing.T) {
		from := gen(key(0)+key(1), "", nil)
		to := gen(key(1)+key(2), "", nil)
		m, collapsed := Intermediate(from, to)
		if collapsed || string(m.Files[CAFile]) != key(1) {
			t.Fatalf("CA intersection = %q (collapsed %t), want only CA 1", m.Files[CAFile], collapsed)
		}
	})
	t.Run("principals_intersection_fixed_header", func(t *testing.T) {
		from := gen(key(0), "", map[string]string{"a": "# from\np1\np2\n"})
		to := gen(key(0), "x", map[string]string{"a": "# to\np2\np3\n"})
		m, _ := Intermediate(from, to)
		if got := string(m.Files[PrincipalsDir+"/a"]); got != intermediateHeader+"p2\n" {
			t.Fatalf("principals = %q", got)
		}
	})
	t.Run("account_on_one_side_only_empty", func(t *testing.T) {
		from := gen(key(0), "", map[string]string{"a": "p1\n", "b": "p1\n"})
		to := gen(key(0), "x", map[string]string{"a": "p1\n", "c": "p2\n"})
		m, _ := Intermediate(from, to)
		for _, acc := range []string{"b", "c"} {
			if got := string(m.Files[PrincipalsDir+"/"+acc]); got != intermediateHeader {
				t.Fatalf("account %s on one side: %q, want the header only", acc, got)
			}
		}
	})
	t.Run("krl_from_target", func(t *testing.T) {
		m, _ := Intermediate(gen(key(0), "old", map[string]string{"a": "p1\n"}), gen(key(0), "new", map[string]string{"a": "p2\n"}))
		if string(m.Files[KRLFile]) != "new" {
			t.Fatalf("KRL = %q", m.Files[KRLFile])
		}
	})
	t.Run("collapses_when_equal_to_target", func(t *testing.T) {
		from := gen(key(0)+key(1), "old", map[string]string{"a": "p1\np2\n"})
		to := gen(key(0), "new", map[string]string{"a": "# rendered\np1\n"})
		if m, collapsed := Intermediate(from, to); !collapsed || m != to {
			t.Fatal("a pure narrowing did not collapse to the target")
		}
	})
	t.Run("collapses_when_equal_to_source", func(t *testing.T) {
		from := gen(key(0), "same", map[string]string{"a": "p1\n"})
		to := gen(key(0)+key(1), "same", map[string]string{"a": "p1\np2\n", "b": "p3\n"})
		if m, collapsed := Intermediate(from, to); !collapsed || m != to {
			t.Fatal("a pure addition under the same KRL did not collapse (to the target itself)")
		}
	})
	t.Run("empty_ca_list_valid", func(t *testing.T) {
		h := newTestHost(t, newFixture(t))
		e := h.engine()
		g := &Generation{Files: map[string][]byte{CAFile: nil, KRLFile: nil}}
		calls := len(h.run.calls)
		if err := e.validate(context.Background(), g, t.TempDir(), nil); err != nil || len(h.run.calls) != calls {
			t.Fatalf("a CA list with no line: %v, %d ssh-keygen calls", err, len(h.run.calls)-calls)
		}
	})
	t.Run("every_generation_field_classified", func(t *testing.T) {
		g, err := Render(u.verified(t, randomSpec(&prng{s: 11})), []ssh.PublicKey{u.host})
		if err != nil {
			t.Fatal(err)
		}
		for name := range g.Files {
			if _, ok := ClassOf(name); !ok {
				t.Fatalf("Render writes %s, which has no FileClass in GenerationFiles", name)
			}
		}
		if len(g.Files) < 2 {
			t.Fatalf("Render wrote %v", g.Files)
		}
	})
}
