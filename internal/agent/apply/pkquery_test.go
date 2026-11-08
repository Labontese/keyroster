//go:build linux

package apply

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// pkServer is an in-process x/crypto SSH server on a loopback address: it
// accepts the certificates accept reports true for in the publickey query,
// and records the remote addresses and what the client offered.
type pkServer struct {
	addr    string
	hostKey ssh.Signer
	mu      sync.Mutex
	remotes []string
	offered []ssh.PublicKey
	authed  int
}

func newPKServer(t *testing.T, listen string, accept func(ssh.PublicKey) bool, noAuth bool) *pkServer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hk, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	s := &pkServer{hostKey: hk}
	//nolint:gosec // G408: a test server; it records what the client offered and never relies on the callback for authorization
	cfg := &ssh.ServerConfig{NoClientAuth: noAuth, PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		s.mu.Lock()
		s.remotes = append(s.remotes, c.RemoteAddr().String())
		s.offered = append(s.offered, key)
		s.mu.Unlock()
		if accept(key) {
			return &ssh.Permissions{}, nil
		}
		return nil, errors.New("refused")
	}}
	cfg.AddHostKey(hk)
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	s.addr = ln.Addr().String()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				if _, _, _, err := ssh.NewServerConn(c, cfg); err == nil {
					s.mu.Lock()
					s.authed++
					s.mu.Unlock()
				}
			}()
		}
	}()
	return s
}

// rawServer accepts and runs serve on each connection.
func rawServer(t *testing.T, serve func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serve(c)
		}
	}()
	return ln.Addr().String()
}

// testProbeCert is a user certificate for a fresh key; its signature is
// not checked by the in-process server.
func testProbeCert(t *testing.T, serial uint64) *ssh.Certificate {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	ca := newTestSigner(t)
	c := &ssh.Certificate{Key: k, Serial: serial, CertType: ssh.UserCert, ValidPrincipals: []string{"keyroster-probe:web1"}, ValidBefore: ssh.CertTimeInfinity}
	c.SignatureKey = ca.PublicKey()
	c.Signature = &ssh.Signature{Format: ssh.KeyAlgoED25519, Blob: make([]byte, ed25519.SignatureSize)}
	return c
}

func newTestSigner(t *testing.T) ssh.Signer {
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

func serialIs(n uint64) func(ssh.PublicKey) bool {
	return func(k ssh.PublicKey) bool {
		c, ok := k.(*ssh.Certificate)
		return ok && c.Serial == n
	}
}

func TestPKQuery(t *testing.T) {
	deadline := func() time.Time { return time.Now().Add(3 * time.Second) }
	target := func(s *pkServer, src string) ProbeTarget {
		return ProbeTarget{Addr: s.addr, Source: src, Account: "probe", HostKeys: []ssh.PublicKey{s.hostKey.PublicKey()}}
	}
	accepted, refused := testProbeCert(t, 1), testProbeCert(t, 2)
	t.Run("accepted", func(t *testing.T) {
		s := newPKServer(t, "127.0.0.1:0", serialIs(1), false)
		if r, err := ProbeQuery(context.Background(), target(s, ProbeSource), accepted, deadline()); r != ProbeAccepted {
			t.Fatalf("%s (%v)", r, err)
		}
	})
	t.Run("refused", func(t *testing.T) {
		s := newPKServer(t, "127.0.0.1:0", serialIs(1), false)
		if r, err := ProbeQuery(context.Background(), target(s, ProbeSource), refused, deadline()); r != ProbeRefused || err != nil {
			t.Fatalf("%s (%v)", r, err)
		}
	})
	t.Run("inconclusive_closed_before_auth", func(t *testing.T) {
		addr := rawServer(t, func(c net.Conn) { _ = c.Close() })
		if r, err := ProbeQuery(context.Background(), ProbeTarget{Addr: addr, Source: ProbeSource, Account: "probe"}, accepted, deadline()); r != ProbeInconclusive || err == nil {
			t.Fatalf("%s (%v)", r, err)
		}
		addr = rawServer(t, func(c net.Conn) { _, _ = c.Write([]byte("Not allowed at this time\r\n")); _ = c.Close() })
		if r, _ := ProbeQuery(context.Background(), ProbeTarget{Addr: addr, Source: ProbeSource, Account: "probe"}, accepted, deadline()); r != ProbeInconclusive {
			t.Fatalf("a dropped source: %s", r)
		}
	})
	t.Run("inconclusive_timeout", func(t *testing.T) {
		addr := rawServer(t, func(c net.Conn) { time.Sleep(3 * time.Second); _ = c.Close() })
		start := time.Now()
		r, err := ProbeQuery(context.Background(), ProbeTarget{Addr: addr, Source: ProbeSource, Account: "probe"}, accepted, time.Now().Add(300*time.Millisecond))
		if r != ProbeInconclusive || err == nil || time.Since(start) > 2*time.Second {
			t.Fatalf("%s (%v) after %s", r, err, time.Since(start))
		}
	})
	t.Run("nil_error_is_inconclusive", func(t *testing.T) {
		s := newPKServer(t, "127.0.0.1:0", serialIs(1), true)
		if r, err := ProbeQuery(context.Background(), target(s, ProbeSource), refused, deadline()); r != ProbeInconclusive || err == nil {
			t.Fatalf("a server that lets the client in: %s (%v)", r, err)
		}
	})
	t.Run("wrong_host_key_is_inconclusive", func(t *testing.T) {
		s := newPKServer(t, "127.0.0.1:0", serialIs(1), false)
		tg := target(s, ProbeSource)
		tg.HostKeys = []ssh.PublicKey{newTestSigner(t).PublicKey()}
		if r, err := ProbeQuery(context.Background(), tg, accepted, deadline()); r != ProbeInconclusive || err == nil {
			t.Fatalf("%s (%v)", r, err)
		}
		if s.offered != nil {
			t.Fatal("a certificate was offered to a server with another host key")
		}
	})
	t.Run("source_is_127_0_0_2", func(t *testing.T) {
		s := newPKServer(t, "127.0.0.1:0", serialIs(1), false)
		if r, err := ProbeQuery(context.Background(), target(s, ProbeSource), accepted, deadline()); r != ProbeAccepted {
			t.Fatalf("%s (%v)", r, err)
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if len(s.remotes) == 0 || !strings.HasPrefix(s.remotes[0], "127.0.0.2:") {
			t.Fatalf("remote addresses %v, want 127.0.0.2", s.remotes)
		}
	})
	t.Run("source_alt_when_target_is_127_0_0_2", func(t *testing.T) {
		s := newPKServer(t, "127.0.0.2:0", serialIs(1), false)
		src, _, _ := probeSource(Dump{}, s.addr)
		if src != ProbeSourceAlt {
			t.Fatalf("source %s for target %s, want %s", src, s.addr, ProbeSourceAlt)
		}
		if r, err := ProbeQuery(context.Background(), target(s, src), accepted, deadline()); r != ProbeAccepted {
			t.Fatalf("%s (%v)", r, err)
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if !strings.HasPrefix(s.remotes[0], "127.0.0.3:") {
			t.Fatalf("remote %v", s.remotes)
		}
	})
	t.Run("no_signature_made", func(t *testing.T) {
		if _, err := (certOnlySigner{c: accepted}).Sign(rand.Reader, []byte("data")); !errors.Is(err, errProbeSentinel) {
			t.Fatalf("Sign: %v, want the sentinel", err)
		}
		s := newPKServer(t, "127.0.0.1:0", serialIs(1), false)
		for _, c := range []*ssh.Certificate{accepted, refused} {
			_, _ = ProbeQuery(context.Background(), target(s, ProbeSource), c, deadline())
		}
		time.Sleep(100 * time.Millisecond)
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.authed != 0 || len(s.offered) != 2 {
			t.Fatalf("server authenticated %d connections and saw %d queries, want 0 and one query each", s.authed, len(s.offered))
		}
	})
	t.Run("non_loopback_target_refused_without_dial", func(t *testing.T) {
		dials := 0
		dial := func(context.Context, *net.TCPAddr, string, time.Time) (net.Conn, error) {
			dials++
			return nil, errors.New("dialed")
		}
		for _, a := range []string{"[2001:db8::1]:22", "localhost:22", "nonsense"} {
			r, err := probeQuery(context.Background(), dial, ProbeTarget{Addr: a, Source: ProbeSource, Account: "probe"}, accepted, deadline())
			if r != ProbeInconclusive || err == nil {
				t.Fatalf("%s: %s (%v)", a, r, err)
			}
			if a != "nonsense" && !errors.Is(err, ErrNoLoopbackListener) {
				t.Fatalf("%s: %v, want no_loopback_listener", a, err)
			}
		}
		if dials != 0 {
			t.Fatalf("%d dials to a non-loopback target", dials)
		}
	})
	t.Run("refusal_text_tripwire", func(t *testing.T) {
		s := newPKServer(t, "127.0.0.1:0", serialIs(1), false)
		conn, err := net.Dial("tcp", s.addr)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		_, _, _, err = ssh.NewClientConn(conn, s.addr, &ssh.ClientConfig{User: "probe", Auth: []ssh.AuthMethod{ssh.PublicKeys(certOnlySigner{c: refused})},
			HostKeyCallback: ssh.FixedHostKey(s.hostKey.PublicKey())})
		if err == nil || !strings.Contains(err.Error(), "unable to authenticate") {
			t.Fatalf("x/crypto's refusal text changed: %v", err)
		}
	})
	t.Run("cert_offered_not_bare_key", func(t *testing.T) {
		s := newPKServer(t, "127.0.0.1:0", serialIs(1), false)
		_, _ = ProbeQuery(context.Background(), target(s, ProbeSource), accepted, deadline())
		s.mu.Lock()
		defer s.mu.Unlock()
		if len(s.offered) == 0 {
			t.Fatal("nothing offered")
		}
		if _, ok := s.offered[0].(*ssh.Certificate); !ok {
			t.Fatalf("offered %s, want the certificate", s.offered[0].Type())
		}
	})
	t.Run("engine_seam", func(t *testing.T) {
		called := false
		e := &engine{cfg: Config{probeQuery: func(context.Context, ProbeTarget, *ssh.Certificate, time.Time) (ProbeOutcome, error) {
			called = true
			return ProbeRefused, nil
		}}}
		if r, _ := e.probeQueryFunc()(context.Background(), ProbeTarget{}, accepted, deadline()); r != ProbeRefused || !called {
			t.Fatalf("the Config seam was not used: %s", r)
		}
		if r, _ := (&engine{}).probeQueryFunc()(context.Background(), ProbeTarget{Addr: "localhost:22"}, accepted, deadline()); r != ProbeInconclusive {
			t.Fatalf("the default query: %s", r)
		}
	})
	t.Run("refused_dial_retried_until_deadline", func(t *testing.T) {
		n := 0
		dial := func(context.Context, *net.TCPAddr, string, time.Time) (net.Conn, error) {
			n++
			return nil, syscall.ECONNREFUSED
		}
		r, _ := probeQuery(context.Background(), dial, ProbeTarget{Addr: "127.0.0.1:22", Source: ProbeSource}, accepted, time.Now().Add(350*time.Millisecond))
		if r != ProbeInconclusive || n < 2 {
			t.Fatalf("%s after %d dials", r, n)
		}
	})
}

func TestProbeSource(t *testing.T) {
	t.Run("ipv4_target_uses_127_0_0_2", func(t *testing.T) {
		if src, shared, note := probeSource(Dump{}, "127.0.0.1:22"); src != ProbeSource || shared || note != "" {
			t.Fatalf("%s %t %q", src, shared, note)
		}
	})
	t.Run("ipv6_only_uses_loopback6_and_logs_shared", func(t *testing.T) {
		if src, shared, note := probeSource(Dump{}, "[::1]:22"); src != "::1" || !shared || note == "" {
			t.Fatalf("%s %t %q", src, shared, note)
		}
	})
	t.Run("netblock_30_shares_block_and_logs", func(t *testing.T) {
		for _, nb := range []string{"30:128", "24:64", "8:48"} {
			if src, shared, note := probeSource(Dump{"persourcenetblocksize": {nb}}, "127.0.0.1:22"); src != ProbeSource || !shared || !strings.Contains(note, nb) {
				t.Fatalf("%s: %s %t %q", nb, src, shared, note)
			}
		}
	})
	t.Run("netblock_31_does_not", func(t *testing.T) {
		for _, nb := range []string{"31:128", "32:128"} {
			if _, shared, note := probeSource(Dump{"persourcenetblocksize": {nb}}, "127.0.0.1:22"); shared || note != "" {
				t.Fatalf("%s: shared %t %q", nb, shared, note)
			}
		}
	})
	t.Run("netblock_absent_defaults_32_128", func(t *testing.T) {
		if _, shared, _ := probeSource(Dump{"port": {"22"}}, "127.0.0.1:22"); shared {
			t.Fatal("9.5p1 prints no persourcenetblocksize: 32:128, not shared")
		}
	})
	t.Run("ipv6_skip_follows_selftest_rules", func(t *testing.T) {
		okConn := func(context.Context, string, string) (net.Conn, error) {
			a, b := net.Pipe()
			_ = b.Close()
			return a, nil
		}
		e := &engine{dump: Dump{"listenaddress": {"[::1]:22", "127.0.0.1:22"}}, dial: okConn, ipv6Off: func() bool { return true }}
		if a, err := e.probeAddr(context.Background(), time.Now().Add(time.Second)); err != nil || a != "127.0.0.1:22" {
			t.Fatalf("IPv6 off: %q %v", a, err)
		}
		e.ipv6Off = func() bool { return false }
		e.dial = func(_ context.Context, _, addr string) (net.Conn, error) {
			if strings.HasPrefix(addr, "[") {
				return nil, syscall.EADDRNOTAVAIL
			}
			return okConn(context.Background(), "", addr)
		}
		if a, err := e.probeAddr(context.Background(), time.Now().Add(time.Second)); err != nil || a != "127.0.0.1:22" {
			t.Fatalf("IPv6 unreachable: %q %v", a, err)
		}
		e.dump = Dump{"listenaddress": {"[::1]:22"}}
		e.ipv6Off = func() bool { return true }
		if a, err := e.probeAddr(context.Background(), time.Now().Add(time.Second)); err == nil {
			t.Fatalf("only an IPv6 target with IPv6 off: %q", a)
		}
	})
}
