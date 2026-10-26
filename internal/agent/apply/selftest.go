//go:build linux

package apply

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Self-test refusals.
var (
	ErrNoLoopbackListener = errors.New("no_loopback_listener")
	ErrSelfTest           = errors.New("self_test_failed")
)

// errHostKeySeen ends a self-test handshake once sshd has proved its host
// key: the key exchange is complete, and nothing past it is attempted.
var errHostKeySeen = errors.New("keyroster self-test: host key seen")

// loopbackTargets returns the addresses the self-test dials, from sshd -T
// (the owner's D-05 answer, loopback-only): for each listenaddress, the
// loopback address itself, 127.0.0.1 for 0.0.0.0 and ::1 for ::, each
// with its port; with no listenaddress line, 127.0.0.1 on each port. An
// address that is not loopback is never dialed. None left is
// no_loopback_listener.
func loopbackTargets(d Dump) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	add := func(host, port string) {
		a := net.JoinHostPort(host, port)
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	var skipped []string
	for _, la := range d["listenaddress"] {
		f := strings.Fields(la) // "addr:port [rdomain X]"
		if len(f) == 0 {
			continue
		}
		host, port, err := net.SplitHostPort(f[0])
		if err != nil {
			skipped = append(skipped, la)
			continue
		}
		ip, err := netip.ParseAddr(host)
		switch {
		case err != nil:
			skipped = append(skipped, la)
		case ip == netip.IPv4Unspecified():
			add("127.0.0.1", port)
		case ip == netip.IPv6Unspecified():
			add("::1", port)
		case ip.IsLoopback():
			add(ip.String(), port)
		default:
			skipped = append(skipped, la)
		}
	}
	if len(d["listenaddress"]) == 0 {
		for _, p := range d["port"] {
			add("127.0.0.1", p)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: sshd listens on no loopback-reachable address (%s); add ListenAddress 127.0.0.1 to sshd_config", ErrNoLoopbackListener, strings.Join(skipped, ", "))
	}
	return out, nil
}

// hostKeys reads the public halves of the host keys sshd -T names
// (hostkey PATH, with PATH.pub beside it).
func hostKeys(d Dump) ([]ssh.PublicKey, error) {
	var out []ssh.PublicKey
	for _, p := range d["hostkey"] {
		f, err := os.Open(p + ".pub") //nolint:gosec // G304: a host key path from sshd's own configuration
		if err != nil {
			return nil, fmt.Errorf("host key %s.pub: %w", p, err)
		}
		b, err := io.ReadAll(io.LimitReader(f, 16<<10))
		_ = f.Close()
		if err != nil {
			return nil, fmt.Errorf("host key %s.pub: %w", p, err)
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey(b)
		if err != nil {
			return nil, fmt.Errorf("host key %s.pub: %w", p, err)
		}
		out = append(out, pub)
	}
	if len(out) == 0 {
		return nil, errors.New("sshd -T names no host key")
	}
	return out, nil
}

// selfTest checks that sshd answers on every loopback address it listens
// on with one of this host's keys. One deadline, Config.SelfTestTimeout,
// covers the whole test: dial, banner and key exchange, set on the
// connection too, so an sshd that accepts and then stalls fails instead
// of hanging the apply. A refused dial is retried until the deadline (a
// reloading sshd re-opens its listeners). The handshake stops once the
// host key is proved, before any authentication.
func (e *engine) selfTest(ctx context.Context, dump Dump, keys []ssh.PublicKey) error {
	targets, err := loopbackTargets(dump)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(e.cfg.SelfTestTimeout)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	for _, addr := range targets {
		var last error
		for {
			if last = probe(ctx, addr, deadline, keys); last == nil {
				break
			}
			if time.Now().Add(100 * time.Millisecond).After(deadline) {
				return fmt.Errorf("%w: %s: %w", ErrSelfTest, addr, last)
			}
			select {
			case <-ctx.Done():
				return fmt.Errorf("%w: %s: %w", ErrSelfTest, addr, last)
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	return nil
}

// probe is one self-test connection to addr, a loopback address.
func probe(ctx context.Context, addr string, deadline time.Time, keys []ssh.PublicKey) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if ip, err := netip.ParseAddr(host); err != nil || !ip.IsLoopback() {
		return fmt.Errorf("%w: refusing to dial %s, which is not a loopback address", ErrNoLoopbackListener, addr)
	}
	d := net.Dialer{Deadline: deadline}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	var seen ssh.PublicKey
	cfg := &ssh.ClientConfig{
		User: "keyroster-selftest",
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			seen = key
			return errHostKeySeen
		},
	}
	_, _, _, err = ssh.NewClientConn(conn, addr, cfg)
	if seen == nil {
		if err == nil {
			err = errors.New("the handshake ended without a host key")
		}
		return err
	}
	if c, ok := seen.(*ssh.Certificate); ok {
		seen = c.Key
	}
	for _, k := range keys {
		if bytes.Equal(k.Marshal(), seen.Marshal()) {
			return nil
		}
	}
	return fmt.Errorf("sshd on %s answered with host key %s, which is not one of the host keys sshd -T names", addr, ssh.FingerprintSHA256(seen))
}
