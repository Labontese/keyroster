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
	"syscall"
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
// (hostkey PATH, with PATH.pub beside it). sshd -T lists its default
// HostKey paths whether or not those keys exist, and sshd skips the
// missing ones; so a HostKey whose private key does not exist is skipped
// here too (PR #67 review). At least one key must remain.
func hostKeys(d Dump) ([]ssh.PublicKey, error) {
	var out []ssh.PublicKey
	for _, p := range d["hostkey"] {
		if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
			continue
		}
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
		return nil, errors.New("sshd -T names no host key that exists")
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
//
// With the default AddressFamily any, sshd -T lists [::]:port beside
// 0.0.0.0:port even where IPv6 is disabled (PR #67 review), so an IPv6
// target is skipped when IPv6 is disabled on lo, or when its dial fails
// EADDRNOTAVAIL or EAFNOSUPPORT. Every target not skipped must pass, at
// least one must, and an IPv4 target is never skipped.
func (e *engine) selfTest(ctx context.Context, dump Dump, keys []ssh.PublicKey) error {
	targets, err := loopbackTargets(dump)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(e.cfg.SelfTestTimeout)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	dial := e.dial
	if dial == nil {
		d := net.Dialer{Deadline: deadline}
		dial = d.DialContext
	}
	ipv6Off := e.ipv6Off
	if ipv6Off == nil {
		ipv6Off = ipv6Disabled
	}
	passed := 0
	var skipped []string
	for _, addr := range targets {
		v6 := strings.HasPrefix(addr, "[")
		if v6 && ipv6Off() {
			skipped = append(skipped, addr+": IPv6 is disabled on lo")
			continue
		}
	retry:
		for {
			last := probe(ctx, dial, addr, deadline, keys)
			switch {
			case last == nil:
				passed++
				break retry
			case v6 && (errors.Is(last, syscall.EADDRNOTAVAIL) || errors.Is(last, syscall.EAFNOSUPPORT)):
				skipped = append(skipped, addr+": "+last.Error())
				break retry
			case time.Now().Add(100 * time.Millisecond).After(deadline):
				return fmt.Errorf("%w: %s: %w", ErrSelfTest, addr, last)
			}
			select {
			case <-ctx.Done():
				return fmt.Errorf("%w: %s: %w", ErrSelfTest, addr, last)
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	if passed == 0 {
		return fmt.Errorf("%w: no loopback address sshd listens on could be reached (%s)", ErrSelfTest, strings.Join(skipped, "; "))
	}
	if len(skipped) > 0 {
		e.logf("self-test skipped %s", strings.Join(skipped, "; "))
	}
	return nil
}

// ipv6Disabled reports whether IPv6 is disabled on lo: disable_ipv6 is 1,
// or the kernel has no IPv6 (no /proc/sys/net/ipv6).
func ipv6Disabled() bool {
	b, err := os.ReadFile("/proc/sys/net/ipv6/conf/lo/disable_ipv6")
	if errors.Is(err, os.ErrNotExist) {
		_, err := os.Stat("/proc/sys/net/ipv6")
		return errors.Is(err, os.ErrNotExist)
	}
	return err == nil && strings.TrimSpace(string(b)) == "1"
}

// probe is one self-test connection to addr, a loopback address.
func probe(ctx context.Context, dial func(ctx context.Context, network, addr string) (net.Conn, error), addr string, deadline time.Time, keys []ssh.PublicKey) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if ip, err := netip.ParseAddr(host); err != nil || !ip.IsLoopback() {
		return fmt.Errorf("%w: refusing to dial %s, which is not a loopback address", ErrNoLoopbackListener, addr)
	}
	conn, err := dial(ctx, "tcp", addr)
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
