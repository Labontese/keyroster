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
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

// The probe constants (03-10b, 'Contracts frozen by this plan', T-03-67).
const (
	// ProbePairSpacing is the least time between two probe pairs, judged at
	// the moment the probes run.
	ProbePairSpacing = 60 * time.Second
	// ProbeNegativesPerHour bounds the negative probes of a sliding hour.
	ProbeNegativesPerHour = 6
	// ProbeOpportunisticEvery is the least time between two opportunistic
	// pairs after a narrowing change, and ProbeOpportunisticNegatives the
	// negatives of the last hour at which they stop (half the budget stays
	// for additions).
	ProbeOpportunisticEvery     = 10 * time.Minute
	ProbeOpportunisticNegatives = 3
	// ProbeSource is the probes' own loopback source address, never the
	// listener test's 127.0.0.1; ProbeSourceAlt is used when sshd listens on
	// ProbeSource itself.
	ProbeSource    = "127.0.0.2"
	ProbeSourceAlt = "127.0.0.3"
	// ProbeBackoffMin and ProbeBackoffMax bound the back-off after a failed
	// gated addition (60 s doubling to 1 h).
	ProbeBackoffMin = 60 * time.Second //nolint:revive // the frozen name (03-10b contracts): the back-off's minimum, not minutes
	ProbeBackoffMax = time.Hour
)

// ProbeOutcome is the result of one PK_OK query.
type ProbeOutcome string

// The three outcomes: sshd accepted the certificate in the unsigned query
// (PK_OK), refused it, or nothing can be concluded.
const (
	ProbeAccepted     ProbeOutcome = "accepted"
	ProbeRefused      ProbeOutcome = "refused"
	ProbeInconclusive ProbeOutcome = "inconclusive"
)

// ProbeTarget is where a probe query goes: a loopback sshd address, the
// loopback source to dial from, the account to authenticate as and the host
// keys sshd -T names (the only keys the query accepts from the server).
type ProbeTarget struct {
	Addr, Source, Account string
	HostKeys              []ssh.PublicKey
}

// errProbeSentinel is what the certificate-only signer returns: sshd asks
// for a signature only after it accepted the certificate in the unsigned
// query (PK_OK), so seeing it means accepted, and no signature is ever
// made.
var errProbeSentinel = errors.New("keyroster probe: PK_OK reached, no signature made")

// certOnlySigner offers a probe certificate as its public key and never
// signs: the probe's private key does not exist any more (it was cleared
// once the issue request was signed).
type certOnlySigner struct{ c *ssh.Certificate }

func (s certOnlySigner) PublicKey() ssh.PublicKey { return s.c }

func (certOnlySigner) Sign(io.Reader, []byte) (*ssh.Signature, error) {
	return nil, errProbeSentinel
}

// probeDial dials addr from the local address local.
type probeDial func(ctx context.Context, local *net.TCPAddr, addr string, deadline time.Time) (net.Conn, error)

func netProbeDial(ctx context.Context, local *net.TCPAddr, addr string, deadline time.Time) (net.Conn, error) {
	d := net.Dialer{LocalAddr: local, Deadline: deadline}
	return d.DialContext(ctx, "tcp", addr)
}

// ProbeQuery is the production PK_OK client (03-10b; the client flow
// 03-10's TestProbeSSHDFacts measured): the none request, then the
// unsigned publickey query offering c through a signer whose Sign returns
// a sentinel. The sentinel is accepted; an error that says "unable to
// authenticate" is refused; everything else, a nil error included, is
// inconclusive: a dial error, a close before the user authentication, a
// timeout, a host key that is not one of t.HostKeys. Only a loopback
// t.Addr is dialed (D-05: loopback-only), from t.Source. A refused dial (a
// reloading sshd) is retried every 100 ms until deadline; a connection that
// was made and then closed is never retried, since a retry would only
// count as another failure at sshd.
func ProbeQuery(ctx context.Context, t ProbeTarget, c *ssh.Certificate, deadline time.Time) (ProbeOutcome, error) {
	return probeQuery(ctx, netProbeDial, t, c, deadline)
}

func probeQuery(ctx context.Context, dial probeDial, t ProbeTarget, c *ssh.Certificate, deadline time.Time) (ProbeOutcome, error) {
	host, _, err := net.SplitHostPort(t.Addr)
	if err != nil {
		return ProbeInconclusive, err
	}
	if ip, err := netip.ParseAddr(host); err != nil || !ip.IsLoopback() {
		return ProbeInconclusive, fmt.Errorf("%w: refusing to probe %s, which is not a loopback address", ErrNoLoopbackListener, t.Addr)
	}
	src, err := netip.ParseAddr(t.Source)
	if err != nil || !src.IsLoopback() {
		return ProbeInconclusive, fmt.Errorf("probe source %q is not a loopback address", t.Source)
	}
	if c == nil {
		return ProbeInconclusive, errors.New("no probe certificate")
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	local := &net.TCPAddr{IP: src.AsSlice()}
	var conn net.Conn
	for {
		conn, err = dial(ctx, local, t.Addr, deadline)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.ECONNREFUSED) || time.Now().Add(100*time.Millisecond).After(deadline) {
			return ProbeInconclusive, err
		}
		select {
		case <-ctx.Done():
			return ProbeInconclusive, err
		case <-time.After(100 * time.Millisecond):
		}
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(deadline); err != nil {
		return ProbeInconclusive, err
	}
	cfg := &ssh.ClientConfig{
		User: t.Account,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(certOnlySigner{c: c})},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if hc, ok := key.(*ssh.Certificate); ok {
				key = hc.Key
			}
			for _, k := range t.HostKeys {
				if bytes.Equal(k.Marshal(), key.Marshal()) {
					return nil
				}
			}
			return fmt.Errorf("sshd on %s answered with host key %s, which is not one of the host keys sshd -T names", t.Addr, ssh.FingerprintSHA256(key))
		},
	}
	cc, chans, reqs, err := ssh.NewClientConn(conn, t.Addr, cfg)
	switch {
	case err == nil:
		_ = ssh.NewClient(cc, chans, reqs).Close()
		return ProbeInconclusive, errors.New("sshd let the probe account in without a signature")
	case errors.Is(err, errProbeSentinel):
		return ProbeAccepted, nil
	case strings.Contains(err.Error(), "unable to authenticate"):
		return ProbeRefused, nil
	}
	return ProbeInconclusive, err
}

// probeSource is the probe's source address for a target, and whether
// 127.0.0.1 (the listener test's source) and it share a PerSourcePenalties
// block, with the note to log once per run when they do: ProbeSource, or
// ProbeSourceAlt when the target host is ProbeSource; ::1 for an IPv6
// target, which the listener test also uses, so only the spacing protects
// it; and an IPv4 persourcenetblocksize of 30 or less puts 127.0.0.1 and
// the source in one block (they differ in the last two bits only).
// persourcenetblocksize is absent on sshd before 9.8 (32:128).
func probeSource(dump Dump, target string) (src string, shared bool, note string) {
	host, _, err := net.SplitHostPort(target)
	ip, perr := netip.ParseAddr(host)
	if err == nil && perr == nil && ip.Is6() && !ip.Is4In6() {
		return "::1", true, "the probes share ::1 with the listener test (an IPv6-only listener); only the spacing protects it"
	}
	src = ProbeSource
	if host == ProbeSource {
		src = ProbeSourceAlt
	}
	v4 := 32
	if nb := dump.One("persourcenetblocksize"); nb != "" {
		a, _, _ := strings.Cut(nb, ":")
		if n, err := strconv.Atoi(a); err == nil {
			v4 = n
		}
	}
	if v4 <= 30 {
		return src, true, fmt.Sprintf("persourcenetblocksize %s puts 127.0.0.1 and the probe source %s in one block; only the spacing protects the listener test", dump.One("persourcenetblocksize"), src)
	}
	return src, false, ""
}

// probeAddr is the loopback address the probes query: the first target of
// loopbackTargets that the skip rules of certTarget (the listener test's)
// leave, an IPv6 target on a host without IPv6 on lo skipped.
func (e *engine) probeAddr(ctx context.Context, deadline time.Time) (string, error) {
	targets, err := loopbackTargets(e.dump)
	if err != nil {
		return "", err
	}
	dial := e.dial
	if dial == nil {
		d := net.Dialer{Deadline: deadline}
		dial = d.DialContext
	}
	addr, err := e.certTarget(ctx, dial, targets)
	if err != nil {
		return "", fmt.Errorf("probe: %s", strings.TrimPrefix(err.Error(), ErrServedCertMismatch.Error()+": "))
	}
	return addr, nil
}

// probeQueryFunc is the engine's probe query: Config's seam, or ProbeQuery.
func (e *engine) probeQueryFunc() func(ctx context.Context, t ProbeTarget, c *ssh.Certificate, deadline time.Time) (ProbeOutcome, error) {
	if e.cfg.probeQuery != nil {
		return e.cfg.probeQuery
	}
	return ProbeQuery
}
