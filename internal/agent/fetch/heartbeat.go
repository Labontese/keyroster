//go:build linux

package fetch

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Labontese/keyroster/internal/agent/heartbeat"
	"github.com/Labontese/keyroster/internal/agent/spool"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/trust"
)

// File names of identity rotation in the fetcher's own directory (03-08).
const (
	// IdentityNextFile is the new identity key a rotation writes (0600)
	// before it asks the server to switch: a lost answer leaves it here,
	// and the next poll that gets unknown_agent with the old key tries it.
	IdentityNextFile = "identity.next"
	// IdentityLockFile is the flock that rotation and every poll hold, so
	// neither ever sends with a half-replaced identity.
	IdentityLockFile = "identity.lock"
)

// lockIdentity takes the exclusive flock on <dir>/identity.lock, waiting
// for a holder. The returned function releases it.
func lockIdentity(dir string) (func(), error) {
	dfd, err := spool.OpenDir(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(dfd) }()
	fd, err := unix.Openat(dfd, IdentityLockFile, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", IdentityLockFile, err)
	}
	for {
		err = unix.Flock(fd, unix.LOCK_EX)
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("lock %s: %w", IdentityLockFile, err)
	}
	return func() { _ = unix.Close(fd) }, nil
}

// readKey reads an Ed25519 PKCS #8 PEM key file from the directory fd;
// unix.ENOENT when it is missing.
func readKey(fd int, name string) (ed25519.PrivateKey, error) {
	b, err := spool.ReadFileAt(fd, name, maxSmallFile)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(b)
	if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
		return nil, fmt.Errorf("%s: not one PEM PRIVATE KEY block", name)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	ek, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an Ed25519 key", name)
	}
	return ek, nil
}

// writeKey writes key as an Ed25519 PKCS #8 PEM file (0600) through
// spool.WriteFileAt.
func writeKey(fd int, name string, key ed25519.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	return spool.WriteFileAt(fd, name, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
}

// RotateIdentity is keyroster-agent-fetch --rotate-identity (03-08,
// AGENT-02): under the identity flock it makes a new Ed25519 key, writes
// it to identity.next (0600) before anything is sent, and posts the new
// SPKI signed by the current key over mTLS with the current certificate.
// On 200 identity.next replaces identity.key (rename) and identity.pub is
// rewritten. Any failure leaves identity.next: when the server switched
// but its answer was lost, the next poll gets unknown_agent with the old
// key and finishes the rotation (recoverRotation); when nothing reached
// the server, the old key keeps working.
//
// An identity.next left by an earlier rotation is never replaced, because
// it may be the only key the server knows (PR #72 review C9, C13): it is
// tried first with a state request, and promoted when the server takes
// it; when the server answers unknown_agent for it, the rotation is asked
// again for that same key. Any other failure of the trial (the server
// unreachable) is an error, and identity.next stays.
func (f *Fetcher) RotateIdentity(ctx context.Context) error {
	unlock, err := lockIdentity(f.cfg.Dir)
	if err != nil {
		return err
	}
	defer unlock()
	if err := f.reloadIdentity(); err != nil {
		return err
	}
	dfd, err := spool.OpenDir(f.cfg.Dir)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(dfd) }()
	next, err := readKey(dfd, IdentityNextFile)
	switch {
	case errors.Is(err, unix.ENOENT):
		if _, next, err = ed25519.GenerateKey(rand.Reader); err != nil {
			return err
		}
		if err := writeKey(dfd, IdentityNextFile, next); err != nil {
			return err
		}
	case err != nil:
		return err
	default:
		v, err := f.cursor()
		if err != nil {
			return err
		}
		switched, err := f.tryNext(ctx, dfd, next, v)
		if err != nil {
			return fmt.Errorf("identity rotation: %s from an earlier rotation is kept, and could not be checked with the server: %w", IdentityNextFile, err)
		}
		if switched {
			f.logf("finished an earlier identity rotation whose answer was lost: the agent identity is now %s", f.Fingerprint())
			return nil
		}
		f.logf("the server does not know %s from an earlier rotation; asking again for that key", IdentityNextFile)
	}
	if err := f.fault("rotate-before-post"); err != nil {
		return err
	}
	spki, err := x509.MarshalPKIXPublicKey(next.Public())
	if err != nil {
		return err
	}
	req := &serverclient.AgentIdentityRequest{NewSPKI: spki, Sig: ed25519.Sign(f.key, serverclient.AgentIdentityMessage(spki))}
	if err := f.client.AgentRotateIdentity(ctx, req); err != nil {
		return fmt.Errorf("identity rotation (the new key stays in %s; the next poll, or the next --rotate-identity, finishes a rotation the server made): %w", IdentityNextFile, err)
	}
	if err := f.promote(dfd); err != nil {
		return err
	}
	f.logf("rotated the agent identity to %s", f.Fingerprint())
	return nil
}

// promote renames identity.next over identity.key and switches to it.
func (f *Fetcher) promote(dfd int) error {
	next, err := readKey(dfd, IdentityNextFile)
	if err != nil {
		return err
	}
	if err := unix.Renameat(dfd, IdentityNextFile, dfd, IdentityKeyFile); err != nil {
		return fmt.Errorf("promote %s: %w", IdentityNextFile, err)
	}
	if err := unix.Fsync(dfd); err != nil {
		return err
	}
	return f.useKey(next)
}

// recoverRotation is called when the current identity got unknown_agent.
// With an identity.next it tries that key (tryNext); when the server
// takes it, the server switched in a rotation whose answer was lost, and
// identity.next is promoted. It reports whether it switched.
func (f *Fetcher) recoverRotation(ctx context.Context, v serverclient.AgentVersions) (bool, error) {
	dfd, err := spool.OpenDir(f.cfg.Dir)
	if err != nil {
		return false, err
	}
	defer func() { _ = unix.Close(dfd) }()
	next, err := readKey(dfd, IdentityNextFile)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	switched, err := f.tryNext(ctx, dfd, next, v)
	if switched {
		f.logf("finished an identity rotation whose answer was lost: the agent identity is now %s", f.Fingerprint())
	}
	return switched, err
}

// tryNext asks the server for the state once with the key next (the
// identity.next in dfd). An answer for that identity (200, or
// not_approved for a row the admin has not approved) means the server
// holds it: identity.next is promoted, and tryNext reports true.
// unknown_agent means the server does not know it (false, nil). Anything
// else (the server unreachable, a 5xx, a rate limit) is an error: the
// outcome is unknown, and identity.next must stay (PR #72 review C9).
func (f *Fetcher) tryNext(ctx context.Context, dfd int, next ed25519.PrivateKey, v serverclient.AgentVersions) (bool, error) {
	trial := &Fetcher{cfg: f.cfg, fc: f.fc}
	if err := trial.useKeyOnly(next); err != nil {
		return false, err
	}
	_, _, err := trial.client.AgentStateAt(ctx, v)
	switch {
	case isAPIError(err, serverclient.AgentErrUnknown):
		return false, nil
	case err != nil && !isAPIError(err, serverclient.AgentErrNotApproved):
		return false, fmt.Errorf("trying %s: %w", IdentityNextFile, err)
	}
	if err := f.promote(dfd); err != nil {
		return false, err
	}
	return true, nil
}

// dropStaleNext removes an identity.next that the server never took: the
// current identity was just accepted, and rotation holds the same flock,
// so no rotation is in flight.
func (f *Fetcher) dropStaleNext() {
	dfd, err := spool.OpenDir(f.cfg.Dir)
	if err != nil {
		return
	}
	defer func() { _ = unix.Close(dfd) }()
	if err := unix.Unlinkat(dfd, IdentityNextFile, 0); err == nil {
		_ = unix.Fsync(dfd)
		f.logf("removed %s: the server never took that rotation; run --rotate-identity again", IdentityNextFile)
	}
}

// journalPrefix is the journald priority prefix of an error line when the
// process logs to the journal.
func journalPrefix() string {
	if os.Getenv("JOURNAL_STREAM") != "" {
		return "<3>"
	}
	return ""
}

// sendHeartbeat posts the applier's status.json from the outbox (03-08,
// AGENT-07), read through spool.ReadFileAt (no symlink, a regular file,
// at most heartbeat.MaxStatus bytes) and checked as the server checks it,
// with clock_offset_s: the server's Date header minus this host's clock
// when the poll's answer arrived, in whole seconds. An offset whose
// magnitude is above heartbeat.ClockSkewS is logged at error level
// (clock_skew). The server answers 409 stale_heartbeat while the status
// is the one it stored already, which is the usual case between the
// applier's writes: that is not an error (owner decision D-2).
func (f *Fetcher) sendHeartbeat(ctx context.Context) error {
	fd, err := spool.OpenDir(f.cfg.Outbox)
	if err != nil {
		return err
	}
	b, err := spool.ReadFileAt(fd, heartbeat.StatusFile, heartbeat.MaxStatus)
	_ = unix.Close(fd)
	if errors.Is(err, unix.ENOENT) {
		f.logf("no %s in the outbox yet (keyroster-agent run writes it); no heartbeat", heartbeat.StatusFile)
		return nil
	}
	if err != nil {
		return fmt.Errorf("%s: %w", heartbeat.StatusFile, err)
	}
	s, err := heartbeat.ParseStatus(b)
	if err != nil {
		return fmt.Errorf("%s: %w", heartbeat.StatusFile, err)
	}
	h := heartbeat.Heartbeat{Status: *s}
	if f.haveOffset {
		h.ClockOffsetS = f.offset
		if heartbeat.ClockSkew(f.offset) {
			_, _ = fmt.Fprintf(f.logw(), "%skeyroster-agent-fetch: ERROR clock_skew: the server's clock minus this host's is %+d s, more than %d s either way; fix this host's clock: the agent's swap timing and certificate expiry rely on it\n",
				journalPrefix(), f.offset, heartbeat.ClockSkewS)
		}
	}
	body, err := trust.CanonicalJSON(h)
	if err != nil {
		return err
	}
	err = f.client.AgentHeartbeat(ctx, body)
	var he *serverclient.HTTPError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &he) && he.Code == http.StatusConflict && he.APIErrorIs(serverclient.AgentErrStaleHeartbeat):
		return nil
	case errors.As(err, &he):
		if _, ok := he.RateLimited(); ok {
			return nil
		}
	}
	return fmt.Errorf("heartbeat: %w", err)
}

// logw is where error lines that carry their own prefix go.
func (f *Fetcher) logw() interface{ Write([]byte) (int, error) } {
	if f.cfg.Log == nil {
		return discard{}
	}
	return f.cfg.Log
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

// clockOffset is date minus received in whole seconds, as clock_offset_s
// carries it (the Date header's resolution is one second).
func clockOffset(date, received time.Time) int64 { return date.Unix() - received.Unix() }
