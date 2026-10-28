//go:build linux

// Package fetch is keyroster-agent-fetch (03-07, D-05): the agent's
// unprivileged half, run as the system user keyroster-agent. It does all
// of the agent's network I/O, to one server only, and writes only its own
// directory and the spool; it runs no program and opens no listening
// socket. It holds no authority: every byte it spools is verified by the
// root applier against the applier's own pins (T-03-41), so a compromised
// fetcher can only withhold or delay.
//
// It authenticates with a self-signed Ed25519 client certificate it
// generated (D-02; no agent CA) and verifies the server like the CLI: a
// pool of the pinned TLS roots plus the host name, and a chain that must
// end in a pinned root (serverclient.New). The closed operation set is
// enrollment and state (AGENT-02).
package fetch

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Labontese/keyroster/internal/agent/enroll"
	"github.com/Labontese/keyroster/internal/agent/join"
	"github.com/Labontese/keyroster/internal/agent/spool"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/trust"
)

// File names in the fetcher's own directory.
const (
	// IdentityKeyFile is the fetcher's Ed25519 identity key, PKCS #8 PEM,
	// mode 0600.
	IdentityKeyFile = "identity.key"
	// JoinTokenFile is the join token install left (join.FetcherToken);
	// the fetcher removes it once the server accepted its enrollment.
	JoinTokenFile = "join-token"
	maxSmallFile  = 64 << 10
)

// DefaultPoll is the poll interval; NextPoll adds a uniform jitter of a
// sixth of it either way, so 60 s polls fall in [50 s, 70 s] (D-10).
// MinPoll is the shortest interval (tests).
const (
	DefaultPoll = 60 * time.Second
	MinPoll     = time.Second
	// MaxRounds bounds the state requests of one poll while the server
	// answers more: true; the server's per-identity burst matches it.
	MaxRounds = serverclient.MaxAgentStateRounds
)

// Refusals.
var (
	// ErrPoPMismatch is an enroll-pop.json that names another identity or
	// token than this fetcher's: it is not posted (F2).
	ErrPoPMismatch = errors.New("enroll_pop_mismatch")
	ErrConfig      = errors.New("fetch_config_invalid")
)

// Config is one fetcher.
type Config struct {
	// ConfigFile is fetch.json (join.FetchConfig); Dir the fetcher's own
	// directory; Spool and Outbox the applier's spool and outbox.
	ConfigFile, Dir, Spool, Outbox string
	// Poll is the poll interval (DefaultPoll when 0).
	Poll time.Duration
	// Log receives one line per event (nil: nowhere).
	Log io.Writer
}

// Fetcher is a configured fetcher with its identity loaded.
type Fetcher struct {
	cfg     Config
	client  *serverclient.Client
	spkiHex string
	lastLog string
}

// New reads fetch.json, loads or creates the identity key in Dir (0600),
// makes its self-signed certificate (CN keyroster-agent, a random serial,
// valid from an hour ago for 100 years: the server ignores validity and
// pins the key), writes identity.pub into the spool and builds the pinned
// mTLS client.
func New(cfg Config) (*Fetcher, error) {
	if cfg.Poll == 0 {
		cfg.Poll = DefaultPoll
	}
	if cfg.Poll < MinPoll {
		return nil, fmt.Errorf("%w: poll interval %s below %s", ErrConfig, cfg.Poll, MinPoll)
	}
	fc, err := readFetchConfig(cfg.ConfigFile)
	if err != nil {
		return nil, err
	}
	key, err := loadIdentity(cfg.Dir)
	if err != nil {
		return nil, err
	}
	cert, err := selfSigned(key)
	if err != nil {
		return nil, err
	}
	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, err
	}
	if err := writeIdentityPub(cfg.Spool, spki); err != nil {
		return nil, err
	}
	client, err := serverclient.New(serverclient.Config{Server: fc.Server, RootsPEM: fc.TLSRoots, Pins: fc.TLSPins, Certificates: []tls.Certificate{cert}})
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(spki)
	return &Fetcher{cfg: cfg, client: client, spkiHex: hex.EncodeToString(sum[:])}, nil
}

// IdentitySPKISHA256 is the lowercase hex SHA-256 of the identity's SPKI.
func (f *Fetcher) IdentitySPKISHA256() string { return f.spkiHex }

// logf writes one line; a line equal to the previous one is not repeated,
// so a host waiting for its approval logs that once.
func (f *Fetcher) logf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if f.cfg.Log == nil || msg == f.lastLog {
		return
	}
	f.lastLog = msg
	_, _ = fmt.Fprintf(f.cfg.Log, "keyroster-agent-fetch: %s\n", msg)
}

// Run polls until ctx ends: Once, then NextPoll(cfg.Poll). Errors are
// logged and never end the loop.
func (f *Fetcher) Run(ctx context.Context) error {
	for {
		if err := f.Once(ctx); err != nil {
			f.logf("ERROR %v", err)
		}
		t := time.NewTimer(NextPoll(f.cfg.Poll))
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}

// NextPoll is base plus a uniform jitter in [-base/6, +base/6], from
// crypto/rand.
func NextPoll(base time.Duration) time.Duration {
	span := int64(base / 6)
	if span <= 0 {
		return base
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return base
	}
	n := int64(binary.BigEndian.Uint64(b[:]) % uint64(2*span+1)) //nolint:gosec // G115: below 2*span+1, which fits an int64
	return base + time.Duration(n-span)
}

// Once is one poll: while the join token is there, the enrollment step;
// otherwise the state, asked again at once while the server answers
// more: true, at most MaxRounds times.
func (f *Fetcher) Once(ctx context.Context) error {
	tok, err := f.readToken()
	if err != nil {
		return err
	}
	if tok != nil {
		return f.enroll(ctx, tok)
	}
	return f.pollState(ctx)
}

// readToken reads the join token install left, or nil when it is gone.
func (f *Fetcher) readToken() (*join.FetcherToken, error) {
	fd, err := spool.OpenDir(f.cfg.Dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(fd) }()
	b, err := spool.ReadFileAt(fd, JoinTokenFile, maxSmallFile)
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var t join.FetcherToken
	if err := trust.DecodeStrict(b, &t); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrConfig, JoinTokenFile, err)
	}
	if err := join.CheckFetcherToken(&t); err != nil {
		return nil, err
	}
	return &t, nil
}

// enroll is the enrollment step (F2): write enroll-request.json into the
// spool, read the applier's enroll-pop.json from the outbox (none yet:
// wait for the next poll), refuse one that names another identity or
// token (enroll_pop_mismatch, logged, not posted), and post it. A 202
// removes the join token and the request. A token the server says is used
// already removes them too when the server knows this identity (an
// earlier 202 that never arrived).
func (f *Fetcher) enroll(ctx context.Context, tok *join.FetcherToken) error {
	raw, err := join.DecodeToken(tok.Token)
	if err != nil {
		return err
	}
	req := enroll.Request{IdentitySPKISHA256: f.spkiHex, TokenSHA256: join.TokenSHA256(raw), ExpectedName: tok.ExpectedName, InstallationID: tok.InstallationID}
	b, err := trust.CanonicalJSON(req)
	if err != nil {
		return err
	}
	if err := writeIfChanged(f.cfg.Spool, enroll.RequestFile, b, 0o644); err != nil {
		return err
	}
	ans, err := f.readAnswer()
	if err != nil {
		return err
	}
	if ans == nil {
		f.logf("waiting for the applier's proof of possession (keyroster-agent run)")
		return nil
	}
	if ans.PoP.IdentitySPKISHA256 != req.IdentitySPKISHA256 || ans.PoP.TokenSHA256 != req.TokenSHA256 || ans.PoP.InstallationID != req.InstallationID {
		f.logf("ERROR %v: %s names another identity, token or installation; not posted, waiting for a fresh one", ErrPoPMismatch, enroll.AnswerFile)
		return nil
	}
	_, err = f.client.AgentEnroll(ctx, &serverclient.AgentEnrollRequest{Token: tok.Token, HostKeys: ans.PoP.HostKeys, Sigs: ans.Sigs, Facts: ans.Facts})
	var he *serverclient.HTTPError
	switch {
	case err == nil:
		f.logf("enrolled as host %s, pending approval (identity %s)", tok.ExpectedName, enroll.IdentityFingerprint(mustHex(f.spkiHex)))
		return f.finishEnrollment()
	case errors.As(err, &he) && he.APIErrorIs(serverclient.AgentErrTokenUsed):
		if _, serr := f.client.AgentState(ctx, serverclient.AgentVersions{}); serr == nil || isAPIError(serr, serverclient.AgentErrNotApproved) {
			f.logf("the server already enrolled this identity (the token is used); pending approval")
			return f.finishEnrollment()
		}
		return fmt.Errorf("enrollment refused: the join token was used already by another agent; ask an admin for a new one (keyroster host join-token): %w", err)
	}
	return fmt.Errorf("enrollment: %w", err)
}

// finishEnrollment removes the join token and the request.
func (f *Fetcher) finishEnrollment() error {
	for _, x := range []struct{ dir, name string }{{f.cfg.Dir, JoinTokenFile}, {f.cfg.Spool, enroll.RequestFile}} {
		fd, err := spool.OpenDir(x.dir)
		if err != nil {
			return err
		}
		err = unix.Unlinkat(fd, x.name, 0)
		_ = unix.Fsync(fd)
		_ = unix.Close(fd)
		if err != nil && !errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("remove %s: %w", x.name, err)
		}
	}
	return nil
}

// readAnswer reads enroll-pop.json from the outbox through
// spool.ReadFileAt, or nil when there is none yet.
func (f *Fetcher) readAnswer() (*enroll.Answer, error) {
	fd, err := spool.OpenDir(f.cfg.Outbox)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(fd) }()
	b, err := spool.ReadFileAt(fd, enroll.AnswerFile, enroll.MaxAnswerFile)
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var a enroll.Answer
	if err := trust.DecodeStrict(b, &a); err != nil {
		return nil, fmt.Errorf("%s: %w", enroll.AnswerFile, err)
	}
	return &a, nil
}

// pollState asks for the state newer than the spool's newest versions and
// spools it, again at once while the server answers more: true, at most
// MaxRounds times. not_approved waits for the next poll.
func (f *Fetcher) pollState(ctx context.Context) error {
	for range MaxRounds {
		v, err := spooledVersions(f.cfg.Spool)
		if err != nil {
			return err
		}
		resp, err := f.client.AgentState(ctx, v)
		if isAPIError(err, serverclient.AgentErrNotApproved) {
			f.logf("enrolled, waiting for an admin's approval (keyroster host approve)")
			return nil
		}
		var he *serverclient.HTTPError
		if errors.As(err, &he) {
			if secs, ok := he.RateLimited(); ok {
				// What was spooled stays; the next poll goes on from it
				// (PR #71 review F4).
				f.logf("the server is rate limiting this agent (retry after %d s); continuing at the next poll", secs)
				return nil
			}
		}
		if err != nil {
			return fmt.Errorf("state: %w", err)
		}
		if err := writeState(f.cfg.Spool, resp); err != nil {
			return err
		}
		if n := len(resp.Bundles) + len(resp.Directories); n > 0 || resp.KRL != nil {
			f.logf("spooled %d bundle and %d directory versions and %d KRL", len(resp.Bundles), len(resp.Directories), boolInt(resp.KRL != nil))
		}
		if !resp.More {
			return nil
		}
	}
	return nil
}

// writeState spools every item of r, one at a time and in the response's
// order (bundles, then directories, then the KRL), through spool.Write:
// each file atomically, signatures before the document they complete.
// The file names come from the item's kind and its uint64 version only.
func writeState(dir string, r *serverclient.AgentStateResponse) error {
	for _, b := range r.Bundles {
		if err := spool.Write(dir, spool.State{
			Bundles:  map[uint64]spool.Doc{b.Version: {Body: b.Bundle, Sigs: b.BundleSigs}},
			Policies: map[uint64]spool.Doc{b.PolicyVersion: {Body: b.Policy, Sigs: b.PolicySigs}},
		}); err != nil {
			return err
		}
	}
	for _, d := range r.Directories {
		if err := spool.Write(dir, spool.State{Directories: map[uint64]spool.Doc{d.Version: {Body: d.Directory, Sigs: d.Sigs}}}); err != nil {
			return err
		}
	}
	if k := r.KRL; k != nil {
		if err := spool.Write(dir, spool.State{KRLs: map[uint64]spool.KRLFiles{k.Version: {KRL: k.KRL, Manifest: k.Manifest, Sig: k.Sig}}}); err != nil {
			return err
		}
	}
	return nil
}

var (
	spoolDocRE = regexp.MustCompile(`^(bundle|directory)-([1-9][0-9]{0,19})\.json$`)
	spoolKRLRE = regexp.MustCompile(`^krl-([1-9][0-9]{0,19})\.krl$`)
)

// spooledVersions are the newest complete bundle, directory and KRL
// versions in the spool: what a state request names.
func spooledVersions(dir string) (serverclient.AgentVersions, error) {
	var v serverclient.AgentVersions
	fd, err := spool.OpenDir(dir)
	if err != nil {
		return v, err
	}
	defer func() { _ = unix.Close(fd) }()
	names, err := spool.ListDir(fd)
	if err != nil {
		return v, err
	}
	present := map[string]bool{}
	for _, n := range names {
		present[n] = true
	}
	for _, n := range names {
		if m := spoolDocRE.FindStringSubmatch(n); m != nil && present[n+".sigs"] {
			x, err := strconv.ParseUint(m[2], 10, 64)
			if err != nil {
				continue
			}
			if m[1] == "bundle" {
				v.Bundle = max(v.Bundle, x)
			} else {
				v.Directory = max(v.Directory, x)
			}
		}
		if m := spoolKRLRE.FindStringSubmatch(n); m != nil {
			base := "krl-" + m[1]
			if x, err := strconv.ParseUint(m[1], 10, 64); err == nil && present[base+".manifest.json"] && present[base+".manifest.sig"] {
				v.KRL = max(v.KRL, x)
			}
		}
	}
	return v, nil
}

// readFetchConfig reads fetch.json: canonical JSON of join.FetchConfig,
// the server, root and pin rules of a join string.
func readFetchConfig(path string) (*join.FetchConfig, error) {
	dir, name := splitPath(path)
	fd, err := spool.OpenDir(dir)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfig, err)
	}
	defer func() { _ = unix.Close(fd) }()
	b, err := spool.ReadFileAt(fd, name, maxSmallFile)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfig, err)
	}
	var c join.FetchConfig
	if err := trust.DecodeStrict(b, &c); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrConfig, path, err)
	}
	if err := join.CheckFetchConfig(&c); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrConfig, path, err)
	}
	return &c, nil
}

// loadIdentity reads the identity key from dir, or makes one and writes
// it there (mode 0600, through spool.WriteFileAt).
func loadIdentity(dir string) (ed25519.PrivateKey, error) {
	fd, err := spool.OpenDir(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(fd) }()
	b, err := spool.ReadFileAt(fd, IdentityKeyFile, maxSmallFile)
	if err == nil {
		block, rest := pem.Decode(b)
		if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
			return nil, fmt.Errorf("%s: not one PEM PRIVATE KEY block", IdentityKeyFile)
		}
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", IdentityKeyFile, err)
		}
		ek, ok := k.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%s: not an Ed25519 key", IdentityKeyFile)
		}
		return ek, nil
	}
	if !errors.Is(err, unix.ENOENT) {
		return nil, err
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := spool.WriteFileAt(fd, IdentityKeyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

// selfSigned makes the identity's self-signed client certificate.
func selfSigned(key ed25519.PrivateKey) (tls.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "keyroster-agent"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(100, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// writeIdentityPub writes the identity's SPKI as a PEM PUBLIC KEY block to
// the spool's identity.pub, for keyroster-agent identity.
func writeIdentityPub(dir string, spki []byte) error {
	return writeIfChanged(dir, enroll.IdentityFile, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}), 0o644)
}

// writeIfChanged writes name in dir through spool.WriteFileAt unless it
// holds exactly data already.
func writeIfChanged(dir, name string, data []byte, mode uint32) error {
	fd, err := spool.OpenDir(dir)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	if old, err := spool.ReadFileAt(fd, name, int64(len(data))); err == nil && string(old) == string(data) {
		return nil
	}
	return spool.WriteFileAt(fd, name, data, mode)
}

// splitPath splits an absolute file path into its directory and name.
func splitPath(p string) (string, string) {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			if i == 0 {
				return "/", p[1:]
			}
			return p[:i], p[i+1:]
		}
	}
	return ".", p
}

// isAPIError reports whether err is an HTTP refusal with code.
func isAPIError(err error, code string) bool {
	var he *serverclient.HTTPError
	return errors.As(err, &he) && (he.Code == http.StatusForbidden || he.Code == http.StatusConflict) && he.APIErrorIs(code)
}

func mustHex(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
