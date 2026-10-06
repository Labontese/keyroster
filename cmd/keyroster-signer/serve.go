//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/keystore"
	"github.com/Labontese/keyroster/internal/signer"
	"github.com/Labontese/keyroster/internal/signerdb"
	"github.com/Labontese/keyroster/internal/wire"
)

func init() {
	register(command{
		Name:    "serve",
		Summary: "serve signing requests on the Unix socket",
		Run:     runServe,
	})
}

// listFlag collects a repeatable string flag.
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }

func (l *listFlag) Set(v string) error {
	*l = append(*l, v)
	return nil
}

func runServe(ctx context.Context, args []string, _, stderr io.Writer) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateDir := fs.String("state-dir", "", "state directory (required; owned by this user, mode 0700); holds signer.db")
	socket := fs.String("socket", "/run/keyroster-signer/signer.sock", "Unix socket path")
	refusalPerMinute := fs.Int("refusal-log-per-minute", signer.DefaultRefusalLogPerMinute, "refused requests logged individually in the audit log per minute; the rest are counted in summary entries")
	refusalBurst := fs.Int("refusal-log-burst", signer.DefaultRefusalLogBurst, "refused requests that may be logged individually at once")
	var allowUIDs, allowGroups, backendOpts listFlag
	fs.Var(&allowUIDs, "allow-uid", "uid allowed to connect (repeatable)")
	fs.Var(&allowGroups, "allow-group", "group name or gid allowed to connect (repeatable); the first one also owns the socket")
	fs.Var(&backendOpts, "backend-opt", "override a backend option stored by ca-init, key=value (repeatable), e.g. socket=PATH; the keys and their custody must still match the trust bundle")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if fs.NArg() != 0 || *stateDir == "" {
		_, _ = fmt.Fprintln(stderr, "serve: --state-dir is required; no positional arguments")
		return errUsage
	}
	if *refusalPerMinute < 1 || *refusalBurst < 1 {
		return errors.New("--refusal-log-per-minute and --refusal-log-burst must be at least 1")
	}
	if err := checkStateDir(*stateDir); err != nil {
		return err
	}
	uids, err := parseUIDs(allowUIDs)
	if err != nil {
		return err
	}
	gids, err := resolveGroups(allowGroups)
	if err != nil {
		return err
	}
	overrides, err := parseBackendOpts(backendOpts)
	if err != nil {
		return err
	}

	logger := slog.New(slog.NewTextHandler(stderr, nil))
	db, err := signerdb.Open(filepath.Join(*stateDir, "signer.db"))
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	backend, be, err := openStoredBackend(ctx, db, overrides, *stateDir)
	if err != nil {
		return err
	}
	defer func() { _ = be.Close() }()

	s, err := signer.New(signer.Config{
		Backend:             be,
		DB:                  db,
		AllowUIDs:           uids,
		AllowGIDs:           gids,
		Logger:              logger,
		RefusalLogPerMinute: *refusalPerMinute,
		RefusalLogBurst:     *refusalBurst,
	})
	if err != nil {
		return err
	}
	socketGID := -1
	if len(gids) > 0 {
		socketGID = int(gids[0]) //nolint:gosec // G115: gids are <= math.MaxInt32 (resolveGroups)
	}
	l, err := signer.Listen(*socket, socketGID)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	logger.Info("serving", "socket", *socket, "backend", backend, "policy_version", s.PolicyVersion(),
		"user_ca", ssh.FingerprintSHA256(s.CAPublicKey(wire.CARoleUser)),
		"host_ca", ssh.FingerprintSHA256(s.CAPublicKey(wire.CARoleHost)),
		"machine_ca", ssh.FingerprintSHA256(s.CAPublicKey(wire.CARoleMachine)),
		"log_key", ssh.FingerprintSHA256(s.LogPublicKey()), "allow_uids", len(uids), "allow_gids", len(gids))
	if err := s.Serve(ctx, l); err != nil {
		return err
	}
	logger.Info("stopped")
	return nil
}

// checkStateDir requires an existing directory owned by the current uid
// with mode exactly 0700.
func checkStateDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("state dir: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("state dir %s is not a directory", dir)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("state dir %s: cannot read owner", dir)
	}
	if int64(st.Uid) != int64(os.Getuid()) {
		return fmt.Errorf("state dir %s is not owned by uid %d", dir, os.Getuid())
	}
	if fi.Mode().Perm() != 0o700 {
		return fmt.Errorf("state dir %s has mode %04o, want 0700", dir, fi.Mode().Perm())
	}
	return nil
}

func parseUIDs(vals []string) ([]uint32, error) {
	out := make([]uint32, 0, len(vals))
	for _, v := range vals {
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("--allow-uid %q: not a uid", v)
		}
		out = append(out, uint32(n)) //nolint:gosec // G115: ParseUint with bitSize 32
	}
	return out, nil
}

// resolveGroups maps group names (or numeric gids) to gids with os/user.
func resolveGroups(vals []string) ([]uint32, error) {
	out := make([]uint32, 0, len(vals))
	for _, v := range vals {
		gidStr := v
		if _, err := strconv.ParseUint(v, 10, 32); err != nil {
			g, err := user.LookupGroup(v)
			if err != nil {
				return nil, fmt.Errorf("--allow-group %q: %w", v, err)
			}
			gidStr = g.Gid
		}
		n, err := strconv.ParseUint(gidStr, 10, 32)
		if err != nil || n > math.MaxInt32 {
			return nil, fmt.Errorf("--allow-group %q: unusable gid %q", v, gidStr)
		}
		out = append(out, uint32(n)) //nolint:gosec // G115: n <= math.MaxInt32, checked above
	}
	return out, nil
}

// openStoredBackend opens the keystore backend ca-init recorded in db, with
// its stored options overridden by overrides (for example a new agent
// socket path). The keys are still selected by the fingerprints in the
// trust bundle, and their custody must match it, so an override cannot
// substitute another key. The backend also gets stateDir as the reserved
// state-dir option.
func openStoredBackend(ctx context.Context, db *signerdb.DB, overrides map[string]string, stateDir string) (string, keystore.Backend, error) {
	name, opts, err := db.BackendConfig(ctx)
	if errors.Is(err, signerdb.ErrNotInitialised) {
		return "", nil, signer.ErrNotInitialised
	}
	if err != nil {
		return "", nil, err
	}
	for k, v := range overrides {
		opts[k] = v
	}
	be, err := openBackend(name, opts, stateDir)
	if err != nil {
		return "", nil, err
	}
	return name, be, nil
}

// openState checks the state directory and opens its database.
func openState(stateDir string) (*signerdb.DB, error) {
	if err := checkStateDir(stateDir); err != nil {
		return nil, err
	}
	return signerdb.Open(filepath.Join(stateDir, "signer.db"))
}

func parseBackendOpts(vals []string) (map[string]string, error) {
	opts := make(map[string]string, len(vals))
	for _, v := range vals {
		k, val, ok := strings.Cut(v, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("--backend-opt %q: want key=value", v)
		}
		if k == keystore.OptStateDir {
			return nil, fmt.Errorf("--backend-opt %s is reserved: it is always the --state-dir directory", k)
		}
		if _, dup := opts[k]; dup {
			return nil, fmt.Errorf("--backend-opt %q given twice", k)
		}
		opts[k] = val
	}
	return opts, nil
}

// openBackend opens the keystore backend name with opts plus the reserved
// state-dir option (the absolute --state-dir), which is never stored.
func openBackend(name string, opts map[string]string, stateDir string) (keystore.Backend, error) {
	abs, err := filepath.Abs(stateDir)
	if err != nil {
		return nil, err
	}
	withDir := make(map[string]string, len(opts)+1)
	for k, v := range opts {
		withDir[k] = v
	}
	withDir[keystore.OptStateDir] = abs
	return keystore.Open(name, withDir)
}
