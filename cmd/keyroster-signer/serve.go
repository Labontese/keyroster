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

	"github.com/Labontese/keyroster/internal/keystore"
	"github.com/Labontese/keyroster/internal/signer"
	"github.com/Labontese/keyroster/internal/signerdb"
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
	backend := fs.String("backend", "agent", "keystore backend")
	userCAFP := fs.String("user-ca-fp", "", "pinned SHA256 fingerprint of the user CA key (SHA256:...)")
	logKeyFP := fs.String("log-key-fp", "", "pinned SHA256 fingerprint of the audit-log checkpoint key, role log, in the same backend (SHA256:...)")
	refusalPerMinute := fs.Int("refusal-log-per-minute", signer.DefaultRefusalLogPerMinute, "refused requests logged individually in the audit log per minute; the rest are counted in summary entries")
	refusalBurst := fs.Int("refusal-log-burst", signer.DefaultRefusalLogBurst, "refused requests that may be logged individually at once")
	var allowUIDs, allowGroups, backendOpts listFlag
	fs.Var(&allowUIDs, "allow-uid", "uid allowed to connect (repeatable)")
	fs.Var(&allowGroups, "allow-group", "group name or gid allowed to connect (repeatable); the first one also owns the socket")
	fs.Var(&backendOpts, "backend-opt", "backend option key=value (repeatable)")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if fs.NArg() != 0 || *stateDir == "" || *userCAFP == "" || *logKeyFP == "" {
		_, _ = fmt.Fprintln(stderr, "serve: --state-dir, --user-ca-fp and --log-key-fp are required; no positional arguments")
		return errUsage
	}
	if !strings.HasPrefix(*userCAFP, "SHA256:") {
		return errors.New("--user-ca-fp must be a SHA256:... fingerprint")
	}
	if !strings.HasPrefix(*logKeyFP, "SHA256:") {
		return errors.New("--log-key-fp must be a SHA256:... fingerprint")
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
	opts, err := parseBackendOpts(backendOpts)
	if err != nil {
		return err
	}

	logger := slog.New(slog.NewTextHandler(stderr, nil))
	be, err := keystore.Open(*backend, opts)
	if err != nil {
		return err
	}
	defer func() { _ = be.Close() }()
	db, err := signerdb.Open(filepath.Join(*stateDir, "signer.db"))
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	s, err := signer.New(signer.Config{
		Backend:             be,
		UserCAFingerprint:   *userCAFP,
		LogKeyFingerprint:   *logKeyFP,
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
	logger.Info("serving", "socket", *socket, "backend", *backend, "user_ca", *userCAFP,
		"log_key", *logKeyFP, "allow_uids", len(uids), "allow_gids", len(gids))
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

func parseBackendOpts(vals []string) (map[string]string, error) {
	opts := make(map[string]string, len(vals))
	for _, v := range vals {
		k, val, ok := strings.Cut(v, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("--backend-opt %q: want key=value", v)
		}
		if _, dup := opts[k]; dup {
			return nil, fmt.Errorf("--backend-opt %q given twice", k)
		}
		opts[k] = val
	}
	return opts, nil
}
