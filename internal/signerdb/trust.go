package signerdb

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"time"
)

// Errors of the trust tables.
var (
	// ErrNotInitialised means ca-init has not run on this database.
	ErrNotInitialised = errors.New("signerdb: CA keys not initialised (run keyroster-signer ca-init)")
	// ErrNoBundle means no trust bundle is installed.
	ErrNoBundle = errors.New("signerdb: no trust bundle installed")
)

// CARoles is the fixed order of the ca_keys roles.
var CARoles = []string{"user", "host", "machine", "ops", "log"}

// CAKey is one row of ca_keys.
type CAKey struct {
	Role      string
	PublicKey []byte // SSH wire encoding
	Alg       string
	Custody   string
}

// StoredBundle is one installed trust bundle with its policy and the
// detached root signatures over both.
type StoredBundle struct {
	Version     uint64
	Bundle      []byte
	BundleSigs  []byte
	Policy      []byte
	PolicySigs  []byte
	InstalledAt time.Time
}

// SaveBackendConfig stores the backend name and options inside tx. It fails
// if a configuration is already stored.
func (d *DB) SaveBackendConfig(tx *sql.Tx, name string, opts map[string]string) error {
	if name == "" {
		return errors.New("signerdb: empty backend name")
	}
	if opts == nil {
		opts = map[string]string{}
	}
	js, err := json.Marshal(opts) // encoding/json sorts map keys
	if err != nil {
		return fmt.Errorf("signerdb: backend options: %w", err)
	}
	if _, err := tx.Exec(`INSERT INTO backend_config (id, name, opts_json) VALUES (1, ?, ?)`, name, string(js)); err != nil {
		return fmt.Errorf("signerdb: insert backend config: %w", err)
	}
	return nil
}

// BackendConfig returns the stored backend name and options, or
// ErrNotInitialised.
func (d *DB) BackendConfig(ctx context.Context) (string, map[string]string, error) {
	var name, js string
	err := d.db.QueryRowContext(ctx, `SELECT name, opts_json FROM backend_config WHERE id = 1`).Scan(&name, &js)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil, ErrNotInitialised
	}
	if err != nil {
		return "", nil, fmt.Errorf("signerdb: read backend config: %w", err)
	}
	opts := map[string]string{}
	if err := json.Unmarshal([]byte(js), &opts); err != nil {
		return "", nil, fmt.Errorf("signerdb: backend options: %w", err)
	}
	return name, opts, nil
}

// SaveCAKeys stores the five role keys inside tx, each also as generation 1
// of its role in ca_key_generations (03-12). Every role must appear exactly
// once; the schema refuses a key used for two roles.
func (d *DB) SaveCAKeys(tx *sql.Tx, keys []CAKey) error {
	if len(keys) != len(CARoles) {
		return fmt.Errorf("signerdb: want %d CA keys, got %d", len(CARoles), len(keys))
	}
	for i, k := range keys {
		if k.Role != CARoles[i] || len(k.PublicKey) == 0 || k.Alg == "" || k.Custody == "" {
			return fmt.Errorf("signerdb: incomplete or misordered CA key %d", i)
		}
		if _, err := tx.Exec(`INSERT INTO ca_keys (role, pubkey, alg, custody) VALUES (?, ?, ?, ?)`,
			k.Role, k.PublicKey, k.Alg, k.Custody); err != nil {
			return fmt.Errorf("signerdb: insert CA key %s: %w", k.Role, err)
		}
		if _, err := tx.Exec(`INSERT INTO ca_key_generations (role, generation, pubkey, alg, custody, location, created_at_us) VALUES (?, 1, ?, ?, ?, '', 0)`,
			k.Role, k.PublicKey, k.Alg, k.Custody); err != nil {
			return fmt.Errorf("signerdb: insert CA key generation 1 of %s: %w", k.Role, err)
		}
	}
	return nil
}

// CAGeneration is one row of ca_key_generations (03-12): a CA key
// generation of a role. Generation 1 is the ca-init key; every later one
// was recorded by ca-rotate prepare together with a ca_generation log
// entry. Location is the backend's handle for the key (empty for the
// software, agent and memory backends); it is not logged.
type CAGeneration struct {
	Role            string
	Generation      uint32
	PublicKey       []byte // SSH wire encoding
	Alg             string
	Custody         string
	Location        string
	CreatedAtMicros int64
}

// CAGenerations returns every stored CA key generation in the order of
// CARoles, then by generation.
func (d *DB) CAGenerations(ctx context.Context) ([]CAGeneration, error) {
	return caGenerations(ctx, d.db)
}

func caGenerations(ctx context.Context, q queryer) ([]CAGeneration, error) {
	rows, err := q.QueryContext(ctx, `SELECT role, generation, pubkey, alg, custody, location, created_at_us FROM ca_key_generations ORDER BY generation`)
	if err != nil {
		return nil, fmt.Errorf("signerdb: read CA key generations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	byRole := map[string][]CAGeneration{}
	for rows.Next() {
		var (
			g   CAGeneration
			gen int64
		)
		if err := rows.Scan(&g.Role, &gen, &g.PublicKey, &g.Alg, &g.Custody, &g.Location, &g.CreatedAtMicros); err != nil {
			return nil, fmt.Errorf("signerdb: read CA key generations: %w", err)
		}
		if gen < 1 || gen > math.MaxUint32 {
			return nil, fmt.Errorf("signerdb: invalid CA key generation %d of %s", gen, g.Role)
		}
		g.Generation = uint32(gen) //nolint:gosec // G115: 1 <= gen <= MaxUint32, checked above
		if !slices.Contains(CARoles, g.Role) {
			return nil, fmt.Errorf("signerdb: CA key generation of unknown role %q", g.Role)
		}
		byRole[g.Role] = append(byRole[g.Role], g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("signerdb: read CA key generations: %w", err)
	}
	var out []CAGeneration
	for _, role := range CARoles {
		out = append(out, byRole[role]...)
	}
	return out, nil
}

// InsertCAGenerationTx stores generation g.Generation of g.Role inside tx.
// It refuses generation 1 (ca-init's) and every generation that is not the
// role's stored maximum plus 1; the schema refuses a key that any stored
// generation of any role already uses.
func (d *DB) InsertCAGenerationTx(tx *sql.Tx, g CAGeneration) error {
	if g.Generation < 2 {
		return fmt.Errorf("signerdb: CA key generation %d of %s: generation 1 is ca-init's", g.Generation, g.Role)
	}
	if len(g.PublicKey) == 0 || g.Alg == "" || g.Custody == "" {
		return fmt.Errorf("signerdb: incomplete CA key generation %d of %s", g.Generation, g.Role)
	}
	var latest int64
	if err := tx.QueryRow(`SELECT COALESCE(MAX(generation), 0) FROM ca_key_generations WHERE role = ?`, g.Role).Scan(&latest); err != nil {
		return fmt.Errorf("signerdb: read CA key generation of %s: %w", g.Role, err)
	}
	if latest < 1 || int64(g.Generation) != latest+1 {
		return fmt.Errorf("signerdb: CA key generation %d of %s is not the next after stored generation %d", g.Generation, g.Role, latest)
	}
	if _, err := tx.Exec(`INSERT INTO ca_key_generations (role, generation, pubkey, alg, custody, location, created_at_us) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		g.Role, int64(g.Generation), g.PublicKey, g.Alg, g.Custody, g.Location, g.CreatedAtMicros); err != nil {
		return fmt.Errorf("signerdb: insert CA key generation %d of %s: %w", g.Generation, g.Role, err)
	}
	return nil
}

// CAKeys returns the stored role keys in the order of CARoles, or
// ErrNotInitialised when there are none.
func (d *DB) CAKeys(ctx context.Context) ([]CAKey, error) {
	return caKeys(ctx, d.db)
}

func caKeys(ctx context.Context, q queryer) ([]CAKey, error) {
	rows, err := q.QueryContext(ctx, `SELECT role, pubkey, alg, custody FROM ca_keys`)
	if err != nil {
		return nil, fmt.Errorf("signerdb: read CA keys: %w", err)
	}
	defer func() { _ = rows.Close() }()
	byRole := map[string]CAKey{}
	for rows.Next() {
		var k CAKey
		if err := rows.Scan(&k.Role, &k.PublicKey, &k.Alg, &k.Custody); err != nil {
			return nil, fmt.Errorf("signerdb: read CA keys: %w", err)
		}
		byRole[k.Role] = k
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("signerdb: read CA keys: %w", err)
	}
	if len(byRole) == 0 {
		return nil, ErrNotInitialised
	}
	out := make([]CAKey, 0, len(CARoles))
	for _, role := range CARoles {
		k, ok := byRole[role]
		if !ok {
			return nil, fmt.Errorf("signerdb: CA key for role %s missing", role)
		}
		out = append(out, k)
	}
	return out, nil
}

// InsertBundle stores an installed bundle inside tx. Versions must
// strictly increase.
func (d *DB) InsertBundle(tx *sql.Tx, b StoredBundle) error {
	v, err := toInt64(b.Version)
	if err != nil {
		return err
	}
	if v < 1 || len(b.Bundle) == 0 || len(b.BundleSigs) == 0 || len(b.Policy) == 0 || len(b.PolicySigs) == 0 || b.InstalledAt.IsZero() {
		return errors.New("signerdb: incomplete trust bundle record")
	}
	var latest int64
	if err := tx.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM trust_bundle`).Scan(&latest); err != nil {
		return fmt.Errorf("signerdb: read bundle version: %w", err)
	}
	if v <= latest {
		return fmt.Errorf("signerdb: bundle version %d is not above the installed version %d", v, latest)
	}
	if _, err := tx.Exec(`INSERT INTO trust_bundle (version, bundle, bundle_sigs, policy, policy_sigs, installed_at_us) VALUES (?, ?, ?, ?, ?, ?)`,
		v, b.Bundle, b.BundleSigs, b.Policy, b.PolicySigs, b.InstalledAt.UnixMicro()); err != nil {
		return fmt.Errorf("signerdb: insert trust bundle: %w", err)
	}
	return nil
}

// LatestBundleVersion returns the highest installed bundle version, or 0
// when none is installed.
func (d *DB) LatestBundleVersion(ctx context.Context) (uint64, error) {
	return latestBundleVersion(ctx, d.db)
}

// LatestBundleVersionTx is LatestBundleVersion inside tx, so that a check
// against it holds until tx commits.
func (d *DB) LatestBundleVersionTx(ctx context.Context, tx *sql.Tx) (uint64, error) {
	return latestBundleVersion(ctx, tx)
}

func latestBundleVersion(ctx context.Context, q queryer) (uint64, error) {
	var v int64
	if err := q.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM trust_bundle`).Scan(&v); err != nil {
		return 0, fmt.Errorf("signerdb: read bundle version: %w", err)
	}
	if v < 0 {
		return 0, errors.New("signerdb: invalid trust bundle version")
	}
	return uint64(v), nil //nolint:gosec // G115: v >= 0, checked above
}

// LatestBundle returns the installed bundle with the highest version, or
// ErrNoBundle.
func (d *DB) LatestBundle(ctx context.Context) (*StoredBundle, error) {
	return latestBundle(ctx, d.db)
}

func latestBundle(ctx context.Context, q queryer) (*StoredBundle, error) {
	var (
		b       StoredBundle
		version int64
		at      int64
	)
	err := q.QueryRowContext(ctx, `SELECT version, bundle, bundle_sigs, policy, policy_sigs, installed_at_us FROM trust_bundle ORDER BY version DESC LIMIT 1`).
		Scan(&version, &b.Bundle, &b.BundleSigs, &b.Policy, &b.PolicySigs, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoBundle
	}
	if err != nil {
		return nil, fmt.Errorf("signerdb: read trust bundle: %w", err)
	}
	if version < 1 {
		return nil, errors.New("signerdb: invalid trust bundle version")
	}
	b.Version = uint64(version) //nolint:gosec // G115: version >= 1, checked above
	b.InstalledAt = time.UnixMicro(at)
	return &b, nil
}

// BundleByVersion returns the installed bundle of version v, or
// ErrNoBundle when none was installed at v (03-07: the chain an agent
// catches up through).
func (d *DB) BundleByVersion(ctx context.Context, v uint64) (*StoredBundle, error) {
	iv, err := toInt64(v)
	if err != nil {
		return nil, err
	}
	var (
		b  StoredBundle
		at int64
	)
	err = d.db.QueryRowContext(ctx, `SELECT bundle, bundle_sigs, policy, policy_sigs, installed_at_us FROM trust_bundle WHERE version = ?`, iv).
		Scan(&b.Bundle, &b.BundleSigs, &b.Policy, &b.PolicySigs, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoBundle
	}
	if err != nil {
		return nil, fmt.Errorf("signerdb: read trust bundle %d: %w", v, err)
	}
	b.Version, b.InstalledAt = v, time.UnixMicro(at)
	return &b, nil
}
