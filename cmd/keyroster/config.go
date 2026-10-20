package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"

	"github.com/Labontese/keyroster/internal/serverclient"
)

// Config is the keyroster CLI's saved server setup, written by keyroster
// init: the server URL, the TLS root certificates and pins the user
// confirmed out of band, the trust-root pins and threshold the served
// trust bundle must match, and the user's name and admin key.
//
// It holds only public data, so what matters is its integrity. On Unix it
// is written 0600 in a 0700 directory. On Windows file modes are a no-op:
// the file inherits the per-user %APPDATA% ACL (the user, SYSTEM and
// Administrators). That is enough, because anyone who can write the
// user's profile can also replace the keyroster binary (02-06-F11).
type Config struct {
	Server         string   `json:"server"`
	TLSRootsPEM    []string `json:"tls_roots_pem"`
	TLSPins        []string `json:"tls_pins"`
	TrustPins      []string `json:"trust_pins"`
	TrustThreshold int      `json:"trust_threshold"`
	User           string   `json:"user,omitempty"`
	AdminKey       string   `json:"admin_key,omitempty"`
}

// userConfigDir is os.UserConfigDir; tests point it at a temporary
// directory on every OS.
var userConfigDir = os.UserConfigDir

// errConfigExists refuses to overwrite a saved config without --force.
var errConfigExists = errors.New("a keyroster config already exists; re-run with --force to replace it")

// configPath returns <user config dir>/keyroster/config.json.
func configPath() (string, error) {
	base, err := userConfigDir()
	if err != nil {
		return "", fmt.Errorf("user config directory: %w", err)
	}
	return filepath.Join(base, "keyroster", "config.json"), nil
}

// configExists reports whether a config file is already saved.
func configExists() (bool, error) {
	p, err := configPath()
	if err != nil {
		return false, err
	}
	_, err = os.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

// loadConfig reads the saved config.
func loadConfig() (*Config, error) {
	p, err := configPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p) //nolint:gosec // G304: the user's own config file
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("no keyroster config at %s; run keyroster init first", p)
		}
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	// A server URL saved before ParseServerURL canonicalized it (an
	// upper-case host, a trailing dot, :443) loads as its canonical form.
	// One it refuses is left as saved, for the command's own check.
	if u, err := serverclient.ParseServerURL(c.Server); err == nil {
		c.Server = u.String()
	}
	return &c, nil
}

// saveConfig writes c as the saved config: 0600 in a 0700 directory, via
// a temporary file renamed into place. It refuses an existing file unless
// force is set.
func saveConfig(c *Config, force bool) (string, error) {
	p, err := configPath()
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: a directory needs its x bit
			return "", err
		}
	}
	if exists, err := configExists(); err != nil {
		return "", err
	} else if exists && !force {
		return "", errConfigExists
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(dir, ".config-*.json")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp.Name(), p); err != nil {
		return "", err
	}
	return p, nil
}
