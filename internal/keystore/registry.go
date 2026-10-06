package keystore

import (
	"fmt"
	"slices"
	"sort"
	"sync"
)

// Factory opens a backend from its options. A factory must refuse option
// keys it does not know (CheckOptions does that).
type Factory func(opts map[string]string) (Backend, error)

var (
	registryMu sync.Mutex
	registry   = map[string]Factory{}
)

// Register makes a backend available under name. Backends call it from an
// init function; a duplicate or empty name panics, since both are
// programming errors.
func Register(name string, f Factory) {
	registryMu.Lock()
	defer registryMu.Unlock()
	if name == "" || f == nil {
		panic("keystore: Register with an empty name or nil factory")
	}
	if _, dup := registry[name]; dup {
		panic("keystore: duplicate backend " + name)
	}
	registry[name] = f
}

// Open opens the backend registered under name. An unknown backend is an
// error, and so is an option key the backend does not know.
func Open(name string, opts map[string]string) (Backend, error) {
	registryMu.Lock()
	f, ok := registry[name]
	registryMu.Unlock()
	if !ok {
		return nil, fmt.Errorf("keystore: unknown backend %q (available: %v)", name, Backends())
	}
	if opts == nil {
		opts = map[string]string{}
	}
	return f(opts)
}

// Backends lists the registered backend names, sorted.
func Backends() []string {
	registryMu.Lock()
	defer registryMu.Unlock()
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// CheckOptions returns an error naming the first option key (in sorted
// order) that is not in allowed. The reserved OptStateDir is always
// allowed.
func CheckOptions(opts map[string]string, allowed ...string) error {
	keys := make([]string, 0, len(opts))
	for k := range opts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if k != OptStateDir && !slices.Contains(allowed, k) {
			return fmt.Errorf("keystore: unknown backend option %q (allowed: %v)", k, allowed)
		}
	}
	return nil
}
