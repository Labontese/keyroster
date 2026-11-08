//go:build linux && keyroster_e2e

package apply

// DisableProbes switches the probe self-test off for cfg (03-10b,
// T-03-243). It exists only in the e2e test build: no default build can
// switch the probes off, and every other file of the package names the
// build only as "the e2e test build".
func DisableProbes(cfg *Config) { cfg.probeOff = true }
