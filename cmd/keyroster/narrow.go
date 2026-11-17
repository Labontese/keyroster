package main

import (
	"context"
	"io"
	"time"

	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/trust"
)

// trustClock is the client's clock for every CA-set reader of the CLI
// (03-12d): the host CA lines of the managed known_hosts, host ca-key,
// init and host status. Tests replace it.
var trustClock = time.Now

// narrowKnownHosts is the line filter of the managed known_hosts file
// (03-12d). Not implemented yet: it returns data unchanged.
func narrowKnownHosts(data []byte, _ []string) ([]byte, int) {
	return data, 0
}

// narrowHostTrust narrows the managed known_hosts file to the host CAs b
// trusts at now (03-12d). Not implemented yet.
func narrowHostTrust(_ *trust.Bundle, _ time.Time, _ io.Writer) {}

// verifiedTrust is the one caller of serverclient.Trust of the CLI
// (03-12d). It returns exactly what Trust returns.
func verifiedTrust(ctx context.Context, c *serverclient.Client, cfg *Config, _ io.Writer) (*trust.Bundle, *trust.Policy, error) {
	return c.Trust(ctx, cfg.TrustPins, cfg.TrustThreshold, cfg.InstallationID)
}
