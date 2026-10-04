package main

import (
	"context"
	"fmt"
	"io"
	"runtime"
	"runtime/debug"
)

func init() {
	register(command{
		Name:    "version",
		Summary: "print the keyroster version and build information",
		Run:     runVersion,
	})
}

func runVersion(_ context.Context, args []string, stdout, _ io.Writer) error {
	if len(args) != 0 {
		return errUsage
	}
	_, err := fmt.Fprintln(stdout, versionString())
	return err
}

// versionString formats "keyroster <module version> (<revision> <time>) <go version>"
// from the build information embedded by the Go toolchain.
func versionString() string {
	version, revision, vcsTime := "(devel)", "unknown", "unknown"
	if info, ok := debug.ReadBuildInfo(); ok {
		if info.Main.Version != "" {
			version = info.Main.Version
		}
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				revision = s.Value
			case "vcs.time":
				vcsTime = s.Value
			}
		}
	}
	return fmt.Sprintf("keyroster %s (%s %s) %s", version, revision, vcsTime, runtime.Version())
}
