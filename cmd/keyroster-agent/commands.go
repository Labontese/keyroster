//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
)

// command is one keyroster-agent subcommand; commands live in their own
// files and register from an init function.
type command struct {
	Name    string
	Summary string
	Run     func(ctx context.Context, args []string, stdout, stderr io.Writer) error
}

// registry holds every registered command by name.
var registry = map[string]command{}

// errUsage reports a command-line usage error (exit status 2).
var errUsage = errors.New("usage error")

// exitError ends a command with a fixed exit status (03-06: preflight
// exits 3 on a refusal and 2 on a tool error, check 3 on drift). err, when
// set, is printed first.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string {
	if e.err == nil {
		return fmt.Sprintf("exit status %d", e.code)
	}
	return e.err.Error()
}

func (e *exitError) Unwrap() error { return e.err }

// register adds c to the registry. It panics on an empty name, a nil Run
// or a duplicate name: programming errors caught at start-up.
func register(c command) {
	if c.Name == "" {
		panic("keyroster-agent: register: empty command name")
	}
	if c.Run == nil {
		panic("keyroster-agent: register: command " + c.Name + " has no Run function")
	}
	if _, dup := registry[c.Name]; dup {
		panic("keyroster-agent: register: duplicate command " + c.Name)
	}
	registry[c.Name] = c
}

// dispatch runs the command named by args[0] and returns the exit status:
// 0 on success, 2 for a missing or unknown command or a usage error, 1
// for any other error.
func dispatch(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}
	c, ok := registry[args[0]]
	if !ok {
		_, _ = fmt.Fprintf(stderr, "keyroster-agent: unknown command %q\n", args[0])
		printUsage(stderr)
		return 2
	}
	if err := c.Run(ctx, args[1:], stdout, stderr); err != nil {
		var ee *exitError
		if errors.As(err, &ee) {
			if ee.err != nil {
				_, _ = fmt.Fprintf(stderr, "keyroster-agent %s: %v\n", c.Name, ee.err)
			}
			return ee.code
		}
		if errors.Is(err, errUsage) {
			printUsage(stderr)
			return 2
		}
		_, _ = fmt.Fprintf(stderr, "keyroster-agent %s: %v\n", c.Name, err)
		return 1
	}
	return 0
}

// printUsage writes the sorted command list to w.
func printUsage(w io.Writer) {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString("usage: keyroster-agent <command> [arguments]\n\ncommands:\n")
	for _, name := range names {
		fmt.Fprintf(&b, "  %-12s %s\n", name, registry[name].Summary)
	}
	_, _ = io.WriteString(w, b.String())
}

func init() {
	register(command{
		Name:    "version",
		Summary: "print the keyroster-agent version and build information",
		Run:     runVersion,
	})
}

func runVersion(_ context.Context, args []string, stdout, _ io.Writer) error {
	if len(args) != 0 {
		return errUsage
	}
	version, revision := "(devel)", "unknown"
	if info, ok := debug.ReadBuildInfo(); ok {
		if info.Main.Version != "" {
			version = info.Main.Version
		}
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" {
				revision = s.Value
			}
		}
	}
	_, err := fmt.Fprintf(stdout, "keyroster-agent %s (%s) %s\n", version, revision, runtime.Version())
	return err
}
