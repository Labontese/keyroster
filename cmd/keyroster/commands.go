package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// command is one keyroster subcommand. Command groups (ca, audit, root,
// trust, ...) live in their own files and add themselves with register from
// an init function, so main.go never changes when a command is added.
type command struct {
	Name    string
	Summary string
	Run     func(ctx context.Context, args []string, stdout, stderr io.Writer) error
}

// registry holds every registered command by name.
var registry = map[string]command{}

// errUsage reports a command-line usage error. dispatch maps it to exit
// status 2 and prints the command list.
var errUsage = errors.New("usage error")

// register adds c to the registry. It panics on an empty name, a nil Run or a
// duplicate name: all three are programming errors caught at start-up.
func register(c command) {
	if c.Name == "" {
		panic("keyroster: register: empty command name")
	}
	if c.Run == nil {
		panic("keyroster: register: command " + c.Name + " has no Run function")
	}
	if _, dup := registry[c.Name]; dup {
		panic("keyroster: register: duplicate command " + c.Name)
	}
	registry[c.Name] = c
}

// dispatch runs the command named by args[0] with the remaining arguments.
// It returns the process exit status: 0 on success, 2 for a missing or
// unknown command or a usage error, and 1 for any other error.
func dispatch(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}
	c, ok := registry[args[0]]
	if !ok {
		// A failed write to stderr cannot be reported anywhere; the exit
		// status still carries the outcome.
		_, _ = fmt.Fprintf(stderr, "keyroster: unknown command %q\n", args[0])
		printUsage(stderr)
		return 2
	}
	if err := c.Run(ctx, args[1:], stdout, stderr); err != nil {
		if errors.Is(err, errUsage) {
			printUsage(stderr)
			return 2
		}
		_, _ = fmt.Fprintf(stderr, "keyroster %s: %v\n", c.Name, err)
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
	b.WriteString("usage: keyroster <command> [arguments]\n\ncommands:\n")
	for _, name := range names {
		fmt.Fprintf(&b, "  %-12s %s\n", name, registry[name].Summary)
	}
	_, _ = io.WriteString(w, b.String())
}
