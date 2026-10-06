//go:build linux

package main

import (
	"context"
	"errors"
	"io"
)

func init() {
	register(command{
		Name:    "doctor",
		Summary: "check the state directory, database, audit log, clock and key custody",
		Run:     runDoctor,
	})
}

func runDoctor(_ context.Context, _ []string, _, _ io.Writer) error {
	return errors.New("not implemented")
}
