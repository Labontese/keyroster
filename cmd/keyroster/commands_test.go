package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestDispatchUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := dispatch(context.Background(), []string{"no-such-command"}, &stdout, &stderr); got != 2 {
		t.Fatalf("dispatch(unknown) = %d, want 2", got)
	}
	if !strings.Contains(stderr.String(), "unknown command") {
		t.Errorf("stderr = %q, want it to mention the unknown command", stderr.String())
	}
	if !strings.Contains(stderr.String(), "version") {
		t.Errorf("stderr = %q, want the command list", stderr.String())
	}
}

func TestDispatchNoCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := dispatch(context.Background(), nil, &stdout, &stderr); got != 2 {
		t.Fatalf("dispatch(no args) = %d, want 2", got)
	}
}

func TestDispatchVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := dispatch(context.Background(), []string{"version"}, &stdout, &stderr); got != 0 {
		t.Fatalf("dispatch(version) = %d, want 0 (stderr %q)", got, stderr.String())
	}
	if !strings.HasPrefix(stdout.String(), "keyroster ") {
		t.Errorf("stdout = %q, want prefix %q", stdout.String(), "keyroster ")
	}
}

func TestDispatchVersionRejectsArguments(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := dispatch(context.Background(), []string{"version", "extra"}, &stdout, &stderr); got != 2 {
		t.Fatalf("dispatch(version extra) = %d, want 2", got)
	}
}

func TestDispatchCommandError(t *testing.T) {
	withTestCommand(t, command{
		Name:    "test-fail",
		Summary: "always fails",
		Run: func(context.Context, []string, io.Writer, io.Writer) error {
			return errors.New("boom")
		},
	})
	var stdout, stderr bytes.Buffer
	if got := dispatch(context.Background(), []string{"test-fail"}, &stdout, &stderr); got != 1 {
		t.Fatalf("dispatch(test-fail) = %d, want 1", got)
	}
	if !strings.Contains(stderr.String(), "boom") {
		t.Errorf("stderr = %q, want the error message", stderr.String())
	}
}

func TestRegisterDuplicatePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("register(duplicate) did not panic")
		}
	}()
	register(command{
		Name: "version",
		Run:  func(context.Context, []string, io.Writer, io.Writer) error { return nil },
	})
}

// withTestCommand registers c for the duration of the test.
func withTestCommand(t *testing.T, c command) {
	t.Helper()
	register(c)
	t.Cleanup(func() { delete(registry, c.Name) })
}
