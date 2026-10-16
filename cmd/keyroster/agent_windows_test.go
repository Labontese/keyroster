//go:build windows

package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

// The help warns against loading keys into the agent pipe with the inbox
// OpenSSH tools, which do not check who serves it (T-02-07 residual risk).
func TestAgentHelpWarnsAgainstSSHAdd(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := runAgent(context.Background(), []string{"-h"}, &stdout, &stderr); !errors.Is(err, errUsage) {
		t.Fatalf("keyroster agent -h = %v, want errUsage", err)
	}
	help := strings.Join(strings.Fields(stderr.String()), " ")
	for _, want := range []string{
		"Only keyroster login adds keys to this agent.",
		"Do not add keys to the pipe with ssh-add or AddKeysToAgent",
		"do not check who serves it",
		"another local account can create a pipe with this name",
	} {
		if !strings.Contains(help, want) {
			t.Errorf("keyroster agent -h does not say %q:\n%s", want, stderr.String())
		}
	}
}
