//go:build windows

package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

// The help advises only a host-scoped IdentityAgent block, never
// SSH_AUTH_SOCK, and warns against loading keys into the agent pipe with the
// inbox OpenSSH tools, which do not check who serves it (T-02-07 residual
// risk; owner decision 2026-10-17).
func TestAgentHelpWarnsAgainstSSHAdd(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := runAgent(context.Background(), []string{"-h"}, &stdout, &stderr); !errors.Is(err, errUsage) {
		t.Fatalf("keyroster agent -h = %v, want errUsage", err)
	}
	help := strings.Join(strings.Fields(stderr.String()), " ")
	for _, want := range []string{
		"Host <your keyroster hosts> IdentityAgent //./pipe/keyroster-agent-<your SID>",
		"Only keyroster login adds keys to this agent.",
		"Do not add keys to the pipe with ssh-add or AddKeysToAgent",
		"do not check who serves it",
		"the pipe name can be taken by a process of another local account or by a sandboxed process of your own (Low integrity, or a restricted or deny-only token)",
		"limits the inbox clients' exposure to such a pipe to your keyroster hosts",
	} {
		if !strings.Contains(help, want) {
			t.Errorf("keyroster agent -h does not say %q:\n%s", want, stderr.String())
		}
	}
	if strings.Contains(help, "SSH_AUTH_SOCK") {
		t.Errorf("keyroster agent -h still advises SSH_AUTH_SOCK:\n%s", stderr.String())
	}
}
