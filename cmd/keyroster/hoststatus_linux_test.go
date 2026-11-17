//go:build linux

package main

import (
	"testing"

	"github.com/Labontese/keyroster/internal/agent/apply"
)

// TestUserCAKeysPath (03-12d): the live count of host status looks for the
// generation file the agent writes its user CA keys to.
func TestUserCAKeysPath(t *testing.T) {
	if userCAKeysPath != apply.CAFile {
		t.Fatalf("userCAKeysPath = %q, the agent writes %q", userCAKeysPath, apply.CAFile)
	}
}
