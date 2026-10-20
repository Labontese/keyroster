package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestRunbookGoToolchain: the install runbooks build with go.mod's
// toolchain line and check it in the binaries. An older toolchain builds
// fine (the go directive is lower) but links a standard library whose
// fixed vulnerabilities the server and client reach, and nothing else
// would notice.
func TestRunbookGoToolchain(t *testing.T) {
	mod, err := os.ReadFile(filepath.Join("..", "..", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^toolchain (go1\.[0-9]+\.[0-9]+)\s*$`).FindSubmatch(mod)
	if m == nil {
		t.Fatal("go.mod has no toolchain line")
	}
	toolchain := string(m[1])
	goVersion := regexp.MustCompile(`go1\.[0-9]+\.[0-9]+`)
	for _, name := range []string{"signer-install.md", "server-install.md"} {
		data, err := os.ReadFile(filepath.Join("..", "..", "docs", "runbooks", name)) //nolint:gosec // G304: a constant runbook name under docs/runbooks
		if err != nil {
			t.Fatal(err)
		}
		doc := string(data)
		for _, v := range goVersion.FindAllString(doc, -1) {
			if v != toolchain {
				t.Errorf("%s names %s, but go.mod's toolchain line is %s", name, v, toolchain)
			}
		}
		if !strings.Contains(doc, `export GOTOOLCHAIN=$(awk '$1 == "toolchain" {print $2}' go.mod)`) {
			t.Errorf("%s does not set GOTOOLCHAIN from go.mod's toolchain line before building", name)
		}
		if !regexp.MustCompile(`(?m)^go version keyroster`).MatchString(doc) {
			t.Errorf("%s does not check the built binaries with go version", name)
		}
	}
}
