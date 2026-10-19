//go:build !linux

// Command keyroster-server is keyroster's web front. It runs next to the
// signer, whose Unix socket needs Linux peer credentials, so on every
// other OS it only reports that (PLAT-05).
package main

import (
	"fmt"
	"os"
)

func main() {
	_, _ = fmt.Fprintln(os.Stderr, "keyroster-server runs on Linux only (PLAT-05)")
	os.Exit(1)
}
