//go:build linux && piv

package main

// The YubiKey PIV backend (KEY-05) is linked only into builds with the piv
// build tag, which need CGO_ENABLED=1 and pcsc-lite. Default and release
// binaries do not include it (docs/backends/piv.md).
import _ "github.com/Labontese/keyroster/internal/keystore/piv"
