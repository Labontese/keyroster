//go:build !e2e && (e2e_pkcs11 || e2e_tpm)

package e2e

import (
	"os"
	"testing"

	"golang.org/x/crypto/ssh"
)

// fingerprint returns the SHA256 fingerprint of an OpenSSH public key file.
// bootstrap_test.go needs it under every e2e build tag; under the e2e tag
// issue_test.go defines it, and this copy serves the hardware-backend
// suites (e2e_pkcs11, e2e_tpm) that build without that file.
func fingerprint(t *testing.T, pubFile string) string {
	t.Helper()
	data, err := os.ReadFile(pubFile) //nolint:gosec // test fixture
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		t.Fatal(err)
	}
	return ssh.FingerprintSHA256(pub)
}
