// Package custodytext holds the user-facing custody warnings that the
// keyroster CLI (and, from 02-06, keyroster-server) print from the custody
// the signer reports over Status (D-18). The text lives here once, and
// docs/security/custody.md quotes it verbatim (custodytext_test.go checks
// that). keyroster-signer never imports this package: the signer reports
// custody, it does not carry UI text.
package custodytext

import (
	"fmt"
	"slices"
	"strings"

	"github.com/Labontese/keyroster/internal/wire"
)

// softwareCABanner is the evaluation-only warning for software CA keys
// (KEY-06). %s is the roles whose custody is software, joined by ", ". It
// is hard-wrapped so that with all five roles no line is longer than 76
// columns, and its first line starts with "EVALUATION ONLY - SOFTWARE CA
// KEY", which tests grep for. HTML collapses the newlines, so a web page
// renders it as one paragraph.
const softwareCABanner = `EVALUATION ONLY - SOFTWARE CA KEY: the %s keys
of this keyroster signer are software keys (custody software). Anyone who
copies the key files and their passphrase can issue certificates. Do not
use this instance for real access (docs/security/custody.md).`

// roleOrder is the signer's fixed role order.
var roleOrder = []string{"user", "host", "machine", "ops", "log"}

// SoftwareCABanner returns the evaluation-only warning for roles, the
// roles whose custody the signer reports as software. It has no trailing
// newline.
func SoftwareCABanner(roles []string) string {
	return fmt.Sprintf(softwareCABanner, strings.Join(roles, ", "))
}

// SoftwareRoles returns the roles of keys whose custody is software, in
// the signer's role order (user, host, machine, ops, log; any other role
// after those, in the order given), or an empty slice when none is.
func SoftwareRoles(keys []wire.KeyStatus) []string {
	out := []string{}
	for _, role := range roleOrder {
		for _, k := range keys {
			if k.Role == role && k.Custody == "software" && !slices.Contains(out, role) {
				out = append(out, role)
			}
		}
	}
	for _, k := range keys {
		if k.Custody == "software" && !slices.Contains(out, k.Role) {
			out = append(out, k.Role)
		}
	}
	return out
}
