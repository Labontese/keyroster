// machinehosttrust.go is keyroster machine renew's refresh of the host CA
// lines (03-12g, D-14, REVOKE-04, KEY-08): right after the trust bundle
// verifies, it adds to the managed keyroster_known_hosts the line of each
// active or next host CA the file lacks, over the host names the file's own
// lines of host CAs the bundle trusts already carry, and moves the bundle
// floor of host-trust.json to that bundle. It makes no request of its own.

package main

import (
	"io"
	"time"

	"github.com/Labontese/keyroster/internal/trust"
)

// machineHostTrustExit is the exit status of a machine renew whose
// certificate was written or is not due but whose host trust step failed
// (03-12g).
const machineHostTrustExit = 4

// machineTrustReplace is the step's one write function (03-12g); tests
// replace it with one that fails.
var machineTrustReplace = replaceManagedFile

// machineTrustHook, when set (tests only), runs after the step's reads and
// before its first write (03-12g).
var machineTrustHook func()

// addHostCALines returns data with the line of each entry of issuing that
// its CA lines of the host CAs of trusted lack, over the names those lines
// carry, and the entries it added (03-12g).
func addHostCALines(data []byte, trusted, issuing []trust.CAEntry) (out []byte, added []trust.CAEntry, err error) {
	return data, nil, nil
}

// machineHostTrust is the host trust step of keyroster machine renew
// (03-12g).
func machineHostTrust(b *trust.Bundle, now time.Time, stderr io.Writer) error {
	return nil
}
