//go:build !unix && !windows

package rootceremony

import "errors"

// readFD is unsupported where descriptors cannot be inherited.
func readFD(int, []byte) (int, error) {
	return 0, errors.New("--passphrase-fd is not supported on this platform")
}
