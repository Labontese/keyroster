//go:build linux

package tpm

import (
	"errors"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"github.com/google/go-tpm/tpm2/transport/linuxudstpm"
)

// DefaultDevice is the kernel's TPM resource manager, the production path.
const DefaultDevice = "/dev/tpmrm0"

// openTransport opens the TPM named by the options: device (default
// /dev/tpmrm0, through the kernel resource manager) or, for tests and
// development only, swtpm-socket (an swtpm "socket --server type=unixio"
// socket carrying raw TPM commands). The two are mutually exclusive.
// go-tpm's simulator transport is never used (it links a cgo simulator).
func openTransport(opts map[string]string) (transport.TPMCloser, error) {
	device, socket := opts["device"], opts["swtpm-socket"]
	switch {
	case device != "" && socket != "":
		return nil, errors.New("keystore tpm: options device and swtpm-socket are mutually exclusive")
	case socket != "":
		return linuxudstpm.Open(socket)
	case device == "":
		device = DefaultDevice
	}
	return linuxtpm.Open(device)
}
