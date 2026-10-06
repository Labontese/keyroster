//go:build linux

package tpm

import (
	"fmt"

	"github.com/Labontese/keyroster/internal/keystore"
)

// Inspect opens the TPM named by the stored backend options (device or
// swtpm-socket), reads its manufacturer ID and returns it with the custody
// the backend derives from it: vtpm for a software or virtual TPM, or when
// the options force custody=vtpm, otherwise tpm. Unlike opening the backend,
// it does not refuse a custody=tpm option on a virtual TPM; it reports what
// the TPM is, so that keyroster-signer doctor can compare it with the
// recorded custody. It loads, creates and signs nothing.
func Inspect(opts map[string]string) (string, keystore.Custody, error) {
	t, err := openTransport(opts)
	if err != nil {
		return "", "", fmt.Errorf("keystore tpm: open TPM: %w", err)
	}
	defer func() { _ = t.Close() }()
	tpmMu.Lock()
	id, err := Manufacturer(t)
	tpmMu.Unlock()
	if err != nil {
		return "", "", fmt.Errorf("keystore tpm: read the TPM manufacturer: %w", err)
	}
	custody := CustodyForManufacturer(id)
	if keystore.Custody(opts["custody"]) == keystore.CustodyVTPM {
		custody = keystore.CustodyVTPM
	}
	return id, custody, nil
}
