//go:build linux

package tpm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/Labontese/keyroster/internal/keystore"
)

// virtualManufacturers are the TPM manufacturer IDs of software and virtual
// TPMs: IBM for swtpm/libtpms (which Proxmox VE and QEMU vTPMs use), MSFT
// for Hyper-V and Microsoft's reference simulator, GOOG for Google Cloud
// vTPMs. Their keys are only as safe as the host that holds the TPM state.
var virtualManufacturers = map[string]bool{"IBM": true, "MSFT": true, "GOOG": true}

// Manufacturer returns the TPM's 4-character manufacturer ID
// (TPM2_GetCapability, TPM_CAP_TPM_PROPERTIES, TPM_PT_MANUFACTURER), with
// trailing NUL and space padding removed, for example "IBM" or "INTC".
// The caller serialises TPM access.
func Manufacturer(t transport.TPM) (string, error) {
	rsp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTManufacturer),
		PropertyCount: 1,
	}.Execute(t)
	if err != nil {
		return "", err
	}
	props, err := rsp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return "", err
	}
	for _, p := range props.TPMProperty {
		if p.Property != tpm2.TPMPTManufacturer {
			continue
		}
		var raw [4]byte
		binary.BigEndian.PutUint32(raw[:], p.Value)
		id := strings.TrimRight(string(raw[:]), "\x00 ")
		if id == "" {
			return "", errors.New("empty TPM manufacturer ID")
		}
		for _, c := range id {
			if c < 0x20 || c > 0x7e {
				return "", fmt.Errorf("TPM manufacturer ID %q is not printable", raw[:])
			}
		}
		return id, nil
	}
	return "", errors.New("the TPM did not report TPM_PT_MANUFACTURER")
}

// CustodyForManufacturer maps a TPM manufacturer ID to custody: vtpm for
// software and virtual TPMs (IBM, MSFT, GOOG), tpm for every other ID.
func CustodyForManufacturer(id string) keystore.Custody {
	if virtualManufacturers[id] {
		return keystore.CustodyVTPM
	}
	return keystore.CustodyTPM
}
