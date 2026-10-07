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

// physicalManufacturers are the TPM manufacturer IDs that map to custody
// tpm: Intel (PTT), AMD (fTPM), Infineon, Nuvoton and STMicroelectronics.
// The list is an allowlist, so the mapping fails closed: every other ID,
// including the software and virtual TPMs (IBM for swtpm/libtpms, which
// Proxmox VE and QEMU vTPMs use; MSFT for Hyper-V and Microsoft's
// simulator; GOOG for Google Cloud) and any ID not listed here, maps to
// vtpm. Add a vendor only with evidence that its ID belongs to physical or
// firmware TPMs.
//
// The ID is what the TPM (or the hypervisor behind it) reports; nothing
// authenticates it. A hypervisor can claim INTC. Verifying the TPM's
// endorsement key certificate against the vendor's CA would close that
// gap; it is not done yet.
var physicalManufacturers = map[string]bool{"INTC": true, "AMD": true, "IFX": true, "NTC": true, "STM": true}

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

// CustodyForManufacturer maps a TPM manufacturer ID to custody: tpm for the
// allowlisted physical and firmware TPM vendors (physicalManufacturers),
// vtpm for every other ID.
func CustodyForManufacturer(id string) keystore.Custody {
	if physicalManufacturers[id] {
		return keystore.CustodyTPM
	}
	return keystore.CustodyVTPM
}

// deriveCustody is the custody of a TPM with manufacturer id, reached
// through the backend options opts. open and Inspect both use it, so
// doctor compares the recorded custody with the same rule. The test-only
// swtpm-socket transport is always vtpm, whatever ID the process behind the
// socket reports, and custody=vtpm forces vtpm; otherwise the manufacturer
// decides (CustodyForManufacturer). A custody=tpm option never changes the
// result: open refuses it when the result is not tpm.
func deriveCustody(id string, opts map[string]string) keystore.Custody {
	if opts["swtpm-socket"] != "" || keystore.Custody(opts["custody"]) == keystore.CustodyVTPM {
		return keystore.CustodyVTPM
	}
	return CustodyForManufacturer(id)
}
