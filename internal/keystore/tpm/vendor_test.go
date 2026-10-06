//go:build linux

package tpm

import (
	"testing"

	"github.com/Labontese/keyroster/internal/keystore"
)

// TestCustodyForManufacturer: software and virtual TPMs are vtpm, physical
// vendors and unknown IDs are tpm. A vTPM-held key is never reported as
// hardware TPM custody.
func TestCustodyForManufacturer(t *testing.T) {
	for id, want := range map[string]keystore.Custody{
		"IBM":  keystore.CustodyVTPM, // swtpm/libtpms: QEMU, Proxmox VE
		"MSFT": keystore.CustodyVTPM, // Hyper-V, Microsoft simulator
		"GOOG": keystore.CustodyVTPM, // Google Cloud vTPM
		"INTC": keystore.CustodyTPM,  // Intel PTT
		"AMD":  keystore.CustodyTPM,  // AMD fTPM
		"IFX":  keystore.CustodyTPM,  // Infineon
		"NTC":  keystore.CustodyTPM,  // Nuvoton
		"STM":  keystore.CustodyTPM,  // STMicroelectronics
		"ibm":  keystore.CustodyTPM,  // IDs are case-sensitive
	} {
		if got := CustodyForManufacturer(id); got != want {
			t.Errorf("CustodyForManufacturer(%q) = %s, want %s", id, got, want)
		}
	}
}

// TestManufacturerSWTPM: swtpm reports IBM through TPM2_GetCapability.
func TestManufacturerSWTPM(t *testing.T) {
	sock := startSWTPM(t)
	tp, err := openTransport(map[string]string{"swtpm-socket": sock})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tp.Close() }()
	tpmMu.Lock()
	id, err := Manufacturer(tp)
	tpmMu.Unlock()
	if err != nil || id != "IBM" {
		t.Fatalf("Manufacturer = %q, %v; want IBM", id, err)
	}
}

// TestInspectSWTPM: Inspect reports swtpm as IBM, custody vtpm, also when
// the options claim custody tpm (it reports, it does not refuse), and fails
// for a TPM that is not there.
func TestInspectSWTPM(t *testing.T) {
	sock := startSWTPM(t)
	for _, custody := range []string{"", "vtpm", "tpm"} {
		id, c, err := Inspect(map[string]string{"swtpm-socket": sock, "custody": custody})
		if err != nil || id != "IBM" || c != keystore.CustodyVTPM {
			t.Fatalf("Inspect(custody=%q) = %q, %q, %v; want IBM, vtpm", custody, id, c, err)
		}
	}
	if _, _, err := Inspect(map[string]string{"swtpm-socket": sock + ".missing"}); err == nil {
		t.Fatal("Inspect of a missing TPM socket succeeded")
	}
}
