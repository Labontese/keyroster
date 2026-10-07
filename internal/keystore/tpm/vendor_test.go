//go:build linux

package tpm

import (
	"testing"

	"github.com/Labontese/keyroster/internal/keystore"
)

// TestCustodyForManufacturer (D-WR-02): the mapping fails closed. Only the
// allowlisted physical and firmware TPM vendors are tpm; the virtual
// IBM/MSFT/GOOG and every unknown ID are vtpm, so a vTPM-held key is never
// reported as hardware TPM custody.
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
		"intc": keystore.CustodyVTPM, // IDs are case-sensitive
		"XYZ":  keystore.CustodyVTPM, // unknown: not hardware
		"QEMU": keystore.CustodyVTPM, // unknown: not hardware
	} {
		if got := CustodyForManufacturer(id); got != want {
			t.Errorf("CustodyForManufacturer(%q) = %s, want %s", id, got, want)
		}
	}
}

// TestDeriveCustody (D-WR-02): the test-only swtpm socket is always vtpm,
// whatever manufacturer the process behind it claims, and custody=vtpm
// only ever weakens the result.
func TestDeriveCustody(t *testing.T) {
	for _, tc := range []struct {
		id   string
		opts map[string]string
		want keystore.Custody
	}{
		{"INTC", map[string]string{"device": "/dev/tpmrm0"}, keystore.CustodyTPM},
		{"INTC", map[string]string{}, keystore.CustodyTPM},
		{"INTC", map[string]string{"swtpm-socket": "/tmp/s"}, keystore.CustodyVTPM},
		{"INTC", map[string]string{"custody": "vtpm"}, keystore.CustodyVTPM},
		{"INTC", map[string]string{"custody": "tpm"}, keystore.CustodyTPM},
		{"IBM", map[string]string{"custody": "tpm"}, keystore.CustodyVTPM},
		{"XYZ", map[string]string{}, keystore.CustodyVTPM},
	} {
		if got := deriveCustody(tc.id, tc.opts); got != tc.want {
			t.Errorf("deriveCustody(%q, %v) = %s, want %s", tc.id, tc.opts, got, tc.want)
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
