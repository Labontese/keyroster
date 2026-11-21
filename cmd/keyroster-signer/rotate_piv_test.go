//go:build linux && piv && pivfake

package main

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/keystore"
	"github.com/Labontese/keyroster/internal/keystore/piv"
	"github.com/Labontese/keyroster/internal/signerdb"
	"github.com/Labontese/keyroster/internal/trust"
)

// In a piv,pivfake build the piv backend opens the in-memory fake card of
// internal/keystore/piv/fake.go, so TestSignerRestartMixedBundle runs its
// piv leg here (03-12f); build-piv runs it.
func init() { pivRestartLeg = pivLeg }

// pivLegSerial is the fake card of the piv leg. The fake cards are
// process-wide per serial and never reset, so no other test of this
// package may use it.
const pivLegSerial = 1203101

// withStoredBackend opens the stored backend of st alone, as serve does,
// calls fn with it and closes it (03-12f).
func withStoredBackend(t *testing.T, st *rotateState, fn func(keystore.Backend)) {
	t.Helper()
	ctx := context.Background()
	db, err := signerdb.Open(st.db)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	_, be, err := openStoredBackend(ctx, db, nil, st.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = be.Close() }()
	fn(be)
}

// pivLeg is the rotation of TestSignerRestartMixedBundle on a PIV signer
// with a fake card (03-12f), in the operator's real state: the
// management-key file is at its stored path only for ca-init, the prepare
// that creates generation 2 and the first successful retire-key, and every
// other command runs with that path naming a missing file and with no
// --backend-opt override. prepare --key is refused by the resolver and uses
// no slot; prepare creates generation 2 in slot 87; the signer restarts
// and issues with generation 1; after the switch install serve refuses;
// retire-key without the management key is refused with no card write,
// and with it overwrites slot 82; a second run finds nothing; doctor does
// not ask the card, before the removal or after it; a restart issues with
// generation 2.
func pivLeg(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("doctor refuses to run as root; run the tests as a normal user")
	}
	secrets := t.TempDir()
	pin := filepath.Join(secrets, "pin")
	if err := os.WriteFile(pin, []byte(piv.FakePIN), 0o600); err != nil {
		t.Fatal(err)
	}
	mgmt := filepath.Join(secrets, "mgmt-key")
	place := func() {
		t.Helper()
		if err := os.WriteFile(mgmt, []byte(piv.FakeManagementKeyHex), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	remove := func() {
		t.Helper()
		if err := os.Remove(mgmt); err != nil {
			t.Fatal(err)
		}
	}
	st := &rotateState{dir: filepath.Join(t.TempDir(), "state")}
	if err := os.Mkdir(st.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	st.db = filepath.Join(st.dir, "signer.db")
	place()
	code, out := runSigner(t, "ca-init", "--backend", "piv", "--backend-opt", "pin-file="+pin, "--backend-opt", "mgmt-key-file="+mgmt,
		"--backend-opt", "serial="+strconv.Itoa(pivLegSerial), "--state-dir", st.dir)
	if code != 0 {
		t.Fatalf("ca-init exited %d:\n%s", code, out)
	}
	remove() // as docs/backends/piv.md step 5 does
	g := genesisFiles(t, st)
	install(t, st, g)
	user, _ := st.caPubKeys(t).Key(trust.RoleUser)
	pub1, err := trust.ParseKey(user.Key)
	if err != nil {
		t.Fatal(err)
	}
	fp1 := ssh.FingerprintSHA256(pub1)

	// --key is refused by the resolver, not by the distinctness check:
	// no prepare file, no row, no slot used.
	generated := piv.FakeCardGenerated(pivLegSerial)
	keyOut := filepath.Join(t.TempDir(), "user-key.json")
	code, out = runSigner(t, "ca-rotate", "prepare", "--state-dir", st.dir, "--role", "user", "--key", fp1, "--out", keyOut)
	if code == 0 || !strings.Contains(out, "signer: CA key selection refused") || !strings.Contains(out, "the generation's location names no slot it may use") ||
		strings.Contains(out, "equals stored generation") {
		t.Fatalf("ca-rotate prepare --key on piv exited %d, want the resolver's refusal:\n%s", code, out)
	}
	if _, err := os.Lstat(keyOut); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the refused prepare left %s: %v", keyOut, err)
	}
	if n := st.count(t, "SELECT count(*) FROM ca_key_generations WHERE role='user'"); n != 1 {
		t.Fatalf("ca_key_generations holds %d user rows after the refused prepare, want 1", n)
	}
	if got := piv.FakeCardGenerated(pivLegSerial); !slices.Equal(got, generated) {
		t.Fatalf("the refused prepare generated into %x, want %x", got, generated)
	}

	outFile := filepath.Join(t.TempDir(), "user-g2.json")
	place()
	code, out = runSigner(t, "ca-rotate", "prepare", "--state-dir", st.dir, "--role", "user", "--out", outFile)
	remove()
	if code != 0 || !strings.HasSuffix(out, "location: 87\n") {
		t.Fatalf("ca-rotate prepare exited %d, want the line location: 87 at the end:\n%s", code, out)
	}
	pf := readPrepareFile(t, outFile)
	pub2, err := trust.ParseKey(pf.Key)
	if err != nil {
		t.Fatal(err)
	}
	fp2 := ssh.FingerprintSHA256(pub2)
	if n := st.count(t, "SELECT count(*) FROM ca_key_generations WHERE role='user' AND generation=2 AND location='87'"); n != 1 {
		t.Fatalf("%d user generation 2 rows at location 87, want 1", n)
	}
	checkMixedBundle(t, st, fp1, fp2)
	issuedBy(t, st, g, fp1)
	v2 := installNext(t, st, g, genesisChain(t, g), pf)
	checkMixedBundle(t, st, fp1, fp2)
	if code, out := installSwitch(t, st, g, userSwitch(t, v2), "--previous", exportLog(t, st)); code != 0 {
		t.Fatalf("install-bundle of the switch exited %d:\n%s", code, out)
	}
	if err := startErr(t, st); err == nil || !strings.Contains(err.Error(), "draining_key_still_usable") {
		t.Fatalf("serve before retire-key: %v, want draining_key_still_usable", err)
	}

	// Without the management key: refused before any card write, and
	// generation 1 stays in slot 82.
	generated = piv.FakeCardGenerated(pivLegSerial)
	code, out = retireKey(t, st, "user")
	if code != 1 || !strings.Contains(out, "role user generation 1 "+fp1+": not removed: ") || !strings.Contains(out, "mgmt-key-file") {
		t.Fatalf("retire-key without the management key exited %d:\n%s", code, out)
	}
	if got := piv.FakeCardGenerated(pivLegSerial); !slices.Equal(got, generated) {
		t.Fatalf("the refused retire-key generated into %x, want %x", got, generated)
	}
	withStoredBackend(t, st, func(be keystore.Backend) {
		key, err := keystore.KeyFor(be, keystore.RoleUser, 1, fp1, "")
		if err != nil {
			t.Fatalf("generation 1 after the refused retire-key: %v", err)
		}
		signs(t, key)
	})
	// doctor does not read the card: with generation 1 still in slot 82 it
	// prints the same unchecked line as after the removal.
	_, out = runSigner(t, "doctor", "--state-dir", st.dir)
	requireLine(t, out, "WARN draining_key_unchecked: user generation 1 "+fp1+": ")
	if !strings.Contains(out, "doctor does not ask the piv backend") {
		t.Fatalf("doctor before retire-key does not give the reason:\n%s", out)
	}

	place()
	code, out = retireKey(t, st, "user")
	remove()
	if code != 0 || !strings.Contains(out, "role user generation 1 "+fp1+": removed\n") || !strings.Contains(out, "retire-key: no draining key of role user is held\n") {
		t.Fatalf("retire-key exited %d:\n%s", code, out)
	}
	if got, want := piv.FakeCardGenerated(pivLegSerial), append(slices.Clone(generated), 0x82); !slices.Equal(got, want) {
		t.Fatalf("retire-key generated into %x, want %x (one throwaway key over slot 82)", got, want)
	}
	withStoredBackend(t, st, func(be keystore.Backend) {
		if _, err := keystore.KeyFor(be, keystore.RoleUser, 1, fp1, ""); err == nil {
			t.Fatal("generation 1 still opens after retire-key")
		}
	})
	code, out = retireKey(t, st, "user")
	if code != 0 || !strings.Contains(out, "role user generation 1 "+fp1+": not held\n") {
		t.Fatalf("the second retire-key exited %d:\n%s", code, out)
	}
	_, out = runSigner(t, "doctor", "--state-dir", st.dir)
	requireLine(t, out, "WARN draining_key_unchecked: user generation 1 "+fp1+": ")
	if !strings.Contains(out, "doctor does not ask the piv backend") {
		t.Fatalf("doctor does not give the reason:\n%s", out)
	}
	issuedBy(t, st, g, fp2)
}
