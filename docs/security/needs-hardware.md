# needs-hardware: checks for the Phase 6 security review

Phase 1 verifies the hardware backends in CI only, with software stand-ins
(D-12): SoftHSM2 for a PKCS#11 HSM, an in-memory fake card for a YubiKey,
and OpenSSH's `sk-dummy.so` for a FIDO2 root. This checklist is what must
still run on **real devices** before the Phase 6 security review can sign
off. It is tracked by the GitHub issue labelled `needs-hardware`.

For every item, record in the issue: the device model and firmware, the
host OS and OpenSSH version, the keyroster commit, the commands run, their
output (fingerprints, custody lines, test results), and anything that
differed from the docs. Fix the docs or code through a normal PR when
something differs.

## 1. YubiHSM 2 through PKCS#11 and ssh-agent (KEY-03)

CI stand-in: SoftHSM2 in `.github/workflows/e2e-pkcs11.yml`, driven by
`test/e2e/pkcs11_test.go` (build tag `e2e_pkcs11`). That suite creates its
tokens with `scripts/softhsm-setup.sh`, so it cannot run against a YubiHSM 2
as is; run the same flow by hand.

- [ ] Set up the YubiHSM 2 as in [docs/backends/pkcs11.md](../backends/pkcs11.md):
      `yubihsm-connector` bound to `127.0.0.1`, `yubihsm_pkcs11.conf`, an
      authentication key with only the signing capabilities it needs, five
      key pairs (user-ca, host-ca, machine-ca, ops, log), a dedicated
      `ssh-agent` with `-P` allowing only `yubihsm_pkcs11.so`, and
      `ssh-add -s`.
- [ ] Repeat with P-256 keys, and with Ed25519 keys in an `ssh-agent` 10.1 or
      newer.
- [ ] Run the steps that `test/e2e/pkcs11_test.go` automates, in order:
      `keyroster-signer ca-init --backend agent --backend-opt
      custody=pkcs11-agent` with the five pinned fingerprints; a root-signed
      bundle (`keyroster root sign`); `keyroster-signer install-bundle`;
      `keyroster-signer serve`; an admin-signed `keyroster ca issue`; a
      login on a real sshd with the certificate; `keyroster audit verify
      --pin`.
- [ ] Check the refusals: a second `ca-init` is refused and changes nothing;
      eight concurrent `keyroster ca issue` calls give distinct, valid
      certificates; the PIN appears in no output and no process command line
      (`ps`).
- [ ] Record: `ca-pubkeys.json` and the bundle show custody `pkcs11-agent`
      for all five keys, `doctor` prints `INFO pkcs11_custody_declared`
      (never `OK custody`), and the five public keys match the HSM's own
      listing (`yubihsm-shell`), since the custody itself is only declared.

## 2. YubiKey 5 PIV (KEY-05)

CI stand-in: the fake card in `internal/keystore/piv/piv_test.go`, run by the
`build-piv` check (`.github/workflows/piv.yml`). Never run on a card:
`internal/keystore/piv/yubikey.go`, piv-go's card code, and every `ykman`,
`pcscd` and polkit step in [docs/backends/piv.md](../backends/piv.md).

Use two YubiKeys: one with firmware **5.7 or newer** (Ed25519) and one with
firmware **5.3 to 5.6** (P-256). For each:

- [ ] Build the signer with `CGO_ENABLED=1 go build -tags piv`, and record
      `go version -m` (piv-go v2.6.0, `-tags=piv`, `CGO_ENABLED=1`).
- [ ] Follow docs/backends/piv.md steps 1-3 exactly: change PIN, PUK and
      management key with `ykman`, add the polkit rule, write the 0600 PIN
      and management key files. Note every command that needed a change.
- [ ] Check that a user other than the signer user cannot use the card
      through `pcscd` (for example `ykman piv info` as another user fails).
- [ ] Before `ca-init`: `ykman piv keys info 82` reports an empty slot, and
      the backend treats it as empty (piv-go maps the card's status word
      0x6A88 to `ErrNotFound`; unverified).
- [ ] `keyroster-signer ca-init --backend piv --backend-opt pin-file=...
      --backend-opt mgmt-key-file=...`. Record the printed firmware and
      algorithm line: `ssh-ed25519` on 5.7+, `ecdsa-sha2-nistp256` on older
      firmware; custody `piv` for all five keys.
- [ ] `ykman piv keys info 82` to `86`: each slot holds a generated key with
      PIN policy ONCE and touch policy NEVER, and its public key matches
      `ca-pubkeys.json`.
- [ ] Root ceremony, `install-bundle`, then remove the management key file
      and run `serve --backend-opt mgmt-key-file=` (piv.md step 5).
- [ ] Issue a certificate with `keyroster ca issue`, log in on a real sshd,
      run `keyroster audit verify --pin`.
- [ ] Restart the signer: the same keys load, and issuance and `audit
      verify` continue. Leave the signer running for a day and issue again
      (PIN policy once over a long-lived session: the backend verifies the
      PIN once at open and every later signature must succeed without
      another PIN check).
- [ ] While the signer runs, try `ykman piv info` from another process:
      expected to fail because piv-go holds the card's PC/SC transaction.
- [ ] Refusals: a second `ca-init` on a fresh state directory with the same
      card is refused because slot 0x82 is occupied, and the card is
      unchanged; a 0644 PIN file is refused; with two YubiKeys attached and
      no `serial` option the backend refuses, and with `serial=` it picks
      the right card.
- [ ] Wrong PIN: put a wrong PIN in the PIN file and start the signer. It
      must refuse to start, and `ykman piv info` must show exactly one PIN
      retry used per start, with no further retries used by signing
      requests. Put the correct PIN back before the counter reaches zero.
- [ ] PIN retry guard (D-CR-01), under the shipped systemd unit: with the
      correct PIN, the backend reads the retry counter in a fresh session
      (piv-go `Retries()`) and starts. With a wrong PIN and 3 retries
      left, `systemctl start` ends with `status=78`, systemd does not
      restart it (`NRestarts=0`), and `ykman piv info` shows 2 left. Start
      it by hand once more: 1 left, status 78. Start again: it refuses
      **without** trying the PIN (message "only 1 PIN retries left") and
      the counter stays at 1. Record the counter after each step. Then
      put the right PIN back, reset the counter by entering the correct
      PIN once by hand with a `ykman piv` command that asks for it (record
      which command, for piv.md), and check that the signer starts.

- [ ] Attestation evidence for the D-WR-04 design (custody `piv` is
      card-reported today): for each slot 0x82-0x86, record whether
      `ykman piv keys attest` produces a certificate, whether it verifies
      against Yubico's PIV CA with piv-go `Verify`, and whether that holds
      for Ed25519 slots on firmware 5.7 and for P-256 on 5.3-5.6. Note
      which Yubico root and intermediates each card's chain uses.

## 3. Hardware root ceremony (D-11)

CI stand-in: `test/e2e/root_sk_test.go` (`TestRootSK`) signs a bundle with an
`sk-ssh-ed25519@openssh.com` key from OpenSSH's test-only `sk-dummy.so`
provider through a real `ssh-agent`, and `test/e2e/pkcs11_test.go` signs with
a root key in a second SoftHSM2 token as the stand-in for a PIV root.

- [ ] Run the "Hardware-root variant" of
      [docs/runbooks/root-ceremony.md](../runbooks/root-ceremony.md) with
      **two FIDO2 security keys** (`ssh-keygen -t ed25519-sk -O resident
      -O verify-required`), threshold 1-of-2 and 2-of-2, on an offline
      ceremony machine.
- [ ] Run it again with **PIV roots** (a key generated on a YubiKey, loaded
      through `libykcs11.so` with `ssh-add -s`), declared `custody=piv` in
      `roots.pub`.
- [ ] For both: `keyroster trust verify` accepts the bundle against the
      pinned root fingerprints; stock `ssh-keygen -Y verify` accepts each
      SSHSIG signature; no `SOFTWARE ROOT:` banner appears; a bundle signed
      by a root not in `roots.pub` is refused.
- [ ] Recover a resident FIDO2 key handle with `ssh-keygen -K` on a second
      machine and sign again, as a later ceremony would.
- [ ] File the filled-in ceremony transcript
      ([ceremony-transcript-template.md](../runbooks/ceremony-transcript-template.md)).

## 4. Physical TPM 2.0 (KEY-04)

CI stand-in: swtpm (`.github/workflows/e2e-tpm.yml`), which reports
manufacturer `IBM` and so only ever yields custody `vtpm`. The production
transport (`/dev/tpmrm0`) and a physical TPM's own behaviour are not run in
CI ([custody.md](custody.md)).

- [ ] On a host with a physical or firmware TPM (Intel PTT, AMD fTPM, or a
      discrete chip): `ca-init --backend tpm`, record the printed
      manufacturer line and custody, and check with `tpm2_readpublic` (or
      the key file) that each key has `noDA`, `fixedtpm`, `fixedparent` and
      `sensitivedataorigin`.
- [ ] Wrong auth (D-WR-01): note `tpm2_getcap properties-variable`
      (`TPM2_PT_LOCKOUT_COUNTER`), corrupt one `{role}.auth`, start the
      service: it ends with `status=78`, is not restarted, and the lockout
      counter is unchanged. Restore the file and start again.
- [ ] Imported key (D-CR-02): a key made with `tpm2_import` +
      `tpm2_encodeobject` and selected with `ca-init --key` is refused
      ("not generated inside this TPM").

## Sign-off

The Phase 6 review closes the `needs-hardware` issue only when every box above
is ticked with recorded evidence, or an item is explicitly descoped with a
reason in the issue.
