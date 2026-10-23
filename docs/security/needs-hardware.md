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
- [ ] `keyroster-signer doctor` prints `INFO piv_custody_reported` naming
      all five keys and no `OK custody` line (doctor does not read the card).
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

## Platform verification (D-16)

What has and has not been run for the login agent on each client platform
(Phase 2, plans 02-02 and 02-14). Anything marked UNVERIFIED has not been
exercised and must not be presented as working.

**End-to-end logins on the homelab (02-14).** The owner ran `keyroster
login` in a real browser and approved with a passkey, then logged in with
the certificate to a stock OpenSSH host. Only the 8 h certificate on each
OS was used for SSH, and each of those two logins is matched in two
records: a `login_issue` entry in the signer's audit-verified log, and a
certificate login (`ED25519-CERT`, kr2 key ID, serial) in the host's sshd
journal. The `--ttl 5m` certificates were not used for SSH: they appear
only in the signer's log and in the agent listings.

| OS | Browser | Authenticator | Agent | SSH client → host | Result |
|---|---|---|---|---|---|
| Windows 11 (Daniel-PC) | Chrome | synced Chrome passkey, unlocked with Windows Hello | `keyroster agent` | inbox `OpenSSH_for_Windows_9.5p2` → stock OpenSSH 10.2p1 (Ubuntu 26.04 test VM) | verified, 2026-10-22: web sign-in and `/account`, `keyroster login`, certificate login, `--ttl 5m` certificate gone from the agent while the 8 h one stayed |
| Ubuntu 26.04, GNOME (laptop) | Chrome | the same synced passkey, unlocked through Google Password Manager | GNOME `gcr-ssh-agent` | OpenSSH 10.2p1 → stock OpenSSH 10.2p1 (zima-srv) | verified, 2026-10-23: `keyroster login`, certificate login, `--ttl 5m` certificate gone from the agent 57 s after its expiry while the 8 h one stayed |
| macOS | any | any | OpenSSH `ssh-agent` | any | **UNVERIFIED**: no Mac in the homelab; the CLI flow runs in CI (`cli-macos`) |
| Windows 11 | Edge, Firefox | any | `keyroster agent` | any | **UNVERIFIED**: not tried |

What these rows do not cover:
- **Approval order.** On both rows the owner saw the fingerprint on the
  approval page before any passkey prompt, and the prompt came only after
  Approve. That is the owner's observation in Chrome, not a measurement.
- **Web sign-in on Linux.** Only the approval page was used on the laptop.
- **Windows expiry timing.** The times of the Windows agent listings were
  not recorded. Removal close to expiry (still listed 2 min 34 s before it,
  gone 57 s after it) is shown only on Linux.
- **The default key first.** On Linux, the first `ssh` after login
  authenticated with the laptop's own plain key, because zima-srv also has
  it in `authorized_keys`. The certificate login was shown by a run with
  `-o PubkeyAcceptedAlgorithms=ssh-ed25519-cert-v01@openssh.com
  -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no`.

**UNVERIFIED:**
- macOS: browser and passkey login (no Mac; the CLI flow runs in CI in
  `cli-macos`);
- Safari; Firefox (any OS); Edge; every browser other than Chrome;
- a hardware or device-bound authenticator (both rows used one synced
  passkey);
- OpenSSH `ssh-agent` in a real login (CI only, see below);
- headless login (deferred, D-12);
- Windows sshd as a certificate target (Phase 5).

- **Windows: verified on Daniel-PC** (Windows 11, inbox
  `OpenSSH_for_Windows_9.5p2`). Login keys go to `keyroster agent`, keyroster's
  own in-memory agent (owner decision D-15 option A), never to the inbox
  `ssh-agent` service, which refuses lifetime constraints and stores keys in the
  registry. The inbox `ssh.exe` and `ssh-add.exe` reach a named-pipe agent
  only in the spelling `//./pipe/<name>` in `IdentityAgent` (the `-o` option
  and `~/.ssh/config`). `\\.\pipe\<name>` in `IdentityAgent` fails with "No
  such file or directory", because OpenSSH reads the backslashes as escapes.
  `SSH_AUTH_SOCK` accepts both spellings. The evidence:
  `TestInboxSSHOffersAgentCert` and the `ensure_starts_real_agent` case each
  ran a freshly built `keyroster.exe` on the account's own per-SID pipe,
  `\\.\pipe\keyroster-agent-<SID>`, with no other keyroster agent running.
  `ssh-add.exe -t 4` loaded the key and certificate, `ssh.exe` offered the
  certificate, both were gone after the lifetime, and the agent exited by
  itself.
- **Pipe-squatting guard:** before keyroster sends a key, `VerifyServerOwner`
  checks that the pipe's server process runs as the caller's SID, with that
  SID not deny-only, at Medium integrity or above (which also excludes
  AppContainers, always Low), and without a restricted token. Sandboxed
  processes of the same user can create the pipe while no agent runs;
  `low_integrity_squatter_refused`, `restricted_squatter_refused` and
  `deny_only_squatter_refused` run such a squatter (Low integrity; restricted
  token at Medium; user SID deny-only with no restricting SIDs, serving the
  pipe with a DACL of its own that grants Authenticated Users) on Daniel-PC
  and check that it gets no key. No AppContainer squatter was run. The pipe's DACL grants only that SID and denies network logons, and a second agent or
  another process cannot create the pipe while it exists. The SID comparison
  (`checkOwner` with LocalSystem) and the fail-closed path are unit-tested.
  `foreign_pipe_refused` runs `VerifyServerOwner` end to end on the EventLog
  service's pipe. From a normal shell (Daniel-PC) the service process cannot
  be opened, so it exercises only the access-denied branch, which names the
  pipe's owner (`S-1-5-19`) as another account. The branch that reads a
  foreign server's token and refuses its SID runs only where that token is
  readable. It is **UNVERIFIED**: it has not run on Daniel-PC, and a green
  `cli-windows` run cannot show it either, because that job runs `go test`
  without `-v` and a passing test's "server token readable" log line is not
  printed (the elevated runner may also be denied that token).
- **Residual risk (T-02-07), inbox OpenSSH clients:** the owner check guards
  only keyroster's own connection. The inbox `ssh.exe` and `ssh-add.exe` do
  not check who serves a pipe (the 02-02 pre-merge review found no reference
  to `GetNamedPipeServerProcessId` or `GetSecurityInfo` in either
  `OpenSSH_for_Windows_9.5p2` binary). The pipe name is derived from the user's SID,
  which is not secret, and is free whenever no agent runs, which is most of
  the time: the agent exits when its last key expires. Between agent runs the
  name can be taken by another local account's process or by a sandboxed
  process of the same user (Low integrity, or a restricted or deny-only
  token). keyroster's own connection refuses all of these, but an inbox
  client pointed at the name does not. Such a process sees every signing
  request from that client, chooses which keys are offered, and receives any
  key added with `ssh-add` or `AddKeysToAgent`. `keyroster agent` warns
  against `ssh-add` and `AddKeysToAgent` on the pipe. By owner decision
  (2026-10-17) keyroster advises only a host-scoped `Host <your keyroster
  hosts>` block with `IdentityAgent` and no longer advises
  `$env:SSH_AUTH_SOCK`, which limits the inbox clients' exposure to such a
  pipe to keyroster hosts. Those hosts still trust whatever serves the name.
- **runas and elevated shells:** each Windows account, including one reached
  through `runas`, gets its own agent on its own per-SID pipe. An agent
  started from an elevated ("Run as administrator") shell cannot be used from
  a normal shell. keyroster refuses it with `ErrOwnerUnverifiable`, whose
  guidance names both causes of an access-denied pipe: an elevated agent of
  your own (stop it or let it exit), or another account's process that took
  the pipe name first (it does not exit on its own). The mapping, and the
  refusal of a pipe whose DACL leaves the user out, are unit-tested, but the
  elevated case itself is **UNVERIFIED**: no agent was started from an
  elevated shell on Daniel-PC.
- **GNOME gcr-ssh-agent (Ubuntu 26.04):** A3 passed in 02-14 (the Ubuntu
  26.04 packages gcr 3.41.2 and gcr4 4.4). The probe from 02-02 added a key
  and a certificate with a 20 s lifetime. Both were listed, both were gone
  25 s later, and the owner's pre-existing key stayed. The 02-14 laptop
  login used gcr-ssh-agent (`SSH_AUTH_SOCK=/run/user/1000/gcr/ssh`). Its
  `--ttl 5m` certificate was still listed 2 min 34 s before its expiry and
  gone 57 s after it (table above). Other gcr versions are UNVERIFIED.
- **Linux, OpenSSH ssh-agent:** `TestAgentLifetime` adds a key and certificate
  with a 2 s lifetime to a real `ssh-agent` and checks that both are gone
  after 3 s. It runs in `build-test`, where `KEYROSTER_REQUIRE_SSH_AGENT=1`
  turns a missing `ssh-agent` into a failure.
- **macOS:** the CLI unit tests and `TestAgentLifetime` run in CI (`cli-macos`),
  where `KEYROSTER_REQUIRE_SSH_AGENT=1` makes a missing `ssh-agent` fail the
  job instead of skipping the lifetime test. A browser and passkey login on
  macOS is **UNVERIFIED**: there is no Mac in the homelab.

## Sign-off

The Phase 6 review closes the `needs-hardware` issue only when every box above
is ticked with recorded evidence, or an item is explicitly descoped with a
reason in the issue.
