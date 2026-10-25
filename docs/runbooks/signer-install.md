# Runbook: install the sandboxed signer (TPM backend)

This runbook takes an admin from a fresh Debian 13 or Ubuntu 24.04 VM with a
TPM 2.0 device to a running, sandboxed `keyroster-signer` whose CA keys live
in the TPM. It ends with `keyroster-signer doctor` reporting no FAIL.

> **What CI covers and what it does not.** The `systemd-sandbox` check runs
> the same units on an Ubuntu 24.04 runner (`test/systemd/smoke.sh`): it
> installs them, bootstraps the signer, issues a certificate as a
> `keyroster-admin` member, checks that the signer's network namespace holds
> only `lo`, checks the sandbox of the signer and of its ssh-agent unit, runs
> `doctor`, and gates `systemd-analyze security` at exposure 2.0 for the
> signer unit and 1.4 for the agent unit. That run uses the **agent**
> backend, because the runner has no TPM.
> The TPM backend itself is tested in CI against swtpm over a Unix socket
> (`e2e-tpm`), not through `/dev/tpmrm0`. **This runbook's TPM path (the
> `tpm.conf` drop-in, `/dev/tpmrm0`, group `tss`, and the
> `runuser -g keyroster-signer -G tss` commands below) has not run in CI.**
> It was run by hand, steps 1 to 9 except the issuance example in step 8, on
> the homelab VM in plan 01-14 (Ubuntu 26.04 guest, Proxmox vTPM, custody
> `vtpm`). The agent unit's PKCS#11 path (`-P` loading a module through
> `ssh-pkcs11-helper` under the unit's sandbox) has still not run anywhere:
> the smoke test loads plain keys only. See
> [docs/security/custody.md](../security/custody.md).

## What you need

- A VM running **Debian 13** or **Ubuntu 24.04** with systemd. On Proxmox VE,
  add a **TPM State** (v2.0) to the VM before first boot, so that the guest
  has `/dev/tpmrm0`.
- Root on that VM.
- The two binaries `keyroster-signer` and `keyroster` for linux/amd64.
- This repository at the same reviewed commit (for `deploy/`).
- For the root ceremony: the offline ceremony machine and transfer USB from
  [root-ceremony.md](root-ceremony.md).

> **A Proxmox vTPM is custody `vtpm`, not `tpm` (D-08).** Proxmox's vTPM is
> swtpm on the Proxmox host; its manufacturer ID is `IBM`. The signer records
> the keys as custody `vtpm`, the root signs that into the bundle, and
> `doctor` prints `WARN vtpm_custody`. The keys are only as safe as the
> Proxmox host: whoever controls that host (root, backups, snapshot exports)
> controls the vTPM state that wraps the CA keys. The guest alone cannot
> export them. This is weaker than a physical TPM and stronger than a
> software key.

## 1. Check the TPM

```
ls -l /dev/tpmrm0
getent group tss
```

`/dev/tpmrm0` must exist and belong to group `tss` (mode `crw-rw----`). If
group `tss` or the udev rule is missing, install the distribution's
`tpm-udev` package, then check again. The signer only needs the resource
manager device; it does not use `tpm2-abrmd` or `tpm2-tools`.

## 2. Verify and install the binaries

Phase 1 has no signed releases yet (Phase 6). Build from the reviewed commit
on two independent machines with the **same Go toolchain version**, the one
in `go.mod`'s `toolchain` line, and compare the hashes. Set `GOTOOLCHAIN`
from that line as below: a local Go of an older version would otherwise
build the binaries too, with a standard library whose fixed
vulnerabilities they reach. Go builds are designed to be reproducible with
these flags, so the hashes should match; keyroster has not yet verified
this itself (release reproducibility is checked in Phase 6). Investigate
any difference before installing:

```
export GOTOOLCHAIN=$(awk '$1 == "toolchain" {print $2}' go.mod)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o keyroster-signer ./cmd/keyroster-signer
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o keyroster ./cmd/keyroster
go version keyroster-signer keyroster      # both must print the toolchain line's version
sha256sum keyroster-signer keyroster
```

Record both SHA-256 values. Copy the binaries to the VM, check the hashes
there again, and install them:

```
sha256sum keyroster-signer keyroster      # must equal the recorded values
install -m 0755 -o root -g root keyroster-signer keyroster /usr/local/bin/
keyroster-signer version
```

## 3. Install the system user, the units and the TPM drop-in

From the repository checkout:

```
install -D -m 0644 deploy/sysusers.d/keyroster.conf /etc/sysusers.d/keyroster.conf
systemd-sysusers /etc/sysusers.d/keyroster.conf
install -m 0644 deploy/systemd/keyroster-signer.service /etc/systemd/system/
install -D -m 0644 deploy/systemd/keyroster-signer.service.d/tpm.conf \
  /etc/systemd/system/keyroster-signer.service.d/tpm.conf
systemctl daemon-reload
```

- `keyroster.conf` creates the system user `keyroster-signer` (no login
  shell) and the group `keyroster-admin`.
- `keyroster-signer.service` runs the signer as `keyroster-signer` with no
  network namespace access (`PrivateNetwork=yes`, `AF_UNIX` sockets only,
  `IPAddressDeny=any`), no capabilities, a system-call filter, a read-only
  file system apart from its state and runtime directories, and no core
  dumps.
- `tpm.conf` adds exactly two things for the TPM backend:
  `SupplementaryGroups=tss` and `DeviceAllow=/dev/tpmrm0 rw`. Install it only
  for the TPM backend: without group `tss` on the host the unit does not
  start.
- `keyroster-signer-agent.service` (the signer's own ssh-agent) is for the
  agent and PKCS#11 backends only. The TPM backend does not need it. **Never
  forward that agent.**

Check the unit before it holds any key:

```
systemd-analyze security keyroster-signer.service
```

CI measured an overall exposure of **0.7 (SAFE)** for the unit without the
drop-in; CI fails above 2.0. If you use the agent or PKCS#11 backend, check
`keyroster-signer-agent.service` the same way: CI fails above 1.4. Its
exposure of **1.3 (OK)** was measured offline (`systemd-analyze security
--offline=yes`, systemd 255.4), not yet on a CI runner (UNVERIFIED).

## 4. Create the state directory and the CA keys in the TPM

`ca-init` and `install-bundle` run before the unit's first start, as the
signer's user. Outside the unit that user is not in group `tss`, so give it
the group for these commands only:

```
install -d -o keyroster-signer -g keyroster-signer -m 0700 /var/lib/keyroster-signer
runuser -u keyroster-signer -g keyroster-signer -G tss -- \
  keyroster-signer ca-init --state-dir /var/lib/keyroster-signer --backend tpm
```

`ca-init` creates the user, host, machine, ops and log keys as ECDSA P-256
keys inside the TPM and prints the manufacturer and custody, for example
`TPM manufacturer: IBM → custody vtpm`. It writes
`/var/lib/keyroster-signer/ca-pubkeys.json`. Copy that file (public keys
only) to the transfer USB:

```
install -m 0644 /var/lib/keyroster-signer/ca-pubkeys.json /media/transfer/ca-pubkeys.json
sha256sum /media/transfer/ca-pubkeys.json   # record in the transcript
```

## 5. Root ceremony

Run [root-ceremony.md](root-ceremony.md) from step 2.2 (genesis policy) to
step 5 on the offline ceremony machine. Each admin listed with `--admin`
will authorize issuance with their own SSH key. The software roots print a
`SOFTWARE ROOT` banner, and `doctor` warns about them later (D-11).

## 6. Install the bundle

Copy the signed bundle and policy where the signer's user can read them,
and pin the root fingerprints **from the paper transcript**:

```
install -d -o keyroster-signer -g keyroster-signer -m 0700 /var/lib/keyroster-signer/incoming
install -o keyroster-signer -g keyroster-signer -m 0600 /media/transfer/ceremony/* /var/lib/keyroster-signer/incoming/
runuser -u keyroster-signer -g keyroster-signer -G tss -- \
  keyroster-signer install-bundle --state-dir /var/lib/keyroster-signer \
  --pin SHA256:<A from paper> --pin SHA256:<B from paper> --threshold 1 \
  --bundle /var/lib/keyroster-signer/incoming/bundle.json \
  --policy /var/lib/keyroster-signer/incoming/policy.json
```

## 7. Start the signer

```
systemctl enable --now keyroster-signer.service
systemctl status keyroster-signer.service
ls -l /run/keyroster-signer/signer.sock    # srw-rw---- keyroster-signer keyroster-admin
```

The unit restarts a failed signer after 5 seconds, at most 5 times in 10
minutes. It never restarts on **exit status 78**: the key store refused the
PIV PIN or a TPM key's auth value (the TPM backend proves each key's
`{role}.auth` with one test signature at start), or the PIV backend
refused to try the PIN with fewer than 2 retries left. Each restart would
spend another of the device's limited attempts. `systemctl status` then
shows `status=78`. Fix the PIN file or restore the `{role}.auth` files from
backup, check the device by hand ([piv.md](../backends/piv.md)), then run `systemctl
reset-failed keyroster-signer.service` and start it again.

Check the sandbox on the running process:

```
pid=$(systemctl show -p MainPID --value keyroster-signer.service)
nsenter -t "$pid" -n ip -br link            # only lo
grep -E '^(CapEff|NoNewPrivs|Seccomp):' /proc/$pid/status   # 0, 1, 2
```

## 8. Add admins

An admin is a local account in group `keyroster-admin` whose SSH key is an
admin in the genesis policy. Group membership lets them reach the socket;
the signer still checks each peer's credentials and requires the admin's
signature (D-13) on every request:

```
usermod -aG keyroster-admin alice
```

Alice logs in again (for the new group), loads her admin key into her own
ssh-agent and issues, for example:

```
keyroster ca issue --admin-key SHA256:<alice admin key> \
  --pubkey ~/.ssh/id_ed25519.pub --principal alice --subject u:alice --ttl 1h
```

## 9. Run doctor

Run `doctor` as the signer's user (as root it fails with
`running_as_root`), with group `tss` so that it can read the TPM's
manufacturer:

```
runuser -u keyroster-signer -g keyroster-signer -G tss -- \
  keyroster-signer doctor --state-dir /var/lib/keyroster-signer
```

It prints one line per check, `LEVEL code: message`, and exits 1 on any
FAIL. It only reads: it opens the database read-only, opens no network
socket and runs no program.

| Result | Meaning | What to do |
|---|---|---|
| `FAIL running_as_root` | doctor ran as root | Run it as `keyroster-signer`. |
| `FAIL state_dir_permissions` | state directory not 0700 or not owned by the signer's user | `chown keyroster-signer: …; chmod 0700 …` |
| `FAIL db_permissions` | `signer.db` readable by others | `chmod 0600 /var/lib/keyroster-signer/signer.db` |
| `FAIL db_integrity` | SQLite integrity check failed, or the database cannot be read | Stop the signer; restore from backup; investigate. |
| `FAIL log_mismatch` | the stored audit log does not reproduce its signed checkpoint, or contradicts what was recorded with it: CA keys but an empty log, or issue entries that do not match the issuance rows and the serial high-water mark (the log tables cut back to an earlier signed prefix, or wiped) | The database was changed outside the signer. Stop, keep a copy, investigate. `serve` refuses to start. |
| `FAIL trust_mismatch` | the installed trust bundle is not one `serve` would load: it does not list the keys ca-init recorded (for example another log key), names an online key or a root (of any bundle the log records) as a policy admin, or is not the bundle the log's last `bundle_install` entry records; or the stored directory is not the one the log's last `directory_install` entry records | The database was changed outside the signer. Stop, keep a copy, investigate. `serve` refuses to start. |
| `FAIL clock_regression` | the wall clock is behind the last issued serial | See [the clock warning](#snapshot-restore-check-the-clock-first). |
| `WARN no_bundle` | no trust bundle installed | Run step 6. |
| `WARN software_root` | a root has custody software (`SOFTWARE ROOT:`) | Expected for the homelab (D-10); move to hardware roots (D-11). |
| `WARN vtpm_custody` | the online keys are in a virtual TPM | Expected on a Proxmox vTPM (D-08); see above. |
| `WARN software_key_in_agent` | the online keys are plain keys in ssh-agent | Test and development only. |
| `WARN custody_mismatch` | the TPM now maps to another custody than the one recorded | The VM may run on another TPM than the bundle claims. Investigate before issuing. |
| `INFO pkcs11_custody_declared` | the online keys are recorded as custody `pkcs11-agent`, which the operator declared at `ca-init` and nothing verifies | Expected with the PKCS#11 backend. Check on the HSM that the keys in `ca-pubkeys.json` are HSM keys ([pkcs11.md](../backends/pkcs11.md)). |
| `WARN tpm_unavailable` | doctor could not read the TPM, or keys are recorded with TPM custody but the TPM was not inspected | Check `/dev/tpmrm0` and group `tss`, and that the recorded backend is `tpm`. Until then the TPM custody is unconfirmed. |

On the homelab VM the expected result is no FAIL, `WARN vtpm_custody` and
one `WARN software_root` per root.

doctor has neither the backend's keys nor your root pins. A database
rewritten consistently, with keys and roots of the rewriter's choosing,
passes doctor. `serve` refuses it only while the rewriter cannot also put
their keys into the backend (it opens every key by its recorded
fingerprint; with the agent backend, whoever can use the agent socket can
add keys). The check that holds is `keyroster audit verify --pin` with
your pins. Compare the root fingerprints doctor prints with your pins.

## Install a successor bundle: stop, install, start

The signer loads the trust bundle and its policy once, when it starts.
Install a successor bundle (from a later ceremony) only with the service
stopped. The successor comes from
[root-ceremony.md, "Rotate the roots"](root-ceremony.md#rotate-the-roots-successor-bundle),
and is checked there with `keyroster trust verify --prev` against the new
roots' paper fingerprints before it is copied to the signer:

```
systemctl stop keyroster-signer.service
runuser -u keyroster-signer -g keyroster-signer -G tss -- \
  keyroster-signer install-bundle --state-dir /var/lib/keyroster-signer \
  --bundle /var/lib/keyroster-signer/incoming/bundle.json \
  --policy /var/lib/keyroster-signer/incoming/policy.json
systemctl start keyroster-signer.service
```

A successor takes no `--pin` or `--threshold`: it is verified against the
installed bundle. Its policy must be the installed policy unchanged, or
the next policy version with the installed policy's SHA-256 as `prev`, so
that `pol=N` in a certificate's key ID names exactly one policy. `serve`, `ca-init` and `install-bundle` hold an exclusive
lock on `signer.lock` in the state directory, so `install-bundle` refuses
with "the state directory is in use by another keyroster-signer process"
while the service runs. If a successor is installed under a running signer
anyway (for example by a process that ignores the lock), that signer
refuses every request with `trust_changed` until it is restarted; it never
issues under the superseded policy.

> **UNVERIFIED on the homelab signer.** The lock and the `trust_changed`
> refusal are exercised by the Go tests only (`TestStateDirLock`,
> `TestTrustChangedUnderLiveSigner`). `TestRootRotationLiveSigner` runs
> stop, install and start for a successor with the real binaries on the
> agent backend. On the homelab vTPM signer, the stop, install and start
> sequence above ran in plan 01-20 (a rehearsal rotation to bundle v2):
> `install-bundle` printed the SHA-256 checked before the copy, and the
> signer was serving again under the new bundle. Plan 02-13 ran the same
> sequence for bundle v3, the policy successor that adds the WebAuthn RP
> (signed by a TEST root on a networked workstation). `install-bundle`
> without `--pin` printed the SHA-256 that `trust verify --prev` had
> accepted, and the signer then served with `policy_version=2`. Doctor
> showed `trust bundle version 3` and no FAIL. Creating
> `signer.lock` inside the systemd sandbox is covered by the CI `systemd`
> smoke check (`test/systemd/smoke.sh`, which starts `serve` in the
> sandbox). On the homelab signer, the sandboxed `serve` of the current
> build created it (plan 01-20); the refusal while it is held was not
> exercised there.

## Snapshot restore: check the clock first

Certificate serials are microsecond timestamps that only increase (CA-03),
so the signer fails closed when the wall clock is behind the last issued
serial (research Pitfall 9). A VM restored from a snapshot starts with the
snapshot's clock until NTP corrects it, and its database holds the
snapshot's high-water mark.

**Before starting a restored signer, check the clock:**

```
systemctl stop keyroster-signer.service      # if it auto-started
timedatectl                                  # "System clock synchronized: yes"
runuser -u keyroster-signer -g keyroster-signer -G tss -- \
  keyroster-signer doctor --state-dir /var/lib/keyroster-signer
```

Start the signer only when `timedatectl` reports a synchronized clock and
`doctor` shows `OK clock`. `FAIL clock_regression` means the clock is still
behind the high-water mark: fix time synchronization first. Never move the
serial high-water mark down by hand.

A restore also brings back an older audit log. Certificates issued after
the snapshot are missing from it, while verifiers (and the bundle) may have
seen a longer log. Record every restore in the operations log.

Neither `doctor` nor `serve` can tell a restored database from a current
one: the whole file is consistent with itself. The same holds for a log
cut back together with its issuance rows and high-water mark, or cut back
by trailing entries that issue nothing (refusals, and trust bundle and
directory installs). Only an earlier export kept outside the signer shows
it: keep each export, and verify the next one with
`keyroster audit verify --previous <earlier export>`.

### A restore brings back the older trust bundle, policy and directory

> **Warning.** Restoring an older `signer.db` also restores the trust
> bundle, policy and directory it held. Admins removed since are accepted
> again, users disabled since can log in again, and credentials removed
> since work again. `serve` and `doctor` accept it, because the older state
> is exactly what the older log records. The same happens when someone
> with write access to `signer.db` cuts the log and those tables back to
> an earlier signed prefix. The CA, ops and log keys cannot be rolled back
> this way (the bundle must list the keys ca-init recorded). Phase 4 makes
> `serve` refuse to start without a witnessed checkpoint at least as new
> as the local one; until then this check is the operator's.

Before starting the signer after a restore:

1. Keep the service stopped, and export the restored log:

   ```
   systemctl stop keyroster-signer.service      # if it auto-started
   runuser -u keyroster-signer -g keyroster-signer -G tss -- \
     keyroster-signer export-log --state-dir /var/lib/keyroster-signer --out /tmp/restored.jsonl
   ```

2. Compare it with the latest export you kept from before the restore:

   ```
   keyroster audit verify --pin SHA256:<A from paper> --pin SHA256:<B from paper> --threshold 1 \
     --previous /root/latest-saved.jsonl /tmp/restored.jsonl
   ```

   A restored log that is older than the saved one is reported as shrunk
   (`log shrank`) or rewritten. Since plan 02-04, `audit verify` verifies
   logs that contain `directory_install` and `login_issue` entries; an
   older `audit verify` binary refuses them, so use a current one. A
   binary built between plans 02-01 and 02-04 says "not verifiable by this
   version". A Phase 1 binary usually stops earlier, at the bundle whose
   policy added the WebAuthn RP (`json: unknown field "webauthn"`), which
   is not a sign of tampering; see the compatibility note in
   [root-ceremony.md](root-ceremony.md#change-the-policy-successor-policy-for-example-add-the-webauthn-rp). `TestAuditLoginAcrossPolicyChange` (e2e) runs this command on two
   exports of a signer with a directory and login certificates: the later
   export verifies with `--previous` set to the earlier one, and the
   earlier export is refused as `log shrank` with `--previous` set to the
   later one. That is two exports of one live signer, not a restored
   database.

   Also compare the versions by hand, in both files, to see what the
   restore took back:

   ```
   grep -o '"bundle_version":[0-9]*' /root/latest-saved.jsonl | tail -n 1
   grep -o '"bundle_version":[0-9]*' /tmp/restored.jsonl | tail -n 1
   grep -c '"kind":"directory_install"' /root/latest-saved.jsonl
   grep -c '"kind":"directory_install"' /tmp/restored.jsonl
   ```

   The first pair is the installed trust bundle version. The second pair
   counts directory installs, which is the installed directory version
   (each install is the next version, starting at 1). If the restored
   numbers are lower, the restore reinstated an older bundle or directory.
   `doctor` also prints the restored bundle version (`OK bundle`).

3. Reinstall what the restore lost, with the same bytes as before and
   before anyone installs anything new. Install the exact versions that
   were lost: a different version 2 built on the restored version 1 is
   accepted too, and the disablements of the lost version are then gone
   for good.

   **Keep users away until the replay is done.** From the moment the
   restored signer starts until the last lost version is back, it serves
   the restored, older directory: a user disabled in a lost version can log
   in again, and a role removed in a lost version grants again. Keep
   keyroster-server unreachable to users for that time, for example with a
   firewall rule that admits only the admin workstation; the admin's
   `keyroster directory install` goes through the server, so stopping it is
   not an option. (UNVERIFIED: no test blocks user access.)

   **Replay the lost installs in log order**, not all bundles first. A
   directory version is checked against the policy in force when it is
   installed (its admin quorum and the user CA cap), so a directory version
   that was installed under bundle v1 can be refused once a later bundle
   v2 with other admins or a lower cap is back. List the order from the
   saved export; the lost entries are the ones after the restored log's
   last entry:

   ```
   grep -n -o '"kind":"\(bundle\|directory\)_install"' /root/latest-saved.jsonl
   ```

   - **A lost `bundle_install`:** stop the signer, run `install-bundle`
     with that bundle (see
     [Install a successor bundle](#install-a-successor-bundle-stop-install-start)),
     and start it again only if a lost directory version follows.
     (UNVERIFIED: no test replays a lost bundle.)
   - **A lost `directory_install`:** write it back as a proposal from the
     saved export and install it with `keyroster directory install`, one
     version at a time, in log order:

     1. Verify the saved export itself, and that the restored log is a
        prefix of it, so that you replay entries the roots vouch for:

        ```
        keyroster audit verify --pin SHA256:<A from paper> --pin SHA256:<B from paper> --threshold 1 \
          /root/latest-saved.jsonl
        keyroster audit verify --pin SHA256:<A from paper> --pin SHA256:<B from paper> --threshold 1 \
          --previous /tmp/restored.jsonl /root/latest-saved.jsonl
        ```

        Both must pass. Step 2 does not do this: it verifies the restored
        export and reads only the last checkpoint of the saved one, and its
        `log shrank` looks the same for a log that was cut back as for one
        that was cut back and rewritten. The first command checks every
        entry of the saved export, and refuses a line whose `directory` or
        `sigs` field is not the document or signatures of its own verified
        `directory_install` leaf, so the bytes the next step writes are the
        ones the signer logged. The second proves that the restored log is a prefix
        of the saved one, so the lost entries are exactly the saved
        export's entries after it.
     2. Write the proposal of the lost version `V` (`directory.json` and
        `directory.json.sigs`) from the export's decoded line:

        ```
        V=2                                   # the lost directory version
        SAVED=/root/latest-saved.jsonl
        D=/root/replay/v$V
        mkdir -p "$D"
        grep '"kind":"directory_install"' "$SAVED" | grep -E ",\"version\":$V[,}]" > "$D/line"
        test "$(wc -l < "$D/line")" -eq 1
        grep -o '"directory":"[^"]*"' "$D/line" | cut -d'"' -f4 | base64 -d > "$D/directory.json"
        grep -o '"sigs":"[^"]*"' "$D/line" | cut -d'"' -f4 | base64 -d > "$D/directory.json.sigs"
        test -s "$D/directory.json"
        test -s "$D/directory.json.sigs"
        rm "$D/line"
        ```

        The decoded `directory` and `sigs` fields are in every export that
        `keyroster-signer export-log` writes since plan 03-02. An older
        export has only `version` and `policy_version` there (the bytes are
        then only inside the leaf, and the `test -s` lines stop): export the
        saved log again with a current binary, or keep the proposal
        directories of past installs.
     3. With the restored signer running, wait at least 5 s after it
        started, or restart keyroster-server: the server keeps the signer's
        status for up to 5 s, and until then it can still report the
        version it served before the restore. Then, as an admin:

        ```
        keyroster directory install /root/replay/v2
        ```

        It must print `The server reports directory version 2 installed`.
        `The server already serves proposal ... nothing to do` means the
        server still reported the pre-restore version: wait and run it
        again. Check on the signer host that the signer holds the version
        (`keyroster audit verify` of a new export counts the directory
        installs).

   **What makes the replay safe, and what it does not cover.** `audit
   verify` does not interpret the `decoded` part of an export line, with
   one exception: a line that carries a `directory` or `sigs` key must be a
   `directory_install` line, with each key once and the standard base64 of
   its leaf's own document and signatures as the value. So after the two
   `audit verify` commands of the first item above, the proposal written
   from the saved export is the document and signatures of a verified
   `directory_install` leaf among the lost entries: an edited `directory`
   or `sigs` field, or a decoy one on another line or nested in the same
   line, is refused, and an escaped or missing field leaves an empty file
   that the `test -s` lines stop. An edited `version` in the decoded part
   can only pick the bytes of another logged version, and the signer
   refuses those, because their `prev` is not the SHA-256 of the version it
   serves. The signer checks the replay again: the directory must carry the
   admin quorum's signatures under the policy in force, and its `prev` must
   be the SHA-256 of the restored version.
   The residual: these checks bind the replay to the saved export's
   checkpoint, which the log key signs. A saved export written by someone
   who holds the log key (a compromised signer) verifies too, until Phase 4
   witnesses the checkpoints. Keep saved exports where only operators can
   write them.

   **A lost version that binds a passkey cannot be replayed.**
   keyroster-server refuses it with 409 `credential_not_pending`, because
   the passkey's pending entry was deleted at the original install, and
   every later lost version chains to it, so none of them installs either.
   Replay up to that version. Then re-invite that user
   (`keyroster user add NAME --reinvite`, see
   [enroll-user.md](enroll-user.md)), approve the new passkey, and make the
   later lost changes again by hand, disablements first. (UNVERIFIED: this
   case and its re-invite path have not been run.)

   **After the replay, the new export is the baseline.** The replayed
   installs are new log entries with new times, so the log no longer
   extends the pre-restore export: `audit verify --previous
   /root/latest-saved.jsonl` refuses the new export. Export the log again
   with step 1's command and `--out /tmp/after-replay.jsonl` (the service
   may keep running), then verify it on its own pins and against the
   export of the restored log from step 1; both must pass:

   ```
   keyroster audit verify --pin SHA256:<A from paper> --pin SHA256:<B from paper> --threshold 1 \
     /tmp/after-replay.jsonl
   keyroster audit verify --pin SHA256:<A from paper> --pin SHA256:<B from paper> --threshold 1 \
     --previous /tmp/restored.jsonl /tmp/after-replay.jsonl
   ```

   The second command proves that the new log extends the restored one,
   so nothing was cut back or rewritten between step 1 and the replay.
   Then keep the new export as the next `--previous`, and keep the
   pre-restore export and `/tmp/restored.jsonl` with the operations log as
   the record of the restore.

> **Run in CI e2e (TestRestoreReplaysLostDirectory, 03-02)** on a test
> signer, for a lost directory version that adds a role and binds no
> passkey: a file-level restore of `signer.db` (its `-wal` and `-shm`
> files replaced together, or SQLite replays the newer WAL onto the older
> file), the signer then reporting the older version, the export of the
> restored log taken while the signer is stopped, step 3's two `audit
> verify` runs of the saved export (on its own pins, and with `--previous`
> set to the restored export), step 3's extraction commands above
> verbatim, the wait, `keyroster directory
> install` of the written proposal with the signer then reporting the lost
> version with the same bytes, the new export verifying on its own pins
> and with `--previous` set to the restored export, and `audit verify
> --previous` refusing it against the pre-restore export.
>
> **UNVERIFIED:** a VM snapshot restore, the replay of a lost
> `bundle_install`, a lost version that binds a passkey and the re-invite
> after it, keeping users away from the server, and the version counts of
> step 2 against a real restored signer. The `grep` patterns of step 2 match
> the export line format written by `keyroster-signer export-log`, not a
> real export of a restored signer.
