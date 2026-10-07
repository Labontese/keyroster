# Runbook: install the sandboxed signer (TPM backend)

This runbook takes an admin from a fresh Debian 13 or Ubuntu 24.04 VM with a
TPM 2.0 device to a running, sandboxed `keyroster-signer` whose CA keys live
in the TPM. It ends with `keyroster-signer doctor` reporting no FAIL.

> **What CI covers and what it does not.** The `systemd-sandbox` check runs
> the same units on an Ubuntu 24.04 runner (`test/systemd/smoke.sh`): it
> installs them, bootstraps the signer, issues a certificate as a
> `keyroster-admin` member, checks that the signer's network namespace holds
> only `lo`, runs `doctor`, and gates `systemd-analyze security` at exposure
> 2.0. That run uses the **agent** backend, because the runner has no TPM.
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
on two independent machines with the **same Go toolchain version** (the one
in `go.mod`'s `toolchain` line, currently go1.27.1) and compare the
hashes. Go builds are designed to be reproducible with these flags, so the
hashes should match; keyroster has not yet verified this itself (release
reproducibility is checked in Phase 6). Investigate any difference before
installing:

```
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o keyroster-signer ./cmd/keyroster-signer
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o keyroster ./cmd/keyroster
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
drop-in; CI fails above 2.0.

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
| `FAIL log_mismatch` | the stored audit log does not reproduce its signed checkpoint | The database was changed outside the signer. Stop, keep a copy, investigate. `serve` refuses to start. |
| `FAIL clock_regression` | the wall clock is behind the last issued serial | See [the clock warning](#snapshot-restore-check-the-clock-first). |
| `WARN no_bundle` | no trust bundle installed | Run step 6. |
| `WARN software_root` | a root has custody software (`SOFTWARE ROOT:`) | Expected for the homelab (D-10); move to hardware roots (D-11). |
| `WARN vtpm_custody` | the online keys are in a virtual TPM | Expected on a Proxmox vTPM (D-08); see above. |
| `WARN software_key_in_agent` | the online keys are plain keys in ssh-agent | Test and development only. |
| `WARN custody_mismatch` | the TPM now maps to another custody than the one recorded | The VM may run on another TPM than the bundle claims. Investigate before issuing. |
| `WARN tpm_unavailable` | doctor could not read the TPM | Check `/dev/tpmrm0` and group `tss`. |

On the homelab VM the expected result is no FAIL, `WARN vtpm_custody` and
one `WARN software_root` per root.

## Install a successor bundle: stop, install, start

The signer loads the trust bundle and its policy once, when it starts.
Install a successor bundle (from a later ceremony) only with the service
stopped:

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
> `TestTrustChangedUnderLiveSigner`). This stop, install and start
> sequence for a successor has not been run on the vTPM signer. Creating
> `signer.lock` inside the systemd sandbox is covered only by the CI
> `systemd` smoke check (`test/systemd/smoke.sh`, which starts `serve` in
> the sandbox).

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
