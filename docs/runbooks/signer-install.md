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

**Before starting a restored signer, check the clock.** The restore
procedure below holds the signer stopped until then:

```
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

**Hold the signer and keyroster-server first.** A restored signer that
logs anything before step 1 exports its log (a request that reaches it,
or the refusal summary it writes when it stops after refusing one) forks
the log, and step 2 then ends the procedure. So hold both units with a
drop-in that makes every start fail, on the signer host that is to serve
the restored `signer.db`, before it is copied in (for a VM snapshot, the
current signer VM: see below). As root:

```
bash -eu -s keyroster-server keyroster-signer <<'EOF'
test "$#" -gt 0
for u in "$@"; do
  install -d -m 0755 "/etc/systemd/system/$u.service.d"
  printf '[Unit]\nAssertPathExists=/nonexistent-restore-hold\n' >"/etc/systemd/system/$u.service.d/restore-hold.conf"
done
systemctl daemon-reload
for u in "$@"; do
  systemctl stop "$u.service"
done
for u in "$@"; do
  test "$(systemctl show -p LoadState --value "$u.service")" = loaded
  systemctl show -p DropInPaths --value "$u.service" | grep -q "/$u.service.d/restore-hold.conf"
  if systemctl start "$u.service"; then
    systemctl stop "$u.service"
    echo "$u.service started: the hold is NOT in force" >&2
    exit 1
  fi
done
echo "held: $*"
EOF
```

Leave out `keyroster-server` where it is not installed. The drop-in
asserts a path that never exists, so every start of the unit fails
loudly, a start that keyroster-server's `Wants=` asks for included: each
`systemctl start` above prints `Assertion failed on job for ...`, which
is the hold working. (A `Condition` would skip the start silently;
`systemctl mask` does not work, because the units are files in
`/etc/systemd/system`.) The block writes both drop-ins and reloads
systemd before it stops the units, so that no new start succeeds after
the stop. A unit already waiting to restart after a crash (`activating`,
`auto-restart`) is not held by the drop-in and can still start before
the stop; the `systemctl stop` that follows stops it, and every start
after that fails. Only the last line's `held:` means the hold is in
force. Keep it until the release after step 2b.

**Keep keyroster-server's KRL copy, right after `held:`.** keyroster-server
keeps the last KRL it served in `/var/lib/keyroster-server/krl-served.json`
(see [server-install.md](server-install.md)). The hold stopped the server, so
the file holds the last KRL any host could have fetched from it, including
revocations made after your latest saved export. Step 2b imports it. Keep a
copy before anything else changes. As root, on the host where
keyroster-server runs:

```
bash -eu <<'EOF'
runuser -u keyroster-server -- test -d /var/lib/keyroster-server -a -x /var/lib/keyroster-server
test ! -e /root/recovery
install -d -m 0700 /root/recovery
listed=$(runuser -u keyroster-server -- find -H /var/lib/keyroster-server -maxdepth 1 -name krl-served.json -print)
if [ -n "$listed" ]; then
  runuser -u keyroster-server -- test -f /var/lib/keyroster-server/krl-served.json
  runuser -u keyroster-server -- head -c 5620745 /var/lib/keyroster-server/krl-served.json > /root/recovery/server-krl.json
  test -s /root/recovery/server-krl.json
  test "$(stat -c %s /root/recovery/server-krl.json)" -le 5620744
  echo "kept: /root/recovery/server-krl.json"
else
  echo "no server KRL copy: /var/lib/keyroster-server/krl-served.json does not exist"
fi
EOF
```

The block prints exactly one of two lines, and that line decides which form
of step 2b applies. Write it into the operations log.

- `kept: /root/recovery/server-krl.json`: the copy is kept, and step 2b
  passes it as `--krl`.
- `no server KRL copy: ...`: keyroster-server has served no KRL since it
  keeps copies (03-06b). Only after this line does step 2b leave `--krl`
  out.

**The copy is only as trustworthy as the keyroster-server account.**
Whoever controls that account can put an older genuine KRL into
`krl-served.json` before the capture (a direct write bypasses the server's
never-lower rule), or remove the file. Such a copy passes every check of
step 2b, and the revocations made after its version and after your latest
saved export would then be silently left out of the recovery. The
cross-check below compares the copy with the KRL the enrolled hosts
enforce (T-03-277). Run it before step 2b.

The block's rules:

- Root reads the server's file only as keyroster-server, and copies it only
  when that account sees a regular file (after following links) of at most
  5 620 744 bytes, the most `keyroster revoke recover` reads from a `--krl`
  file. A link still reaches any regular file that account can read. Root
  writes only its own directory, `/root/recovery`.
- Only a listing of the state directory that succeeded and does not name
  the file prints `no server KRL copy`. A listing that fails stops the
  block. The listing (`find -H`) follows the state directory when it is
  itself a link, for example to state kept on another disk, and follows
  no link inside it.
- The block stops when it ends without one of the two lines, and then it
  claims neither:
  - the server account cannot reach or list its state directory
    (keyroster-server is not installed on this host, or the directory is
    missing or unreadable);
  - `/root/recovery` exists from an earlier run (move it into the
    operations record first, then run the block again; never remove it);
  - the file is listed but is not a regular file (a link that leads
    nowhere or to a device, a FIFO), cannot be read, or is larger than
    5 620 744 bytes.

  Keep the hold and find out why, and escalate if you cannot. A file that
  the server account turns into a FIFO between the block's check and its
  copy makes the block wait instead: stop it with Ctrl-C, move
  `/root/recovery` into the operations record, and escalate.
- Where keyroster-server runs on another host, hold it there with the hold
  block (naming only `keyroster-server`), because the hold block holds only
  the units on the host where it runs. Then run this block there, and copy
  `/root/recovery/server-krl.json` to `/root/recovery/` on the signer host,
  into a directory of mode 0700 that only root can read. (UNVERIFIED: no
  test copies the file from another host.)
- Where no keyroster-server runs anywhere, the block stops at its first
  line. Keep the hold and escalate: this runbook covers only a signer
  behind keyroster-server.

Run in CI (`systemd-sandbox`, `test/systemd/smoke.sh`, 03-06c), with the
block verbatim:

- without the state directory: it stops and prints neither line;
- with the directory and no file: `no server KRL copy`;
- with the directory unreadable to the server account: it stops and prints
  neither line;
- over an existing `/root/recovery`: it stops;
- with the file a link that leads nowhere, a link to `/dev/zero`, a FIFO,
  a file of mode 000, or a file of 5 620 745 bytes: it stops, prints
  neither line and writes at most 5 620 745 bytes;
- with the state directory a link to a directory elsewhere: `kept:` when
  that directory holds a fixture file, with a copy equal to the fixture
  byte for byte; and, when that directory is unreadable to the server
  account, it stops and prints neither line;
- with a fixture file written as keyroster-server: `kept:`, with a copy
  equal to the fixture byte for byte.

UNVERIFIED on a real host, and a listing that fails on a disk error (CI
runs only an unreadable directory).

**Cross-check the copy against the hosts (T-03-277).** Hosts get a KRL
only through keyroster-server, which writes `krl-served.json` before it
serves a KRL (03-06b). So a genuine copy is never older than the KRL any
host enforces, and a host that enforces a newer KRL than the copy proves
that the copy was rolled back or removed. The hold keeps every host where
it is: no new KRL reaches a host until the release.

1. On at least one enrolled host, and preferably on every enrolled host
   you can reach, run as root:

   ```
   keyroster-agent krl-version
   ```

   It prints one line, `installed KRL version: <N>`, and changes nothing
   (it reads the agent's state and takes no lock). Write each host's name
   and number into the operations log.

2. As root, on the host that holds `/root/recovery`, run this block with
   every number from part 1 as its arguments:

   ```
   bash -eu -s <host KRL version> [<host KRL version> ...] <<'EOF'
   KEPT=/root/recovery/server-krl.json
   set -o pipefail
   stop() { echo "cross-check: $*" >&2; exit 1; }
   [ "$#" -gt 0 ] || stop "no host's installed KRL version given; run keyroster-agent krl-version on at least one enrolled host"
   v=0
   if [ -e "$KEPT" ]; then
     [ "$(wc -l <"$KEPT")" -eq 1 ] || stop "$KEPT is not one line"
     grep -Eqx '\{"krl":"[A-Za-z0-9+/=]+","manifest":"[A-Za-z0-9+/=]+","sig":"[A-Za-z0-9+/=]+"\}' "$KEPT" || stop "$KEPT is not a KRL document as keyroster-server writes it"
     v=$(cut -d'"' -f8 "$KEPT" | base64 -d | grep -o '"krl_version":[0-9]*' | cut -d: -f2) || stop "$KEPT has no KRL version"
   fi
   for n in "$v" "$@"; do
     case "$n" in '' | *[!0-9]* | 0?* | ???????????????????*) stop "'$n' is not a KRL version" ;; esac
   done
   for h in "$@"; do
     [ "$h" -le "$v" ] || stop "a host enforces KRL v$h, above v$v of the kept server copy: the copy was rolled back or removed. Keep the hold and escalate"
   done
   echo "cross-check passed: the kept server copy's KRL v$v is at least every host's installed KRL version ($*)"
   EOF
   ```

Only the last line's `cross-check passed:` lets step 2b run; write it into
the operations log. If the block stops, keep the hold and escalate. After
the capture block printed `no server KRL copy`, the copy counts as version
0, so any host that enforces a KRL stops the block: either the copy was
removed, or the server's state directory was lost with it, and either way
revocations after your latest saved export may be lost.

The cross-check cannot help where no host is enrolled, or where every host
you reach is under the same control as the keyroster-server account (it
could then set what `keyroster-agent krl-version` prints). In those cases,
escalate a restore after a suspected compromise of the server host.

Run in CI e2e: the block on fixture copies, with hosts above, equal to and
below the copy and with no copy (`TestRestoreCrossCheck`), and
`keyroster-agent krl-version` on an enrolled host against the server's own
`krl-served.json`, then against an older genuine copy, which stops the block
(`TestAgentEnrollEndToEnd`, 03-07). UNVERIFIED on a real host until 03-16.

**Keep users away until the replay is done.** From the moment the
restored signer starts again until the last lost version is back (step
3), it serves the restored, older directory: a user disabled in a lost
version can log in again, and a role removed in a lost version grants
again. Keep keyroster-server unreachable to users for that time, for
example with a firewall rule that admits only the admin workstation; set
it before you release the hold. The admin's `keyroster directory install` goes through the
server, so stopping it is not an option. (UNVERIFIED: no test blocks user
access.)

**Taking a file backup of `signer.db`.** No other document describes
it, and keyroster-signer has no backup command. Copy `signer.db` and its
`-wal` and `-shm` files, those that exist, as one set, and only while
the signer is stopped and cannot start: run the hold block above, copy
the files into a directory of mode 0700 that only root can read, then
run step 2's release block below and start the signer again. A backup
restores nothing, so it needs neither the capture block nor step 2b. A copy of
a running signer's files is not a backup, because SQLite may write to
them during the copy. An online copy (SQLite's `.backup` command, or
`VACUUM INTO` on a read-only connection, run as keyroster-signer) needs
the `sqlite3` program, which this runbook does not install, and has not
been tried (UNVERIFIED). Keep backups, like saved exports, off the
signer VM's disk.

**From a file backup of `signer.db`:** with the hold in force, replace
`signer.db` and its `-wal` and `-shm` files together with those in the
backup directory `<backup>` (an absolute path). Files the backup does not
have are removed, or SQLite would replay the newer WAL onto the older
file. The block refuses unless the signer is `inactive` or `failed` (not
`activating`, which includes a pending restart), and it holds the state
directory's lock (`signer.lock`, which `serve`, `ca-init` and
`install-bundle` hold while they run) until it ends, so it refuses while
any of them runs, also one started outside systemd:

```
bash -eu -s <backup> <<'EOF'
S=/var/lib/keyroster-signer
test -e /etc/systemd/system/keyroster-signer.service.d/restore-hold.conf
st=$(systemctl show -p ActiveState --value keyroster-signer.service)
if [ "$st" != inactive ] && [ "$st" != failed ]; then
  echo "keyroster-signer.service is $st: hold it first" >&2
  exit 1
fi
exec 9<"$S/signer.lock"
if ! flock -n 9; then
  echo "$S is in use by another keyroster-signer process" >&2
  exit 1
fi
test -s "$1/signer.db"
rm -f "$S/signer.db" "$S/signer.db-wal" "$S/signer.db-shm"
for f in signer.db signer.db-wal signer.db-shm; do
  if [ -e "$1/$f" ]; then
    install -o keyroster-signer -g keyroster-signer -m 0600 "$1/$f" "$S/$f"
  fi
done
echo "restored signer.db from $1"
EOF
```

**From a disk-only VM snapshot (Proxmox): never boot the snapshot.** A
signer VM booted from a rolled-back disk starts the signer and
keyroster-server before you can hold them. So do not roll back the
signer VM (that would also discard the current VM's disk, its saved
exports included), and never boot its snapshot or a copy of it. Take
the three files out of the snapshot's disk instead, and restore them on
the current signer VM as a file backup (UNVERIFIED: no step of this
paragraph has run, and none can run in CI):

- On the current signer VM, run the hold block and the capture block
  above, and set the firewall rule (above).
- On the Proxmox host, make a copy of only the signer VM's system disk
  as it was at the snapshot, with the storage's own tools (for example a
  ZFS clone of the disk's snapshot, or `qemu-img convert` of a qcow2
  disk's internal snapshot), and attach the copy to a helper VM (any
  Linux VM other than the signer VM, `<helper id>`) as an extra disk. Do
  not clone the whole signer VM with `qm clone <id>`: that also copies its
  vTPM state, which wraps the TPM backend's CA keys, into a second VM.
- In the helper VM, mount the copy's root file system read-only
  (`mount -o ro`) and copy `var/lib/keyroster-signer/signer.db` and its
  `-wal` and `-shm` files, those that exist, as one set, with their
  `sha256sum`. Mounting the copy on the Proxmox host itself also works
  for some storage types, but it makes the host's kernel parse a file
  system that the signer VM wrote; prefer the helper VM.
- An encrypted disk (LUKS) opens in the helper VM only with a passphrase
  or recovery key. If its only key is sealed to the signer VM's vTPM,
  nothing outside that VM can open it, and this restore is not possible:
  escalate.
- Copy the set to the current signer VM, into a new directory
  `<backup>` of mode 0700 owned by root, check the `sha256sum` values
  there, and run the file restore block above with that `<backup>`. Then
  delete the disk copy and the helper's copy of the files.
- Continue with step 1. The saved export of step 2 is the one kept on
  the current signer VM or off it, never one from the snapshot's disk.

**If the current signer VM cannot be used,** install a fresh signer VM
by this runbook, steps 1 to 3, and create the state directory of step 4,
but run neither `ca-init` nor `install-bundle` (step 6): the restored
`signer.db` brings the key records, the trust bundle and the policy of
the same genesis. Create the lock file as the signer's user
(`runuser -u keyroster-signer -- touch /var/lib/keyroster-signer/signer.lock`),
then hold, run the capture block on the host where keyroster-server runs,
take the three files out of the snapshot's disk as above, run the file
restore and continue with step 1. If keyroster-server ran on the old VM
and its state directory is lost with it, the capture block cannot keep
its copy, and step 2b then imports only the saved export: revocations
made after the latest saved export stay lost (T-03-207's remaining
residual). This works only where
the fresh signer reaches the same CA keys: `serve` opens every key by
its recorded fingerprint, so it needs the same HSM or keys behind the
agent backend, or for the software backend its `software` directory
taken from the snapshot's disk with the three files. Keys in a TPM
cannot leave the old VM's TPM, so for the TPM backend it is not
possible. If it is not possible, or `serve` or
step 2 refuses, escalate. (UNVERIFIED: no part of this has run.)

**A VM snapshot with RAM is not supported for the signer VM.** Never
resume one: the signer process would run on from the snapshot's memory
and can log entries (for example a refusal summary it was holding)
before any hold. This runbook does not cover taking the disk out of one
either; escalate. Take disk-only snapshots of the signer VM.

If the signer logged entries after the restore anyway, step 2 shows the
fork and you stop and escalate: that stays the rule whenever step 2
detects a fork. Phase 4's witnessed checkpoint removes the problem
structurally (see the warning above).

1. With the hold in force, export the restored log:

   ```
   runuser -u keyroster-signer -g keyroster-signer -G tss -- \
     keyroster-signer export-log --state-dir /var/lib/keyroster-signer --out /tmp/restored.jsonl
   ```

2. Verify the restored export on its own first:

   ```
   keyroster audit verify --pin SHA256:<A from paper> --pin SHA256:<B from paper> --threshold 1 \
     /tmp/restored.jsonl
   ```

   It must pass. If it fails, do not compare it with anything and read
   nothing from it: stop there, keep the signer stopped, record the result
   in the operations log, and escalate; this runbook does not cover that
   case. Keep the hold in force. The comparisons and the `grep` commands below read the restored
   export's fields as well as the saved export's, and only this command
   checks every entry of the restored export.

   Then compare it with the latest export you kept from before the
   restore. That saved export must come from storage that no restore
   rolled back: the current signer VM's own disk, or a copy kept off the
   signer VM. Never take it from a snapshot's disk or from the backup you
   restored: an export from there is as old as the restored log, and the
   comparison would show nothing lost.

   ```
   keyroster audit verify --pin SHA256:<A from paper> --pin SHA256:<B from paper> --threshold 1 \
     --previous /root/latest-saved.jsonl /tmp/restored.jsonl
   ```

   A restored log that is older than the saved one is reported as shrunk
   (`log shrank`) or rewritten. Since plan 02-04, `audit verify` verifies
   logs that contain `directory_install` and `login_issue` entries, and
   `audit verify` checks revoke and krl_publish entries since 03-03 (the
   signer writes them since plan 03-01); an older `audit verify` binary
   refuses them, so use a current one. A binary built between plans 02-01
   and 02-04, or before plan 03-03 for a log with a `revoke` or
   `krl_publish` entry, says "not verifiable by this version", which is
   not a sign of tampering. A Phase 1 binary usually stops earlier, at the
   bundle whose policy added the WebAuthn RP (`json: unknown field
   "webauthn"`), which is not a sign of tampering either; see the
   compatibility note in
   [root-ceremony.md](root-ceremony.md#change-the-policy-successor-policy-for-example-add-the-webauthn-rp).
   `TestAuditLoginAcrossPolicyChange` (e2e) runs this command on two
   exports of a signer with a directory and login certificates: the later
   export verifies with `--previous` set to the earlier one, and the
   earlier export is refused as `log shrank` with `--previous` set to the
   later one. That is two exports of one live signer, not a restored
   database.

   If it passes, the restored log extends the saved one: the restore took
   back nothing that the saved export records, and there is nothing in it
   to compare or replay. Run step 2b all the same: a revocation made after
   the saved export is in neither file.

   If it fails, whatever it reports (`log shrank`, `log rewritten` or
   another refusal), verify the saved export itself, and that the restored
   log is a prefix of it, before you read anything from the saved export:

   ```
   keyroster audit verify --pin SHA256:<A from paper> --pin SHA256:<B from paper> --threshold 1 \
     /root/latest-saved.jsonl
   keyroster audit verify --pin SHA256:<A from paper> --pin SHA256:<B from paper> --threshold 1 \
     --previous /tmp/restored.jsonl /root/latest-saved.jsonl
   ```

   Both must pass. If either fails, do not use the saved export at all:
   not for the counts below, and not for step 3's list and proposals. Stop
   there, keep the signer stopped, record both results in the operations
   log, and escalate; this runbook does not cover that case. The second
   command also fails when the restored signer logged entries after the
   restore, which the hold is there to prevent: the restored log is then
   no prefix of the saved one, and its lost entries cannot be told apart
   this way. The command above does not do
   these checks: it verifies the restored export (which the standalone
   command above has already checked; `log shrank` and `log rewritten` are
   reported only after it did) and reads only the last checkpoint of the
   saved one, and what it reports looks the same for a
   log that was cut back as for one that was cut back and rewritten. The
   first command checks every entry of the saved export, including the
   decoded fields that the `grep` commands below and in step 3 read (see
   "What makes the replay safe" in step 3), so the counts, the list and
   the bytes they give are the ones the signer logged. The second proves
   that the restored log is a prefix of the saved one, so the lost entries
   are exactly the saved export's entries after it.

   Once both pass, compare the versions by hand, in both files, to see
   what the restore took back:

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

   Then count the revocations in both verified exports:

   ```
   grep -c '"kind":"revoke"' /root/latest-saved.jsonl
   grep -c '"kind":"revoke"' /tmp/restored.jsonl
   ```

   Record both counts in the operations log. Whatever they show, recover
   in step 2b before you release the hold. The restored log is a prefix of
   the saved one (the second check above), so the difference is exactly
   the number of lost revoke entries. The count reads only the `"kind":`
   key, which `audit verify` binds once per line to the entry's own kind.
   It cannot see a revocation made after the latest saved export (T-03-207),
   which only keyroster-server's copy holds.

   So take a saved export after every revocation (see
   [revoke.md](revoke.md#7-the-audit-log-after-a-revocation)). The recovery
   also imports keyroster-server's copy, kept by the capture block, which
   covers the revocations after the latest saved export while that
   server's state directory survives the restore. When the server's state
   directory is lost with the restore, only the saved export is imported,
   and revocations after it stay lost.

   **2b. Recover the revocations the restore lost (every restore, before
   the release).** Run it after every restore, whatever the counts above
   show, and with the hold in force, and only after the cross-check of the
   server copy against the hosts printed `cross-check passed:` (T-03-277).
   The restored signer's first KRL after the restore must be the
   recovery's, and it lists every revocation that either import holds. Every lost user certificate is revoked too. Lost
   host and machine certificates are listed, and are revoked only when the
   admin names them (the owner's answer `revoke-users-list-others`,
   03-06b). Run the five parts in this order:

   1. **Check the clock, under the hold, before the recovery.** The
      recovery publishes a KRL whose version comes from the signer's
      clock, and that version must be above every KRL version it imports.
      As root:

      ```
      timedatectl                                  # "System clock synchronized: yes"
      runuser -u keyroster-signer -g keyroster-signer -G tss -- \
        keyroster-signer doctor --state-dir /var/lib/keyroster-signer
      ```

      Go on only when `timedatectl` reports a synchronized clock and
      `doctor` shows `OK clock`, as in [Snapshot restore: check the clock
      first](#snapshot-restore-check-the-clock-first).

   2. **Copy the inputs to the admin.** An admin account (section 8, for
      example `alice`, with her own ssh-agent and `keyroster` config) signs
      the recovery. It must be an admin of the **restored** policy: a
      policy restored older can lack admins added since. Root must not
      create, change or write a path the admin can write (step 3 below
      explains why). So the block writes as the admin with `runuser`, and
      root reads only its own files and passes their bytes on standard
      input. As root, with `<admin>` that account:

      ```
      bash -eu -s <admin> <<'EOF'
      A=$1
      H=$(getent passwd "$A" | cut -d: -f6)
      test -n "$H"
      test -d /root/recovery
      runuser -u "$A" -- sh -c 'umask 077 && mkdir -m 0700 "$1"' sh "$H/recovery-in"
      copy_in() {
        runuser -u "$A" -- sh -c 'umask 077 && set -C && cat >"$1" && chmod 0600 "$1"' sh "$H/recovery-in/$1" <"$2"
      }
      copy_in restored.jsonl /tmp/restored.jsonl
      copy_in latest-saved.jsonl /root/latest-saved.jsonl
      files="restored.jsonl latest-saved.jsonl"
      if [ -e /root/recovery/server-krl.json ]; then
        copy_in server-krl.json /root/recovery/server-krl.json
        files="$files server-krl.json"
      fi
      echo "copied $files to $H/recovery-in for $A"
      EOF
      ```

      Only the last line's `copied` means the files are there. It names
      `server-krl.json` exactly when the capture block printed `kept:`.
      `mkdir` refuses a name that exists, a planted link included, and
      root does not remove it. The admin removes it, or you ask them which
      name is free and use that one.

   3. **The admin signs the recovery.** In their own session, with their
      ssh-agent and `keyroster` config, and with the directory the copy
      printed:

      ```
      keyroster revoke recover --restored /home/<admin>/recovery-in/restored.jsonl \
        --saved /home/<admin>/recovery-in/latest-saved.jsonl \
        --krl /home/<admin>/recovery-in/server-krl.json \
        --out /home/<admin>/recovery-in/recovery.bin
      ```

      Leave out `--krl ...` only when the capture block printed `no server
      KRL copy`. When it printed `kept:`, the summary must list the server
      copy among the imports, as a line that starts `import:
      /home/<admin>/recovery-in/server-krl.json: KRL v`. That line ends
      with the KRL's counts or, when the copy is the saved export's last
      KRL, with `same as saved export, log entry <n>, imported once`. If no
      such line is there, answer `n` and run the command again with
      `--krl`. Root's release check in part 5 checks the same again.

      Read the summary before you answer `y` at `Sign this recovery?
      [y/N]`:

      - `installation:` names the installation.
      - `restored log:` gives both logs' sizes.
      - Each `import:` line names a KRL and its version. A line that ends
        `same as ..., imported once` names an input identical to an
        earlier one, which the request carries once.
      - `lost certificate: ... : revoke` lines name the lost user
        certificates, which are always revoked.
      - `lost certificate: ... : keep; public key ...` lines name lost host
        and machine certificates. Each of these lines prints the
        certificate's public key. Revoke one now by adding `--revoke-lost
        SERIAL` (repeatable) and running the command again, or later with
        `keyroster revoke key` and that public key (see
        [revoke.md](revoke.md#7-the-audit-log-after-a-revocation)).
      - `lost certificates expired before this request, not carried: <n>`
        counts the lost host and machine certificates that had expired.

      The command ends `wrote the signed recovery request to
      /home/<admin>/recovery-in/recovery.bin`.

   4. **Read the request back.** As root:

      ```
      bash -eu -s <admin> <<'EOF'
      H=$(getent passwd "$1" | cut -d: -f6)
      test -n "$H"
      if [ -e /root/recovery/recovery.bin ]; then
        echo "/root/recovery/recovery.bin exists: move the refused request aside first (step 2b)" >&2
        exit 1
      fi
      runuser -u "$1" -- test -f "$H/recovery-in/recovery.bin"
      runuser -u "$1" -- head -c 9470227 "$H/recovery-in/recovery.bin" > /root/recovery/recovery.bin
      test -s /root/recovery/recovery.bin
      test "$(stat -c %s /root/recovery/recovery.bin)" -le 9470226
      echo "read the recovery request back to /root/recovery/recovery.bin"
      EOF
      ```

      Root reads the admin's file only as the admin, and copies it only
      when that account sees a regular file (after following links) of at
      most 9 470 226 bytes, the most `recover-revocations` reads. Root
      writes only its own directory. Only the last line's `read the
      recovery request back` means the copy is there. The block stops when
      the admin's file is not a regular file (a link that leads nowhere or
      to a device, a FIFO), cannot be read, or is larger, and it stops with
      a reason when `/root/recovery/recovery.bin` exists from an earlier
      read-back: move that file aside first, with the block below the
      refusals. A file the admin turns into a FIFO between the check and
      the copy makes the block wait instead: stop it with Ctrl-C, move the
      partial file aside the same way, and escalate.

   5. **Apply it under the hold.** As root:

      ```
      runuser -u keyroster-signer -g keyroster-signer -G tss -- \
        keyroster-signer recover-revocations --state-dir /var/lib/keyroster-signer < /root/recovery/recovery.bin
      ```

      It takes the state directory's lock, runs every start-up check of
      the signer and applies the request in one transaction. It writes
      one `revocation_recovery` entry and publishes one KRL, and it never
      serves. It prints `recovered: <n> entries from <n> imported KRLs, <n>
      lost certificates revoked, <n> kept; KRL v<v> (log entries <i>,
      <j>)`: write that line into the operations log. Then export the log
      again and verify it, on its own pins and as an extension of the
      restored log:

      ```
      runuser -u keyroster-signer -g keyroster-signer -G tss -- \
        keyroster-signer export-log --state-dir /var/lib/keyroster-signer --out /tmp/recovered.jsonl
      ```

      ```
      keyroster audit verify --pin SHA256:<A from paper> --pin SHA256:<B from paper> --threshold 1 \
        /tmp/recovered.jsonl
      keyroster audit verify --pin SHA256:<A from paper> --pin SHA256:<B from paper> --threshold 1 \
        --previous /tmp/restored.jsonl /tmp/recovered.jsonl
      ```

      Both verifies must pass. Then, as root, run the release check:

      ```
      bash -eu <<'EOF'
      RESTORED=/tmp/restored.jsonl
      RECOVERED=/tmp/recovered.jsonl
      KEPT=/root/recovery/server-krl.json
      set -o pipefail
      stop() { echo "release check: $*" >&2; exit 1; }
      test -s "$RESTORED"
      test -s "$RECOVERED"
      n=$(($(wc -l <"$RESTORED") - 1))
      [ "$(wc -l <"$RECOVERED")" -eq $((n + 3)) ] || stop "$RECOVERED does not hold exactly two entries after the $n of $RESTORED"
      [ "$(sed -n "$((n + 1))p" "$RECOVERED" | grep -c "^{\"index\":$n,.*\"kind\":\"revocation_recovery\"")" = 1 ] || stop "entry $n is not a revocation_recovery"
      [ "$(sed -n "$((n + 2))p" "$RECOVERED" | grep -c "^{\"index\":$((n + 1)),.*\"kind\":\"krl_publish\"")" = 1 ] || stop "entry $((n + 1)) is not a krl_publish"
      imported=$(sed -n "$((n + 1))p" "$RECOVERED" | grep -o '"import_krl_versions":\[[0-9,]*\]' | tr -dc '0-9,') || stop "entry $n names no imported KRL versions"
      if [ -e "$KEPT" ]; then
        [ "$(wc -l <"$KEPT")" -eq 1 ] || stop "$KEPT is not one line"
        grep -Eqx '\{"krl":"[A-Za-z0-9+/=]+","manifest":"[A-Za-z0-9+/=]+","sig":"[A-Za-z0-9+/=]+"\}' "$KEPT" || stop "$KEPT is not a KRL document as keyroster-server writes it"
        v=$(cut -d'"' -f8 "$KEPT" | base64 -d | grep -o '"krl_version":[0-9]*' | cut -d: -f2) || stop "$KEPT has no KRL version"
        case "$v" in '' | *[!0-9]*) stop "$KEPT has no single KRL version" ;; esac
        printf '%s\n' "$imported" | tr , '\n' | grep -x "$v" >/dev/null || stop "the recovery did not import the kept server copy, KRL v$v (it imported KRL versions [$imported])"
        echo "release check passed: entries $n (revocation_recovery) and $((n + 1)) (krl_publish), imported KRL versions [$imported], the kept server copy's v$v among them"
      else
        echo "release check passed: entries $n (revocation_recovery) and $((n + 1)) (krl_publish), imported KRL versions [$imported], no server KRL copy kept"
      fi
      EOF
      ```

      Only the last line's `release check passed:` counts, and its two
      entries must be the `log entries <i>, <j>` of the `recovered:` line.
      The check reads only what the two verifies bound: an export holds
      its entries one per line, indices in order, and a checkpoint line
      last; and the `"kind":` key of every line, and on a
      `revocation_recovery` line the `"import_krl_versions":` key, occur
      once each with the leaf's own value. So it passes only when this
      recovery appended exactly its two entries to the restored log (a
      restored log that already holds a recovery from an earlier restore
      included) and, after `kept:`, when the recovery imported the kept
      copy's KRL version, also where that version came in through the
      saved export. It reads the kept copy only in the form keyroster-server
      writes it: one line holding the document's three fields. If either
      verify fails or the release check stops, keep the hold and escalate.

   **The refusals and outcomes of step 2b, and what to do.** Both commands
   exit 1 on a refusal and write nothing. `keyroster revoke recover`
   prints `keyroster revoke: refused (<name>): <reason>`, and
   `recover-revocations` prints `refused: <name>: <reason>`. Keep the hold
   for every one of them:

   - `nothing to recover` (from `keyroster revoke recover`, exit 0, no
     file written): neither export's trust bundle has an installation ID
     and no `--krl` was given, so no KRL was ever published, and there is
     no recovery to apply. Release the hold only when the capture block
     printed `no server KRL copy`. After `kept:`, a `nothing to recover`
     keeps the hold: the server copy was left out. Run the command again
     with `--krl`, which then refuses `recovery_installation_lost`, and
     escalate.
   - `recovery_installation_lost`: the restored trust bundle has no
     installation ID, but the saved export's bundle has one, or a server
     copy was given. A lost bundle added the installation ID, or the
     server copy proves that a KRL was published under one. Escalate.
     (UNVERIFIED: no restore of such a bundle has run.)
   - `recovery_fork`: neither export extends the other. Escalate, as for
     a fork in step 2.
   - `... does not verify on your trust pins: ...`: an export does not
     verify on the admin's pins. Escalate, as in step 2.
   - `--out ... exists`: an earlier attempt left `recovery.bin`. Ask the
     admin to move it aside, then run the command again.
   - `recovery_import_invalid`: a `--krl` file that is not a KRL
     document, or an import that does not verify under the restored bundle
     and its installation ID. Check that `server-krl.json` is the file
     the capture block kept. If it is, escalate. An import signed under
     another ops key is possible only after 03-13 rotates the ops key, and
     a certificate that only a lost bundle's CA generation names
     (`recovery_certificate_invalid`) is possible only after 03-12. 03-12
     and 03-13 own making those cases recoverable (UNVERIFIED).
   - `recovery_revoke_lost_unknown`: `--revoke-lost` named a serial that
     is not a lost host or machine certificate. Correct the serial from
     the summary.
   - `recovery_too_large`: the live revocations do not fit in one recovery
     (about 80 000 serials under a P-256 CA and 128 000 under Ed25519,
     T-03-269). Escalate.
   - `the state directory is in use by another keyroster-signer process
     ...` (from `recover-revocations`): something else holds the state
     directory's lock. Find it (the hold must keep the unit stopped), then
     run the same line again.
   - `recovery_version_not_above_import`: the signer's clock is not yet
     past the newest imported version (T-03-208). Wait the seconds the
     reason names, then run the same line again with the same file.
   - `recovery_evidence_invalid`: the admin who signed is not an admin of
     the restored policy. Move the refused request aside (below), and have
     one who is make and sign it again, from part 2 on, which copies the
     inputs to that admin. Escalate when there is none (T-03-276).
   - `recovery_log_mismatch`: the request was made for another log state.
     Either the restored signer logged something after the export of step
     1, or the recovery already ran. If an earlier run of this file
     printed `recovered:`, the recovery is done: go on with its export.
     Otherwise stop and escalate, as for a fork.
   - `recovery_malformed`, `recovery_installation_mismatch`,
     `duplicate_request`, `recovery_certificate_not_lost`,
     `recovery_certificate_expired` or `recovery_user_certificate_kept`:
     the file is not the request this runbook's `keyroster revoke recover`
     wrote for this restore. Move the refused request aside (below), make
     it again from part 3 on with a current binary, and escalate if the
     refusal repeats.
   - `unavailable: ...` (`krl_no_installation_id`, `ops_key_unavailable`,
     `trust_changed`): the signer cannot sign now. Escalate.

   **Move a refused request aside** before you read a new one back. As
   root:

   ```
   bash -eu <<'EOF'
   test -f /root/recovery/recovery.bin
   d=/root/recovery/refused-$(date -u +%Y%m%dT%H%M%SZ)
   mkdir -m 0700 "$d"
   mv /root/recovery/recovery.bin "$d/recovery.bin"
   echo "moved the refused request to $d/recovery.bin"
   EOF
   ```

   Write its last line into the operations log. The refused request stays
   in `/root/recovery` as part of the operations record. Never delete it,
   and never remove `/root/recovery`, which holds the kept server copy.
   The admin moves their own `recovery.bin` aside too (see `--out ...
   exists` above). Part 4 then reads the new request back.

   **Release the hold** only after step 2b, in one of two cases:

   - the recovery's two `audit verify` runs passed and the release check
     printed `release check passed:`;
   - `keyroster revoke recover` printed `nothing to recover` after the
     capture block printed `no server KRL copy`.

   No restored signer starts before that, so none publishes a KRL that
   lacks a lost revocation. The clock was checked in step 2b. Make sure
   the firewall rule keeps users away, and then, as root:

   ```
   bash -eu -s keyroster-server keyroster-signer <<'EOF'
   test "$#" -gt 0
   for u in "$@"; do
     rm "/etc/systemd/system/$u.service.d/restore-hold.conf"
   done
   systemctl daemon-reload
   for u in "$@"; do
     if systemctl is-failed --quiet "$u.service"; then systemctl reset-failed "$u.service"; fi
   done
   echo "released: $*"
   EOF
   systemctl start keyroster-signer.service keyroster-server.service
   ```

   Name the same units as for the hold. Where keyroster-server runs on
   another host, the release on the signer host names only
   `keyroster-signer` and starts only `keyroster-signer.service`. Then, as
   root on the server's host, run the release block naming only
   `keyroster-server`, and start `keyroster-server.service` there.
   (UNVERIFIED: no test releases a server held on another host.) The
   release resets a unit that had failed before the hold, for example a
   signer that crash-looped on a damaged database until systemd's start
   limit stopped it: without the reset, systemd refuses its start until
   the limit's 10 minutes have passed.

3. Reinstall what the restore lost, with the same bytes as before and
   before anyone installs anything new. Install the exact versions that
   were lost: a different version 2 built on the restored version 1 is
   accepted too, and the disablements of the lost version are then gone
   for good.

   Keep users away until the last lost version is back (the firewall
   rule set before step 1).

   **Enrolled hosts and a re-made version (owner decision D-R2, PR #71).**
   An enrolled host whose agent already accepted a lost version refuses a
   *different* version with that number, and every version built on it:
   its applier reports `directory_not_verified` ("does not chain") on
   every run. Its KRLs keep applying (the applier verifies them against
   the bundle it accepted and installs them alone), but its principals
   stay at the lost version until it is re-bootstrapped.

   - **Escalate before you install a lost version differently, or a
     different version with a lost number, while any host is enrolled.**
     Replaying the exact bytes from the saved export (below) needs none of
     this: a host that saw the lost version accepts the same bytes as a
     no-op.
   - **Which hosts saw a lost version.** On each enrolled host, as root,
     `/var/lib/keyroster-agent/outbox/accepted.json` names the directory
     version the agent accepted. A host whose `directory` is above the
     restored signer's version saw a lost one. A host you cannot reach
     must be assumed to have seen it.
   - **Re-bootstrap each such host** once the re-made chain is installed,
     as root on the host:

     ```
     keyroster-agent reset-directory
     ```

     It drops the accepted directory and the spool's directory files,
     prints the version and SHA-256 it dropped, and writes the outbox's
     `accepted.json`. It accepts nothing itself. At the fetcher's next poll
     the agent receives the server's current directory and accepts it the
     way a first install does: signed by the admin quorum of the policy it
     accepted, for its pinned installation, with no chain to anything it
     held before. So check, after the next poll, that `last_apply` in
     `/var/lib/keyroster-agent/status.json` names the directory version
     that `keyroster directory show` reports on your workstation, and that
     its `errors` are empty; a different version means the server served
     another admin-signed version than the one you installed: escalate.
     Until the new directory arrives the host keeps the principals it had.
   - Run in CI: `TestResetDirectory` and `TestKRLAlone` (the agent's
     apply tests), and `TestInstallLayout` (the command after an install).
     UNVERIFIED: no restore with a re-made version has been run against an
     enrolled host, and `reset-directory` has not run on a real host.

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
     saved export, which step 2 verified, and install it with `keyroster
     directory install`, one version at a time, in log order:

     1. Write the proposal of the lost version `V` (`directory.json` and
        `directory.json.sigs`) from the export's decoded line:

        ```
        bash -eu <<'EOF'
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
        echo "wrote the proposal of directory version $V to $D"
        EOF
        ```

        Paste it whole: it runs in its own `bash -eu`, which stops at the
        first line that fails, so your shell stays open. Only the last
        line's `wrote the proposal` means the proposal is complete; without
        it, do not install anything from that directory.

        The decoded `directory` and `sigs` fields are in every export that
        `keyroster-signer export-log` writes since plan 03-02. An older
        export has only `version` and `policy_version` there (the bytes are
        then only inside the leaf, and the `test -s` lines stop): export the
        saved log again with a current binary, or keep the proposal
        directories of past installs.
     2. Copy the proposal to the admin who installs it. `/root` is mode
        0700, so an admin account (section 8, for example `alice`, with
        her own ssh-agent and `keyroster` config) cannot read
        `/root/replay`. Root must not create, change or write any path
        the admin can write: the admin can plant a symbolic link in their
        own home (for example `~/replay` pointing at
        `/var/lib/keyroster-signer`), and root would follow it. So the
        block below writes as the admin, with `runuser`, and root only
        reads its own files and passes their bytes on standard input. As
        root, with `<admin>` that account and `V` the lost version:

        ```
        bash -eu -s <admin> <<'EOF'
        V=2                                   # the lost directory version
        H=$(getent passwd "$1" | cut -d: -f6)
        test -n "$H"
        runuser -u "$1" -- sh -c 'umask 077 && mkdir -m 0700 "$1"' sh "$H/replay-v$V"
        for f in directory.json directory.json.sigs; do
          runuser -u "$1" -- sh -c 'umask 077 && set -C && cat >"$1" && chmod 0600 "$1"' sh "$H/replay-v$V/$f" <"/root/replay/v$V/$f"
        done
        echo "copied the proposal of directory version $V to $H/replay-v$V for $1"
        EOF
        ```

        Only the last line's `copied the proposal` means both files are
        there. The block sets the modes itself (0700 and 0600), so that
        neither a umask nor a default ACL inherited from the home
        directory widens them. `mkdir` refuses a name that exists, a planted link
        included; root does not remove it. The admin removes it, or you
        ask them which name is free and use that one.

        If the admin runs `keyroster` on a workstation instead, copy the
        two files there, into a directory only that admin can read, and
        use that path below.
     3. With the restored signer running, wait at least 5 s after it
        started, or restart keyroster-server: the server keeps the signer's
        status for up to 5 s, and until then it can still report the
        version it served before the restore. Then, as that admin, with
        the directory the copy printed:

        ```
        keyroster directory install /home/<admin>/replay-v2
        ```

        It must print `The server reports directory version 2 installed`.
        `The server already serves proposal ... nothing to do` means the
        server still reported the pre-restore version: wait and run it
        again. Check on the signer host that the signer holds the version
        (`keyroster audit verify` of a new export counts the directory
        installs).

   **What makes the replay safe, and what it does not cover.** `audit
   verify` does not interpret the `decoded` part of an export line, except
   for the fields these `grep` commands read. `kind` on every line,
   `bundle_version` on every `bundle_install` line, and `version`,
   `directory` and `sigs` on a `directory_install` line that carries them
   must each occur once, with the value of the line's own leaf (for
   `directory` and `sigs`, the standard base64 of its document and
   signatures), and on no line of another kind. So after step 2's two
   `audit verify` commands, the counts of step 2 and the list above come
   from the verified leaves, and the proposal written from the saved export
   is the document and signatures of the verified `directory_install` leaf
   of version `V`: an edited or relabelled field, or a decoy one on another
   line or nested in the same line, is refused, and an escaped or missing
   field makes the `test` lines stop. The signer checks the replay again:
   the directory must carry the admin quorum's signatures under the policy
   in force, and its `prev` must be the SHA-256 of the restored version.
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
   case and its re-invite path have not been run.) Those are different
   versions with the lost numbers: escalate first while any host is
   enrolled, and re-bootstrap every enrolled host that saw a lost version
   (**Enrolled hosts and a re-made version**, at the start of this step).

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
> restored log taken while the signer is stopped, step 2's `audit verify`
> of the restored export on its own, step 2's two `audit verify` runs of
> the saved export (on its own pins, and with `--previous`
> set to the restored export), step 3's extraction commands above
> verbatim, a copy of the proposal to another directory of mode 0700
> with files of mode 0600 (as the test's own user, so not the runbook's
> `runuser` copy block, which the `systemd-sandbox` check below runs),
> the wait, `keyroster directory install` of
> that copy with the signer then reporting the lost
> version with the same bytes, the new export verifying on its own pins
> and with `--previous` set to the restored export, and `audit verify
> --previous` refusing it against the pre-restore export.
>
> **Run in CI (`systemd-sandbox`, `test/systemd/smoke.sh`, 03-02)** with
> the repository's units on an Ubuntu 24.04 runner: the hold block above
> verbatim for keyroster-server and keyroster-signer, each start then
> refused with `Assertion failed on job for ...`; the file restore block
> verbatim, from a copy of the signer's database taken under the hold,
> refusing first while another process holds `signer.lock`, with stale
> `-wal` and `-shm` files in the state directory and a backup set of
> `signer.db` and an empty `-wal`: the restored `signer.db` and `-wal` are
> the backup's bytes, keyroster-signer 0600, and the stale `-shm` is gone;
> the release block verbatim, with the signer crash-looped into its
> start limit before the hold (a temporary drop-in), so that it starts
> again only because the release resets it; and the signer starting again with
> `doctor` passing. No keyroster-server runs in that check: its unit is
> held and its start refused, never started. It also runs step 3's copy
> block verbatim for an admin account: it refuses with the account's
> `~/replay-v2` planted as a link to a directory of root's, which keeps
> its owner, mode and contents, and once the admin has removed the link
> it writes both files as the admin, mode 0600 in a directory of mode
> 0700, with root's bytes.
>
> **Run in CI e2e (TestRestoreRecoversLostRevocations, 03-06c)** on a
> test signer behind a test keyroster-server, with the harness's agent
> backend. The setup:
>
> - user certificates A, B and C (three subjects), and a control
>   certificate E that is never revoked, are issued before the backup;
> - after the backup, a user certificate D and host certificates H and H2
>   are issued, A is revoked by key ID, C with `keyroster revoke user`, H2
>   with `keyroster revoke serial --ca host` and a plain key K with
>   `keyroster revoke key`;
> - the saved export is taken, and then B is revoked with `keyroster
>   revoke serial`, so only the server's `krl-served.json` holds that
>   revocation;
> - the server and the signer are stopped, the server's copy is kept, and
>   the backup is restored.
>
> C is a certificate the restored log knows and H2 a lost host
> certificate, so only the imported KRLs keep them revoked; the rule that
> revokes every lost user certificate covers neither. Then the restored
> export (taken while the signer is stopped) and step 2's three verifies;
> `keyroster revoke recover` with the kept copy as `--krl`, whose summary
> lists the copy among the imports, revokes the lost user certificate D
> and keeps H and H2 with their public keys; and `keyroster-signer
> recover-revocations` before the restored signer ever starts. It is
> refused while another process holds `signer.lock` and with the evidence
> of a key that is no admin (`recovery_evidence_invalid`), each time with
> the log unchanged, then applies the file once, and a second run is
> refused `recovery_log_mismatch`. The recovered log adds exactly one
> `revocation_recovery` entry and one `krl_publish` to the restored log,
> at the indices its `recovered:` line names, so no KRL was published
> between them, and it verifies on its own and with `--previous` set to
> the restored export. The release check passes on it with the kept copy,
> and stops on the restored export given as the recovered one and on a
> server copy whose version the recovery did not import. With both
> started again, the served KRL makes `ssh-keygen -Q` refuse A, B, C, D,
> H2 and K and accept E and H, and sshd refuses A, B, C and D and accepts
> E. `keyroster revoke key` with the public key the summary printed then
> revokes H. A restarted signer serves the same KRL version, which still
> refuses all of them, and the final export verifies. The test runs the
> commands as its own user, not the runbook's `runuser` blocks, which the
> `systemd-sandbox` check below runs; it runs the release check's script
> as the runbook has it.
>
> **Run in CI e2e (TestRestoreRecoveryAfterRecovery, PR #70 review)**: a
> restore whose backup already holds a recovery, and whose server copy is
> the saved export's last KRL because the saved export was taken after
> the last revocation. `keyroster revoke recover` lists the copy as `same
> as saved export, log entry <n>, imported once` and imports one KRL; the
> recovery appends its two entries to the restored log, which then holds
> two recoveries; and the release check passes by the saved export's
> version. The served KRL then refuses both revoked certificates.
>
> **Run in CI (`systemd-sandbox`, `test/systemd/smoke.sh`, 03-06c)** with
> the blocks of step 2b verbatim, under the hold, for the admin account:
> the copy block refusing a planted `~/recovery-in` link and then copying
> with the server copy kept and without it; the read-back block stopping
> on a request planted as a FIFO, a link to `/dev/zero` or a link that
> leads nowhere, and then reading the request back; the recovery line
> with a request that does not parse, refused `recovery_malformed` with
> `signer.db` unchanged; after that refusal, the read-back stopping with
> its reason, the move block moving the refused request aside, and a new
> request read back and refused the same way; and the release check on
> fixture exports (no recovery is applied in that job), passing on a
> restored log that already holds a recovery, with the kept copy's
> version imported and without a kept copy, and stopping on a version
> that was not imported (v9, and v1, which only a prefix match would
> find in v19) and on a recovered
> log that adds nothing. The capture block's runs are listed with that
> block above.
>
> **UNVERIFIED (step 2b):** a real signer host, and the TPM and PKCS#11
> backends for `recover-revocations` (CI e2e runs the harness's agent
> backend); the copy of the server's file from another host, and the
> release of a server held on another host; a request or server copy
> turned into a FIFO between a block's check and its copy (the block
> waits; the runbook says to stop it); and a fresh signer VM whose server
> copy died with the old VM, after which only the saved export's KRL is
> imported and revocations after the latest saved export stay lost
> (T-03-207's remaining residual).
>
> **UNVERIFIED:** a VM snapshot restore (the disk copy, the helper VM,
> the read-only mount and the transfer of the three files to the current
> signer VM) and the fresh signer VM when the current one cannot be
> used, the hold and the file restore on a
> real signer host (a running keyroster-server, or the TPM drop-in beside
> the hold), the file restore's refusal of a signer that is `activating`
> (run once by hand against a throwaway unit in auto-restart, not in
> CI), a backup whose `-wal` holds committed frames (CI's backup `-wal`
> is empty, so only the file handling is run), the replay of a lost
> `bundle_install`, a lost version that
> binds a passkey and the re-invite after it, keeping users away from the server, the version counts of
> step 2 against a real restored signer, the stop in step 2 for a
> restored export that does not verify on its own (the refusals
> themselves are run in the audit unit tests), and step 2 when the saved
> export's prefix check fails and the procedure stops, for example for a
> restored signer that logged K > 0 entries after the restore despite
> the hold and had lost L > 0:
> step 2's first command then reports `log shrank` when K < L and `log
> rewritten` otherwise, and the prefix check `log rewritten` when K <= L
> and `log shrank` when K > L. The `grep` patterns of step 2 match
> the export line format written by `keyroster-signer export-log`, not a
> real export of a restored signer.
