# Runbook: install keyroster-server

This runbook takes an admin from a host that already runs `keyroster-signer`
to a running, sandboxed `keyroster-server` in front of it, and then sets up
the first admin's `keyroster` client with `keyroster init`.

`keyroster-server` is the untrusted web front: it proposes, and the signer
decides. It has no configuration for its own identity. The WebAuthn relying
party (RP ID and origins) and every custody fact come from the signer's
Status, that is, from the root-signed policy and the signer's own key
report. The server refuses to start when the policy has no WebAuthn RP,
when its certificate does not cover the RP ID, or when the certificate has
expired.

> **What CI covers and what it does not.** The e2e suite
> (`TestServerInitEndToEnd`, `TestServerRefusesStart` and
> `TestServerSIGHUPDuringStartup` in `test/e2e/server_test.go`) runs the real
> `keyroster-server` binary against a real signer. It uses a test CA and the
> name `keyroster.localhost`, and runs `keyroster init` against it. Those
> tests cover the start-up refusals, the headers, the banner, the JSON log
> lines and a SIGHUP reload. **No CI job runs the systemd units below.**
> `systemd-analyze verify` passed on them on the development workstation.
>
> **Run on the homelab in 02-13.** Steps 1 to 5 ran, with Tailscale, on
> the homelab signer VM (Ubuntu 26.04, systemd 259, vTPM signer, bundle v3
> signed by a TEST root on a networked workstation), and step 5 ran from
> the Windows `keyroster.exe`. Two things differed from the text:
>
> - The Tailscale prerequisites in [What you need](#what-you-need) were
>   met out of band before step 1, not by a step of this runbook.
> - In step 5.4 the `--root-pin` values came from the fingerprints
>   `root init` printed for the TEST roots, not from a paper record. Init
>   ran with `--force`, which replaces an existing config, and with
>   `--user` and `--admin-key` as in step 5.4.
>
> What was checked:
>
> - `id keyroster-server` listed `keyroster-admin`;
> - the certificate unit ended `Result=success` before the server's first
>   start, with `key.pem` `root keyroster-server` mode `-rw-r-----`;
> - the timer was active;
> - the server logged `tls certificate loaded` (trigger `start`) and
>   `serving` with `policy_version` 2 and `bundle_version` 3;
> - `/healthz` answered `{"status":"ok"}` over the tailnet from a Windows
>   client with the system trust store;
> - `systemd-analyze security keyroster-server.service` printed 2.1 OK on
>   the host.
>
> Only these units, on this one host, have run. Other distributions, and
> any path without Tailscale, remain **UNVERIFIED**.

## What you need

- A signer installed per [signer-install.md](signer-install.md), on the same
  host, whose root-signed **policy carries the WebAuthn RP**. A genesis
  policy made without `--webauthn-rp-id` has none. Add it with a successor
  policy as described in
  [root-ceremony.md, "Change the policy: successor policy"](root-ceremony.md#change-the-policy-successor-policy-for-example-add-the-webauthn-rp).
- The `keyroster-server` binary for linux/amd64, built from the same
  reviewed commit as the signer, and this repository at that commit (for
  `deploy/`).
- A TLS certificate and key for the RP ID (next sections).
- For the **With Tailscale** path of step 3: `tailscaled` installed on the
  host and joined to the tailnet, with **MagicDNS** and **HTTPS
  Certificates** enabled in the tailnet's admin console. Without them the
  machine has no MagicDNS name to use as the RP ID, and `tailscale cert`
  fails. Enabling HTTPS Certificates publishes the name in Certificate
  Transparency logs (see the warning below). This runbook does not install
  Tailscale.

> **Warning: the RP ID and hostname are a one-way choice (D-09).**
>
> - The RP ID is the server's **exact full hostname**, for example
>   `<server>.<tailnet>.ts.net`. IP addresses are refused, because WebAuthn
>   rejects IP origins.
> - On Tailscale, use the **machine's full name, never the tailnet domain**.
>   `ts.net` is on the **Public Suffix List**, so `<tailnet>.ts.net` is a
>   registrable domain. An RP ID of `<tailnet>.ts.net` would let any machine
>   in the tailnet that can get a certificate act as the relying party for
>   these passkeys. The policy refuses such an RP ID.
> - Passkeys are bound to the RP ID. **Renaming the machine or the tailnet
>   later invalidates every enrolled passkey.** Every user would have to
>   enroll again.
> - The name is public. Every publicly trusted certificate, `tailscale cert`
>   included, is published in **Certificate Transparency** logs, so the
>   machine name and tailnet name become visible to anyone.

## TLS certificate

`keyroster-server` serves HTTPS (TLS 1.3 only) from an operator-provided
certificate file (leaf first, then the intermediates) and key file. It does
no ACME itself. Use one of:

- `tailscale cert` (the homelab deployment, D-11), with the timer below;
- an internal CA;
- your own ACME client.

The certificate must be trusted by your users' **browsers**: browsers refuse
WebAuthn on a certificate error. **A self-signed certificate is not
supported.**

The server checks the files every 60 s and on SIGHUP. It swaps in new files
only when they are a matching pair, the leaf covers the RP ID, and the leaf
is valid now. Otherwise it keeps the last good certificate, logs
`tls certificate reload refused`, and tries the files again every 60 s
until they load (so fixing only the key's group or mode is picked up too). Every successful load is logged as
`tls certificate loaded` (see "Logs" below). When less than 14 days of
validity remain, it logs `tls certificate expires soon` once a day.

### Tailscale certificates: what the timer is for

- A `tailscale cert` certificate is valid for **90 days**.
  `tailscale cert` renews it once **two thirds** of that lifetime have
  passed, and otherwise keeps the files it has.
- Each renewal creates a **new key**. That is why `keyroster init` pins the
  CA's **root**, not the leaf (RESEARCH Q1).
- The files on disk change only when `tailscale cert` runs.
  `deploy/systemd/keyroster-tailscale-cert.timer` runs it daily through
  `keyroster-tailscale-cert.service`. That oneshot unit:
  1. writes `/etc/keyroster/tls/fullchain.pem` and `key.pem`;
  2. gives the key to group `keyroster-server` with mode 0640;
  3. runs `systemctl try-reload-or-restart keyroster-server.service`.

## 1. Install the binary

Build it on a trusted machine from the reviewed commit (there are no signed
releases before Phase 6), with the Go toolchain in `go.mod`'s `toolchain`
line. A local Go of an older version would otherwise build it too, with a
standard library whose fixed vulnerabilities this network-facing server
reaches:

```
export GOTOOLCHAIN=$(awk '$1 == "toolchain" {print $2}' go.mod)
CGO_ENABLED=0 go build -trimpath -o keyroster-server ./cmd/keyroster-server
go version keyroster-server      # must print the toolchain line's version
```

Copy it to the server host and install it:

```
install -o root -g root -m 0755 keyroster-server /usr/local/bin/keyroster-server
```

## 2. System user

```
install -o root -g root -m 0644 deploy/sysusers.d/keyroster.conf /etc/sysusers.d/keyroster.conf
systemd-sysusers
id keyroster-server
```

`id` must list group `keyroster-admin`. That membership lets the server
connect to the signer socket (group `keyroster-admin`, mode 0660). It grants
access to the socket only: the signer still requires admin signatures or
passkey evidence for everything it signs.

## 3. TLS directory

```
install -d -o root -g keyroster-server -m 0750 /etc/keyroster/tls
```

The directory is `root:keyroster-server 0750` and the key file
`root:keyroster-server 0640`. The server reads them and cannot change them;
its unit mounts the directory read-only.

**Without Tailscale**, copy your certificate chain and key into place:

```
install -o root -g keyroster-server -m 0644 fullchain.pem /etc/keyroster/tls/fullchain.pem
install -o root -g keyroster-server -m 0640 key.pem /etc/keyroster/tls/key.pem
```

Then continue with step 4. When you replace the files later, while the
server runs, use the same two `install` lines and then run
`systemctl reload keyroster-server` so it loads them at once instead of
at the next 60 s check.

**With Tailscale**, do the following before the server is ever started.
Order matters: **certificate unit, timer, server**. The server needs the
certificate to start. The certificate unit's last line does nothing while
the server is not running.

1. Create the env file. `/etc/keyroster/tailscale-cert.env` is
   **`root:root 0644`**. The name in it is public. Only root may write the
   file, because the unit that reads it runs as root.

   ```
   install -d -o root -g root -m 0755 /etc/keyroster
   printf 'KEYROSTER_TLS_NAME=%s\n' '<server>.<tailnet>.ts.net' > /etc/keyroster/tailscale-cert.env
   chown root:root /etc/keyroster/tailscale-cert.env
   chmod 0644 /etc/keyroster/tailscale-cert.env
   ```

2. Install the units:

   ```
   install -o root -g root -m 0644 deploy/systemd/keyroster-tailscale-cert.service deploy/systemd/keyroster-tailscale-cert.timer /etc/systemd/system/
   systemctl daemon-reload
   ```

3. Start the certificate unit once, then enable the timer:

   ```
   systemctl start keyroster-tailscale-cert.service
   systemctl status keyroster-tailscale-cert.service
   ls -l /etc/keyroster/tls
   systemctl enable --now keyroster-tailscale-cert.timer
   systemctl list-timers keyroster-tailscale-cert.timer
   ```

   The unit must end with `status=0/SUCCESS`, and `key.pem` must be
   `root keyroster-server` with mode `-rw-r-----`.

## 4. Install and start the server unit

```
install -o root -g root -m 0644 deploy/systemd/keyroster-server.service /etc/systemd/system/keyroster-server.service
systemctl daemon-reload
systemctl enable --now keyroster-server.service
journalctl -u keyroster-server
```

The unit runs the server as `keyroster-server` with only
`CAP_NET_BIND_SERVICE`. Everything else is read-only (`ProtectSystem=strict`,
`ReadOnlyPaths=/etc/keyroster/tls`), except its state directory
`/var/lib/keyroster-server` (`StateDirectory=`, mode 0700, `--state-dir`). That
directory holds `server.db`: pending accounts, invites (as SHA-256 only) and
used admin nonces. Nothing in it is authority; only the admin-signed directory
the signer installs binds a passkey to a user.

The directory also holds `krl-served.json`: the last KRL document the server
served, which it writes, verified against the signer's trust bundle, before it
serves it. Like the rest of the directory it is no authority, because every
reader verifies the KRL against its own root-pinned bundle. It is, however, the
restore source for revocations that a signer restore lost (the restore
procedure lands with 03-06c). Never delete it, and back it up with the
directory. The server's KRL route answers 503, and logs why, rather than serve
a KRL it could not keep (`KRL not kept: ...`), one that does not verify (`KRL
not served: it does not verify ...`), or one below the version it served
(`KRL not served: version X is below version Y this server served ...`).
Hosts then keep their last KRL. This behaviour is run in CI (internal/server
tests, 03-06b).

Network access is limited to IPv4,
IPv6 and Unix sockets. At start the server asks the signer for its Status,
retrying for up to 30 s. It then exits non-zero if:

- the policy has no WebAuthn RP: `the installed policy has no WebAuthn RP;
  add it with keyroster root successor-policy`;
- the certificate does not cover the RP ID: `the certificate does not cover
  the RP ID ...`;
- the certificate is not valid now: `the certificate is valid from ... to
  ..., not now`;
- `krl-served.json` exists but does not parse: `server:
  /var/lib/keyroster-server/krl-served.json does not parse: ... keep it, do not
  delete it, and see docs/runbooks/server-install.md`. Do not delete the file,
  because it is the restore source for lost revocations. Put back the copy from
  the backup of the state directory. That remedy is UNVERIFIED; the refusal
  itself is run in CI (internal/server tests, 03-06b).

If the unit is not running, read `journalctl -u keyroster-server` for one
of these lines.

## Logs

The server writes one JSON object per line on stderr, which journald
records. Lines to look for:

- `serving` with `listen`, `rp_id`, `origins`, `policy_version` and
  `bundle_version`;
- `tls certificate loaded` with `fingerprint`, `not_after` and `trigger`.
  The trigger is `start` for the load at start, `file_change` for a reload
  after the files changed, and `sighup` for a reload on SIGHUP (also when
  the files did not change). The fingerprint is the lowercase hex SHA-256
  of the leaf. It equals the output of
  `openssl x509 -noout -fingerprint -sha256 -in /etc/keyroster/tls/fullchain.pem`
  with the colons removed and in lower case;
- `tls certificate reload refused`, with the reason, when new files were
  not swapped in;
- `tls certificate expires soon`, with `not_after`;
- `signer status refused; restart keyroster-server to serve the new RP ID`,
  after a successor policy changed `rp_id` while the server ran. The server
  answers 503 until you install a certificate for the new hostname and run
  `systemctl restart keyroster-server`;
- `signer status unavailable`. While the server cannot reach its signer,
  it answers every page and API call with 503 and shows no RP, policy,
  custody or directory data.

### What a Tailscale renewal looks like

- **The unit against a running server.** Run
  `systemctl start keyroster-tailscale-cert.service` while the server runs.
  `journalctl -u keyroster-server` then shows `tls certificate loaded` with
  the trigger `sighup`, the leaf's fingerprint and its not_after.
  **Run on the homelab in 02-13**, together with the first run before
  the server starts (step 3):
  - both runs ended `Result=success`;
  - the run against the running server logged `tls certificate loaded`
    with trigger `sighup` within a second;
  - that line's fingerprint equalled the `openssl` fingerprint of the
    certificate on disk;
  - `tailscale cert` printed `Public cert unchanged` and
    `Private key unchanged`, so no new key was loaded.
- **A stopped or failed server.** The unit does not start a server that is
  stopped or failed. Start it with
  `systemctl start keyroster-server.service`.
- **A renewal started by the timer**, in which `tailscale cert` writes a
  new certificate and key, is **UNVERIFIED: 02-13 starts the unit by hand
  and checks only that the timer is active.** A renewal comes at about
  day 60 of a 90-day certificate, so no test has observed one.

## 5. First admin client: keyroster init

`keyroster init` pins two things:

- the **TLS root CA(s)** of the server's certificate;
- the **trust roots** (fingerprints and threshold) that must have signed
  the trust bundle the server serves.

After init, every `keyroster` command that talks to the server trusts only
those pinned TLS roots. It never uses the system roots, and it never trusts
a bundle that the pinned roots did not sign.

1. **On the server host, compute the TLS root's pin.** `root.pem` is the
   root certificate of the CA that issued your certificate:
   - for an internal CA, its root file;
   - for a public CA (Let's Encrypt, which `tailscale cert` uses, or your
     ACME client), the root named as the issuer of the last certificate in
     `fullchain.pem`, from the host's trust store, for example
     `/etc/ssl/certs/ISRG_Root_X1.pem`.

   ```
   openssl x509 -noout -subject -in root.pem
   echo "sha256/$(openssl x509 -pubkey -noout -in root.pem | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64)"
   ```

   This prints the pin in the same `sha256/<base64>` form that
   `keyroster init` uses. The pipeline was checked against the client's own
   pin function with OpenSSL 3.0.13. In 02-13, OpenSSL 3.5.5 on the
   homelab host printed the same ISRG Root X1 pin that `keyroster init`
   printed on Windows.

2. **On the client, list the roots the server presents:**

   ```
   keyroster init --server https://<server>.<tailnet>.ts.net
   ```

   Add `--tls-root-file root.pem` for a private CA, whose root is not in the
   system trust store. Init prints each root's subject and pin, then exits
   with status 2 and saves nothing.

3. **Compare the two pins out of band.** Pass a pin with `--tls-pin` only
   if it matches the one you computed on the server host. A pin taken only
   from init's own output is trust on first use, and **is not acceptable**.
   A public CA can chain to more than one root (for example ISRG Root X1,
   and X2 cross-signed by X1). Pin every root that you confirmed.

4. **Run init with both sets of pins:**

   ```
   keyroster init --server https://<server>.<tailnet>.ts.net \
     --tls-pin sha256/<confirmed pin> \
     --root-pin SHA256:<root A> --root-pin SHA256:<root B> --threshold <n> \
     --user <your name> --admin-key SHA256:<your admin key>
   ```

   Take the `--root-pin` fingerprints and `--threshold` from the root
   ceremony's paper record, never from the server.

   For an admin, `--server` must be one of the policy's webauthn origins,
   the URL the login page is served from. Admin commands sign that origin,
   and the server refuses an admin request signed for any other origin
   with "admin authentication failed", so a signed request cannot be
   replayed against another deployment that trusts the same admin key.
   Init stores the URL in canonical form: a lowercase host, no trailing
   dot and no `:443`.

   Init checks two things:
   - the served trust bundle carries its own roots' signatures;
   - its root set is exactly your pins at exactly that threshold.

   It then prints the bundle version, the roots, each CA key with its
   custody, and the RP. When any key is in software custody, init prints
   the evaluation-only banner, and so does every later command against
   this server. Last, it saves the config, 0600 in a 0700 directory:
   - Linux: `$XDG_CONFIG_HOME/keyroster/config.json` (default
     `~/.config/keyroster/config.json`);
   - macOS: `~/Library/Application Support/keyroster/config.json`;
   - Windows: `%AppData%\keyroster\config.json`. File modes do not apply
     there; the file inherits the per-user profile's ACL.

   An existing config is replaced only with `--force`.

## TLS root changed

When a `keyroster` command fails with "the server's TLS certificate does
not chain to a root you pinned", the server's chain does not end in a
pinned root.

**First rule out a server that is not sending its full chain.** That gives
the same error, because the client never sees the missing intermediate.
On the server host, run:

```
grep -c 'BEGIN CERTIFICATE' /etc/keyroster/tls/fullchain.pem
```

It must print 2 or more when the CA issues through an intermediate. If it
prints 1 for such a CA, fix the certificate file and **do not re-pin**.
**Run on the homelab in 02-13.** A `tailscale cert` file printed **4**:
- the leaf;
- the Let's Encrypt intermediate;
- two cross-signed root certificates, the last one issued by ISRG Root X1.

Both the Windows client and the host's trust store ended the chain at
ISRG Root X1, and the pins matched.

Otherwise the CA has moved to a new root:

1. On the server host, compute the new root's pin with the openssl line
   from step 5.
2. On the client, run `keyroster init --server <URL>` without `--tls-pin`
   to print the roots the server now presents. For a private or internal
   CA, whose new root is not in the system trust store, add
   `--tls-root-file <new root PEM>`. Without it, the chain cannot be
   verified and no pin is printed.
3. Compare the two out of band.
4. Re-run init with
   `--tls-pin <new pin> --root-pin ... --threshold ... --user <your name> [--admin-key SHA256:<your admin key>] --force`,
   plus the same `--tls-root-file` for a private CA. `--force` replaces
   the whole config, so pass `--user` and, for an admin, `--admin-key`
   again.

A new intermediate or a new leaf under the same root needs nothing: root
pins survive both (RESEARCH Q1). You cannot pin a future root in advance.
Init stores only roots it observed, because the client trusts stored root
certificates, not bare pins.

If the **trust roots** were rotated instead, commands fail with "the
server's trust bundle is signed by roots that do not match the --root-pin
set". Follow
[root-ceremony.md, "Rotate the roots", step 9](root-ceremony.md#rotate-the-roots-successor-bundle).

## Restoring an older signer state

The server shows whatever the signer reports. A restored older `signer.db`
brings back that state's policy, admins and directory. The server does not
notice and cannot prevent it (residual C-WR-01, Phase 4). See
[signer-install.md, "Snapshot restore"](signer-install.md#snapshot-restore-check-the-clock-first).
