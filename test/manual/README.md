# Manual checks

Checks that CI cannot run. Each one names the requirement it covers, what it
touches, and where its result goes.

## Windows inbox OpenSSH 9.5p2 (CA-08)

CA-08 requires that real sshd accepts keyroster certificates on OpenSSH 9.5p2
and on the latest release. `OpenSSH_for_Windows_9.5p2` is Microsoft's own build
that ships with Windows. Upstream never released a 9.5p2: the portable tarballs
go from 9.5p1 to 9.6p1, so CI cannot build it. The CI `e2e` jobs therefore run
portable **9.5p1**, the closest upstream code, and **10.5p1**. This script is
the 9.5p2 evidence and runs by hand on a Windows machine with the inbox
OpenSSH.

### What it does

`windows-openssh-9.5p2.ps1 -CertDir DIR -Principal NAME [-Port 2222]`

1. Refuses to run unless all of the following hold:
   - the PowerShell is elevated (exit 3);
   - `sshd.exe -V` reports `OpenSSH_for_Windows_9.5p2`;
   - `-Principal` is the account running the script, in lowercase (a temporary
     sshd that runs as you can only log you in);
   - the port is free and is not 22.
2. Creates a temp directory whose ACL allows only SYSTEM, Administrators and
   the current user (`icacls /inheritance:r`). It copies the inputs there and
   generates a throwaway host key.
3. Writes a temporary `sshd_config`, validates it with `sshd.exe -t` and uses
   it for the run. The config:
   - `ListenAddress 127.0.0.1`
   - `AuthorizedKeysFile none`
   - `TrustedUserCAKeys` (the user CA key)
   - `AuthorizedPrincipalsFile` (the one principal)
   - password and keyboard-interactive authentication off
   - `LogLevel VERBOSE`
4. Runs two cases. For each it starts `sshd.exe -d -f {config}`, which serves
   exactly one connection in debug mode, and then logs in with `ssh.exe` as
   `-Principal` and runs `whoami`:
   - **accept:** `test-cert.pub` names the listed principal. PASS when the
     login succeeds and `whoami` names the principal.
   - **reject:** `reject-cert.pub` names `keyroster-reject-test`, which is not
     listed. PASS only when both hold:
     - the login, as the same user, fails with `Permission denied`;
     - sshd logs that the certificate does not contain an authorized principal.

     A refused connection or a crashed sshd counts as FAIL, not as a rejection.
5. Writes `{CertDir}\result.json` with `sshd_version`, `accept`, `reject`
   (`PASS` or `FAIL`) and `finished_at` (UTC, ISO 8601). It stops the temporary
   sshd, deletes the temp directory and exits 0 only when both cases pass. When
   a case fails, the script first copies that case's sshd and client logs into
   `CertDir`.

### What it never touches

The installed `sshd` service and its port 22 stay as they are: the script
never stops, restarts or reconfigures the service, and never uses or changes
the service's `sshd_config`, host keys or authorized-keys files. The temporary
sshd listens on 127.0.0.1 only, serves one
connection per case, and runs from its own config and host key. It is killed
by process ID if it has not exited.

### Inputs

`CertDir` holds four files:

- `test`: a throwaway private key. Delete it after the run.
- `test-cert.pub` and `reject-cert.pub`: issued for that key by the user CA,
  for example with `keyroster ca issue --ca user --pubkey test.pub --principal
  NAME --subject u:windows-check --ttl 12h --admin-key SHA256:...`, and again
  with `--principal keyroster-reject-test --out reject-cert.pub`.
- `user_ca.pub`: the user CA public key, the `user` entry of the signer's
  `ca-pubkeys.json`.

Run it from an elevated PowerShell:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File test\manual\windows-openssh-9.5p2.ps1 -CertDir C:\path\to\certdir -Principal yourname
```

### Last result

2026-10-07 (`finished_at` 2026-10-07T02:19:03Z), on a lab Windows Server 2025
with the inbox OpenSSH (`sshd.exe` file version 9.5.5.1): `sshd_version`
`OpenSSH_for_Windows_9.5p2, LibreSSL 3.8.2`, accept **PASS**, reject **PASS**.
Both certificates came from the homelab signer (plan 01-15), and the service
on port 22 kept running.
