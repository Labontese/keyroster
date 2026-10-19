---
phase: 02-passkey-login-mvp
plan: 06
subsystem: server
tags: [server, tls, csp, custody, key-06, ui-01, plat-05, init, pinning, systemd, tailscale]

requires:
  - phase: 02-passkey-login-mvp
    provides: "02-05: signer Status (0x04/0x84) with custody per key, custodytext.SoftwareCABanner/SoftwareRoles; 02-04: successor policy with the WebAuthn RP; 02-01..02-05 merged (#33-#36, #38-#40)"
provides:
  - "keyroster-server serve (Linux only): HTTPS from operator files (TLS 1.3), RP from the signer's root-signed policy, refuses to start without an RP or with a certificate that does not cover it or has expired"
  - "internal/server: signerAPI seam (socketSigner, newServer), currentStatus (5 s fail-closed cache) and dropStatus, secure() headers + CrossOriginProtection, embedded templates and app.css, staticTypes, GET /, /static/, /api/v1/trust, /healthz; CertHolder (Reload/Watch/GetCertificate)"
  - "internal/serverclient: pinned-root HTTPS client (New, GetJSON, PostJSON, Trust, PinOf, ParseServerURL, ParseRoots, CheckPin), TrustResponse, CustodyHeader + CustodyHeaderValue/ParseCustodyHeader, ErrTLSRootNotPinned, ErrTrustRootNotPinned, ErrSignerUnavailable, ErrPolicyNotBundled, ErrNoCustody"
  - "keyroster init and the CLI Config (cmd/keyroster/config.go: loadConfig, saveConfig)"
  - "e2e: serverBin, newTestCA, startServerEnv, TestServerInitEndToEnd, TestServerSIGHUPDuringStartup, TestServerRefusesStart"
  - "deploy: keyroster-server.service, keyroster-tailscale-cert.service/.timer, sysusers lines; docs/runbooks/server-install.md; root-ceremony.md step 9"
affects: [02-07, 02-08, 02-09, 02-10, 02-11, 02-12, 02-13, 02-14, KEY-06, UI-01, PLAT-05]

actuals:
  tokens: 42700   # chars/4 over the added lines of the code, test, deploy and docs diff (170707 chars); planning docs excluded
  tasks: 3        # Tasks 1-3 executed; Task 4 is the owner merge gate
  commits: 5      # git rev-list --count plan_head_before..HEAD at SUMMARY write; this docs commit follows
plan_head_before: 2d9fc80b547e11d653279b1bbdb6510def09d66a
plan_head_after: 4d222d0a4e48e71fc9059b11ac71bef24b550f0e

tech-stack:
  added: []   # stdlib only: net/http, html/template, embed, crypto/tls, crypto/x509, log/slog
  patterns:
    - "One signer seam per package: an interface in signer.go, one production adapter, one test fake with a per-method blocking hook"
    - "One status accessor with a fail-closed rule; handlers set Keyroster-Custody only from a current status"
    - "A wire contract shared by server and CLI lives in the client package, so the CLI never links the server"

key-files:
  created:
    - cmd/keyroster-server/main.go
    - cmd/keyroster-server/main_other.go
    - cmd/keyroster-server/serve.go
    - internal/server/server.go
    - internal/server/headers.go
    - internal/server/signer.go
    - internal/server/render.go
    - internal/server/tlsreload.go
    - internal/server/server_test.go
    - internal/server/tlsreload_test.go
    - internal/server/web/embed.go
    - internal/server/web/templates/base.html
    - internal/server/web/templates/index.html
    - internal/server/web/templates/error.html
    - internal/server/web/static/app.css
    - internal/serverclient/client.go
    - internal/serverclient/client_test.go
    - internal/serverclient/fuzz_test.go
    - cmd/keyroster/config.go
    - cmd/keyroster/init.go
    - cmd/keyroster/init_test.go
    - test/e2e/tlsca_test.go
    - test/e2e/server_test.go
    - deploy/systemd/keyroster-server.service
    - deploy/systemd/keyroster-tailscale-cert.service
    - deploy/systemd/keyroster-tailscale-cert.timer
    - docs/runbooks/server-install.md
  modified:
    - test/e2e/harness_test.go
    - deploy/sysusers.d/keyroster.conf
    - docs/runbooks/root-ceremony.md

key-decisions:
  - "The /api/v1/trust document and the Keyroster-Custody header are defined once in internal/serverclient; keyroster-server imports them, so the CLI never links internal/server, html/template or the embedded assets"
  - "A 2xx response without Keyroster-Custody is refused (ErrNoCustody); a 503 is never parsed for custody (ErrSignerUnavailable)"
  - "serverclient.Trust adds the policy binding: the served policy must be the one the verified bundle names (policy_sha256), else ErrPolicyNotBundled; ErrTrustRootNotPinned never names the served roots"
  - "A refreshed Status whose policy does not parse, has no WebAuthn RP, or whose role or custody is not a lowercase token is a failed refresh (503, nothing cached)"
  - "The certificate holder is exported as CertHolder/NewCertHolder/CertConfig, because cmd/keyroster-server constructs it from another package"

patterns-established:
  - "fakeSigner methods read their result when the call starts and then call enter(method); a held call returns the answer from before any later change"
  - "The custody header carries only lowercase tokens; both the formatter and the parser enforce it"

requirements-completed: [KEY-06]

coverage:
  - id: D1
    description: "keyroster-server serves the signer's state over TLS 1.3 from operator files; keyroster init pins the TLS root and the trust roots, verifies the served bundle, prints the evaluation-only banner and saves a 0600 config; every page carries the exact headers and the banner; an agent-custody control shows no banner"
    requirement: KEY-06
    verification:
      - kind: e2e
        ref: "test/e2e/server_test.go#TestServerInitEndToEnd (WSL, sshd 10.5p1 and 9.5p1; full suite 23/23 on each)"
        status: pass
    human_judgment: false
  - id: D2
    description: "Start-up refusals: no WebAuthn RP in the policy, a leaf for another name, an expired leaf; control starts"
    verification:
      - kind: e2e
        ref: "test/e2e/server_test.go#TestServerRefusesStart"
        status: pass
    human_judgment: false
  - id: D3
    description: "SIGHUP during start-up does not end the server; the real binary logs the start load and a SIGHUP reload as JSON lines with the exact strings 02-13 greps"
    verification:
      - kind: e2e
        ref: "test/e2e/server_test.go#TestServerSIGHUPDuringStartup, TestServerInitEndToEnd/logs_start_load_json, TestServerInitEndToEnd/sighup_reload_logs_json"
        status: pass
    human_judgment: false
  - id: D4
    description: "Certificate holder: swap a valid certificate, keep the last good one on a mismatched pair, an expired leaf, a wrong host or an unreadable file; reload on a file change and on SIGHUP; one 'tls certificate loaded' record per load with fingerprint, not_after and trigger; 'tls certificate expires soon' once a day under 14 days; a queued start-up SIGHUP reloads once"
    verification:
      - kind: unit
        ref: "internal/server/tlsreload_test.go#TestCertHolder (go test -race, WSL; -count=5 clean)"
        status: pass
    human_judgment: false
  - id: D5
    description: "Status cache and seam: fail closed after the 5 s TTL (synthetic trust_changed), dropStatus forces a refresh and waits for an in-flight one, the fake's hook holds only the armed method, a policy without an RP fails closed; headers on every route including 404, 403 (CSRF), static and 503; static content types; cross-origin protection"
    requirement: UI-01
    verification:
      - kind: unit
        ref: "internal/server/server_test.go#TestServerStatus, TestServerPages, TestServerHeaders (go test -race, WSL)"
        status: pass
    human_judgment: false
  - id: D6
    description: "Pinned client: unpinned root and missing intermediate give ErrTLSRootNotPinned with the re-pin text; a new intermediate under the same root is accepted; wrong host and expired leaf keep their x509 errors; banner once per client; missing or malformed custody refused; 503 never parsed; rotated trust roots give ErrTrustRootNotPinned without the served fingerprints; a policy the bundle does not name is refused; parsers fuzzed"
    verification:
      - kind: unit
        ref: "internal/serverclient/client_test.go#TestClientTLS, TestClientCustody, TestClientTrust, TestParseServerURL, TestPinOf; fuzz_test.go (20 s each, WSL)"
        status: pass
    human_judgment: false
  - id: D7
    description: "keyroster init: refuses an http URL, an IP literal, a URL with a path, an unobserved TLS pin, a wrong root pin, a threshold above the roots, system roots for a private CA, and an existing config without --force; no config written on any refusal; discovery without --tls-pin exits 2"
    verification:
      - kind: unit
        ref: "cmd/keyroster/init_test.go#TestInit (WSL -race and natively on Windows)"
        status: pass
    human_judgment: false
  - id: D8
    description: "systemd units and sysusers lines, the Tailscale certificate timer, server-install.md and root-ceremony step 9"
    verification:
      - kind: other
        ref: "Task 3 grep verify; systemd-analyze verify (systemd 255, WSL): no unknown key, section, invalid value or parse failure"
        status: pass
    human_judgment: true
    rationale: "No host has run the units; installing and starting them, tailscale cert under the sandbox and the timer-driven renewal are UNVERIFIED until 02-13 (the renewal also after it)"

duration: 45min
completed: 2026-10-19
status: complete
---

# Phase 2 Plan 06: Server Core Summary

**keyroster-server now serves the signer's state over TLS 1.3 from operator certificate files. It takes its WebAuthn identity and every custody fact from the signer's Status alone and shows the evaluation-only banner on every page. `keyroster init` pins the server's TLS root and the trust roots, verifies the served bundle and prints the same banner in the terminal.**

## Performance

- **Duration:** about 45 min, 2026-10-19T08:48Z to 09:32Z.
- **Tasks:** Tasks 1 (tracer), 2 (TDD) and 3 (deploy, docs and publish) were executed. Task 4 is the owner's merge gate.
- **Files:** 30 code, test, deploy and docs files, plus the planning docs.

## Delivery

- **Branch:** `p02/06-server-core`, cut from origin/main `2a76227`. It also carries the orchestrator's `2d9fc80 docs(phase-02): mark 02-05 complete and record the passphrase-source deferral`.
- **PR:** keyroster-bot opens it after the single push that carries this SUMMARY. The title is `feat(server): keyroster-server with strict headers, custody banner and pinned keyroster init`. The PR number and check results go in the merge-gate checkpoint, not in this file (Delivery Protocol step 4; 02-05 Deviation 15 did the same).
- **Commits:** all are SSH-signed by keyroster-bot.

## Accomplishments

- **keyroster-server** (`cmd/keyroster-server`, Linux only; `main_other.go` imports only `fmt` and `os`).
  - **First statements.** `serve` registers SIGHUP before anything else, on a channel with buffer 1. It then builds its JSON logger on stderr.
  - **Start-up, in order:**
    1. It asks for the signer's Status, retrying for up to 30 s.
    2. It parses the policy and refuses to start without a WebAuthn RP.
    3. It loads the certificate with `Reload("start")`. The leaf must cover the RP ID and be valid now.
    4. It listens with TLS 1.3, with header, read, write and idle timeouts and a 16 KiB header limit.
  - **While running.** Watch rechecks the files every 60 s and reloads on every SIGHUP. SIGINT and SIGTERM shut the server down gracefully.
- **internal/server**
  - **The signer seam.** `signerAPI` has `Status` only. `socketSigner` is the only importer of signerclient. Tests build a Server with `newServer(cfg, fakeSigner)`.
  - **`currentStatus`.** It serves an entry younger than 5 s from the cache. An older entry is refreshed under the mutex, with a 3 s timeout on a context that does not cancel. A failed refresh drops the entry and answers 503: `{"error":"signer unavailable"}` on the API, error.html on pages. The 503 carries no RP, policy, custody or directory data and no custody header.
  - **`dropStatus`.** It takes the same mutex, so it waits for a refresh that is in flight. No handler calls it yet; 02-09 is its first caller.
  - **Headers.** `secure()` sets six headers on every response and then applies `http.CrossOriginProtection`: CSP with `connect-src 'self'`, HSTS max-age=63072000, COOP same-origin, nosniff, Referrer-Policy no-referrer and Cache-Control no-store. The headers are set outside the protection, so a 403 from it carries them too.
  - **Pages.** html/template from embedded files, rendered into a buffer first. There is no script, no inline style and no third-party asset. base.html shows `<div class="kr-banner" role="alert">` with the exact `custodytext.SoftwareCABanner` text whenever any key is in software custody. The index shows the RP ID, the bundle, policy and directory versions, and each key with its custody.
  - **Static files.** `staticTypes` maps `.css` and `.js` to explicit types. Any other extension, a missing file and the bare directory all get 404.
- **internal/serverclient**
  - **Transport.** RootCAs holds only the pinned roots. VerifyConnection requires a chain that ends in a pinned SPKI. Proxy is nil, redirects are refused, a request times out after 30 s and a response is capped at 4 MiB.
  - **Error mapping.** `x509.UnknownAuthorityError` and a pin mismatch become `ErrTLSRootNotPinned`. Its message also names a missing intermediate (`not sending its full chain`). A hostname or expiry error keeps its own x509 error.
  - **Custody.** `checkCustody` prints the framed banner once per Client. It requires the header on a 2xx response and never parses one from a 503.
  - **`Trust`.** It runs `CheckPins`, `VerifySelfSigned` and `MatchPins` (a failure there becomes `ErrTrustRootNotPinned` with no fingerprints), then the policy_sha256 binding, the bundle version, `ParsePolicy` and `CheckAdminsNotRoots`.
- **keyroster init.**
  1. It validates the URL: https, a DNS host, an optional port, nothing else.
  2. It builds the pool from `--tls-root-file`, or the system roots without it.
  3. It dials the server and prints the root of every verified chain with its pin. Without `--tls-pin` it stops here with exit 2.
  4. Every pin given must have been observed. Only those roots are kept.
  5. It runs `Trust` through serverclient, then prints the bundle version, the roots, the CA, ops and log keys with custody (from the signed bundle) and the RP.
  6. It saves the config, 0600 in 0700.
- **Deploy and docs.** See "Unit hardening" below, server-install.md, and step 9 "Re-pin every client" in root-ceremony.md "Rotate the roots".

## Contracts for later plans

**GET /api/v1/trust** (JSON; byte fields are standard base64):

| Field | Content |
|---|---|
| `bundle`, `bundle_sigs`, `policy`, `policy_sigs` | the trust_bundle row the signer runs on, exactly as Status reports it |
| `bundle_version` | uint64 |
| `directory_version` | uint64, 0 for none |
| `custody` | list of `{role, alg, custody, fingerprint}` in the signer's role order |

**Keyroster-Custody:** `user=<c>, host=<c>, machine=<c>, ops=<c>, log=<c>`, in the signer's order. Roles and custodies are lowercase tokens (`[a-z0-9][a-z0-9-]{0,63}`). The header is set on every response built from a current status, never on a 503.

**Client config** (`keyroster init`, JSON: `server`, `tls_roots_pem`, `tls_pins`, `trust_pins`, `trust_threshold`, `user`, `admin_key`):

| OS | Path |
|---|---|
| Linux | `$XDG_CONFIG_HOME/keyroster/config.json` (default `~/.config/keyroster/config.json`) |
| macOS | `~/Library/Application Support/keyroster/config.json` |
| Windows | `%AppData%\keyroster\config.json` (file modes are a no-op; it inherits the per-user ACL) |

**How keyroster.localhost resolved:**
- **WSL:** natively. The CGO_ENABLED=0 resolver got `[::1 127.0.0.1]` from WSL's DNS, so no hosts entry and no flag were needed.
- **CI:** `.github/workflows/e2e.yml` gets no /etc/hosts step in this push. Whether the GitHub runner resolves the name natively is shown by the e2e lanes of this PR and reported in the merge-gate checkpoint. If it does not, the step is added and this paragraph is updated in the same push.

**Unit hardening (keyroster-server.service):**
- **Identity:** `User=`/`Group=keyroster-server`, `SupplementaryGroups=keyroster-admin` (socket access only).
- **Capabilities:** `AmbientCapabilities=` and `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`; `NoNewPrivileges=yes`.
- **File system:** `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `PrivateDevices=yes`, `ReadOnlyPaths=/etc/keyroster/tls`.
- **Network:** `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`.
- **Kernel and process:** `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectKernelLogs`, `ProtectControlGroups`, `ProtectClock`, `ProtectHostname`, `RestrictNamespaces`, `RestrictRealtime`, `LockPersonality`, `MemoryDenyWriteExecute`, `SystemCallArchitectures=native`, `SystemCallFilter=@system-service`, `UMask=0077`.
- **Reload and restart:** `ExecReload=/bin/kill -HUP $MAINPID`, `Restart=on-failure`, `RestartSec=5s`.
- **Exposure:** `systemd-analyze security --offline=yes` (systemd 255, WSL) gives 2.1 OK. This is informational; no CI gate runs it.
- **keyroster-tailscale-cert.service** is a root oneshot:
  - `EnvironmentFile=/etc/keyroster/tailscale-cert.env` (root:root 0644), passed as the braced `${KEYROSTER_TLS_NAME}`;
  - `ExecStartPost=` lines that chgrp and chmod the key, then end with `systemctl try-reload-or-restart keyroster-server.service`;
  - `ProtectSystem=strict`, `ReadWritePaths=/etc/keyroster/tls`, `NoNewPrivileges=yes`.
- **Timer:** `OnCalendar=daily`, `RandomizedDelaySec=1h`, `Persistent=true`.

## Task Commits

1. **Task 1, tracer.** `c2038c3` (feat). Tracer gate: the e2e verify (`TestServerInitEndToEnd|TestSoftwareCAEndToEnd`, sshd 10.5p1) was re-run on the committed head and passed. The task has no `gate` attribute, its verify is automated only and human_verify_mode is end-of-phase, so execution continued to Task 2.
2. **Task 2, TDD.**
   - `c1fdc74` (test, RED; includes a Watch stub so the suite compiles);
   - `7b623da` (feat, GREEN);
   - `46fe011` (test: fuzz targets).
3. **Task 3.** `4d222d0` (docs: units, sysusers, runbooks).
4. **Task 4, merge gate.** Not attempted. It is the owner's `checkpoint:human-action`.

**Plan metadata:** `docs(02-06): complete server-core plan` (this file, STATE.md, REQUIREMENTS.md).

## TDD record (Task 2; workflow.tdd_mode is false, so the gate sequence is advisory)

- **RED (`c1fdc74`).** gsd-tools' RED classifier has no Go adapter, so this is a recorded semantic assessment, not a classifier verdict.
  - **Unit tests.** `go test ./internal/server/` failed only in `TestCertHolder`. Ten subtests failed on their target assertions:
    - no `tls certificate loaded` record;
    - `timed out waiting for the SIGHUP reload`;
    - no expiry warning;
    - `timed out waiting for the queued sighup load`.

    These are missing behaviour, not compile, fixture or setup failures. A one-line Watch stub kept the suite compiling.
  - **The keeps_last_good_* subtests.** They failed only on the record count. Their keep-last-good assertions already passed, because Task 1 built the validation.
  - **e2e** (WSL, sshd 10.5p1):
    - `TestServerSIGHUPDuringStartup` failed with "keyroster-server ended on a SIGHUP during start-up (state signal: hangup)";
    - `logs_start_load_json` failed with "0 lines ... want 1";
    - `sighup_reload_logs_json` found no sighup line.
- **GREEN (`7b623da`).** The same commands pass:
  - `go test -race` on internal/server, serverclient and cmd/keyroster, with all eleven names from the plan's fails_when list in the PASS lines and no DATA RACE;
  - `TestCertHolder` five times under -race;
  - the e2e set.
- **Unexpected green, recorded honestly.** These suites passed on their first run, because the Task 1 tracer had built the code:
  - TestServerStatus, TestServerPages and TestServerHeaders;
  - TestClientTLS, TestClientCustody and TestClientTrust;
  - TestInit;
  - TestServerRefusesStart.

  **Bite tests:** one mutant per guarded check, 12 in all (one more, below, was set aside as redundant), every counted one killed. Production files were restored byte for byte from copies.

  | Mutant | Killed by |
  |---|---|
  | cache never expires | `status_refresh_failure_fails_closed` |
  | dropStatus without the mutex | `drop_during_inflight_refresh` |
  | no CrossOriginProtection | `cross_origin_protection` |
  | headers set inside the protection | TestServerHeaders (403 without headers) |
  | static file with a wrong Content-Type | `static_content_types` |
  | UnknownAuthority not mapped | `unpinned_root_error_names_repin`, `missing_intermediate_reports_root_error` |
  | every TLS error mapped to the root error | `wrong_hostname_not_root_error`, `expired_leaf_not_root_error` |
  | MatchPins detail leaked into the error | `rotated_roots_error_names_reinit` |
  | banner on every response | `banner_once_per_client` |
  | custody header not required | `missing_custody_refused` |
  | policy hash unchecked | `policy_not_bundled_refused` |
  | unobserved TLS pin accepted | `refuses_unobserved_tls_pin` |

  One mutant was not counted: removing init's early existing-config check survives, because `saveConfig` refuses again before writing. That second check is deliberate.

## Verification run

| Check | Where | Result |
|---|---|---|
| Task 1 verify: e2e `TestServerInitEndToEnd\|TestSoftwareCAEndToEnd`, sshd 10.5p1 | WSL | PASS before the commit and on the committed head |
| Task 1 verify: `GOOS=linux` build of keyroster-server; `GOOS=windows` and `darwin` builds of `./cmd/...` | Windows host | PASS |
| Task 1 acceptance (CSP grep, no `<script>` or ` style=`, no addLogKey, signer graph without internal/server or net/http (0), the seam and dropStatus greps, signer.go the only signerclient importer) | Windows host | all PASS |
| Task 2 verify 1: `go test -race -count=1 -v` server, serverclient, cmd/keyroster | WSL | PASS; all 11 named cases present; 0 DATA RACE |
| Task 2 verify 2: e2e `TestServerInitEndToEnd\|TestServerSIGHUPDuringStartup` | WSL | PASS, both subtests and TestServerSIGHUPDuringStartup |
| Task 2 verify 3: `go test -count=1 -v -run TestInit ./cmd/keyroster/` | Windows (native) | PASS |
| Task 2 acceptance greps (named cases; one `"tls certificate expires soon"`; SIGHUP and the JSON logger before the first Status call; fake, hook, enter and logBuffer greps; slog grep = 0; sentinels; currentStatus) | Windows host | all PASS |
| Task 3 verify 1 (unit and sysusers greps) | Windows host | PASS |
| Task 3 verify 2: `systemd-analyze verify` | WSL, systemd 255 | 0 unknown key, section, invalid or parse lines. The only complaints are the missing `/usr/local/bin/keyroster-server` and `/usr/bin/tailscale` on the workstation, and the DrvFs file modes |
| Task 3 verify 3: `go test -race ./...`, `go vet ./...`, `go vet -tags e2e`, gofmt (GOROOT gofmt, from a script file), golangci-lint (linux, windows, darwin), capslock-check, dep-firewall, testonly-firewall | WSL | all pass. Lint: 0 issues for each OS. capslock 90/90. dep-firewall: only the documented libc exception. testonly-firewall: clean, 6 combinations |
| Full e2e suite (`-tags e2e`) | WSL | sshd 10.5p1: 23 PASS, 0 FAIL, 0 SKIP. sshd 9.5p1: 23 PASS, 0 FAIL, 0 SKIP |
| `go test -count=1 ./...`; `go vet` for darwin and windows | Windows (native) | PASS |
| openssl pin line from the runbook vs `serverclient.PinOf` | WSL, OpenSSL 3.0.13 | identical. The runbook's fingerprint statement (openssl `-fingerprint -sha256`, colons removed, lower case, equals the SHA-256 of the DER) was also checked |
| Task 3 verify 4 (SUMMARY on the pushed head) and 5 (required checks) | GitHub | after the push; reported in the merge-gate checkpoint |

`TestCheckLogAgainstLiveSigner` (the known ~1-in-40 `-race` flake) did not fail in this run.

## Decisions Made

See `key-decisions` in the frontmatter.

## Deviations from Plan

### Auto-fixed Issues and interpretations

**1. [Plan structure] Task 1 created internal/server/tlsreload.go**
- Task 1's start-up step 3 needs a certificate holder, but the file is listed only under Task 2.
- Task 1 built the validated static load, `Reload("start")` without the log record, and GetCertificate. Task 2 added the record, Watch and the expiry warning.
- **Commits:** c2038c3, 7b623da.

**2. [Naming] `certHolder` is exported as `CertHolder`, `NewCertHolder` and `CertConfig`**
- cmd/keyroster-server builds it from another package. No acceptance grep names the type.

**3. [Rule 2, advisor] serverclient.Trust binds the policy to the bundle**
- `VerifySelfSigned` does not check that the policy is the bundle's policy. Without the check, a server could serve an older policy signed by the same roots.
- Trust now requires `policy_sha256` to match (ErrPolicyNotBundled), the bundle version to match, and no admin to be a root (CheckAdminsNotRoots).
- **Test:** `policy_not_bundled_refused`.

**4. [Rule 2] Strict custody header**
- A 2xx response without Keyroster-Custody is refused (ErrNoCustody), so a later handler that forgets the header fails loudly instead of hiding the banner.
- Malformed values are refused.
- The server refuses a role or custody that is not a lowercase token; that counts as a failed refresh, so the request gets 503.

**5. [Rule 2] Client hardening**
- No redirects (`http.ErrUseLastResponse`) and a 4 MiB response cap.

**6. [Interpretation, advisor] The TrustResponse type lives in serverclient, and the server imports it**
- One definition. The CLI binary does not link internal/server or html/template.
- The client decodes leniently (unknown fields are ignored), so a later server field does not break older CLIs.

**7. [Interpretation] fakeSigner reads its result before `enter(method)`**
- The plan says each method "starts with" `enter`.
- The Status result is snapshotted first, so a held call returns the answer from before the test's switch. That is what makes `drop_during_inflight_refresh` show that an old answer is not served after the drop. If the snapshot came after release, the test would pass even without the mutex. The mutant table shows it is killed with the snapshot first.

**8. [Interpretation] Refused starts are tested in e2e with the real binary**
- `TestServerRefusesStart` covers: no RP, a leaf for another name, an expired leaf, and a control that starts.
- The expired-leaf case uses the `expiredLeaf` variant of newTestCA.

**9. [Process, TDD] The RED commit contains a Watch stub (`<-ctx.Done()`)**
- Without it the suite would not compile, and a compile failure is INVALID_RED.

**10. [Rule 2, project rule] Fuzz targets for the two client parsers**
- `FuzzParseCustodyHeader` and `FuzzParseServerURL`. They run 20 s each in WSL; `scripts/fuzz.sh` discovers them in CI.

**11. [Interpretation] serve.go builds the logger as `slog.NewJSONHandler(os.Stderr, nil)`**
- This is the literal form the acceptance grep requires. Flag errors go to the `stderr` parameter, which main sets to `os.Stderr`.

**12. [Interpretation] init order and the discovery exit**
- When `--tls-pin` is given, init checks `--root-pin`, `--threshold`, `--admin-key` and an existing config before it connects. saveConfig checks the existing config again.
- Discovery without `--tls-pin` returns errUsage, so the dispatcher also prints the command list after init's own message.

**13. [Scope] Extra tests**
- TestServerPages (mixed custody, the trust document fields), TestClientCustody (malformed header, 503), TestParseServerURL, TestPinOf.
- `refuses_url_with_path`, `refuses_http_url` and `refuses_system_roots_for_private_ca` in TestInit.

**14. [Rule 2] The index page lists each signer key with its algorithm, custody and fingerprint**
- This serves the visibility core value. The data is the same Status report.

**15. [Process] The SUMMARY comes before the push**
- It therefore cannot name the PR number, the CI results, or how keyroster.localhost resolved on the runner. Those go in the merge-gate checkpoint (Delivery Protocol step 4).

**16. [Process] ROADMAP.md is not touched**
- The environment forbids marking 02-06 complete, and `roadmap.update-plan-progress` counts SUMMARY files, so it was not run.
- STATE.md position and metrics were updated, and REQUIREMENTS.md marks KEY-06 complete. `requirements.ready-ids` reported KEY-06 ready and UI-01 and PLAT-05 blocked by later plans.

---

**Total deviations:** 16:
- 7 interpretations and naming;
- 5 Rule 2 additions;
- 1 scope item;
- 3 process notes.

**Impact on plan:** there is no new module dependency. No production code path exists only for tests. The signer's dependency graph is unchanged: dep-firewall and capslock are 90/90 and the signer does not import internal/server.

## Issues Encountered

- **Python heredoc edits turned `\n` inside Go strings into real newlines in two files.** gofmt and vet caught it before any commit, and the lines were fixed with exact edits.
- **Git Bash expanded `$(go env GOROOT)` before the command reached WSL.** Every WSL command that contains `$` ran from a script file under `.git/gsd-tmp/`, which is never committed.

## Not exercised (UNVERIFIED)

- **The systemd units on a host.** `keyroster-server.service`, `keyroster-tailscale-cert.service` (its first run before the server starts, and its run against a running server) and the sandbox lines under which `tailscale cert` must work are all UNVERIFIED until the homelab install (02-13). No CI job runs these units; `systemd-analyze verify` ran on the workstation only.
- **A renewal started by the timer**, in which `tailscale cert` writes a new certificate and key. UNVERIFIED, and it stays so after 02-13 (02-13-R2-F4).
- **The full-chain count for a `tailscale cert` file** (the runbook's `grep -c 'BEGIN CERTIFICATE'`). UNVERIFIED until 02-13.
- **The server failing closed on a real signer's `trust_changed`** (02-05's open item).
  - `status_refresh_failure_fails_closed` feeds the exact `*wire.ErrorResponse{Code: CodeUnavailable, Message: "trust_changed"}` from fakeSigner and requires 503s with no status data.
  - A real signer was not used. The acceptance grep allows only signer.go to import signerclient in internal/server, so a real signer cannot be used there. In e2e, the state-dir lock makes `install-bundle` refuse while `serve` runs, so a foreign install cannot be staged cheaply. A real signer's `trust_changed` reaching the server is therefore not exercised.
- **The few milliseconds between process start and the SIGHUP registration** are uncovered, as the plan says.
- **Root pinning when the server's root is also in the system pool.** The client never consults the system pool (RootCAs holds only the pinned roots), so the planned case "refused even if that root is in the system pool" holds by construction. The test cannot add a root to the real system pool; it uses a root outside the pinned set.
- **Re-pinning real clients after a real root rotation** (root-ceremony step 9). UNVERIFIED until the next rotation that has keyroster clients.
- **`keyroster.localhost` on the GitHub runner, and every CI lane of this PR.** The results come after the push and are reported in the merge-gate checkpoint.
- **Browsers.** No browser has loaded the pages, so CSP behaviour in Chrome, Edge and Firefox is UNVERIFIED. The headers are asserted byte for byte in e2e.

## Known Stubs

None. `dropStatus` has no production caller yet, by plan: 02-09's directory install is its first caller. It is tested directly.

## Threat Flags

None beyond the plan's threat model:
- the new HTTPS listener and the GET routes are T-02-25..31 and T-02-87;
- the CLI config file is T-02-88;
- the certificate unit is T-02-89;
- the re-init hint is T-02-93.

## User Setup Required

None for CI. Installing on a host follows docs/runbooks/server-install.md (02-13).

## Next Phase Readiness

- **02-07** adds `GetDirectory` to `signerAPI`, `socketSigner` and `fakeSigner` (with `enter("GetDirectory")`). A 1 MiB directory costs about 4.4 MiB of allocation per reply, so if the server calls GetDirectory on every request, cache it by `DirectoryVersion`/`DirectorySHA256` from the current status, or note the cost.
- **02-08 and 02-09** read the server's log lines through the `newTestServer` helper's `logBuffer`.
- **02-09** calls `dropStatus()` after its directory install.
- **02-13** greps `"msg":"tls certificate loaded"` with `"trigger":"start"` and `"trigger":"sighup"`. The real binary writes them; the e2e subtests pin them.
- Agent hints: this plan prints none. Later CLI text must follow the owner's 2026-10-17 decision (only a host-scoped `IdentityAgent` block for the Windows agent).
- Blocked on the owner's merge gate for this plan's PR.

## Self-Check: PASSED

- Every file in key-files.created exists. Commits c2038c3, c1fdc74, 7b623da, 46fe011 and 4d222d0 are ancestors of HEAD.
- Every acceptance criterion of Tasks 1-3 was re-run and passes:
  - the server-install.md words (Public Suffix List, Certificate Transparency, self-signed, UNVERIFIED, TLS root changed, --force, the openssl pin line, root:root 0644, tls certificate loaded, not sending its full chain);
  - the order "certificate unit, timer, server", and the timer-renewal sentence carrying UNVERIFIED;
  - exactly one `try-reload-or-restart` line, as the unit's last `ExecStartPost=`, with UNVERIFIED in the comment above it;
  - step 9 "Re-pin every client" with `--root-pin` and `--force`.
- The PR acceptance (open, auto-merge, green, SUMMARY on its head) is checked after the push and reported in the checkpoint.

---
*Phase: 02-passkey-login-mvp*
*Completed: 2026-10-19 (before the merge gate)*
