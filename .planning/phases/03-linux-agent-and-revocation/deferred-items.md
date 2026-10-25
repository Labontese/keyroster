# Deferred Items (Phase 3)

## Deferred Items

- The comment on the default branch of the kind switch in internal/audit/verify.go says no leaf reaches it and calls it UNVERIFIED. Since 03-01 that is false: revoke (9) and krl_publish (10) leaves reach it, and TestVerifyKindsWithoutChecks/revoke_not_verifiable and /krl_publish_not_verifiable exercise it.
  status: resolved
  **Owner:** 03-03, which adds the checks for kinds 9 and 10 and edits that switch anyway. 03-01 must leave internal/audit/verify.go unchanged (acceptance criterion).
  **Resolved in 03-03:** Verify's switch has a case for revoke and krl_publish, the two interim cases became `revoke_unproven_refused` and `krl_publish_unproven_refused` with real checks, and the comment now says that the branch was reached from 03-01 until 03-03 and that since 03-03 no kind tlog decodes reaches it.
- WSL on Daniel-PC no longer resolves `keyroster.localhost` (the WSL DNS proxy answers no such host). Phase 2 recorded that it resolved natively. The server e2e tests therefore fail locally unless run in a user and mount namespace with a hosts entry (`unshare --user --map-current-user --mount`, then a bind-mounted /etc/hosts). Inside that namespace `TestSSHDRejects/pty_allowed` fails (pty allocation), and it passes outside. CI resolves the name natively.
  status: open
  **What:** a local test-environment issue, not a product defect. Either restore the resolution in WSL or add the namespace runner to scripts/ as a reviewed helper.
