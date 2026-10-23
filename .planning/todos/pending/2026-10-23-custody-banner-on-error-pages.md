---
created: 2026-10-23T12:00:00.000Z
title: Show the software-custody banner on error, 404 and 429 pages
area: server
severity: minor
resolves_phase: 4
files:
  - internal/server/login.go
  - internal/server/ratelimit.go
  - internal/server/render.go
---

## Problem

Phase 2 code review, finding B-IN-02 (Info, low, not adversarially verified). Filed after the phase 2 verification (owner decision 2026-10-23).

When the signer reports software custody, `GET /login/<id>` for an expired or used approval calls `loginGone` (internal/server/login.go, about L429). It renders a 404 with `pageData` that bypasses `statusPage`, so the page has no evaluation-only banner, although the handler fetched the status a few lines earlier. The same gap is in:
- the HTML 429 pages (`ratelimit.go`, about L239; `login.go`, about L178);
- `internalErrorPage` (`render.go`, about L117).

KEY-06 promises the warning on every UI page. The finding comes from code reading only; no test exercises it (UNVERIFIED).

## Solution

- Pass the held `statusView` into `loginGone`.
- Build the 429 and 500 pages through `statusPage` from a fresh cached status.
- Only `signerUnavailable` stays without a banner (custody is unknown there).
- Extend the custody-banner tests to these pages.
