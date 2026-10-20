---
created: 2026-10-20T12:00:00.000Z
title: Cap keyroster-server's connections and memory
area: server
severity: minor
resolves_phase: 6
files:
  - cmd/keyroster-server/serve.go
  - deploy/systemd/keyroster-server.service
  - docs/runbooks/server-install.md
---

## Problem

keyroster-server's listener has no connection cap, so idle keep-alive TLS connections are a cheaper way to grow the server's memory than any request body. The 02-07 pre-merge review closed the request-body memory path: the admin route's handler now verifies the signature before it reads any body and never buffers an unauthenticated one, and the invite routes take no body. The connection path is still open.

Stalled admin-route bodies are part of that exposure. When requireAdmin refuses without reading the body, net/http still reads and discards up to 256 KiB of it (`maxPostHandlerReadBytes`) before the response goes out, and a body that stalls holds the goroutine and the connection until `ReadTimeout` (30 s in serve.go). A check on PR 45 measured this with an httptest server and a byte-counting listener, counting every byte read from the connection (headers and chunk framing included): 204 918 bytes before the 401 for a 200 KiB body with Content-Length, 205 031 for the same body chunked, and 266 490 for a chunked 1.1 MiB body. Nothing is buffered. `Connection: close` did not stop the drain.

A skeptic's probe during that review measured about 28 KB of heap plus stack per idle HTTP/1.1 connection. It held 3000 connections with serve.go's timeouts over TLS 1.3. Extrapolated from that, about 21 000 connections would hold about 560 MiB, for about 2.3 Mbit/s of ramp-up traffic. These are the skeptic's measurements and arithmetic. Nothing was run on a deployed host, so the effect on a real 1 to 2 GiB host is UNVERIFIED: whether it ends in an OOM kill or a crash loop, and what it does to the co-located keyroster-signer.

deploy/systemd/keyroster-server.service sets no `LimitNOFILE=`, `MemoryMax=` or `MemoryHigh=`. An exhaustion is therefore not confined to the server's cgroup on the host it shares with keyroster-signer.

Found by the 02-07 pre-merge review. The owner deferred it to Phase 6 (hardening and operations) on 2026-10-20.

## Solution

Options for Phase 6:
- **A connection cap on the listener.** A small limit listener built on the standard library only: a semaphore around Accept and a release on Close. It needs no new dependency.
- **A per-source connection cap.** This uses the rate limiter's client key: the RemoteAddr host, with IPv6 keyed by its /64. One source then cannot hold the whole cap.
- **Containment in the unit.** Set `MemoryHigh=` and `MemoryMax=` in keyroster-server.service so an exhaustion stays in the server's cgroup, plus a `LimitNOFILE=` that matches the connection cap.
- **Keep the co-located signer out of the OOM killer's way.** For example, `OOMScoreAdjust=` on the units, so the kernel kills the web front before the signer.

Each option needs a measurement on a real host before it counts as verified.
