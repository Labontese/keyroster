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

keyroster-server's listener has no connection cap, so idle keep-alive TLS connections are a cheaper way to grow the server's memory than any request body. The 02-07 pre-merge review closed the request-body memory path in the handlers only: the admin route's handler now verifies the signature before it reads any body and never buffers an unauthenticated one, and the invite routes' handlers take no body. It did not close it in net/http. Over HTTP/2, which keyroster-server negotiates by default (serve.go sets no `TLSNextProto` or `Protocols`), net/http buffers request DATA in memory whether or not the handler reads, on any route (see below). The connection path is still open.

Unread request bodies are part of that exposure, and what net/http does with one depends on the protocol.

- **HTTP/1.1.** When requireAdmin refuses without reading the body, net/http still reads and discards up to 256 KiB of it (`maxPostHandlerReadBytes`) before the response goes out, and a body that stalls holds the goroutine and the connection until `ReadTimeout` (30 s in serve.go). A check on PR 45 measured this over HTTP/1.1 with an httptest server and a byte-counting listener, counting every byte read from the connection (headers and chunk framing included): 204 918 bytes before the 401 for a 200 KiB body with Content-Length, 205 031 for the same body chunked, and 266 490 for a chunked 1.1 MiB body. Over HTTP/1.1 nothing is buffered. `Connection: close` did not stop the drain.
- **HTTP/2.** There is no 256 KiB drain. net/http's h2 server (Go 1.27.2, `net/http/internal/http2/server.go`, `processData`) writes every DATA frame of an open stream into that stream's memory buffer whether or not the handler reads it. The receive windows bound that buffer: `MaxReceiveBufferPerStream` and `MaxReceiveBufferPerConnection`, both 1 MiB by default (`config.go:55,60`). So one connection can hold up to about 1 MiB of unread request data however many streams it opens. `runHandler` closes the request body when the handler returns, which frees the buffer, and the server then resets the stream. A later independent check, with serve.go's exact `http.Server` settings (ALPN `h2`), sent a 4 MiB POST to a handler that held 1.5 s without reading `r.Body`: net/http read 1 053 797 bytes from the connection over h2, and 2 785 over HTTP/1.1. The admin route answers without reading the body, after at most one signer Status refresh (requireAdminLimit calls currentStatus before the origin check and Verify; statusTimeout 3 s, a failed refresh is not cached) and one signature check. On that route the buffer is therefore held for at most about 3 s per request, a bound derived from the code and not measured. UNVERIFIED: how long the handlers of other routes can run and so hold the buffer, how long an h2 connection whose body stalled stays open after the reset, and what an idle h2 connection costs in memory.

A skeptic's probe during that review measured about 28 KB of heap plus stack per idle HTTP/1.1 connection (HTTP/1.1 only; the h2 figure is UNVERIFIED). It held 3000 connections with serve.go's timeouts over TLS 1.3. Extrapolated from that, about 21 000 connections would hold about 560 MiB, for about 2.3 Mbit/s of ramp-up traffic. These are the skeptic's measurements and arithmetic. Nothing was run on a deployed host, so the effect on a real 1 to 2 GiB host is UNVERIFIED: whether it ends in an OOM kill or a crash loop, and what it does to the co-located keyroster-signer.

deploy/systemd/keyroster-server.service sets no `LimitNOFILE=`, `MemoryMax=` or `MemoryHigh=`. An exhaustion is therefore not confined to the server's cgroup on the host it shares with keyroster-signer.

Found by the 02-07 pre-merge review. The owner deferred it to Phase 6 (hardening and operations) on 2026-10-20.

## Solution

Options for Phase 6:
- **A connection cap on the listener.** A small limit listener built on the standard library only: a semaphore around Accept and a release on Close. It needs no new dependency.
- **A per-source connection cap.** This uses the rate limiter's client key: the RemoteAddr host, with IPv6 keyed by its /64. One source then cannot hold the whole cap.
- **Containment in the unit.** Set `MemoryHigh=` and `MemoryMax=` in keyroster-server.service so an exhaustion stays in the server's cgroup, plus a `LimitNOFILE=` that matches the connection cap.
- **Lower HTTP/2's receive windows.** Set `http.Server.HTTP2` to an `http.HTTP2Config` with smaller `MaxReceiveBufferPerStream` and `MaxReceiveBufferPerConnection`, so an unread body costs less per connection. A smaller window also slows a verified admin's legitimate upload of up to `maxAdminBody`; by how much is UNVERIFIED. Turning HTTP/2 off is the blunter alternative.
- **Keep the co-located signer out of the OOM killer's way.** For example, `OOMScoreAdjust=` on the units, so the kernel kills the web front before the signer.

Each option needs a measurement on a real host before it counts as verified.
