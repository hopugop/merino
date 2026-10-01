# Embedded Real-Time Statistics Web Service — Implementation Plan

Phased plan for embedding a read-only web service into the `merino` proxy that
exposes real-time statistics: connected clients, DNS cache activity, and
traffic counters.

The service is **embedded**: it runs inside the same binary and runtime as the
proxy, is **off by default** (`--stats-addr` unset → no socket, behaviour
identical to today), and is **additive** — it never changes the SOCKS5 wire
protocol or the public library API.

The plan is intentionally incremental: counters land first with tests (no web
service yet), then the web layer is added on top and proven against those
counters, then real-time streaming and hardening.

Each phase is independently committable and verifiable.

## Constraints & conventions

- Rust edition 2024 (toolchain pinned in `rust-toolchain.toml`); keep
  `#![forbid(unsafe_code)]` in every new module.
- The repo denies `clippy::unwrap_used`, `clippy::expect_used`, `clippy::panic`
  and `clippy::indexing_slicing` — new code must be written bounds-safe from
  the start (reuse the `take()`-style slicing discipline already used by the
  parsers in `src/lib.rs`).
- **No code comments unless they already exist** (repo convention) — document
  in doc-comments and this file.
- Dependencies are deliberately minimal: `Cargo.toml` trims `tokio` to only
  what the proxy uses and the README advertises a standalone, dependency-light
  binary. Adding a web framework is a decision to be confirmed (see
  ["Web server choice"](#web-server-choice)); the default plan adds **zero**
  new dependencies.
- Defaults must keep previous behaviour exactly: no stats socket, no counters
  visible in logs, no new listener, unless the operator opts in.
- Both backends (`Merino` tokio loop and actix `SocksServer`) share
  `ServerContext`, `accept_loop`, `run_client` and `SOCKClient`, so
  instrumentation placed there serves both for free. The binary runs the actix
  backend; tests cover both.
- Run `cargo test` and `cargo clippy --all-targets` locally before each commit.

## Baseline (what exists today)

- Every connection flows through one choke point, `run_client` in `src/lib.rs`
  (spawned by `Merino::serve` and by the `SocksConnection` actor), after the
  shared `accept_loop` has acquired a connection `Semaphore` permit and an
  optional per-IP `IpSlot`.
- `ServerContext` carries the shared `users` / `auth_methods` / `timeout` /
  `dns_cache` / `per_ip` handles to every accept loop.
- `DnsCache` (`src/lib.rs`) is a `Mutex<HashMap<String, CacheEntry>>` keyed on
  `"host:port"`, positive-only, bounded by `max_entries`, TTL-lived, with
  expiry-then-oldest eviction. It has no counters and no read-side snapshot.
- `handle_request` relays `CONNECT`/`BIND` through `copy_bidirectional` and
  already receives both direction byte counts (only the target→client count is
  currently returned). `UDP ASSOCIATE` relays per-datagram and currently
  returns `0`.
- `PerIpLimiter`/`IpSlot` track per-source active counts, but only when
  `--max-connections-per-ip` is set (off by default).
- Tests: `tests/support/mod.rs` (`start_merino`, `connect`, echo helpers),
  `tests/actors.rs`, `tests/socks5.rs`, `tests/cli.rs` (spawns the real
  binary), `benches/proxy.rs` / `benches/parse.rs` (criterion). Lint stance,
  Dockerfile (`EXPOSE 1080`) and `packaging/merino.service` are documented
  upstream.

---

## Phase 0 — This planning document

**Deliverable.** `AGENTS/STATS_WEB_SERVICE_PLAN.md` (this file).

**Commit.** `docs: add embedded stats web service plan`

---

## Phase 1 — Stats core (counters, no web)

**Goal.** Introduce a shared, always-on statistics core that the whole proxy
updates cheaply, plus a serde-`Serialize` snapshot type the web layer will
later serve. No HTTP anywhere yet.

**Files.**
- `src/stats.rs` (new) — `pub mod stats;` added to `src/lib.rs`.
- `src/lib.rs` — thread `Arc<Stats>` through `ServerContext`; record events in
  `accept_loop` and `run_client`.
- `src/actors.rs` — no change required (it builds `ServerContext`; an
  `Arc<Stats>` member is created/defaulted here or in `SocksServer::bind`).

**Design.**
- `Stats` is an `Arc`-shared struct of atomics plus two `Mutex`-guarded maps
  (reusing the poison-recovering `lock_counts` discipline already in the file):
  - `AtomicU64` / `AtomicUsize`: `accepted_total`, `refused_per_ip`,
    `handshake_timeouts`, `auth_failures`, `disconnects` (routine client
    disconnects classified by `is_client_disconnect`), plus a placeholder group
    for phase 2 (`requests_*`, `bytes_*`, `dns_*`).
  - `Mutex<HashMap<IpAddr, u64>>` `active_per_ip` — always-on equivalent of
    `PerIpLimiter`, updated only at connection start/end, not per byte.
- **Active-connection tracking via RAII.** A `ActiveGuard` struct created at
  the top of `run_client` increments `active` + `active_per_ip[peer]` and
  decrements both on `Drop` — the same pattern as `IpSlot`, so every exit path
  (success, error, panic unwind, actor stop) frees the slot exactly once. This
  single choke point covers both backends.
- `Snapshot` (`#[derive(Serialize)]`, no `Default` that hides a stale read):
  a plain struct built on demand by `Stats::snapshot()` that copies the atomics
  and a bounded, sorted view of `active_per_ip` (top N, configurable const).
  No locks are held while the web layer formats it.
- `Stats` is cheap enough to be **always on** (a few atomic ops per connection,
  two map touches per connection). It is invisible unless somebody reads it;
  phase 3 gates the *socket*, not the counters. A `no-stats` Cargo feature was
  considered and rejected: it forks every `fetch_add` site for no measurable
  win and makes tests/builds diverge.

**Test cases** (inline `mod tests` in `src/stats.rs` or `src/lib.rs`).
- `Stats` increments land in the right counter and `snapshot()` reflects them.
- `ActiveGuard` increments/decrements `active` and the per-IP map, including on
  `drop` (simulate early return).
- Snapshot serde round-trip / field presence with `serde_json`.
- `active_per_ip` map recovers from a poisoned lock (mirrors `lock_counts`
  tests).

**Verification.**
```
cargo test
cargo clippy --all-targets
```

**Commit.** `feat: add always-on connection statistics core`

---

## Phase 2 — Instrument the hot paths

**Goal.** Wire every metric the dashboard should show: DNS cache activity,
per-command request counts, bytes relayed, error counters.

**Files.**
- `src/stats.rs` — extend `Stats` with the new counter groups.
- `src/lib.rs` — `DnsCache` gains a `&Stats` handle (or a dedicated
  `Arc<DnsStats>` group) and exposes `snapshot()`; `handle_request` records
  command + bytes; `SOCKClient`'s error paths record auth/timeout/refused
  events.
- `src/main.rs` — the `--dns-cache-*` flags already exist; nothing changes here
  yet.

**Metrics added.**
- **DNS cache** (`DnsCache::get` / `insert` / eviction paths):
  `hits`, `misses` (cached lookup that expired → counted as miss), `inserts`,
  `evictions` (oldest-drop), `expired_dropped`, plus a `snapshot()` returning
  `enabled`, `ttl_secs`, `max_entries`, `entries` count and the top-N names
  with seconds-to-expiry. Names are rendered through the existing
  `sanitize_domain` before ever leaving the process.
- **Requests:** `AtomicU64` per `SockCommand` (`connect` / `bind` /
  `udp_associate`) in `handle_request`.
- **Traffic:** record `copy_bidirectional`'s returned counts
  (`s_to_t` = client→target, `t_to_s` = target→client). Because the counts are
  returned once per relay, this is one `fetch_add` pair per connection — no
  per-byte cost. UDP: count datagrams (and optionally bytes) in the relay loop
  with a single atomic per datagram; this is the only per-datagram cost and is
  identical to the existing `trace!` cost.
- **Errors:** one `AtomicU64` per `ResponseCode` that `run_client` replies
  with, so the dashboard can show why connections die without parsing logs.

**Test cases.**
- Existing `DnsCache` unit tests extended: after N lookups the hit/miss/insert
  counters are exact; expiry increments `expired_dropped`; eviction of the
  oldest at capacity increments `evictions`.
- Integration (`tests/support` harness): start a server, run a CONNECT relay to
  the echo target, and assert `bytes_client_to_target` /
  `bytes_target_to_client` equal the bytes actually echoed; `requests.connect`
  incremented; `active` returns to 0 after the peer drops.
- With `--dns-cache-ttl N` enabled, two CONNECTs to the same domain produce
  `hits == 1` and only one real `insert`.
- Refused / timeout paths increment their counters (`refused_per_ip` when a
  per-IP cap is hit, `handshake_timeouts` for a silent client).

**Verification.**
```
cargo test
cargo clippy --all-targets
cargo bench -- --quick   # sanity: counters on by default must not regress
```

**Commit.** `feat: instrument dns cache, commands, bytes and errors`

---

## Phase 3 — Embedded web server

**Goal.** Serve the snapshot as JSON plus a self-contained HTML dashboard, over
an HTTP listener that is off unless configured.

### Web server choice

With only `actix` (not `actix-web`) and a deliberately trimmed `tokio`
dependency set, the options are:

| Option | Trade-off |
| ------ | --------- |
| **A. Hand-rolled minimal HTTP/1.1 on `tokio::net` (recommended)** | Zero new dependencies, matches the repo's hand-rolled protocol parsers and `#![forbid(unsafe_code)]` stance. The surface is read-only GETs with tiny payloads; ~250 lines. Needs hand-written request parsing (bounded reads, no indexing — the `take()` discipline transfers directly). |
| B. `actix-web` | Full-featured, integrates with the existing actix system, but a large dependency tree that pulls in its own runtime/feature surface, against the minimal-dependency convention. |
| C. `axum` + `hyper` | Popular and small-ish, but needs additional `tokio` features (`fs` isn't needed) and still adds a dependency subtree. |

**Decision for this plan: Option A**, with B as the fallback if the real-time
requirements in phase 4 outgrow the minimal server (e.g. WebSocket needs).
This should be confirmed in review before phase 3 starts.

**Files.**
- `src/stats/http.rs` (new) — the HTTP listener, request parse, router.
- `src/stats.rs` — expose the pre-built dashboard HTML as a `const &str` and
  the `Snapshot` JSON renderer.
- `src/main.rs` — new clap flags and wiring.
- `Cargo.toml` — only if Option B/C is chosen.

**Flags (all default off).**
- `--stats-addr <IP:PORT>` — enable the listener. Unset → no socket (default
  behaviour unchanged).
- `--stats-token <TOKEN>` — require `Authorization: Bearer <TOKEN>` on every
  request; recommended whenever `--stats-addr` binds anything but loopback.

**Endpoints.**
- `GET /` — the dashboard: fully static HTML+JS served from a `const`, with no
  external assets, that polls `GET /stats` every 1 s (`setInterval` +
  `fetch`). Values are rendered as text (`textContent`), never `innerHTML`, so
  client-supplied domain/IP data cannot inject markup.
- `GET /stats` — `application/json` snapshot
  (`Cache-Control: no-store`). Structure groups `server` (version, uptime,
  `started_at`, listener addresses), `connections` (`active`,
  `active_per_ip`, `accepted_total`, `refused_per_ip`, `handshake_timeouts`,
  `auth_failures`, `disconnects`), `dns` (`enabled`, `ttl_secs`,
  `max_entries`, `entries`, `hits`, `misses`, `inserts`, `evictions`,
  `expired_dropped`, top names), `traffic` (`bytes_client_to_target`,
  `bytes_target_to_client`, `requests.{connect,bind,udp_associate}`,
  `udp_datagrams`), `errors` (`by_code`).
- `GET /healthz` — `200 OK` + uptime as plain text, for load balancers and
  `packaging/merino.service` health checks.

**Web server hardening (Phase 3 baseline).**
- Binds **loopback by default**: `--stats-addr` is an explicit `IP:PORT`, and
  binding a non-loopback address without `--stats-token` logs a warning.
- Bounded request parsing: cap the request line + headers at 8 KiB total, 400
  on anything malformed, one fixed-size read buffer, no allocation per request.
- Idle/read timeout on stats sockets (e.g. 30 s) so the stats listener is not a
  slowloris hole.
- Stats connections are **not** counted against the proxy's connection
  `Semaphore`; give them their own small budget (e.g. 64 concurrent) so a
  dashboard flood cannot starve proxying.
- Only `GET`; anything else → `405`. No body handling, no chunked requests,
  `Connection: close` responses (keep it stateless and simple).

**Test cases** (`tests/stats.rs` new + `tests/cli.rs` extension).
- Start a server with `--stats-addr 127.0.0.1:0` (or an equivalent in-process
  `bind`), make a raw HTTP GET via a tiny hand-written test client, assert
  `200` + parseable JSON with the expected top-level groups.
- `GET /` returns the dashboard HTML (`200`, `text/html`).
- With `--stats-token set`, a tokenless GET → `401`; with the right
  `Authorization` header → `200`.
- `POST /stats` → `405`.
- Overlong request line → `400`, and the connection is closed.
- CLI test: `--stats-addr` parses; both the SOCKS listener and the stats
  listener come up; unset flag binds no stats socket.
- Metrics sanity end-to-end: drive one CONNECT relay through the SOCKS port,
  then GET `/stats` and assert `active == 0` (relay finished), `accepted_total
  >= 1`, `traffic` byte counts match the echoed payload.

**Verification.**
```
cargo test
cargo clippy --all-targets
cargo run -- --no-auth --ip 127.0.0.1 --port 1080 --stats-addr 127.0.0.1:9090
# then: curl http://127.0.0.1:9090/  and  curl http://127.0.0.1:9090/stats
```

**Commit.** `feat: serve real-time stats over an embedded HTTP listener`

---

## Phase 4 — Real-time detail, hardening, docs

**Goal.** Per-connection detail, fresher-than-polling updates, security audit,
and complete documentation so the feature is shippable and maintained.

**Files.**
- `src/stats/http.rs` / `src/stats.rs` — new endpoints and streaming.
- `src/main.rs` — any final flag tweaks (e.g. `--stats-max-sockets`).
- `README.md` — new flags + a short "observability" section.
- `AGENTS/ROADMAP.md` — add and tick a "stats web service" item.
- `AGENTS/STATS_WEB_SERVICE_PLAN.md` — mark phases done.
- `packaging/merino.service` — commented `--stats-addr` example + optional
  `Restart` note; `Dockerfile` — optionally `EXPOSE` comment for the stats
  port.

**Items.**
- **`GET /clients`** — live per-connection table: peer/local addrs, state
  (`negotiating` | `relaying`), command once known, `started_at`, elapsed
  seconds, and per-direction byte totals. Backed by a `Mutex<HashMap<u64,
  ClientInfo>>` registry keyed by a monotonically increasing connection id;
  entries are removed when `run_client` returns (same RAII point as
  `ActiveGuard`). This map lives always-on but is small (bounded by
  `max_connections`).
- **Real-time push.** Two options, decide in review:
  - *Preferred:* keep 1 s polling of `/stats` but add `ETag`/`If-None-Match`
    hashing of the snapshot so idle dashboards cost nothing (a cheap
    incremental hash of the atomics).
  - *Alternative:* `GET /events` — server-sent events stream of snapshots
    (hand-written `text/event-stream` with keep-alive; still no new
    dependency). Only reach for this if sub-second freshness is required.
- **Security audit.** Confirm the Phase 3 hardening holds under a fuzz-ish
  input pass (malformed request lines, huge headers, slow-drip clients);
  confirm no credential/username data can reach any endpoint (dashboard shows
  counts + sanitized IPs/names only); confirm default-bind loopback.
- **Overhead proof.** Extend `benches/proxy.rs` to run the full
  handshake+relay with counters enabled (they are always on) and record the
  delta against the pre-Phase 1 numbers; target < 2% on relay throughput.
  Document the result here.
- **Docs.** README observability section, ROADMAP tick, service-file example.
  Note in README that `/stats` JSON is the stable machine interface and the
  dashboard is intentionally dependency-free.

**Test cases.**
- `/clients` shows one entry while a relay is open and zero after it closes.
- `If-None-Match` with the current `ETag` → `304 Not Modified`.
- (If SSE) `/events` yields a stream of snapshots and keeps the connection
  alive between frames.
- Hardening: token required on non-loopback bind warning appears in logs;
  overlong header closes; stats-socket budget rejects beyond cap with a clean
  `429`/close rather than affecting the SOCKS listener.

**Verification.**
```
cargo test
cargo clippy --all-targets
cargo bench
```

**Commit(s).** one per item, e.g.
`feat: add live client table endpoint`,
`feat: conditional GET for stats snapshots`,
`docs: document the stats web service and mark roadmap complete`.

---

## Rollback / risk notes

- Every phase is independently revertible; counters in Phase 1 are invisible
  to users and tests, so a revert never affects the protocol.
- If the hand-rolled HTTP parser proves fragile under fuzzing, fall back to
  Option B (`actix-web`) only for the listener — the `Stats`/`Snapshot` layer
  is framework-agnostic by design.
- The per-IP map and client registry are `Mutex`-guarded and only touched at
  connection start/end; the poison-recovery pattern (`lock_counts`) already
  used for `PerIpLimiter` must be reused so a panic in one thread never wedges
  stats.
- Never let stats traffic bypass or consume the proxy semaphore; the separate
  stats budget in Phase 3 is the guard.
- Keep `Snapshot` fields additive-only after release (add fields, never rename)
  so the machine interface stays stable for dashboards.

## Open decisions to confirm

1. **Web server choice** — Option A (hand-rolled, zero deps, recommended) vs B
   (`actix-web`) vs C (`axum`).
2. **Always-on counters** — recommended yes (negligible, keeps tests uniform);
   a `no-stats` feature is possible but forks every increment site.
3. **Real-time mechanism** — 1 s polling + conditional GET (recommended) vs
   hand-rolled SSE.
4. **Client detail endpoint** — include `GET /clients` (recommended, opt-in via
   token) or keep the dashboard to aggregates only.
5. **Token auth scheme** — `Bearer` header (recommended) vs `?token=` query.