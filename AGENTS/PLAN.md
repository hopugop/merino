# Merino Implementation Plan

Phased plan for the two roadmap items requested:

1. **Unit tests** (roadmap item 6)
2. **Actix-based backend** (roadmap item 7)

The plan is intentionally incremental: tests land first to lock in current
behaviour, then the actix backend is added alongside the existing Tokio loop,
proven at parity, and only then can the old loop be retired.

Each phase is independently committable and verifiable.

## Constraints & conventions

- Rust edition 2024 (toolchain pinned in `rust-toolchain.toml`); keep `#![forbid(unsafe_code)]`.
- CI only builds Docker today. Run `cargo test` and `cargo clippy --all-targets`
  locally before each commit.
- Do not break the public `Merino` / `SOCKClient` API mid-migration; the actix
  backend is additive until phase 4.
- No comments in source unless they already exist (repo convention).

## Baseline

```
$ cargo test
test result: ok. 0 passed ... (lib)
test result: ok. 0 passed ... (bin)
test result: ok. 1 passed ... (tests/common.rs)
```

Only `tests/common.rs::merino_contructor` exists. `src/lib.rs` exposes no
`#[cfg(test)]` module, and the protocol types (`AddrType`, `SockCommand`,
`SOCKSReq`) are private.

---

## Phase 0 — Planning docs

**Deliverable.** `AGENTS/ROADMAP.md` and `AGENTS/PLAN.md` (this file).

**Commit.** `docs: add detailed roadmap and implementation plan`

---

## Phase 1 — Unit tests for protocol logic

**Goal.** Cover the pure (non-I/O) parsing/encoding logic in `src/lib.rs` so the
actix refactor has a safety net.

**Files.**
- `src/lib.rs` — add `#[cfg(test)] mod tests`; adjust visibility of a few
  internals.

**Visibility changes (minimal).**
- `AddrType::from(usize) -> Option<AddrType>` and `SockCommand::from(usize)`
  are already private `fn`s in the same module, so an inline `mod tests` can
  call them without changing visibility. Prefer inline tests and leave the
  public API untouched.
- If integration tests in phase 2 need these, promote `pub` in that phase
  instead.

**Test cases.**
- `AddrType::from`: `1 -> V4`, `3 -> Domain`, `4 -> V6`, unknown -> `None`.
- `SockCommand::from`: `1 -> Connect`, `2 -> Bind`, `3 -> UdpAssosiate`,
  unknown -> `None`.
- `pretty_print_addr`: dotted quad for `V4`, colon-hex for `V6`, UTF-8 passthrough
  for `Domain`.
- `SocksReply::new`: assert the 10-byte wire layout `[0x05, REP, 0x00, 0x01,
  0,0,0,0, 0,0]` for a `Success` reply and for a failure reply.
- `addr_to_socket` (V4/V6 branches): assert the produced `SocketAddr` matches
  the raw bytes + big-endian port. Domain branch is DNS-dependent and belongs in
  phase 2 or is skipped.
- `User` deserialization: feed a CSV row through `csv::Reader` and assert the
  parsed `username`/`password`.
- `MerinoError -> ResponseCode` conversion: `Socks(e)` round-trips the code;
  `Io(_)` maps to `ResponseCode::Failure`.
- `AuthMethods` discriminants: `NoAuth == 0x00`, `UserPass == 0x02`,
  `NoMethods == 0xFF`; `ResponseCode` discriminants match RFC 1928.

**Verification.**
```
cargo test
cargo clippy --all-targets
```

**Commit.** `test: add unit tests for SOCKS5 protocol logic`

---

## Phase 2 — Integration tests over loopback

**Goal.** Exercise the real handshake and `CONNECT` relay end to end against
`Merino::serve`, without changing production behaviour.

**Files.**
- `tests/socks5.rs` (new) — end-to-end client tests.
- `tests/common.rs` — keep the smoke test; move shared helpers into
  `tests/support/mod.rs` if useful.
- `src/lib.rs` — small, additive helpers required by the tests:
  - `Merino::local_addr(&self) -> io::Result<SocketAddr>` so the OS can pick an
    ephemeral port (`port = 0`) and the test can discover it.
  - `pub fn shutdown(...)` / keep `SOCKClient::shutdown` public.
  - Possibly `pub` on `AddrType`, `SockCommand`, `SOCKSReq` if tests build raw
    frames; otherwise keep tests byte-oriented and no visibility change is
    needed.

**Harness design.**
- Bind `Merino` on `127.0.0.1:0`, spawn `serve()` in a `tokio::spawn`, read
  `local_addr()`.
- A raw test client that writes SOCKS5 frames over `TcpStream` (no extra
  dependency):
  - `greeting(methods)` → assert version byte and selected method.
  - `userpass(user, pass)` → assert status byte.
  - `connect(addr_type, addr, port)` → assert `REP` and then relay bytes.
- A loopback echo server task (or a tiny HTTP responder) as the CONNECT target.

**Test cases.**
- `NOAUTH` negotiation succeeds and selects `0x00`.
- Server configured `NoAuth` rejects a client offering only `USERPASS`.
- `USERPASS` happy path authenticates and proceeds to a successful `CONNECT`.
- `USERPASS` bad credentials get `0x01` and the socket closes.
- `CONNECT` to the echo server relays data bidirectionally.
- `CONNECT` to a dead port returns `ResponseCode::ConnectionRefused`.
- `BIND` / `UDP ASSOCIATE` return `ResponseCode::CommandNotSupported`.
- Unsupported version byte is rejected.

Each test uses an ephemeral port and its own echo target; no fixed-port
dependencies, safe for parallel execution.

**Verification.**
```
cargo test
cargo clippy --all-targets
```

**Commit.** `test: add loopback integration tests for SOCKS5 handshake and CONNECT`

---

## Phase 3 — Actix actor backend

**Goal.** Add an `actix`-based server that reuses the existing `SOCKClient`
protocol code, leaving `Merino` intact for parity comparison.

**Dependency.** `actix = "0.13"` (actor framework, not `actix-web`). It runs on
`actix-rt`/Tokio, which the crate already uses.

**Files.**
- `src/actors.rs` (new) — actor definitions, re-exported from `src/lib.rs`.
- `src/lib.rs` — `mod actors; pub use ...`; refactor the per-connection error
  reply/shutdown into a reusable async helper so both backends share it.
- `src/main.rs` — switch the run path to the actix `System`; keep all CLI
  parsing and config loading as-is.
- `Cargo.toml` — add `actix`.

**Actors.**

1. `SocksConnection` — one actor per accepted TCP stream.
   - State: `SOCKClient<TcpStream>` and the peer `SocketAddr`.
   - `Actor::started` takes the client out and spawns a `fut::wrap_future`
     running `client.init()`. On completion it logs, sends the error reply +
     shutdown when `init` failed (same behaviour as the current `serve` loop),
     and calls `ctx.stop()`.
   - Holds `Arc<Vec<User>>`, `Arc<Vec<u8>>`, `Option<Duration>` config.

2. `SocksServer` — the supervisor / listener owner.
   - State: `Option<TcpListener>` + shared config.
   - `SocksServer::bind(ip, port, auth_methods, users, timeout) -> io::Result<Self>`
     performs the async bind.
   - `Actor::started` moves the listener into a spawned accept loop;
     for each `(stream, peer)` it calls
     `SocksConnection::create(move |_| SocksConnection::new(...))`.
   - Accept errors are logged; fatal errors call `ctx.stop()` (and
     `System::current().stop()` for graceful process exit).
   - Implement `Supervised` with `restart()`/`stopping()` so a crashed server
     actor is restarted, satisfying the "supervision tree" goal.

**Entry point.** Add a `pub async fn run(...)` (or `ServerHandle`) so
`main.rs` becomes:

```rust
let sys = actix::System::new();
let server = sys.block_on(async { SocksServer::bind(...).await })?;
server.start();
sys.run()?;
```

`main` keeps `#[forbid(unsafe_code)]` and its current argument/CSV handling.

**Compatibility.** `Merino` and `SOCKClient` remain public and unchanged in
behaviour; `serve()` is only deprecated in docs, not removed.

**Verification.**
```
cargo build
cargo test          # existing tests must still pass
cargo clippy --all-targets
```
Manually smoke test: `cargo run -- --no-auth --ip 127.0.0.1 --port 1080` then
`curl --socks5 127.0.0.1:1080 https://example.com` (or an equivalent local
echo test).

**Commit.** `feat: add actix-based actor backend`

---

## Phase 4 — Parity tests, benchmarks wiring, docs

**Goal.** Prove the actix backend matches the Tokio backend, then update the
public roadmap.

**Files.**
- `tests/actors.rs` (new) — run the phase 2 scenarios against `SocksServer`.
  Share the raw SOCKS5 client/echo helpers from phase 2.
- `benches/` — replace the nightly `powf` placeholder with `criterion`
  (`Cargo.toml` dev-dependency `criterion = "0.5"`, `[[bench]] harness = false`):
  parse, handshake, and relay benches. (Roadmap item 5; can be a follow-up
  commit if this phase grows.)
- `README.md` — tick `Benchmarks & Unit tests` and `Actix based backend`.
- `AGENTS/ROADMAP.md` — mark items 6 and 7 complete.

**Test cases (parity).**
- `NOAUTH` handshake.
- `USERPASS` success and failure.
- `CONNECT` relay.
- Unsupported command replies.

**Verification.**
```
cargo test
cargo bench --no-run
cargo clippy --all-targets
```

**Commit.** `test: add actix backend parity tests and wire up benchmarks`

---

## Rollback / risk notes

- If `actix::System` integration fights `#[tokio::main]`, keep `main` on
  `actix::System::new().block_on(...)` as shown, or use `#[actix::main]`; both
  run on Tokio, so `SOCKClient` is unaffected.
- Protocol helpers are `async fn` with `read_exact`, so tests must always write
  a complete frame before awaiting a read; the harness writes then reads, which
  avoids deadlock.
- Keep every phase's commit green (`cargo test` + `clippy`) so a phase can be
  reverted independently.
