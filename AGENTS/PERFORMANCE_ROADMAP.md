# Merino Performance & Follow-up Roadmap

Review of the codebase (September) produced a list of concrete, independently
committable next steps in two buckets:

1. **Performance** — throughput, latency, build time, allocation hygiene.
2. **Security follow-ups** — gaps found in a fresh pass over `src/`, `fuzz/`,
   CI, and deployment artifacts.

This document complements [`HARDENING.md`](HARDENING.md) (which owns the
adversarial-input work and its remaining open items) and
[`ROADMAP.md`](ROADMAP.md) (feature direction). Items already tracked there are
linked, not duplicated.

## Status

| Item | Bucket | Status | Where |
| ---- | ------ | ------ | ----- |
| P1 — users-file permission check (group bits) | security | done | `src/main.rs` |
| P2 — wire `parse_udp_header` fuzz target into CI | security | done | `fuzz/`, `.github/workflows/security.yml` |
| P3 — sanitize client bytes in logs | security | open | `src/lib.rs` |
| P4 — bound `handle_client` with the handshake timeout | security | open | `src/lib.rs` |
| P5 — RFC-correct reply codes for DNS/network errors | security | open | `src/lib.rs` |
| P6 — short-circuit failed USERPASS auth | security | open | `src/lib.rs` |
| T1 — trim tokio `"full"` features | performance | open | `Cargo.toml` |
| T2 — drop per-login allocations in USERPASS auth | performance | open | `src/lib.rs` |
| T3 — parse + `USERPASS` lookup benchmarks | performance | open | `benches/` |
| T4 — optional DNS cache for `Domain` CONNECT | performance | open | `src/lib.rs` |
| T5 — de-duplicate the two accept loops | maintenance | open | `src/lib.rs`, `src/actors.rs` |

Cross-referenced, already-tracked work (see `HARDENING.md` → *Remaining open
items* and `ROADMAP.md` → item 5): per-IP rate limiting, ASan/TSan, Miri on
async paths, `clippy::indexing_slicing`, Docker image scan, pinned CI action
SHAs, and the general *relay is intentionally unbounded* design decision.

---

## Security follow-ups (priority order)

### P1 — Users-file permission check must cover group bits

**Severity.** Medium. Credential file leak on shared-group hosts.

**Location.** `src/main.rs`, `load_users`.

The check only inspects the "others" bits:

```rust
// 7 is (S_IROTH | S_IWOTH | S_IXOTH) or the "permisions for others" in unix
if (metadata.mode() & 7) > 0 && !allow_insecure {
```

A `0o640` file (group-readable) passes, contradicting the stated intent
(`README.md` "must not be group- or world-readable"; `packaging/merino.service`
comments) and the claim in `HARDENING.md` G7 ("rejects group/world-readable
files"). On a shared primary group this leaks credentials.

**Fix.**
- Change the mask to `metadata.mode() & 0o077` (group **and** other bits).
- Add a test mirroring `load_users_rejects_world_readable_file` with mode
  `0o640` (none exists today, which is why the gap went unnoticed).
- Update the comment in `main.rs` (the current one's math is correct but the
  policy it documents is incomplete).

**Acceptance.**
- `0o640` and `0o644` files are rejected without `--allow-insecure`;
  `0o600` loads; `--allow-insecure` still bypasses.

---

### P2 — Wire `parse_udp_header` fuzz target into the build and CI

**Severity.** Medium. The newest, most complex parser (variable-length domain
branch) has zero fuzz coverage.

**Location.** `fuzz/Cargo.toml`, `fuzz/fuzz_targets/parse_udp_header.rs`,
`.github/workflows/security.yml`.

`fuzz/fuzz_targets/parse_udp_header.rs` exists but `fuzz/Cargo.toml` declares
only four `[[bin]]` targets and the `fuzz` job runs only those four. The target
is never compiled or executed.

**Fix.**
- Add the missing `[[bin]]` entry to `fuzz/Cargo.toml`.
- Add a `cargo +nightly fuzz run parse_udp_header -- -max_total_time=60
  -rss_limit_mb=2048` step to the `fuzz` job in `.github/workflows/security.yml`.
- Update the "4 targets" claim in `HARDENING.md` Phase C to 5.

**Acceptance.** `cargo +nightly fuzz build` compiles five targets; the CI
`fuzz` job exercises all five.

---

### P3 — Sanitize client-controlled bytes before logging

**Severity.** Low–medium. Log injection into operator terminals.

**Location.** `src/lib.rs`, `handle_request` / `pretty_print_addr`.

`AddrType::Domain` payloads (up to 255 bytes, `from_utf8_lossy`) are logged
verbatim via `info!`. A client can embed ANSI escapes or forged log lines.

**Fix.** Escape non-printable/control bytes when pretty-printing domains for
logs (`escape_default()` or equivalent). Keep the wire bytes untouched.

**Acceptance.** A domain containing `\x1b[31m...` renders as an escaped
sequence in `RUST_LOG=merino=trace` output; a unit test locks the behaviour.

---

### P4 — Bound the public `handle_client` path with the handshake timeout

**Severity.** Low. Downstream crates using the public API lose slowloris
protection.

**Location.** `src/lib.rs`, `SOCKClient::handle_client`.

`init()` is bounded by `DEFAULT_HANDSHAKE_TIMEOUT`, but the compatibility
method `handle_client()` calls `SOCKSReq::from_stream` unbounded. Route it
through the same `timeout(self.handshake_timeout, …)` used by `init()`, or
document explicitly that callers must bound it.

**Acceptance.** `handle_client` on a client that never sends a request errors
with `TtlExpired` within the configured budget.

---

### P5 — RFC-correct reply codes for DNS/network errors

**Severity.** Low. Spec fidelity + client observability.

**Location.** `src/lib.rs`, `handle_request` (CONNECT) and `addr_to_socket`.

Only `ConnectionRefused` maps specifically (`0x05`); DNS resolution failures
and `HostUnreachable` / `NetworkUnreachable` / `AddrNotAvailable` all collapse
to generic `Failure` (`0x01`). Map them to `0x03` (network unreachable) /
`0x04` (host unreachable) per RFC 1928 §6.

**Acceptance.** A `CONNECT` to an unresolvable or unroutable destination
surfaces `0x03`/`0x04`, covered by an integration test.

---

### P6 — Short-circuit failed USERPASS authentication

**Severity.** Low. Convoluted teardown; second reply attempted on a closed
stream.

**Location.** `src/lib.rs`, `SOCKClient::auth`.

On access denied the function writes the failure response and calls
`shutdown()` but returns `Ok(())`, so `negotiate()` proceeds to read a request
from a closed stream, and `run_client` then attempts a second error reply.
Return `Err(MerinoError::Socks(ResponseCode::Failure))` (or a dedicated
variant) after the failure response so teardown happens exactly once.

**Acceptance.** A wrong-password client still receives `0x01` and a close, but
no second reply is attempted (verify via the existing `run_client` error path
or a duplex-stream test).

---

## Performance next steps

### T1 — Trim tokio's `"full"` feature set

**Location.** `Cargo.toml`.

`tokio = { version = "1.53.1", features = ["full"] }` pulls in `fs`, `process`,
`signal`, `rt`, etc. The code only exercises:

- `rt-multi-thread` (actix runtime),
- `net` (TcpListener/TcpStream/UdpSocket/lookup_host),
- `io-util` (AsyncReadExt/AsyncWriteExt, `copy_bidirectional`),
- `time` (`timeout`, `Duration`),
- `sync` (`Semaphore`),
- `macros` (tests; actix re-enables what it needs transitively).

Slimming the manifest to those features shrinks build time, binary size, and
the dependency/supply-chain surface without runtime change. Verify with
`cargo tree -e features` and the test suite.

**Acceptance.** `cargo build --locked` and `cargo test --locked` pass with the
trimmed feature list; `cargo llvm-cov` CI job unaffected.

---

### T2 — Drop per-login allocations in USERPASS auth

**Location.** `src/lib.rs`, `SOCKClient::auth`.

Every login builds two heap strings:

```rust
let username = String::from_utf8_lossy(parsed.username).to_string();
let password = String::from_utf8_lossy(parsed.password).to_string();
```

`authed()` then compares `&[u8]` slices. Compare the parsed slices directly
against candidate `User` byte slices (CSV values are byte-comparable) to skip
the copies. Only reachable before the handshake timeout, so absolute cost is
small — but the allocation is trivial to remove and matters for the
`USERPASS`-against-large-user-list benchmark (T3).

**Acceptance.** A `USERPASS` lookup benchmark shows no worse numbers; auth
logic stays constant-time across the candidate list.

---

### T3 — Parse and `USERPASS` lookup benchmarks

**Location.** `benches/` (extends roadmap item 5).

Only the end-to-end `noauth_connect_handshake` bench exists. Add pure,
socket-free benches:

- `parse_request` / `parse_udp_header` with worst-case 255-byte domain names;
- `parse_greeting` / `parse_userpass` (including the re-assembly path);
- `USERPASS` lookup against a large user list (e.g. 10k users), which also
  guards the T2 change.

**Acceptance.** `cargo bench` reports per-phase numbers; a non-blocking CI job
(`cargo bench -- --quick` or a criterion baseline) makes regressions visible in
PRs.

---

### T4 — Optional DNS cache for `Domain` CONNECT

**Location.** `src/lib.rs`, `addr_to_socket`.

Every `Domain` CONNECT performs a fresh `lookup_host`. A small TTL-respecting
positive cache would cut handshake latency for repeated hostnames (proxy
clients re-resolving popular sites).

**Caution — weigh before investing.** Caching client-supplied names trades
DNS-rebinding fidelity for latency. For a security-minded proxy this is likely
**not** worth it unless real-world profiling shows DNS dominates handshake
latency. Treat as a measurement-first item: profile first, implement only if
the data supports it.

**Acceptance (if pursued).** Cache honours TTL, bounds memory and entry count,
is configurable, and never caches negative results.

---

### T5 — De-duplicate the two accept loops

**Location.** `src/lib.rs` (`Merino::serve`), `src/actors.rs`
(`SocksServer::started`).

The semaphore + accept + spawn/create logic is implemented twice (Tokio loop
for `Merino`, actor loop for `SocksServer`) and has already drifted once
(permit handling differs on accept errors). Make one a thin front-end for the
other, or extract a shared accept-loop helper, so backpressure behaviour cannot
diverge again.

**Acceptance.** `tests/hardening.rs` connection-cap tests keep passing
unchanged on both backends; behaviour differences (if any) are deliberate and
documented.

---

## Verification

```bash
cargo test --locked
cargo clippy --all-targets -- -D warnings
cargo llvm-cov --locked --all-targets --html
cargo +nightly fuzz build && cargo +nightly fuzz run parse_udp_header
cargo bench
```

## Suggested sequencing

1. P1 + P2 (small, close real gaps; P2 also unblocks the 5-target fuzz claim).
2. P3 + P4 + P6 (error-path and logging hygiene, all integration-testable).
3. P5 (reply-code fidelity).
4. T2 + T3 together (remove the allocation, then prove the lookup is cheap).
5. T1 (one-line manifest change, verify with the suite).
6. T5 (refactor; needs the connection-cap tests as a safety net).
7. T4 only if profiling justifies it.