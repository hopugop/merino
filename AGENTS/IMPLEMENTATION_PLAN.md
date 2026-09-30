# Implementation Plan — Batch A (P3, P4, P6) and Batch C (T3, T2)

Scope and acceptance criteria for the next two implementation batches drawn from
[`PERFORMANCE_ROADMAP.md`](PERFORMANCE_ROADMAP.md). Batch order follows the
roadmap's own suggested sequencing: small, test-gated fixes first, then the
measurement-driven performance work.

Everything here stays inside the existing toolchain: pinned stable via
`rust-toolchain.toml`, `cargo-llvm-cov` ≥ 95% lines (baseline 96.08%), and
`clippy --all-targets -D warnings`.

## Status

| Item | Batch | Status | Where |
| ---- | ----- | ------ | ----- |
| P3 — sanitize client bytes in logs | A | **done** | `src/lib.rs` (`sanitize_domain`) |
| P4 — bound `handle_client` with the handshake timeout | A | **done** | `src/lib.rs` (`SOCKClient::handle_client`) |
| P6 — short-circuit failed USERPASS auth | A | **done** | `src/lib.rs` (`SOCKClient::auth`, `run_client`) |
| T3 — parse + `USERPASS` lookup benchmarks | C | **done** | `benches/parse.rs` |
| T2 — drop per-login allocations in USERPASS auth | C | **done** | `src/lib.rs` (`SOCKClient::auth`, `authed`) |

Deferred on purpose: T1 (Batch D), T5 (Batch E), T4 (measure-first, likely not
worth it), and the feature-sized `ROADMAP.md` items (`GSSAPI`, middleware,
`SOCKS4`/`SOCKS4a`). `HARDENING.md` follow-ups (`ASan`/`TSan`, deny
`clippy::indexing_slicing`, per-IP throttling) are untouched by this work.

---

## Batch A — error-path and logging hygiene

Each step is an independent commit. All three touch `src/lib.rs` only.

### A1 — P3: sanitize the domain before logging

`pretty_print_addr` returns the raw decoding of client-supplied bytes and
`handle_request` logs it with `info!`. A client can embed ANSI escapes or forge
log lines. The function is only ever used for display (verified: the sole
callers are the request log at `src/lib.rs` and unit/property/fuzz tests), so
escaping there cannot affect wire bytes or replies.

**Change.** In the `AddrType::Domain` arm, escape every byte that is not
printable ASCII (`0x20..=0x7E`) with `escape_default`. Leave `V4`/`V6` arms
alone: they are already rendered from numeric octets and cannot carry control
bytes.

**Acceptance.**
- `pretty_print_addr(&AddrType::Domain, b"example.com")` is unchanged
  (existing test locks this).
- A domain containing `\x1b[31m` renders with visible escapes, never raw.
- Property tests and the `pretty_print_addr` fuzz target still pass unchanged
  (they only assert "does not panic").

### A2 — P4: bound `handle_client`

`init()` wraps negotiation in `timeout(self.handshake_timeout, …)`; the public
compatibility method calls `SOCKSReq::from_stream` unbounded, so downstream
crates using the public API lose slowloris protection.

**Change.** Wrap the read in `handle_client` in the same
`timeout(self.handshake_timeout, …)` and map elapsed Budget to
`MerinoError::Socks(ResponseCode::TtlExpired)`, mirroring how `init()` reports
a stalled handshake. No change to `init()` itself, so current callers see no
behaviour difference.

**Acceptance.** A `handle_client` call against a peer that sends nothing errors
with `TtlExpired` within the configured budget; existing `handle_client` unit
test still passes.

### A3 — P6: single teardown on failed USERPASS auth

Today the denial branch writes the failure reply, shuts the stream down, and
returns `Ok(())`. `negotiate()` then tries to read a request from the closed
stream and `run_client` attempts a second error reply.

**Change.** Return `Err(MerinoError::Socks(ResponseCode::Failure))` after the
denial reply (do not double-`shutdown`: the following error paths already
close). This matches the existing behaviour of the neighbouring branches —
unsupported sub-negotiation version and no-suitable-method already return `Err`
after replying.

**Acceptance.** A wrong-password client still receives the 2-byte failure reply
and the connection closes; the server writes exactly one reply. Verified with a
duplex-stream test that asserts the byte stream after the denial contains no
second 10-byte SOCKS reply.

### Batch A verification

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test --locked
cargo llvm-cov --locked --all-targets --fail-under-lines 95
```

---

## Batch C — measure, then remove the allocation

Order matters: T3 lands first so T2's change has a number attached to it.

### C1 — T3: new `benches/parse.rs`

`benches/proxy.rs` measures end-to-end handshake + relay only. Add a second
criterion harness (registered in `Cargo.toml` alongside `proxy`) with pure,
socket-free benchmarks:

- `parse_greeting`, `parse_userpass`, `parse_request`, `parse_udp_header` fed a
  worst-case frame carrying a 255-byte domain;
- `USERPASS` lookup against a 10 000-entry user list.

The last one is the guard rail for C2: it must not regress.

**Acceptance.** `cargo bench --bench parse` reports per-phase numbers on stable;
`cargo build --locked --benches` passes.

### C2 — T2: compare bytes, not `String`s

`auth` builds two heap strings per login (`String::from_utf8_lossy(...).to_string()`)
purely to satisfy `authed(&User)`, which compares byte slices internally.

**Change.** Compare the parsed username/password slices against each candidate's
bytes directly, keeping the existing constant-time full-list scan semantics:
iterate every entry, fold comparisons with a constant-time accumulator, never
early-exit. Candidate values from the CSV are byte-comparable, so no trimming or
case folding is introduced or lost. Keep `User` unchanged — it is part of the
public surface.

**Acceptance.** The 10k-user lookup benchmark is no worse; the full integration
and hardening suites pass unchanged (including wrong-password and
non-UTF-8 credential cases).

### Batch C verification

```bash
cargo bench --bench parse          # before C2, keep the baseline output
cargo fmt --all && cargo clippy --all-targets -- -D warnings
cargo test --locked
cargo llvm-cov --locked --all-targets --fail-under-lines 95
```

---

## Result

Both batches are done. Verification after Batch C:

```
Filename      Regions    Cover   Functions  Cover    Lines    Cover
actors.rs         128   93.75%          12  100.00%     84    94.05%
lib.rs           2204   93.28%         142   99.30%   1283    95.64%
main.rs           355   99.15%          23  100.00%    219    99.54%
TOTAL            2687   94.08%         177   99.44%   1586    96.09%
```

126 tests pass, `cargo clippy --all-targets -D warnings` is clean, and coverage
is above the 95% gate (Batch A: 96.22%, Batch C: 96.09%).

### Benchmark baseline (`cargo bench --bench parse`)

Measured for T3, used to check T2:

| Bench | Before T2 | After T2 |
| ----- | --------- | -------- |
| `parse/greeting` | 5.80 ns | — (parsers untouched) |
| `parse/userpass` | 0.98 ns | — |
| `parse/request_ipv4` | 12.09 ns | — |
| `parse/request_domain_255` | 16.07 ns | — |
| `parse/udp_header_domain_255` | 5.44 ns | — |
| `parse/pretty_print_addr_domain_255` | 144.4 ns | — |
| `userpass_lookup/1_user` | 53.3 µs | 53.8 µs |
| `userpass_lookup/10k_users` | 89.7 µs | 89.1 µs |

The loopback TCP handshake dominates the lookup bench by ~3 orders of magnitude
over the two allocations T2 removes, so its numbers move inside the noise band;
that item rests on the removed work, not on a measured win. A socket-free lookup
bench would need `authed` to be public, which is not worth widening the API for.

---

## Commit conventions

One item per commit, Conventional Commit prefixes as in the existing history
(`fix:`, `test:`, `perf:`, `docs:`), on a feature branch. The status table above
and the corresponding `PERFORMANCE_ROADMAP.md` rows flip to *done* in the same
commit as the change.
