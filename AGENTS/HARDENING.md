# Merino Hardening & Security Test Plan

This document tracks the work to prove and improve the security posture of the
SOCKS5 proxy. It complements [`PLAN.md`](PLAN.md) (features) and
[`ROADMAP.md`](ROADMAP.md) (product direction) by focusing exclusively on
adversarial input, resource exhaustion, authentication soundness, and
supply-chain hygiene.

Each phase is independently committable and verifiable.

## Status

| Phase | Status | Where |
| ----- | ------ | ----- |
| A — adversarial integration tests | done | `tests/hardening.rs` |
| B — property tests | done | `tests/properties.rs` |
| C — fuzzing | done | `fuzz/` (4 targets, smoke-run clean) |
| D — supply chain + CI | done | `.github/workflows/security.yml`, `deny.toml` |
| E — dynamic/static hardening | mostly | clippy restriction denies + Miri in CI; ASan/TSan pending |
| F — code coverage | done | `cargo-llvm-cov`, `coverage` job in `.github/workflows/security.yml` |
| G1–G7 fixes | done | see "Product fixes" below |

## Threat model

| Untrusted input | Parsed at |
| --- | --- |
| Arbitrary TCP bytes on the proxy port | `SOCKClient::init` → `auth` → `parse_request` |
| DNS responses for `AddrType::Domain` | `addr_to_socket` |
| CSV contents and file mode | `src/main.rs` user loading |
| CLI args / `RUST_LOG` | `src/main.rs` |

Merino is an **open relay by design**: any authenticated client may `CONNECT` to
any reachable address. Until a middleware/ACL layer exists, "secure" means:

1. memory-safe parsing of arbitrary bytes (no panic, no unbounded allocation);
2. no authentication bypass and no false positive;
3. no trivial remote resource-exhaustion (slowloris, unbounded tasks);
4. well-formed, spec-correct replies on every error path;
5. a clean, audited dependency tree and a least-privilege deployment.

## Baseline gaps found during review

| # | Gap | Location |
| - | --- | -------- |
| G1 | Handshake reads have no read/idle timeout (slowloris DoS). The configured timeout only guards the upstream `CONNECT`. | `SOCKClient::init` |
| G2 | Raw slice indexing with no length guard. | `pretty_print_addr`, `addr_to_socket` |
| G3 | Bad SOCKS version path shuts the socket down but keeps parsing (fallthrough). | `SOCKSReq::from_stream` |
| G4 | USERPASS sub-negotiation ignores the version byte. | `SOCKClient::auth` |
| G5 | Credential check is not constant-time (`Vec::contains` + `String` eq). | `SOCKClient::authed` |
| G6 | No connection cap / per-IP throttle. | `SocksServer` accept loop (open) |
| G7 | Committed sample credentials in `users.csv`; file-mode check untested. | repo root / `main.rs` |

## Phases

### Phase A — Adversarial integration tests

Deterministic, no new dependencies, run against the loopback server via
`tests/support`. Cover:

- framing: byte-at-a-time and fragmented delivery, truncated frames, half-close;
- method negotiation abuse: `nmethods = 0`, `nmethods = 255` with a short body,
  duplicate/unknown methods;
- USERPASS abuse: declared length with a short body, zero length, invalid
  UTF-8 / control bytes, wrong sub-negotiation version, no false positives;
- request abuse: non-zero RSV, unknown `ATYP`/`CMD`, oversized domain prefix
  with no body;
- error-path replies: `0x07` for unsupported command, `0x08` for unsupported
  address type;
- concurrency smoke test.

### Phase B — Property tests (`proptest`)

Pure, fast, no sockets:

- `parse_greeting` / `parse_userpass` / `parse_request` never panic on arbitrary
  bytes and never claim to consume more than the input length;
- `AddrType::from` / `SockCommand::from` are total for all `u8`;
- `SocksReply::new` is always exactly 10 bytes with `VER = 0x05`;
- `parse_udp_header` never panics and never claims to consume more than the
  input length;
- `pretty_print_addr` never panics;
- parsed addresses are always the length implied by their `AddrType`.

### Phase C — Fuzzing (`cargo-fuzz`)

Requires a nightly toolchain and `cargo install cargo-fuzz`. Prerequisite
(refactor in this branch): the protocol parsing is split into pure
`&[u8] -> Result<..>` functions so a fuzzer needs no sockets.

Targets: `parse_greeting`, `parse_userpass`, `parse_request`,
`parse_udp_header`, `pretty_print_addr`, and a differential target that feeds
identical bytes to the Tokio and actix backends over `tokio::io::duplex` and
compares replies.

Run:

```bash
cargo +nightly fuzz run parse_request
cargo +nightly fuzz run parse_greeting -- -max_total_time=60
```

### Phase D — Supply chain and CI

- `cargo audit` (RUSTSEC advisories) and `cargo deny check` (advisories,
  licenses, bans, sources) as gating jobs.
- `cargo clippy --all-targets -- -D warnings` for the whole crate.
- `cargo build --locked` (already used by the Dockerfile); commit `Cargo.lock`.
- Optional: `cargo geiger` to quantify `unsafe` in dependencies, since the
  "100% Safe Rust" claim only covers this crate.

### Phase E — Dynamic/static hardening (follow-up)

- Miri over the pure tests; ASan/TSan nightly run of the integration suite.
- Deny lints in the library (`clippy::indexing_slicing`, `unwrap_used`,
  `expect_used`, `panic`) once the gaps above are closed.
- `systemd-analyze security packaging/merino.service` and a container image
  scan (`trivy`/`grype`) in CI.

### Phase F — Code coverage

Line/region coverage is measured with [`cargo-llvm-cov`](https://github.com/taiki-e/cargo-llvm-cov),
which runs on the pinned stable toolchain (the `llvm-tools-preview` component
is declared in `rust-toolchain.toml`). The library and binary are instrumented;
the `fuzz` crate is a separate workspace and is measured separately.

```bash
cargo install cargo-llvm-cov --locked   # once
cargo llvm-cov --locked --all-targets --html   # HTML in target/llvm-cov/html
```

Baseline before this phase was 82.79% of lines (88.67% of regions) with
`src/main.rs` at 0% because all of its logic lived in `main` behind
`std::process::exit`. The CLI argument/auth selection and CSV user loading were
extracted into `log_level_for`, `select_auth_methods`, and `load_users` so they
are unit-testable without spawning a process. Coverage is now roughly 92% of
lines (89% of regions) across `src/{lib,actors,main}.rs`; the remaining
uncovered lines are defensive error paths (accept failures, `copy_bidirectional`
errors) and the `main` entry point itself, which is only exercised by running
the binary.

CI runs coverage in its own `coverage` job and uploads `lcov.info` plus the
HTML report as a build artifact. It is informational only — no threshold gate
yet, so it cannot fail a PR on a coverage regression.

## Product fixes driven by these tests

Implemented in this branch:

- G1: `SOCKClient` gains a handshake timeout (`DEFAULT_HANDSHAKE_TIMEOUT`, 30s,
  configurable via `set_handshake_timeout`). The budget covers greeting,
  authentication and reading the request only; the relay is deliberately left
  unbounded. A stalled handshake replies `TTL expired (0x06)` and closes.
- G2: `addr_to_socket` / `pretty_print_addr` length guards return an error or a
  placeholder instead of panicking.
- G3: `parse_request` rejects a bad version with an error instead of falling
  through, and `from_stream` assembles the exact frame then delegates to it.
- G4: USERPASS version `!= 0x01` is rejected.
- G5: constant-time username/password comparison (`ct_eq`) that inspects the
  whole user list.
- G6: both backends cap simultaneous connections
  (`DEFAULT_MAX_CONNECTIONS`, 1024; `set_max_connections` / `--max-connections`).
  A `tokio::sync::Semaphore` permit is acquired before `accept`, so excess
  connections wait in the kernel backlog rather than spawning unbounded
  tasks/actors. Zero is clamped to one.
- G7: the committed credential file moved to `users.example.csv` with
  placeholder values; real `/users.csv` is gitignored and the README says to
  `chmod 600` it. `main.rs` already rejects group/world-readable files.

Phase E also added `clippy::unwrap_used` / `expect_used` / `panic` as hard
denies in the library and binary, and a Miri CI job over the pure unit tests.

The protocol parsing was split into pure `&[u8] -> Result<..>` functions
(`parse_greeting`, `parse_userpass`, `parse_request`, `pretty_print_addr`) so
both the property tests and the fuzzers exercise the wire format without
sockets.

## Remaining open items

- **Sanitizers.** No ASan/TSan nightly job yet; Miri covers the pure tests but
  not the async/network paths.
- **`clippy::indexing_slicing`.** Not yet denied: the parsers and
  `addr_to_socket` still index slices directly. The length guards plus fuzzing
  make this safe today, but converting to `get`/array patterns would let the
  lint be enabled.
- **Per-IP rate limiting.** The cap is global; a single source can still
  occupy all slots. A per-IP throttle/ACL belongs with the middleware work.
- **Timing hardening.** `ct_eq` still reveals string length; consider a
  fixed-length comparison if usernames/passwords are high value.

## Verification

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo llvm-cov --all-targets --html          # after cargo install cargo-llvm-cov
cargo +nightly miri test --lib -- --skip addr_to_socket
cargo +nightly fuzz run parse_request   # after cargo install cargo-fuzz
cargo audit
cargo deny --all-features check
```
