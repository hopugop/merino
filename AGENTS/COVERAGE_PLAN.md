# Merino Test Coverage Improvement Plan

Plan to lift coverage from the 2026-09-29 baseline (**87.2% regions / 95.4%
functions / 89.7% lines**) toward the reachable ceiling. Phases 1–5 are now
complete; status and final numbers are recorded at the bottom.

## Phase 1 — Pure-parser unit gaps (done)

Small deterministic unit tests in `src/lib.rs`:

- `expected_ip` IPv6 branch (concrete address, `::` unspecified, short input).
- `encode_udp_header` IPv6 arm via a `SocketAddrV6` round-trip.
- `parse_udp_header` domain-without-length-byte, declared domain length
  exceeding the body, and short-IPv6 truncation arms.

## Phase 2 — Relay protocol branches via in-memory duplex (done)

The SOCKS relay error/edge paths were unmeasured because the `Server` test
helper `abort()`s the serve task before teardown paths can run. New
`tests/relay.rs` drives `SOCKClient::init` directly over
`tokio::io::duplex` (shared `tests/helpers.rs`), so clients exit naturally:

- `bind_with_unexpected_peer_gets_rule_failure` — BIND peer validation.
- `bind_without_inbound_peer_times_out` — BIND accept timeout → `TtlExpired`.
- `connect_to_blackholed_destination_fails_within_budget` — CONNECT budget
  expiry (accepts TTL-expired or a network's fast rejection).
- `udp_control_data_is_ignored_and_close_ends_relay` — control-channel bytes
  are ignored; closing the control connection tears the association down
  cleanly (returns `Ok`).
- `udp_first_datagram_from_unexpected_source_is_dropped` — spoofed client
  address never pins the association.
- `udp_invalid_header_and_unresolvable_destination_are_dropped` — reserved
  ATYP and NXDOMAIN destinations are skipped without killing the relay.
- `tests/relay_reset.rs::connect_relay_reports_upstream_failure` — upstream
  RST mid-relay makes `copy_bidirectional` fail (closed with unread data, so
  the kernel sends RST instead of FIN).
- `handle_client` (previously zero callers): covered by a direct unit test.

## Phase 3 — `main.rs` binary smoke tests (done)

`main()` had 0% coverage. New `tests/cli.rs` runs the real binary via
`tokio::process` + `env!("CARGO_BIN_EXE_merino")`, discovering the bound port
race-free by parsing the `Listening on` log line from stderr (`--port 0`):

- `version_and_help_succeed`, `conflicting_flags_fail` — clap surface.
- `noauth_binary_starts_serves_and_stops` — startup, RUST_LOG-override
  warning, real NOAUTH handshake.
- `no_flags_defaults_to_noauth_and_warns` — the documented NOAUTH default.
- `userpass_binary_authenticates_real_clients` — real USERPASS handshake
  against a 0600 CSV.
- `busy_port_exits_with_error`, `world_readable_users_file_is_refused_at_startup`
  — failure exits.
- `quiet_flag_suppresses_logs` — `-q` emits nothing.
- `ctrl_c_stops_server_cleanly` — SIGINT exits with status 0.

Product change discovered by this phase: children killed with `SIGKILL` never
flush their coverage profile, and a proxy with no stop path cannot exit at
all. `main.rs` now installs Ctrl+C and SIGTERM handlers that stop the actix
`System` (`actix::System::current().stop()`), and the tests assert graceful
exit. This matches ROADMAP item 7's motivation for the actix backend
("restart, graceful shutdown").

## Phase 4 — Testability refactor + unreachable-arm policy (done)

- `bind_all` split into `bind_all` (resolve) + `bind_listeners(&[SocketAddr])`
  (bind loop, sync via `std::net` + `from_std` so plain unit tests can call
  it). Testable now: empty-input error, all-binds-fail (last error reported),
  partial success skipping failed addresses.
- Residual policy: the remaining uncovered arms are accepted, not padded with
  contrived tests. Documented in `HARDENING.md` Phase F.

## Phase 5 — CI guardrails (done)

- The `coverage` job gates with `--fail-under-lines 95` (baseline 96.08%), so
  a coverage regression now fails the PR. Raise by ~1 point whenever the
  residual shrinks.
- Fuzzing stays scheduled-only (60 s smokes); with `#![forbid(unsafe_code)]`
  verified, the fuzz targets' role is panic/hang detection, which
  `tests/properties.rs` already largely covers on the PR path.

## Final state (after this plan)

```
Filename        Regions    Cover   Functions  Cover    Lines    Cover
actors.rs           128   93.75%          12  100.00%     84    94.05%
lib.rs             2051   93.13%         135   99.26%   1204    95.60%
main.rs             355   99.15%          23  100.00%    219    99.54%
TOTAL              2534   94.00%         170   99.41%   1507    96.08%
```

Residual uncovered (all defensive OS-error or structurally unreachable):
accept-loop `accept()`/semaphore failures (`serve` + `actors`), reply/shutdown
failures while already handling an error, `copy_bidirectional`
`NotConnected` arms, UDP `recv_from`/`send_to` failure warns, the
`bind_all` "resolved to zero addresses" branch (a resolver returning an
empty successful lookup, which `std`/`tokio` never produce), and closing
braces that LLVM attributes to regions.
