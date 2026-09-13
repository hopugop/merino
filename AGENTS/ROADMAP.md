# Merino Roadmap

Detailed breakdown of the open items in the top-level [`README.md`](../README.md)
roadmap. Each entry describes the goal, a suggested approach, acceptance
criteria, and rough effort so it can be picked up independently.

## Status legend

| Symbol | Meaning |
| ------ | ------- |
| `[x]`  | Complete and released |
| `[~]`  | Partially implemented / needs hardening |
| `[ ]`  | Not started |

Current state (from `README.md` and `src/lib.rs`):

- `[x]` IPv6 support
- `[x]` `NOAUTH`
- `[x]` `USERPASS`
- `[x]` `CONNECT`
- `[ ]` `GSSAPI`
- `[ ]` Custom plugin / middleware support
- `[ ]` `BIND`
- `[ ]` `UDP ASSOCIATE`
- `[x]` Benchmarks & unit tests
- `[x]` Actix-based backend
- `[ ]` `SOCKS4` / `SOCKS4a` support

---

## 1. `SOCKS5` `GSSAPI` authentication

**Goal.** Support the `GSSAPI` authentication method (`0x01`, RFC 1928 §3) so
Kerberos-joined clients can authenticate without a username/password file.

**Why it is open.** The method is advertised as "coming soon" but the enum
variant is commented out in `src/lib.rs`:

```rust
pub enum AuthMethods {
    NoAuth = 0x00,
    // GssApi = 0x01,
    UserPass = 0x02,
    NoMethods = 0xFF,
}
```

**Suggested approach.**
1. Add `GssApi = 0x01` behind a `gssapi` Cargo feature so the default build
   stays free of platform Kerberos dependencies.
2. Negotiate `0x01` in `SOCKClient::auth` when it is the client's preferred and
   server-advertised method.
3. Perform the RFC 1928 §3 token exchange: client sends `VER (0x01)`,
   `ULEN`, token; server replies with a 2-byte status (accept/reject) plus an
   optional token.
4. Use the `libgssapi` or `cross-krb5` crate to acquire/accept security
   contexts against a configurable service principal.

**Acceptance criteria.**
- A client offering only `GSSAPI` receives `0x01` from the method selector.
- A valid Kerberos ticket authenticates; an invalid one is rejected with
  `0x01`/failure and the connection is shut down.
- Default `cargo build` does not pull in Kerberos system libraries.

**Effort.** Large. Platform/credential setup makes CI coverage hard; start with
a unit test around method negotiation and keep the token exchange behind a
feature flag.

**Depends on.** None, but benefits from the middleware work so policies can be
applied to authenticated identities.

---

## 2. Custom plugin / middleware support

**Goal.** Let operators hook into the request lifecycle (allow/deny, target
rewriting, metrics, rate limiting) without forking `Merino`.

**Suggested approach.**
1. Define a middleware trait in `src/lib.rs`, e.g.

   ```rust
   pub trait Middleware: Send + Sync {
       fn on_request(&self, req: &mut SOCKSReq) -> Result<(), ResponseCode>;
       fn on_connect(&self, addr: &SocketAddr) -> Result<(), ResponseCode>;
   }
   ```

2. Store `Arc<Vec<Box<dyn Middleware>>>` on `Merino` and thread it into
   `SOCKClient`, invoking hooks before `CONNECT` and after the upstream socket
   is established.
3. Ship at least one built-in middleware (CIDR allowlist/denylist) and a way to
   configure it from `main.rs` / CLI flags.
4. Document how a downstream crate registers a custom middleware.

**Acceptance criteria.**
- A middleware can reject a request with a specific `ResponseCode` and the
  client sees the correct reply byte.
- At least one built-in middleware has integration test coverage.
- Adding a middleware does not require changing the core proxy loop.

**Effort.** Medium.

**Depends on.** A stable `SOCKSReq` type (currently private, see the testing
plan) and ideally the actix backend so hooks compose with actor state.

---

## 3. `BIND` command (`0x02`)

**Goal.** Implement the `BIND` request used by protocols that need the proxy to
listen for an inbound connection (historically FTP active mode).

**Suggested approach.**
1. Widen `SocksReply` so it can carry a real `BND.ADDR` / `BND.PORT` instead of
   the fixed all-zero buffer in `src/lib.rs`.
2. On `BIND`, bind a fresh `TcpListener` on the proxy interface, reply with its
   address/port, then wait for the expected peer (optionally validating the
   client's supplied address) and relay with `copy_bidirectional`.
3. Enforce the connection timeout and clean up the listener on error.

**Acceptance criteria.**
- Client receives a valid `BND.ADDR`/`BND.PORT` in the reply.
- A second connection to that bound port is relayed to the first client.
- Timeout/refused paths return `ResponseCode::ConnectionRefused`.

**Effort.** Medium–large (second listener state machine).

**Depends on.** Reply encoder refactor (shared with `UDP ASSOCIATE`).

---

## 4. `UDP ASSOCIATE` command (`0x03`)

**Goal.** Implement UDP relay so clients can send datagrams through the proxy
(DNS, QUIC, WebRTC, etc.).

**Suggested approach.**
1. On `UDP ASSOCIATE`, bind a `UdpSocket`; reply with its address/port.
2. Parse the RFC 1928 §7 UDP request header
   (`RSV(2) FRAG(1) ATYP(1) DST.ADDR DST.PORT`) on each datagram.
3. Relay datagrams to the destination and map replies back to the client.
4. Maintain association lifetime until the TCP control connection closes or
   the configured timeout elapses.

**Acceptance criteria.**
- A UDP echo round-trip through the proxy succeeds.
- Association is torn down when the TCP control channel closes.
- `FRAG != 0` is rejected (fragmentation is optional and rarely implemented).

**Effort.** Large.

**Depends on.** Reply encoder refactor; likely easiest on top of the actix
backend where each association can be its own actor.

---

## 5. Benchmarks

**Status: partly complete.** `benches/proxy.rs` (criterion, stable) benchmarks a
full `NOAUTH` handshake + `CONNECT` relay against a loopback echo server;
`cargo bench` is documented in `README.md`. Remaining follow-ups: dedicated
parse micro-benchmarks and `USERPASS` lookup benchmarks, plus a CI bench job.

**Goal.** Track handshake and relay performance and catch regressions.

**Suggested approach.**
1. Replace the placeholder `benches/common.rs` (which only benchmarks `powf`
   and requires nightly `#![feature(test)]`) with [`criterion`](https://docs.rs/criterion),
   which runs on stable.
2. Benchmarks to add:
   - Address/command parsing (`AddrType`, `SockCommand`, `SOCKSReq`).
   - Full `NOAUTH` handshake against a loopback server.
   - `CONNECT` relay throughput against a loopback echo server.
   - `USERPASS` lookup against a large user list.
3. Add a non-blocking CI job (`cargo bench -- --quick` or criterion baseline)
   so budgets are visible in PRs.

**Acceptance criteria.**
- `cargo bench` runs on stable.
- At least the handshake and relay benchmarks are present.
- Benchmarks are documented in `README.md` or `AGENTS/`.

**Effort.** Small–medium.

**Depends on.** The unit/integration test harness (`AGENTS/PLAN.md` phase 2) for
reusable loopback fixtures.

---

## 6. Unit / integration tests

**Status: complete.** Protocol unit tests live inline in `src/lib.rs`; loopback
integration tests in `tests/socks5.rs` and `tests/actors.rs` cover the
`NOAUTH`/`USERPASS` handshakes and the `CONNECT` relay on both backends.

**Goal.** Cover protocol parsing, authentication, and relaying with automated
tests.

**Details and phased execution are in [`PLAN.md`](PLAN.md).** Summary of gaps:

- Only one test currently exists (`tests/common.rs`) and it only asserts that
  `Merino::new` succeeds.
- `SOCKSReq`, `AddrType`, and `SockCommand` are private, so they cannot be unit
  tested from outside the crate.
- No end-to-end test exercises the SOCKS5 handshake or `CONNECT` relay.

**Acceptance criteria.** See `PLAN.md` phases 1–2 and 4.

**Effort.** Medium.

---

## 7. Actix-based backend

**Status: complete.** Implemented in [`PLAN.md`](PLAN.md) phases 3–4:
`SocksServer` / `SocksConnection` actors in `src/actors.rs`, the binary now
runs on an `actix::System`, and `tests/actors.rs` covers parity with the
original Tokio loop.

**Goal.** Replace the bespoke `tokio::spawn` accept loop with an
[`actix`](https://github.com/actix/actix) actor supervision tree.

**Details and phased execution are in [`PLAN.md`](PLAN.md).** Rationale:

- Per-connection actors get lifecycle hooks, mailboxes, and supervision for
  free (restart, graceful shutdown).
- Makes future `BIND`/`UDP ASSOCIATE` state machines and middleware actors
  easier to model and test.
- `actix` runs on the existing Tokio runtime, so the networking code is
  reusable rather than rewritten.

**Acceptance criteria.** See `PLAN.md` phases 3–4.

**Effort.** Medium.

**Depends on.** Tests (phases 1–2) to prove parity before the old loop is
removed.

---

## 8. `SOCKS4` / `SOCKS4a` support

**Goal.** Accept version `0x04` clients in addition to SOCKS5.

**Suggested approach.**
1. In `SOCKClient::init`, branch on the first byte before the SOCKS5 handshake.
2. Implement the SOCKS4 request format (`VN(1) CD(1) DSTPORT(2) DSTIP(4)
   USERID(variable) NULL`); `SOCKS4a` uses `0.0.0.x` plus a trailing domain.
3. Map `CD` values (connect / bind) onto the existing `SockCommand`, and reply
   with the 8-byte SOCKS4 response instead of the SOCKS5 reply.

**Acceptance criteria.**
- A SOCKS4 and a SOCKS4a client can `CONNECT` through the proxy.
- Version dispatch does not regress the SOCKS5 path.

**Effort.** Medium.

**Depends on.** None, though a shared connection state machine (actix) reduces
duplication.

---

## Suggested sequencing

1. Unit + integration tests (item 6) — de-risks everything else.
2. Actix backend (item 7) — structural foundation for stateful commands.
3. Benchmarks (item 5) — after the harness exists.
4. Reply/encoder refactor → `BIND` (item 3) → `UDP ASSOCIATE` (item 4).
5. Middleware (item 2).
6. `SOCKS4`/`SOCKS4a` (item 8).
7. `GSSAPI` (item 1) — largest and most environment-dependent.
