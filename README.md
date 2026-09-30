```
                     _
 _ __ ___   ___ _ __(_)_ __   ___
| '_ ` _ \ / _ \ '__| | '_ \ / _ \
| | | | | |  __/ |  | | | | | (_) |
|_| |_| |_|\___|_|  |_|_| |_|\___/
```

**A `SOCKS5` Proxy server written in Rust**

[![Crates.io](https://img.shields.io/crates/v/merino.svg)](https://crates.io/crates/merino)
[![stego](https://docs.rs/merino/badge.svg)](https://docs.rs/merino)
[![License](https://img.shields.io/crates/l/merino.svg)](https://github.com/hopugop/merino/blob/master/LICENSE.md)
[![dependency status](https://deps.rs/repo/github/hopugop/merino/status.svg)](https://deps.rs/repo/github/hopugop/merino)

## 🎁 Features

- Written in **100% Safe Rust**
- Multi-threaded connection handler
- Lightweight (Less than 0.6% CPU usage while surfing the web/streaming YouTube)
- Standalone binary (no system dependencies)
- `1+ Gb/second` connection speeds (**On Gigabit LAN network over ethernet. Results may vary!**)
- Tunable logging (by flags or `RUST_LOG` environmental variable)
- `SOCKS5` Compatible Authentication methods:
  - `NoAuth`
  - Username & Password
  - `GSSAPI` Coming Soon!

## 📦 Installation & 🏃 Usage

### Installation

```bash
cargo install merino
```

OR

```bash
git clone https://github.com/hopugop/merino
cd merino
cargo install --path .
```

OR

```bash
docker image pull ghcr.io/hopugop/merino:latest
```

### Usage

```bash
# Start a SOCKS5 Proxy server listening on port 1080 without authentication
merino --no-auth

# Use username/password authentication and read users from users.csv
cp users.example.csv users.csv && chmod 600 users.csv
# edit users.csv with real credentials, then start the proxy
merino --users users.csv

# Display a help menu
merino --help
```

OR

```bash
docker container run --pull=always --name=merino -p=8001:8001 ghcr.io/hopugop/merino:latest --no-auth --port=8001
```

## 🧪 Development

```bash
# Unit + integration tests (protocol parsing, NOAUTH/USERPASS, CONNECT relay)
cargo test

# End-to-end handshake/relay and per-stage parse/DNS/lookup benchmarks
cargo bench

# Lints
cargo clippy --all-targets

# Code coverage (HTML report in target/llvm-cov/html; install once with
# `cargo install cargo-llvm-cov`)
cargo llvm-cov --all-targets --html
```

See [`AGENTS/ROADMAP.md`](AGENTS/ROADMAP.md) for the detailed roadmap,
[`AGENTS/PLAN.md`](AGENTS/PLAN.md) for the implementation plan, and
[`AGENTS/HARDENING.md`](AGENTS/HARDENING.md) for the security/hardening plan
(fuzzing, property tests, Miri, ASan/TSan, supply-chain checks).

### Hardening / performance flags

Both are off by default; the defaults keep the previous behaviour exactly.

```bash
# Cap simultaneous connections per source IP (0 = unlimited)
merino --no-auth --max-connections-per-ip 64

# Cache successful DNS lookups for 60s, at most 512 names
merino --no-auth --dns-cache-ttl 60 --dns-cache-entries 512
```

The DNS cache trades DNS-rebinding fidelity for latency: `getaddrinfo` does not
expose record TTLs, so entries live for `--dns-cache-ttl` rather than the
authoritative TTL, and only successful lookups are stored.

# 🚥 Roadmap

- [x] IPV6 Support
- [ ] `SOCKS5` Authentication Methods
  - [x] `NOAUTH`
  - [x] `USERPASS`
  - [ ] `GSSAPI` Coming Soon!
- [ ] Custom plugin/middleware support
- [ ] `SOCKS5` Commands
  - [x] `CONNECT`
  - [x] `BIND`
  - [x] `ASSOCIATE`
- [x] Benchmarks & Unit tests
- [x] [Actix](https://github.com/actix-rs/actix) based backend
- [ ] `SOCKS4`/`SOCKS4a` Support
