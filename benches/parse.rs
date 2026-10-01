//! Pure, socket-free benchmarks for the protocol parsers plus the `USERPASS`
//! credential lookup.
//!
//! [`proxy.rs`](proxy.rs) measures the whole loopback `NOAUTH` handshake and
//! relay; these are the per-phase numbers that make a regression in an
//! individual stage visible.

use criterion::{Criterion, criterion_group, criterion_main};
use merino::*;
use std::hint::black_box;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::runtime::Runtime;

/// Longest name the wire format allows, so the parsers are measured on the
/// worst-case frame a client can send.
const MAX_DOMAIN: u8 = 255;

fn worst_case_domain() -> Vec<u8> {
    vec![b'a'; usize::from(MAX_DOMAIN)]
}

fn greeting_frame() -> Vec<u8> {
    let mut frame = vec![0x05, 0x03];
    frame.extend_from_slice(&[AuthMethods::NoAuth as u8, AuthMethods::UserPass as u8, 0x7f]);
    frame
}

fn userpass_frame() -> Vec<u8> {
    let mut frame = vec![0x01, MAX_DOMAIN];
    frame.extend_from_slice(&worst_case_domain());
    frame.push(MAX_DOMAIN);
    frame.extend_from_slice(&worst_case_domain());
    frame
}

fn request_frame() -> Vec<u8> {
    let mut frame = vec![
        0x05,
        SockCommand::Connect as u8,
        0x00,
        AddrType::Domain as u8,
        MAX_DOMAIN,
    ];
    frame.extend_from_slice(&worst_case_domain());
    frame.extend_from_slice(&8080u16.to_be_bytes());
    frame
}

fn udp_frame() -> Vec<u8> {
    let mut frame = vec![0x00, 0x00, 0x00, AddrType::Domain as u8, MAX_DOMAIN];
    frame.extend_from_slice(&worst_case_domain());
    frame.extend_from_slice(&53u16.to_be_bytes());
    frame
}

fn bench_parsers(c: &mut Criterion) {
    let greeting = greeting_frame();
    let userpass = userpass_frame();
    let request = request_frame();
    let udp = udp_frame();
    let domain = worst_case_domain();

    let mut group = c.benchmark_group("parse");

    group.bench_function("greeting", |b| {
        b.iter(|| parse_greeting(black_box(&greeting)).unwrap())
    });
    group.bench_function("userpass", |b| {
        b.iter(|| parse_userpass(black_box(&userpass)).unwrap())
    });
    group.bench_function("request_ipv4", |b| {
        b.iter(|| {
            parse_request(black_box(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 31, 144])).unwrap()
        })
    });
    group.bench_function("request_domain_255", |b| {
        b.iter(|| parse_request(black_box(&request)).unwrap())
    });
    group.bench_function("udp_header_domain_255", |b| {
        b.iter(|| parse_udp_header(black_box(&udp)).unwrap())
    });
    group.bench_function("pretty_print_addr_domain_255", |b| {
        b.iter(|| pretty_print_addr(black_box(&AddrType::Domain), black_box(&domain)))
    });

    group.finish();
}

async fn spawn_userpass_server(users: Vec<User>) -> SocketAddr {
    let mut merino = Merino::new(
        0,
        "127.0.0.1",
        vec![AuthMethods::UserPass as u8],
        users,
        None,
    )
    .await
    .unwrap();
    let addr = merino.local_addr().unwrap();
    tokio::spawn(async move {
        merino.serve().await;
    });
    addr
}

async fn userpass_auth(proxy: SocketAddr, username: &str, password: &str) {
    let mut stream = TcpStream::connect(proxy).await.unwrap();

    stream.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
    let mut selected = [0u8; 2];
    stream.read_exact(&mut selected).await.unwrap();

    let mut frame = vec![0x01, username.len() as u8];
    frame.extend_from_slice(username.as_bytes());
    frame.push(password.len() as u8);
    frame.extend_from_slice(password.as_bytes());
    stream.write_all(&frame).await.unwrap();

    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [0x01, 0x00]);
}

/// The `authed` scan inspects every configured user, so moving from one entry
/// to many is what exposes the cost of the lookup itself.
fn bench_userpass_lookup(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let target = format!("user{}", 10_000 - 1);

    let small =
        rt.block_on(async { spawn_userpass_server(vec![User::new(&target, "secret")]).await });
    let large = rt.block_on(async {
        let users = (0..10_000)
            .map(|i| User::new(format!("user{i}"), "secret"))
            .collect();
        spawn_userpass_server(users).await
    });

    let mut group = c.benchmark_group("userpass_lookup");
    group.sample_size(50);

    group.bench_function("1_user", |b| {
        b.to_async(&rt)
            .iter(|| userpass_auth(small, &target, "secret"));
    });
    group.bench_function("10k_users", |b| {
        b.to_async(&rt)
            .iter(|| userpass_auth(large, &target, "secret"));
    });

    group.finish();
}

/// What a `Domain` CONNECT pays before it can even dial: one `getaddrinfo`
/// round per request. Kept to `localhost` so the bench is offline and
/// deterministic.
fn bench_dns_lookup(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("dns");
    group.sample_size(50);
    group.bench_function("lookup_host_localhost", |b| {
        b.to_async(&rt).iter(|| async {
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host("localhost:80")
                .await
                .expect("localhost must resolve")
                .collect();
            assert!(!addrs.is_empty());
        });
    });
    group.finish();
}

/// Cost of the always-on connection accounting and of building a snapshot —
/// the two operations the stats web service adds. The relay itself already
/// runs with these counters enabled (see [`proxy.rs`](proxy.rs)), so this
/// isolates the per-connection and read-path costs.
fn bench_stats_core(c: &mut Criterion) {
    let stats = std::sync::Arc::new(Stats::new());
    let peer: SocketAddr = "127.0.0.1:9".parse().unwrap();

    let mut group = c.benchmark_group("stats");
    group.bench_function("begin_client_drop", |b| {
        b.iter(|| {
            let guard = stats.begin_client(peer, None);
            drop(guard);
        });
    });
    group.bench_function("active_guard_with_registry", |b| {
        b.iter(|| {
            let guard = stats.begin_client(peer, None);
            stats.note_request(Some(guard.id()), SockCommand::Connect);
            let counters = guard.relay_counters();
            counters.0.store(8192, std::sync::atomic::Ordering::Relaxed);
            counters.1.store(8192, std::sync::atomic::Ordering::Relaxed);
            drop(guard);
        });
    });
    group.bench_function("snapshot", |b| {
        b.iter(|| black_box(stats.snapshot()));
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_parsers,
    bench_userpass_lookup,
    bench_dns_lookup,
    bench_stats_core
);
criterion_main!(benches);
