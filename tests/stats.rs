mod support;

use merino::*;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use support::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

/// A raw HTTP GET against `addr`, with optional extra headers, returning the
/// whole response (the server always closes the connection).
async fn raw_get(addr: SocketAddr, path: &str, headers: &[(&str, &str)]) -> String {
    let mut stream = timeout(IO_TIMEOUT, TcpStream::connect(addr))
        .await
        .expect("stats connect timed out")
        .expect("stats connect failed");
    let mut request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n");
    for (key, value) in headers {
        request.push_str(&format!("{key}: {value}\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    response
}

/// Run one CONNECT relay through a proxy and wait for the connection guard to
/// be released.
async fn run_one_relay(server: &Server) {
    let echo = spawn_echo().await;
    let mut stream = connect(server.addr).await;
    assert_eq!(greet(&mut stream, &[0x00]).await, 0x00);

    let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    req.extend_from_slice(&echo.port().to_be_bytes());
    stream.write_all(&req).await.unwrap();
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x00, "CONNECT must succeed");

    stream.write_all(b"ping").await.unwrap();
    let mut echoed = [0u8; 4];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"ping");
    drop(stream);

    // The relay task finishes asynchronously; wait for the active guard to
    // drop rather than asserting a still-running connection count.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while server.stats.snapshot().connections.active != 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "active connections never returned to zero"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn counters_track_a_relayed_connection() {
    let server = start_no_auth().await;
    run_one_relay(&server).await;

    let snap = server.stats.snapshot();
    assert!(snap.connections.accepted_total >= 1);
    assert_eq!(snap.traffic.requests.connect, 1);
    assert_eq!(snap.traffic.bytes_client_to_target, 4, "one 'ping' payload");
    assert_eq!(snap.traffic.bytes_target_to_client, 4);
}

#[tokio::test]
async fn active_per_ip_tracks_an_open_connection() {
    let server = start_no_auth().await;
    let echo = spawn_echo().await;
    let mut stream = connect(server.addr).await;
    assert_eq!(greet(&mut stream, &[0x00]).await, 0x00);

    let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    req.extend_from_slice(&echo.port().to_be_bytes());
    stream.write_all(&req).await.unwrap();
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x00);

    // While the relay is open the per-IP view and the live client registry
    // must both show the source.
    let per_ip = server.stats.snapshot().connections.active_per_ip;
    assert!(
        per_ip
            .iter()
            .any(|entry| entry.ip.is_loopback() && entry.count >= 1),
        "expected the relay source in the per-IP view, got {per_ip:?}"
    );
    assert!(
        server
            .stats
            .clients()
            .iter()
            .any(|client| client.peer.ip().is_loopback() && client.command == Some("connect")),
        "expected a live client row with a command"
    );

    drop(stream);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while server.stats.snapshot().connections.active != 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "active connections never returned to zero"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn web_service_serves_a_running_proxy_snapshot() {
    let server = start_no_auth().await;
    run_one_relay(&server).await;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stats_addr = listener.local_addr().unwrap();
    let serve = tokio::spawn(async move {
        serve_stats(listener, server.stats.clone(), None).await;
    });

    let response = raw_get(stats_addr, "/stats", &[]).await;
    let head = response.split("\r\n\r\n").next().unwrap_or("");
    assert!(head.contains("200 OK"), "got: {head}");
    assert!(
        response.contains(r#""accepted_total":1"#),
        "got: {response}"
    );
    assert!(response.contains(r#""connect":1"#), "got: {response}");
    assert!(
        response.contains(r#""bytes_client_to_target":4"#),
        "got: {response}"
    );

    serve.abort();
}

#[tokio::test]
async fn stats_endpoints_cover_dashboard_health_clients_and_404() {
    let stats = Arc::new(Stats::new());
    stats.note_accepted();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let serve = tokio::spawn(async move {
        serve_stats(listener, stats, None).await;
    });

    let dashboard = raw_get(addr, "/", &[]).await;
    assert!(dashboard.contains("200 OK") && dashboard.contains("text/html"));
    assert!(dashboard.contains("merino"));

    let health = raw_get(addr, "/healthz", &[]).await;
    assert!(health.contains("200 OK") && health.contains("uptime_secs"));

    let clients = raw_get(addr, "/clients", &[]).await;
    assert!(clients.contains("200 OK") && clients.contains("[]"));

    let missing = raw_get(addr, "/nope", &[]).await;
    assert!(missing.contains("404 Not Found"), "got: {missing}");

    serve.abort();
}

#[tokio::test]
async fn non_get_methods_are_rejected() {
    let stats = Arc::new(Stats::new());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let serve = tokio::spawn(async move {
        serve_stats(listener, stats, None).await;
    });

    let mut stream = timeout(IO_TIMEOUT, TcpStream::connect(addr))
        .await
        .expect("connect timed out")
        .expect("connect failed");
    stream
        .write_all(b"POST /stats HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    assert!(
        response.contains("405 Method Not Allowed"),
        "got: {response}"
    );

    serve.abort();
}

#[tokio::test]
async fn stats_token_is_enforced() {
    let stats = Arc::new(Stats::new());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let serve = tokio::spawn(async move {
        serve_stats(listener, stats, Some(Arc::from("s3cret"))).await;
    });

    let denied = raw_get(addr, "/stats", &[]).await;
    assert!(denied.contains("401 Unauthorized"), "got: {denied}");

    let allowed = raw_get(addr, "/stats", &[("Authorization", "Bearer s3cret")]).await;
    assert!(allowed.contains("200 OK"), "got: {allowed}");

    serve.abort();
}

#[tokio::test]
async fn conditional_get_returns_304() {
    let stats = Arc::new(Stats::new());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let serve = tokio::spawn(async move {
        serve_stats(listener, stats, None).await;
    });

    let first = raw_get(addr, "/stats", &[]).await;
    let etag = first
        .lines()
        .find(|line| line.starts_with("ETag: "))
        .and_then(|line| line.strip_prefix("ETag: "))
        .expect("response must carry an ETag")
        .to_string();

    let fresh = raw_get(addr, "/stats", &[("If-None-Match", etag.as_str())]).await;
    assert!(fresh.contains("304 Not Modified"), "got: {fresh}");
    assert!(
        !fresh.contains("accepted_total"),
        "304 must not repeat the body"
    );

    serve.abort();
}

#[tokio::test]
async fn dns_cache_counters_flow_through_the_server() {
    let mut merino = Merino::new(
        0,
        "127.0.0.1",
        vec![AuthMethods::NoAuth as u8],
        Vec::new(),
        None,
    )
    .await
    .expect("failed to bind Merino");
    let stats = Arc::new(Stats::new());
    merino.set_stats(stats.clone());
    merino.set_dns_cache(Duration::from_secs(60), 1024);
    let addr = merino.local_addr().expect("failed to read local addr");
    tokio::spawn(async move {
        merino.serve().await;
    });

    // Two CONNECTs to the same name: the first resolves and caches, the
    // second is answered from the cache. Port 1 is privileged/closed, so the
    // reply is a refusal rather than a resolution failure.
    for _ in 0..2 {
        let mut stream = connect(addr).await;
        assert_eq!(greet(&mut stream, &[0x00]).await, 0x00);
        let mut req = vec![0x05, 0x01, 0x00, 0x03, b"localhost".len() as u8];
        req.extend_from_slice(b"localhost");
        req.extend_from_slice(&1u16.to_be_bytes());
        stream.write_all(&req).await.unwrap();
        let mut reply = [0u8; 10];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(
            reply[1], 0x05,
            "expected connection refused, not a resolution failure"
        );
        drop(stream);
    }

    let dns = stats.snapshot().dns;
    assert!(dns.enabled, "the cache must be registered in the snapshot");
    assert!(dns.inserts >= 1, "first CONNECT must insert, got {dns:?}");
    assert!(dns.hits >= 1, "second CONNECT must hit, got {dns:?}");
    assert!(dns.entries >= 1, "the name must still be cached");
}
