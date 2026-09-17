mod support;

use actix::Actor;
use merino::*;
use std::sync::Arc;
use std::time::Duration;
use support::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::task::JoinSet;
use tokio::time::timeout;

fn dup_client(auth_methods: Vec<u8>, users: Vec<User>) -> (DuplexStream, SOCKClient<DuplexStream>) {
    let (peer, server) = tokio::io::duplex(64);
    let client = SOCKClient::new(server, Arc::new(users), Arc::new(auth_methods), None);
    (peer, client)
}

fn ipv4_request(cmd: u8, addr_type: u8, ip: [u8; 4], port: u16) -> Vec<u8> {
    let mut buf = vec![0x05, cmd, 0x00, addr_type];
    buf.extend_from_slice(&ip);
    buf.extend_from_slice(&port.to_be_bytes());
    buf
}

#[tokio::test]
async fn byte_at_a_time_greeting_is_reassembled() {
    let server = start_no_auth().await;
    let mut stream = connect(server.addr).await;

    for byte in [0x05u8, 0x01, 0x00] {
        stream.write_all(&[byte]).await.unwrap();
    }

    let mut resp = [0u8; 2];
    timeout(IO_TIMEOUT, stream.read_exact(&mut resp))
        .await
        .expect("greeting timed out")
        .unwrap();
    assert_eq!(resp, [0x05, 0x00]);
}

#[tokio::test]
async fn fragmented_connect_request_is_reassembled() {
    let echo = spawn_echo().await;
    let server = start_no_auth().await;
    let mut stream = connect(server.addr).await;

    assert_eq!(greet(&mut stream, &[0x00]).await, 0x00);

    for byte in ipv4_request(0x01, 0x01, [127, 0, 0, 1], echo.port()) {
        stream.write_all(&[byte]).await.unwrap();
    }

    assert_eq!(read_reply(&mut stream).await[1], 0x00);

    stream.write_all(b"fragmented").await.unwrap();
    let mut buf = [0u8; 10];
    timeout(IO_TIMEOUT, stream.read_exact(&mut buf))
        .await
        .expect("echo timed out")
        .unwrap();
    assert_eq!(&buf, b"fragmented");
}

#[tokio::test]
async fn truncated_greeting_is_answered_with_failure() {
    let server = start_no_auth().await;
    let mut stream = connect(server.addr).await;

    stream.write_all(&[0x05]).await.unwrap();
    stream.shutdown().await.unwrap();

    let reply = read_reply(&mut stream).await;
    assert_eq!(reply[1], 0x01, "truncated greeting should fail (0x01)");

    let mut buf = [0u8; 1];
    let n = timeout(IO_TIMEOUT, stream.read(&mut buf))
        .await
        .expect("expected connection to close")
        .unwrap();
    assert_eq!(n, 0);
}

#[tokio::test]
async fn invalid_command_gets_command_not_supported() {
    let server = start_no_auth().await;
    let mut stream = connect(server.addr).await;

    assert_eq!(greet(&mut stream, &[0x00]).await, 0x00);
    // 0x09 is not a defined SOCKS5 command; no address bytes follow.
    stream.write_all(&[0x05, 0x09, 0x00, 0x01]).await.unwrap();

    assert_eq!(read_reply(&mut stream).await[1], 0x07);
}

#[tokio::test]
async fn invalid_addr_type_gets_addr_type_not_supported() {
    let server = start_no_auth().await;
    let mut stream = connect(server.addr).await;

    assert_eq!(greet(&mut stream, &[0x00]).await, 0x00);
    // ATYP 0x02 is reserved.
    stream.write_all(&[0x05, 0x01, 0x00, 0x02]).await.unwrap();

    assert_eq!(read_reply(&mut stream).await[1], 0x08);
}

#[tokio::test]
async fn nonzero_reserved_byte_is_ignored() {
    let echo = spawn_echo().await;
    let server = start_no_auth().await;
    let mut stream = connect(server.addr).await;

    assert_eq!(greet(&mut stream, &[0x00]).await, 0x00);

    let mut req = ipv4_request(0x01, 0x01, [127, 0, 0, 1], echo.port());
    req[2] = 0xAB; // RSV should be 0x00 but is ignored by the parser
    stream.write_all(&req).await.unwrap();

    assert_eq!(read_reply(&mut stream).await[1], 0x00);
}

#[tokio::test]
async fn userpass_non_utf8_password_is_rejected() {
    let server = start_userpass(vec![User::new("alice", "secret")]).await;
    let mut stream = connect(server.addr).await;

    assert_eq!(greet(&mut stream, &[0x02]).await, 0x02);

    let mut frame = vec![0x01, 5];
    frame.extend_from_slice(b"alice");
    frame.push(2);
    frame.extend_from_slice(&[0xFF, 0xFE]);
    stream.write_all(&frame).await.unwrap();

    let mut resp = [0u8; 2];
    timeout(IO_TIMEOUT, stream.read_exact(&mut resp))
        .await
        .expect("auth timed out")
        .unwrap();
    assert_eq!(resp, [0x01, 0x01]);
}

#[tokio::test]
async fn many_concurrent_greetings_are_served() {
    let server = start_no_auth().await;

    let mut tasks = JoinSet::new();
    for _ in 0..32 {
        let addr = server.addr;
        tasks.spawn(async move {
            let mut stream = connect(addr).await;
            greet(&mut stream, &[0x00]).await
        });
    }

    let mut served = 0;
    while let Some(result) = tasks.join_next().await {
        assert_eq!(result.unwrap(), 0x00);
        served += 1;
    }
    assert_eq!(served, 32);
}

#[tokio::test]
async fn relay_survives_handshake_timeout() {
    let echo = spawn_echo().await;
    let (mut peer, server_stream) = tokio::io::duplex(1024);
    let mut client = SOCKClient::new(
        server_stream,
        Arc::new(Vec::new()),
        Arc::new(vec![AuthMethods::NoAuth as u8]),
        None,
    );
    client.set_handshake_timeout(Duration::from_millis(100));

    let task = tokio::spawn(async move { client.init().await });

    peer.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut selection = [0u8; 2];
    peer.read_exact(&mut selection).await.unwrap();
    assert_eq!(selection, [0x05, 0x00]);

    let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    req.extend_from_slice(&echo.port().to_be_bytes());
    peer.write_all(&req).await.unwrap();
    let mut reply = [0u8; 10];
    peer.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x00);

    // Outlive the handshake budget: the relay must stay up.
    tokio::time::sleep(Duration::from_millis(300)).await;
    peer.write_all(b"alive").await.unwrap();
    let mut buf = [0u8; 5];
    timeout(IO_TIMEOUT, peer.read_exact(&mut buf))
        .await
        .expect("relay should still be alive after the handshake timeout")
        .unwrap();
    assert_eq!(&buf, b"alive");

    drop(peer);
    let _ = task.await;
}

#[tokio::test]
async fn stalled_handshake_times_out() {
    let (_peer, mut client) = dup_client(vec![AuthMethods::NoAuth as u8], Vec::new());
    client.set_handshake_timeout(Duration::from_millis(50));

    let err = client
        .init()
        .await
        .expect_err("a stalled client should time out");
    assert!(matches!(err, MerinoError::Socks(ResponseCode::TtlExpired)));
}

#[tokio::test]
async fn nmethods_overflow_times_out() {
    let (mut peer, mut client) = dup_client(vec![AuthMethods::NoAuth as u8], Vec::new());
    client.set_handshake_timeout(Duration::from_millis(50));

    // Claims 255 methods but never sends any.
    peer.write_all(&[0x05, 0xFF]).await.unwrap();

    let err = client
        .init()
        .await
        .expect_err("a lying greeting should time out");
    assert!(matches!(err, MerinoError::Socks(ResponseCode::TtlExpired)));
}

#[tokio::test]
async fn userpass_wrong_version_is_rejected() {
    let (mut peer, mut client) = dup_client(
        vec![AuthMethods::UserPass as u8],
        vec![User::new("alice", "secret")],
    );
    client.set_handshake_timeout(Duration::from_secs(5));

    let task = tokio::spawn(async move { client.init().await });

    // Greeting offering USERPASS.
    peer.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
    let mut selection = [0u8; 2];
    peer.read_exact(&mut selection).await.unwrap();
    assert_eq!(selection, [0x05, 0x02]);

    // Sub-negotiation version 0x02 instead of the required 0x01.
    let mut frame = vec![0x02, 5];
    frame.extend_from_slice(b"alice");
    frame.push(6);
    frame.extend_from_slice(b"secret");
    peer.write_all(&frame).await.unwrap();

    let mut response = [0u8; 2];
    peer.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [0x01, 0x01]);

    let err = task.await.unwrap().expect_err("handshake should fail");
    assert!(matches!(err, MerinoError::Socks(ResponseCode::Failure)));
}

#[actix::test]
async fn actix_connection_cap_throttles_excess_clients() {
    let mut server = SocksServer::bind(
        0,
        "127.0.0.1",
        vec![AuthMethods::NoAuth as u8],
        Vec::new(),
        None,
    )
    .await
    .expect("failed to bind SocksServer");
    server.set_max_connections(1);
    let addr = server.local_addr();
    server.start();

    // Occupy the only slot: the connection stays in negotiation waiting for
    // its request, so its permit is held.
    let mut first = connect(addr).await;
    assert_eq!(greet(&mut first, &[0x00]).await, 0x00);

    // A second client connects at the TCP level but is not served.
    let mut second = connect(addr).await;
    second.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut buf = [0u8; 2];
    let throttled = timeout(Duration::from_millis(400), second.read_exact(&mut buf)).await;
    assert!(
        throttled.is_err(),
        "second client must not be served while the cap is reached"
    );

    // Freeing the slot lets the queued client through.
    drop(first);
    timeout(IO_TIMEOUT, second.read_exact(&mut buf))
        .await
        .expect("queued client should be served once a slot frees")
        .unwrap();
    assert_eq!(buf, [0x05, 0x00]);
}

#[tokio::test]
async fn merino_connection_cap_throttles_excess_clients() {
    let mut merino = Merino::new(
        0,
        "127.0.0.1",
        vec![AuthMethods::NoAuth as u8],
        Vec::new(),
        None,
    )
    .await
    .expect("failed to bind Merino");
    merino.set_max_connections(1);
    let addr = merino.local_addr().expect("failed to read local addr");
    tokio::spawn(async move {
        merino.serve().await;
    });

    let mut first = connect(addr).await;
    assert_eq!(greet(&mut first, &[0x00]).await, 0x00);

    let mut second = connect(addr).await;
    second.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut buf = [0u8; 2];
    let throttled = timeout(Duration::from_millis(400), second.read_exact(&mut buf)).await;
    assert!(
        throttled.is_err(),
        "second client must not be served while the cap is reached"
    );

    drop(first);
    timeout(IO_TIMEOUT, second.read_exact(&mut buf))
        .await
        .expect("queued client should be served once a slot frees")
        .unwrap();
    assert_eq!(buf, [0x05, 0x00]);
}
