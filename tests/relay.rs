mod helpers;
mod support;

use helpers::*;
use merino::*;
use std::net::SocketAddr;
use std::time::Duration;
use support::{spawn_udp_echo, udp_packet};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

#[tokio::test]
async fn bind_with_unexpected_peer_gets_rule_failure() {
    let (mut peer, mut client) = duplex_client(vec![AuthMethods::NoAuth as u8], Vec::new(), None);
    let task = tokio::spawn(async move { client.init().await });

    start_noauth(&mut peer).await;
    // Requested peer is 127.0.0.2; the actual connection will come from 127.0.0.1.
    let reply = request_on(&mut peer, 0x02, [127, 0, 0, 2], 0).await;
    let (_bnd_ip, bnd_port) = support::parse_bnd(&reply);

    let inbound = TcpStream::connect(("127.0.0.1", bnd_port)).await.unwrap();

    let err = timeout(IO_TIMEOUT, task)
        .await
        .expect("init hung")
        .expect("task panicked")
        .expect_err("mismatched BIND peer should fail");
    assert!(matches!(err, MerinoError::Socks(ResponseCode::RuleFailure)));
    drop(inbound);
}

#[tokio::test]
async fn bind_without_inbound_peer_times_out() {
    let (mut peer, mut client) = duplex_client(
        vec![AuthMethods::NoAuth as u8],
        Vec::new(),
        Some(Duration::from_millis(150)),
    );
    let task = tokio::spawn(async move { client.init().await });

    start_noauth(&mut peer).await;
    // First reply advertises the bound address, then no anticipated peer ever
    // shows up.
    request_on(&mut peer, 0x02, [0, 0, 0, 0], 0).await;

    let err = timeout(IO_TIMEOUT, task)
        .await
        .expect("init hung")
        .expect("task panicked")
        .expect_err("BIND without a peer should time out");
    assert!(matches!(err, MerinoError::Socks(ResponseCode::TtlExpired)));
}

#[tokio::test]
async fn connect_to_blackholed_destination_fails_within_budget() {
    let (mut peer, mut client) = duplex_client(
        vec![AuthMethods::NoAuth as u8],
        Vec::new(),
        Some(Duration::from_millis(300)),
    );
    let task = tokio::spawn(async move { client.init().await });

    start_noauth(&mut peer).await;
    // 192.0.2.0/24 (TEST-NET-1) is reserved and unroutable by definition.
    peer.write_all(&ipv4_request(0x01, [192, 0, 2, 1], 80))
        .await
        .unwrap();

    let err = timeout(IO_TIMEOUT, task)
        .await
        .expect("init hung")
        .expect("task panicked")
        .expect_err("connect to a reserved prefix should fail within the budget");
    assert!(
        matches!(
            err,
            MerinoError::Socks(ResponseCode::TtlExpired) | MerinoError::Io(_)
        ),
        "blackholed destinations yield TTL expired, networks that reject them yield I/O: {err:?}"
    );
}

#[tokio::test]
async fn connect_io_error_maps_to_failure() {
    let (mut peer, mut client) = duplex_client(vec![AuthMethods::NoAuth as u8], Vec::new(), None);
    let task = tokio::spawn(async move { client.init().await });

    start_noauth(&mut peer).await;
    // The limited broadcast address is rejected without SO_BROADCAST, which is
    // an I/O error rather than a refusal.
    peer.write_all(&ipv4_request(0x01, [255, 255, 255, 255], 1))
        .await
        .unwrap();

    let err = timeout(IO_TIMEOUT, task)
        .await
        .expect("init hung")
        .expect("task panicked")
        .expect_err("broadcast connect should fail");
    match err {
        MerinoError::Io(e) => {
            assert_eq!(e.kind(), std::io::ErrorKind::NetworkUnreachable);
        }
        other => panic!("expected an I/O error, got {other:?}"),
    }
}

#[tokio::test]
async fn udp_control_data_is_ignored_and_close_ends_relay() {
    let echo = spawn_udp_echo().await;
    let (mut peer, mut client) = duplex_client(vec![AuthMethods::NoAuth as u8], Vec::new(), None);
    let task = tokio::spawn(async move { client.init().await });

    let relay_port = start_noauth_and_associate(&mut peer, [0, 0, 0, 0], 0x03).await;
    let relay: SocketAddr = ([127, 0, 0, 1], relay_port).into();

    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.send_to(&udp_packet(echo, b"ping"), relay)
        .await
        .unwrap();
    let mut buf = [0u8; 128];
    let (n, _) = timeout(IO_TIMEOUT, sock.recv_from(&mut buf))
        .await
        .expect("udp relay timed out")
        .unwrap();
    assert_eq!(&buf[10..n], b"ping");

    // Data on the control channel is ignored, not fatal.
    peer.write_all(b"stray").await.unwrap();

    // The relay still functions afterwards.
    sock.send_to(&udp_packet(echo, b"post-stray"), relay)
        .await
        .unwrap();
    let (n, _) = timeout(IO_TIMEOUT, sock.recv_from(&mut buf))
        .await
        .expect("relay died on control data")
        .unwrap();
    assert_eq!(&buf[10..n], b"post-stray");

    // Closing the control connection tears the association down cleanly.
    drop(peer);
    let result = timeout(IO_TIMEOUT, task)
        .await
        .expect("init hung")
        .expect("task panicked");
    assert!(result.is_ok());
}

#[tokio::test]
async fn udp_first_datagram_from_unexpected_source_is_dropped() {
    let echo = spawn_udp_echo().await;
    let (mut peer, mut client) = duplex_client(vec![AuthMethods::NoAuth as u8], Vec::new(), None);
    let task = tokio::spawn(async move { client.init().await });

    // The client declares 127.0.0.2 as its address; loopback sockets will
    // always arrive from 127.0.0.1, so nothing may be relayed.
    let relay_port = start_noauth_and_associate(&mut peer, [127, 0, 0, 2], 0x03).await;
    let relay: SocketAddr = ([127, 0, 0, 1], relay_port).into();

    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.send_to(&udp_packet(echo, b"spoofed"), relay)
        .await
        .unwrap();

    let mut buf = [0u8; 128];
    let quiet = timeout(Duration::from_millis(300), sock.recv_from(&mut buf)).await;
    assert!(quiet.is_err(), "unexpected source must not be relayed");

    drop(peer);
    timeout(IO_TIMEOUT, task)
        .await
        .expect("init hung")
        .expect("task panicked")
        .unwrap();
}

#[tokio::test]
async fn udp_invalid_header_and_unresolvable_destination_are_dropped() {
    let echo = spawn_udp_echo().await;
    let (mut peer, mut client) = duplex_client(vec![AuthMethods::NoAuth as u8], Vec::new(), None);
    let task = tokio::spawn(async move { client.init().await });

    let relay_port = start_noauth_and_associate(&mut peer, [0, 0, 0, 0], 0x03).await;
    let relay: SocketAddr = ([127, 0, 0, 1], relay_port).into();

    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.send_to(&udp_packet(echo, b"ok"), relay).await.unwrap();
    let mut buf = [0u8; 128];
    let (n, _) = timeout(IO_TIMEOUT, sock.recv_from(&mut buf))
        .await
        .expect("udp relay timed out")
        .unwrap();
    assert_eq!(&buf[10..n], b"ok");

    // Reserved ATYP in a subsequent datagram: parse error, dropped.
    sock.send_to(&[0, 0, 0, 0x02, 0, 0, 0, 0, 0, 0], relay)
        .await
        .unwrap();

    // A domain destination that cannot resolve: dropped after resolution fails.
    let domain = b"invalid.invalid";
    let mut bogus = vec![0, 0, 0, 0x03, domain.len() as u8];
    bogus.extend_from_slice(domain);
    bogus.extend_from_slice(&12345u16.to_be_bytes());
    sock.send_to(&bogus, relay).await.unwrap();

    let quiet = timeout(Duration::from_millis(300), sock.recv_from(&mut buf)).await;
    assert!(quiet.is_err(), "malformed datagrams must not yield replies");

    drop(peer);
    timeout(IO_TIMEOUT, task)
        .await
        .expect("init hung")
        .expect("task panicked")
        .unwrap();
}
