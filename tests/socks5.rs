mod support;

use merino::*;
use std::net::SocketAddr;
use std::time::Duration;
use support::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::timeout;

#[tokio::test]
async fn merino_listens_on_every_resolved_address() {
    let mut merino = Merino::new(
        0,
        "localhost",
        vec![AuthMethods::NoAuth as u8],
        Vec::new(),
        None,
    )
    .await
    .expect("failed to bind Merino");
    let addrs = merino.local_addrs().expect("failed to read local addrs");
    tokio::spawn(async move {
        merino.serve().await;
    });

    assert!(!addrs.is_empty(), "expected at least one bound address");
    for addr in addrs {
        let mut stream = connect(addr).await;
        assert_eq!(greet(&mut stream, &[0x00]).await, 0x00);
    }
}

#[tokio::test]
async fn noauth_negotiation_succeeds() {
    let server = start_no_auth().await;
    let mut stream = connect(server.addr).await;

    assert_eq!(greet(&mut stream, &[0x00]).await, 0x00);
}

#[tokio::test]
async fn noauth_server_rejects_userpass_only_client() {
    let server = start_no_auth().await;
    let mut stream = connect(server.addr).await;

    assert_eq!(greet(&mut stream, &[0x02]).await, 0xFF);
}

#[tokio::test]
async fn userpass_success_then_connect_relays_data() {
    let echo = spawn_echo().await;
    let server = start_userpass(vec![User::new("alice", "secret")]).await;
    let mut stream = connect(server.addr).await;

    assert_eq!(greet(&mut stream, &[0x02]).await, 0x02);
    assert_eq!(userpass_auth(&mut stream, "alice", "secret").await, 0x00);

    let echoed = request_ipv4(&mut stream, 0x01, [127, 0, 0, 1], echo.port()).await;
    assert_eq!(echoed, 0x00);

    stream.write_all(b"hello socks").await.unwrap();
    let mut buf = [0u8; 11];
    timeout(IO_TIMEOUT, stream.read_exact(&mut buf))
        .await
        .expect("echo timed out")
        .unwrap();
    assert_eq!(&buf, b"hello socks");
}

#[tokio::test]
async fn userpass_bad_credentials_are_rejected() {
    let server = start_userpass(vec![User::new("alice", "secret")]).await;
    let mut stream = connect(server.addr).await;

    assert_eq!(greet(&mut stream, &[0x02]).await, 0x02);
    assert_eq!(userpass_auth(&mut stream, "alice", "wrong").await, 0x01);

    let mut buf = [0u8; 1];
    let n = timeout(IO_TIMEOUT, stream.read(&mut buf))
        .await
        .expect("expected connection to close")
        .unwrap();
    assert_eq!(n, 0);
}

#[tokio::test]
async fn connect_relays_data_bidirectionally() {
    let echo = spawn_echo().await;
    let server = start_no_auth().await;
    let mut stream = connect(server.addr).await;

    assert_eq!(greet(&mut stream, &[0x00]).await, 0x00);
    assert_eq!(
        request_ipv4(&mut stream, 0x01, [127, 0, 0, 1], echo.port()).await,
        0x00
    );

    for msg in [&b"first"[..], &b"second"[..]] {
        stream.write_all(msg).await.unwrap();
        let mut buf = vec![0u8; msg.len()];
        timeout(IO_TIMEOUT, stream.read_exact(&mut buf))
            .await
            .expect("echo timed out")
            .unwrap();
        assert_eq!(buf, msg);
    }
}

#[tokio::test]
async fn connect_by_domain_name_succeeds() {
    let echo = spawn_echo().await;
    let server = start_no_auth().await;
    let mut stream = connect(server.addr).await;

    assert_eq!(greet(&mut stream, &[0x00]).await, 0x00);
    assert_eq!(
        request_domain(&mut stream, 0x01, "localhost", echo.port()).await,
        0x00
    );
}

#[tokio::test]
async fn connect_to_dead_port_is_refused() {
    let dead = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        addr
    };
    let server = start_no_auth().await;
    let mut stream = connect(server.addr).await;

    assert_eq!(greet(&mut stream, &[0x00]).await, 0x00);
    assert_eq!(
        request_ipv4(&mut stream, 0x01, [127, 0, 0, 1], dead.port()).await,
        0x05
    );
}

#[tokio::test]
async fn bind_relays_an_inbound_connection() {
    let server = start_no_auth().await;
    let mut control = connect(server.addr).await;

    assert_eq!(greet(&mut control, &[0x00]).await, 0x00);

    // 0.0.0.0 would mean "any"; 127.0.0.1 restricts the expected peer.
    let first = send_request_ipv4(&mut control, 0x02, [127, 0, 0, 1], 0).await;
    assert_eq!(first[1], 0x00);
    let (bnd_ip, bnd_port) = parse_bnd(&first);

    // The anticipated peer connects to the advertised address.
    let mut peer = connect(SocketAddr::new(bnd_ip.into(), bnd_port)).await;

    // The second reply reports the connected peer.
    let second = read_reply(&mut control).await;
    assert_eq!(second[1], 0x00);

    peer.write_all(b"from peer").await.unwrap();
    let mut buf = [0u8; 9];
    timeout(IO_TIMEOUT, control.read_exact(&mut buf))
        .await
        .expect("bind relay timed out")
        .unwrap();
    assert_eq!(&buf, b"from peer");

    control.write_all(b"from client").await.unwrap();
    let mut buf = [0u8; 11];
    timeout(IO_TIMEOUT, peer.read_exact(&mut buf))
        .await
        .expect("bind relay timed out")
        .unwrap();
    assert_eq!(&buf, b"from client");
}

#[tokio::test]
async fn udp_associate_relays_datagrams() {
    let echo = spawn_udp_echo().await;
    let server = start_no_auth().await;
    let mut control = connect(server.addr).await;

    assert_eq!(greet(&mut control, &[0x00]).await, 0x00);
    let reply = send_request_ipv4(&mut control, 0x03, [0, 0, 0, 0], 0).await;
    assert_eq!(reply[1], 0x00);
    let (bnd_ip, bnd_port) = parse_bnd(&reply);

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay = SocketAddr::new(bnd_ip.into(), bnd_port);
    client
        .send_to(&udp_packet(echo, b"ping-udp"), relay)
        .await
        .unwrap();

    let mut buf = [0u8; 128];
    let (n, _) = timeout(IO_TIMEOUT, client.recv_from(&mut buf))
        .await
        .expect("udp relay timed out")
        .unwrap();
    // RSV(2) FRAG(1) ATYP(1) IPv4(4) PORT(2) = 10-byte header.
    assert_eq!(&buf[10..n], b"ping-udp");
}

#[tokio::test]
async fn udp_associate_drops_fragmented_datagrams() {
    let echo = spawn_udp_echo().await;
    let server = start_no_auth().await;
    let mut control = connect(server.addr).await;

    assert_eq!(greet(&mut control, &[0x00]).await, 0x00);
    let reply = send_request_ipv4(&mut control, 0x03, [0, 0, 0, 0], 0).await;
    let (bnd_ip, bnd_port) = parse_bnd(&reply);

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay = SocketAddr::new(bnd_ip.into(), bnd_port);
    let mut packet = udp_packet(echo, b"frag");
    packet[2] = 0x01; // FRAG != 0
    client.send_to(&packet, relay).await.unwrap();

    let mut buf = [0u8; 128];
    let relayed = timeout(Duration::from_millis(300), client.recv_from(&mut buf)).await;
    assert!(relayed.is_err(), "fragmented datagrams must be dropped");
}

#[tokio::test]
async fn unsupported_version_is_rejected() {
    let server = start_no_auth().await;
    let mut stream = connect(server.addr).await;

    stream.write_all(&[0x04, 0x01, 0x00]).await.unwrap();

    let mut buf = [0u8; 1];
    let n = timeout(IO_TIMEOUT, stream.read(&mut buf))
        .await
        .expect("expected connection to close")
        .unwrap();
    assert_eq!(n, 0);
}
