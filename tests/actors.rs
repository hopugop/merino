mod support;

use actix::Actor;
use merino::*;
use std::net::SocketAddr;
use support::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;

async fn start_actors(auth_methods: Vec<u8>, users: Vec<User>) -> SocketAddr {
    let server = SocksServer::bind(0, "127.0.0.1", auth_methods, users, None)
        .await
        .expect("failed to bind SocksServer");
    let addr = server.local_addr();
    server.start();
    addr
}

async fn start_actors_no_auth() -> SocketAddr {
    start_actors(vec![AuthMethods::NoAuth as u8], Vec::new()).await
}

async fn start_actors_userpass(users: Vec<User>) -> SocketAddr {
    start_actors(
        vec![AuthMethods::NoAuth as u8, AuthMethods::UserPass as u8],
        users,
    )
    .await
}

#[actix::test]
async fn listens_on_every_resolved_address() {
    let server = SocksServer::bind(
        0,
        "localhost",
        vec![AuthMethods::NoAuth as u8],
        Vec::new(),
        None,
    )
    .await
    .expect("failed to bind SocksServer");
    let addrs = server.local_addrs().to_vec();
    assert!(!addrs.is_empty(), "expected at least one bound address");
    server.start();

    for addr in addrs {
        let mut stream = connect(addr).await;
        assert_eq!(greet(&mut stream, &[0x00]).await, 0x00);
    }
}

#[actix::test]
async fn noauth_negotiation_succeeds() {
    let addr = start_actors_no_auth().await;
    let mut stream = connect(addr).await;

    assert_eq!(greet(&mut stream, &[0x00]).await, 0x00);
}

#[actix::test]
async fn noauth_server_rejects_userpass_only_client() {
    let addr = start_actors_no_auth().await;
    let mut stream = connect(addr).await;

    assert_eq!(greet(&mut stream, &[0x02]).await, 0xFF);
}

#[actix::test]
async fn userpass_success_then_connect_relays_data() {
    let echo = spawn_echo().await;
    let addr = start_actors_userpass(vec![User::new("alice", "secret")]).await;
    let mut stream = connect(addr).await;

    assert_eq!(greet(&mut stream, &[0x02]).await, 0x02);
    assert_eq!(userpass_auth(&mut stream, "alice", "secret").await, 0x00);

    assert_eq!(
        request_ipv4(&mut stream, 0x01, [127, 0, 0, 1], echo.port()).await,
        0x00
    );

    stream.write_all(b"hello actors").await.unwrap();
    let mut buf = [0u8; 12];
    timeout(IO_TIMEOUT, stream.read_exact(&mut buf))
        .await
        .expect("echo timed out")
        .unwrap();
    assert_eq!(&buf, b"hello actors");
}

#[actix::test]
async fn userpass_bad_credentials_are_rejected() {
    let addr = start_actors_userpass(vec![User::new("alice", "secret")]).await;
    let mut stream = connect(addr).await;

    assert_eq!(greet(&mut stream, &[0x02]).await, 0x02);
    assert_eq!(userpass_auth(&mut stream, "alice", "wrong").await, 0x01);

    let mut buf = [0u8; 1];
    let n = timeout(IO_TIMEOUT, stream.read(&mut buf))
        .await
        .expect("expected connection to close")
        .unwrap();
    assert_eq!(n, 0);
}

#[actix::test]
async fn connect_relays_data_bidirectionally() {
    let echo = spawn_echo().await;
    let addr = start_actors_no_auth().await;
    let mut stream = connect(addr).await;

    assert_eq!(greet(&mut stream, &[0x00]).await, 0x00);
    assert_eq!(
        request_ipv4(&mut stream, 0x01, [127, 0, 0, 1], echo.port()).await,
        0x00
    );

    stream.write_all(b"actors echo").await.unwrap();
    let mut buf = [0u8; 11];
    timeout(IO_TIMEOUT, stream.read_exact(&mut buf))
        .await
        .expect("echo timed out")
        .unwrap();
    assert_eq!(&buf, b"actors echo");
}

#[actix::test]
async fn connect_by_domain_name_succeeds() {
    let echo = spawn_echo().await;
    let addr = start_actors_no_auth().await;
    let mut stream = connect(addr).await;

    assert_eq!(greet(&mut stream, &[0x00]).await, 0x00);
    assert_eq!(
        request_domain(&mut stream, 0x01, "localhost", echo.port()).await,
        0x00
    );
}

#[actix::test]
async fn connect_to_dead_port_is_refused() {
    let dead = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        addr
    };
    let addr = start_actors_no_auth().await;
    let mut stream = connect(addr).await;

    assert_eq!(greet(&mut stream, &[0x00]).await, 0x00);
    assert_eq!(
        request_ipv4(&mut stream, 0x01, [127, 0, 0, 1], dead.port()).await,
        0x05
    );
}

#[actix::test]
async fn bind_command_is_not_supported() {
    let addr = start_actors_no_auth().await;
    let mut stream = connect(addr).await;

    assert_eq!(greet(&mut stream, &[0x00]).await, 0x00);
    assert_eq!(
        request_ipv4(&mut stream, 0x02, [127, 0, 0, 1], 0).await,
        0x07
    );
}

#[actix::test]
async fn unsupported_version_is_rejected() {
    let addr = start_actors_no_auth().await;
    let mut stream = connect(addr).await;

    stream.write_all(&[0x04, 0x01, 0x00]).await.unwrap();

    let mut buf = [0u8; 1];
    let n = timeout(IO_TIMEOUT, stream.read(&mut buf))
        .await
        .expect("expected connection to close")
        .unwrap();
    assert_eq!(n, 0);
}
