use merino::*;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::timeout;

const IO_TIMEOUT: Duration = Duration::from_secs(5);

struct Server {
    addr: SocketAddr,
    handle: JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

async fn start_merino(auth_methods: Vec<u8>, users: Vec<User>) -> Server {
    let mut merino = Merino::new(0, "127.0.0.1", auth_methods, users, None)
        .await
        .expect("failed to bind Merino");
    let addr = merino.local_addr().expect("failed to read local addr");
    let handle = tokio::spawn(async move {
        merino.serve().await;
    });
    Server { addr, handle }
}

async fn start_no_auth() -> Server {
    start_merino(vec![AuthMethods::NoAuth as u8], Vec::new()).await
}

async fn start_userpass(users: Vec<User>) -> Server {
    start_merino(
        vec![AuthMethods::NoAuth as u8, AuthMethods::UserPass as u8],
        users,
    )
    .await
}

async fn spawn_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

async fn connect(addr: SocketAddr) -> TcpStream {
    timeout(IO_TIMEOUT, TcpStream::connect(addr))
        .await
        .expect("connect timed out")
        .expect("connect failed")
}

/// Send a SOCKS5 method-selection greeting and return the server's chosen method.
async fn greet(stream: &mut TcpStream, methods: &[u8]) -> u8 {
    let mut buf = vec![0x05, methods.len() as u8];
    buf.extend_from_slice(methods);
    stream.write_all(&buf).await.unwrap();

    let mut resp = [0u8; 2];
    timeout(IO_TIMEOUT, stream.read_exact(&mut resp))
        .await
        .expect("greeting timed out")
        .unwrap();
    assert_eq!(resp[0], 0x05, "unexpected SOCKS version in greeting reply");
    resp[1]
}

/// Perform the USERPASS sub-negotiation and return the status byte.
async fn userpass_auth(stream: &mut TcpStream, user: &str, pass: &str) -> u8 {
    let mut buf = vec![0x01, user.len() as u8];
    buf.extend_from_slice(user.as_bytes());
    buf.push(pass.len() as u8);
    buf.extend_from_slice(pass.as_bytes());
    stream.write_all(&buf).await.unwrap();

    let mut resp = [0u8; 2];
    timeout(IO_TIMEOUT, stream.read_exact(&mut resp))
        .await
        .expect("auth timed out")
        .unwrap();
    resp[1]
}

async fn read_reply(stream: &mut TcpStream) -> [u8; 10] {
    let mut resp = [0u8; 10];
    timeout(IO_TIMEOUT, stream.read_exact(&mut resp))
        .await
        .expect("reply timed out")
        .unwrap();
    assert_eq!(resp[0], 0x05, "unexpected SOCKS version in reply");
    resp
}

async fn request_ipv4(stream: &mut TcpStream, cmd: u8, ip: [u8; 4], port: u16) -> u8 {
    let mut buf = vec![0x05, cmd, 0x00, 0x01];
    buf.extend_from_slice(&ip);
    buf.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&buf).await.unwrap();
    read_reply(stream).await[1]
}

async fn request_domain(stream: &mut TcpStream, cmd: u8, domain: &str, port: u16) -> u8 {
    let mut buf = vec![0x05, cmd, 0x00, 0x03, domain.len() as u8];
    buf.extend_from_slice(domain.as_bytes());
    buf.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&buf).await.unwrap();
    read_reply(stream).await[1]
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
async fn bind_command_is_not_supported() {
    let server = start_no_auth().await;
    let mut stream = connect(server.addr).await;

    assert_eq!(greet(&mut stream, &[0x00]).await, 0x00);
    assert_eq!(
        request_ipv4(&mut stream, 0x02, [127, 0, 0, 1], 0).await,
        0x07
    );
}

#[tokio::test]
async fn udp_associate_command_is_not_supported() {
    let server = start_no_auth().await;
    let mut stream = connect(server.addr).await;

    assert_eq!(greet(&mut stream, &[0x00]).await, 0x00);
    assert_eq!(
        request_ipv4(&mut stream, 0x03, [127, 0, 0, 1], 0).await,
        0x07
    );
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
