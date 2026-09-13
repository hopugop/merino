#![allow(dead_code)]

use merino::*;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::timeout;

pub const IO_TIMEOUT: Duration = Duration::from_secs(5);

pub struct Server {
    pub addr: SocketAddr,
    pub handle: JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

pub async fn start_merino(auth_methods: Vec<u8>, users: Vec<User>) -> Server {
    let mut merino = Merino::new(0, "127.0.0.1", auth_methods, users, None)
        .await
        .expect("failed to bind Merino");
    let addr = merino.local_addr().expect("failed to read local addr");
    let handle = tokio::spawn(async move {
        merino.serve().await;
    });
    Server { addr, handle }
}

pub async fn start_no_auth() -> Server {
    start_merino(vec![AuthMethods::NoAuth as u8], Vec::new()).await
}

pub async fn start_userpass(users: Vec<User>) -> Server {
    start_merino(
        vec![AuthMethods::NoAuth as u8, AuthMethods::UserPass as u8],
        users,
    )
    .await
}

pub async fn spawn_echo() -> SocketAddr {
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

pub async fn connect(addr: SocketAddr) -> TcpStream {
    timeout(IO_TIMEOUT, TcpStream::connect(addr))
        .await
        .expect("connect timed out")
        .expect("connect failed")
}

/// Send a SOCKS5 method-selection greeting and return the server's chosen method.
pub async fn greet(stream: &mut TcpStream, methods: &[u8]) -> u8 {
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
pub async fn userpass_auth(stream: &mut TcpStream, user: &str, pass: &str) -> u8 {
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

pub async fn read_reply(stream: &mut TcpStream) -> [u8; 10] {
    let mut resp = [0u8; 10];
    timeout(IO_TIMEOUT, stream.read_exact(&mut resp))
        .await
        .expect("reply timed out")
        .unwrap();
    assert_eq!(resp[0], 0x05, "unexpected SOCKS version in reply");
    resp
}

pub async fn request_ipv4(stream: &mut TcpStream, cmd: u8, ip: [u8; 4], port: u16) -> u8 {
    let mut buf = vec![0x05, cmd, 0x00, 0x01];
    buf.extend_from_slice(&ip);
    buf.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&buf).await.unwrap();
    read_reply(stream).await[1]
}

pub async fn request_domain(stream: &mut TcpStream, cmd: u8, domain: &str, port: u16) -> u8 {
    let mut buf = vec![0x05, cmd, 0x00, 0x03, domain.len() as u8];
    buf.extend_from_slice(domain.as_bytes());
    buf.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&buf).await.unwrap();
    read_reply(stream).await[1]
}
