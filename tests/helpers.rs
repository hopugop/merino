// Shared helpers for duplex-driven (in-memory stream) protocol tests.
#![allow(dead_code)]

use merino::{AuthMethods, SOCKClient, User};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::time::timeout;

pub const IO_TIMEOUT: Duration = Duration::from_secs(5);

pub fn duplex_client(
    auth_methods: Vec<u8>,
    users: Vec<User>,
    connect_timeout: Option<Duration>,
) -> (DuplexStream, SOCKClient<DuplexStream>) {
    let (peer, server) = tokio::io::duplex(4096);
    let client = SOCKClient::new(
        server,
        Arc::new(users),
        Arc::new(auth_methods),
        connect_timeout,
    );
    (peer, client)
}

pub async fn start_noauth(peer: &mut DuplexStream) {
    peer.write_all(&[0x05, 0x01, AuthMethods::NoAuth as u8])
        .await
        .unwrap();
    let mut selection = [0u8; 2];
    timeout(IO_TIMEOUT, peer.read_exact(&mut selection))
        .await
        .expect("greeting timed out")
        .unwrap();
    assert_eq!(selection, [0x05, 0x00]);
}

pub async fn request_on(peer: &mut DuplexStream, cmd: u8, ip: [u8; 4], port: u16) -> [u8; 10] {
    let mut buf = vec![0x05, cmd, 0x00, 0x01];
    buf.extend_from_slice(&ip);
    buf.extend_from_slice(&port.to_be_bytes());
    peer.write_all(&buf).await.unwrap();
    let mut reply = [0u8; 10];
    timeout(IO_TIMEOUT, peer.read_exact(&mut reply))
        .await
        .expect("reply timed out")
        .unwrap();
    assert_eq!(&reply[..3], &[0x05, 0x00, 0x00]);
    reply
}

pub async fn start_noauth_and_associate(peer: &mut DuplexStream, ip: [u8; 4], cmd: u8) -> u16 {
    start_noauth(peer).await;
    let reply = request_on(peer, cmd, ip, 0).await;
    u16::from_be_bytes([reply[8], reply[9]])
}

pub fn ipv4_request(cmd: u8, ip: [u8; 4], port: u16) -> Vec<u8> {
    let mut buf = vec![0x05, cmd, 0x00, 0x01];
    buf.extend_from_slice(&ip);
    buf.extend_from_slice(&port.to_be_bytes());
    buf
}
