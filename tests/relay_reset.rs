// Deterministic coverage for the upstream-reset path inside the CONNECT relay.
//
// The destination reads only part of the forwarded payload and then closes.
// A close with unread data in the receive buffer makes the kernel send an RST,
// so the relay's copy fails instead of ending cleanly.
mod helpers;

use helpers::*;
use merino::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;

#[tokio::test]
async fn connect_relay_reports_upstream_failure() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let resetter = tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let mut buf = [0u8; 16];
            let _ = sock.read(&mut buf).await;
            // Leaves bytes unread: the close becomes an RST.
            drop(sock);
        }
    });

    let (mut peer, mut client) = duplex_client(vec![AuthMethods::NoAuth as u8], Vec::new(), None);
    let task = tokio::spawn(async move { client.init().await });

    start_noauth(&mut peer).await;
    let reply = request_on(&mut peer, 0x01, [127, 0, 0, 1], addr.port()).await;
    assert_eq!(reply[1], 0x00);

    // Push more than the sink drains so the write side observes the reset.
    peer.write_all(&[7u8; 2048]).await.unwrap();
    let mut sink = [0u8; 8];
    let _ = timeout(IO_TIMEOUT, peer.read(&mut sink)).await;

    let err = timeout(IO_TIMEOUT, task)
        .await
        .expect("init hung")
        .expect("task panicked")
        .expect_err("a reset destination should fail the relay");
    assert!(matches!(err, MerinoError::Io(_)), "got {err:?}");

    drop(peer);
    resetter.abort();
}
