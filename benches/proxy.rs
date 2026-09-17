use criterion::{Criterion, criterion_group, criterion_main};
use merino::*;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;

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

async fn spawn_merino() -> SocketAddr {
    let mut merino = Merino::new(
        0,
        "127.0.0.1",
        vec![AuthMethods::NoAuth as u8],
        Vec::new(),
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

async fn handshake(proxy: SocketAddr, echo: SocketAddr) {
    let mut stream = TcpStream::connect(proxy).await.unwrap();

    stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut selected = [0u8; 2];
    stream.read_exact(&mut selected).await.unwrap();

    let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    req.extend_from_slice(&echo.port().to_be_bytes());
    stream.write_all(&req).await.unwrap();
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.unwrap();

    stream.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).await.unwrap();
}

fn bench_proxy(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let (proxy, echo) = rt.block_on(async { (spawn_merino().await, spawn_echo().await) });

    c.bench_function("noauth_connect_handshake", |b| {
        b.to_async(&rt).iter(|| handshake(proxy, echo));
    });
}

criterion_group!(benches, bench_proxy);
criterion_main!(benches);
