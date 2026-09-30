use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::time::{sleep, timeout};

const BIN: &str = env!("CARGO_BIN_EXE_merino");
const START_TIMEOUT: Duration = Duration::from_secs(10);

fn write_users_file(name: &str, mode: u32) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path =
        std::env::temp_dir().join(format!("merino-cli-test-{}-{name}.csv", std::process::id()));
    std::fs::write(&path, "username,password\nalice,secret\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    path
}

fn spawn(args: &[&str], rust_log: Option<&str>) -> Child {
    let mut cmd = Command::new(BIN);
    cmd.args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    match rust_log {
        Some(filter) => cmd.env("RUST_LOG", filter),
        None => cmd.env_remove("RUST_LOG"),
    };
    cmd.spawn().expect("failed to spawn merino")
}

/// Read stderr lines until the "Listening on <addr>" announcement, returning
/// the parsed address and every line seen so far (race-free startup on
/// `--port 0`).
async fn wait_until_listening(child: &mut Child) -> (SocketAddr, Vec<String>) {
    let stderr = child.stderr.as_mut().expect("stderr not piped");
    let mut lines = BufReader::new(stderr).lines();
    let mut seen = Vec::new();
    let deadline = tokio::time::Instant::now() + START_TIMEOUT;
    loop {
        let line = timeout(
            deadline.saturating_duration_since(tokio::time::Instant::now()),
            lines.next_line(),
        )
        .await
        .expect("merino did not start listening in time")
        .expect("stderr read failed")
        .expect("stderr closed before merino started");
        seen.push(line.clone());
        if let Some(rest) = line.split("Listening on ").nth(1) {
            let addr = rest
                .split_whitespace()
                .next()
                .unwrap_or_else(|| panic!("no address in log line: {line}"));
            return (
                addr.parse()
                    .unwrap_or_else(|e| panic!("unparsable listen address {addr:?}: {e}")),
                seen,
            );
        }
    }
}

async fn greet_noauth(addr: SocketAddr) {
    let mut stream = timeout(START_TIMEOUT, tokio::net::TcpStream::connect(addr))
        .await
        .expect("connect timed out")
        .expect("connect failed");
    stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [0x05, 0x00]);
}

/// Ask a running server to stop via a signal and assert it exits cleanly.
async fn stop_with(child: &mut Child, signal: &str) {
    let pid = child
        .id()
        .expect("child should still be running")
        .to_string();
    let flag = format!("-{signal}");
    let signalled = Command::new("kill")
        .args([&flag, &pid])
        .status()
        .await
        .expect("failed to signal merino");
    assert!(signalled.success(), "kill {flag} failed");
    let status = timeout(START_TIMEOUT, child.wait())
        .await
        .expect("merino did not exit after the signal")
        .unwrap();
    assert!(status.success(), "merino should exit cleanly on {signal}");
}

async fn terminate(child: &mut Child) {
    stop_with(child, "TERM").await;
}

#[tokio::test]
async fn version_and_help_succeed() {
    let out = Command::new(BIN).arg("--version").output().await.unwrap();
    assert!(out.status.success());

    let out = Command::new(BIN).arg("--help").output().await.unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("SOCKS5"));
}

#[tokio::test]
async fn conflicting_flags_fail() {
    let out = Command::new(BIN)
        .args(["--no-auth", "--users", "u.csv"])
        .output()
        .await
        .unwrap();
    assert!(!out.status.success());

    let out = Command::new(BIN)
        .args(["--no-auth", "-v", "-q"])
        .output()
        .await
        .unwrap();
    assert!(!out.status.success());
}

#[tokio::test]
async fn noauth_binary_starts_serves_and_stops() {
    let mut child = spawn(&["--port", "0", "--no-auth", "-v"], Some("merino=info"));
    let (addr, lines) = wait_until_listening(&mut child).await;

    // RUST_LOG takes precedence over the verbosity flags, and says so.
    assert!(
        lines
            .iter()
            .any(|l| l.contains("overriden by environmental")),
        "expected RUST_LOG override warning, got: {lines:?}"
    );

    greet_noauth(addr).await;
    terminate(&mut child).await;
}

#[tokio::test]
async fn no_flags_defaults_to_noauth_and_warns() {
    let mut child = spawn(&["--port", "0"], None);
    let (addr, lines) = wait_until_listening(&mut child).await;

    assert!(
        lines.iter().any(|l| l.contains("defaulting to NOAUTH")),
        "expected NOAUTH default warning, got: {lines:?}"
    );
    greet_noauth(addr).await;
    terminate(&mut child).await;
}

#[tokio::test]
async fn ctrl_c_stops_server_cleanly() {
    let mut child = spawn(&["--port", "0", "--no-auth"], None);
    let addr = wait_until_listening(&mut child).await.0;
    greet_noauth(addr).await;
    stop_with(&mut child, "INT").await;
}

#[tokio::test]
async fn userpass_binary_authenticates_real_clients() {
    let path = write_users_file("auth", 0o600);
    let mut child = spawn(
        &["--port", "0", "--users", path.to_str().unwrap()],
        Some("merino=info"),
    );
    let addr = wait_until_listening(&mut child).await.0;

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [0x05, 0x02]);

    let mut frame = vec![0x01, 5];
    frame.extend_from_slice(b"alice");
    frame.push(6);
    frame.extend_from_slice(b"secret");
    stream.write_all(&frame).await.unwrap();
    stream.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [0x01, 0x00]);

    drop(stream);
    terminate(&mut child).await;
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn busy_port_exits_with_error() {
    let taken = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = taken.local_addr().unwrap().port().to_string();
    let mut child = spawn(&["--port", &port, "--no-auth"], None);
    let status = timeout(START_TIMEOUT, child.wait())
        .await
        .expect("merino should exit when the port is taken")
        .unwrap();
    assert!(!status.success());
}

#[tokio::test]
async fn world_readable_users_file_is_refused_at_startup() {
    let path = write_users_file("open", 0o644);
    let mut child = spawn(&["--port", "0", "--users", path.to_str().unwrap()], None);
    let status = timeout(START_TIMEOUT, child.wait())
        .await
        .expect("merino should exit on an insecure users file")
        .unwrap();
    assert!(!status.success());
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn quiet_flag_suppresses_logs() {
    let mut child = spawn(&["--port", "0", "--no-auth", "-q"], None);
    sleep(Duration::from_millis(500)).await;
    assert!(
        child.try_wait().unwrap().is_none(),
        "-q server should be running"
    );
    let mut stderr = child.stderr.take().expect("stderr not piped");
    terminate(&mut child).await;
    let mut text = String::new();
    stderr.read_to_string(&mut text).await.unwrap();
    assert!(!text.contains("Listening"), "quiet mode logged: {text}");
}
