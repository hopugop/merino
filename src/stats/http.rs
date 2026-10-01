//! Minimal, read-only HTTP/1.1 server for the statistics endpoints.
//!
//! Deliberately dependency-light: it uses only what `tokio::net` and this
//! module provide. Every connection is bounded — request head size, idle
//! timeout, and a separate connection budget — so the stats listener can
//! neither act as a slowloris hole nor starve the proxy's connection
//! semaphore.

use crate::stats::Stats;
use serde::Serialize;
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;

/// Cap on simultaneously served stats connections, independent of the proxy's
/// own connection budget.
const MAX_STATS_SOCKETS: usize = 64;

/// Idle budget for reading a complete request head.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum bytes accepted for the request line plus headers.
const MAX_HEAD: usize = 8192;

/// Serve the statistics endpoints on `listener` until it stops accepting.
///
/// When `token` is set, every request must present that bearer token or it
/// receives `401 Unauthorized`.
pub async fn serve_stats(listener: TcpListener, stats: Arc<Stats>, token: Option<Arc<str>>) {
    let budget = Arc::new(Semaphore::new(MAX_STATS_SOCKETS));
    loop {
        let permit = match budget.clone().acquire_owned().await {
            Ok(permit) => permit,
            // The semaphore is never closed; treat it as a stop signal.
            Err(_) => break,
        };
        match listener.accept().await {
            Ok((stream, _peer)) => {
                let stats = Arc::clone(&stats);
                let token = token.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let _ = timeout(REQUEST_TIMEOUT, handle_conn(stream, stats, token)).await;
                });
            }
            Err(e) => {
                warn!("Stats accept error: {}", e);
                drop(permit);
            }
        }
    }
}

/// A parsed request head (request line plus headers we care about).
struct ParsedHead<'a> {
    method: &'a str,
    path: &'a str,
    bearer: Option<&'a str>,
    if_none_match: Option<&'a str>,
}

/// Serve one stats connection to completion. The response is always
/// `Connection: close`, so no keep-alive state is kept.
async fn handle_conn(
    mut stream: TcpStream,
    stats: Arc<Stats>,
    token: Option<Arc<str>>,
) -> io::Result<()> {
    let Some(head) = read_head(&mut stream).await? else {
        return respond(
            &mut stream,
            "400 Bad Request",
            "text/plain",
            b"bad request\n",
            &[],
        )
        .await;
    };
    let Some(request) = parse_head(&head) else {
        return respond(
            &mut stream,
            "400 Bad Request",
            "text/plain",
            b"bad request\n",
            &[],
        )
        .await;
    };

    if request.method != "GET" {
        return respond(
            &mut stream,
            "405 Method Not Allowed",
            "text/plain",
            b"method not allowed\n",
            &[("Allow", "GET")],
        )
        .await;
    }

    if let Some(expected) = token.as_deref() {
        let authorized = request.bearer.is_some_and(|given| ct_eq(expected, given));
        if !authorized {
            return respond(
                &mut stream,
                "401 Unauthorized",
                "text/plain",
                b"unauthorized\n",
                &[],
            )
            .await;
        }
    }

    route(&mut stream, &request, &stats).await
}

async fn route(stream: &mut TcpStream, request: &ParsedHead<'_>, stats: &Stats) -> io::Result<()> {
    match request.path {
        "/" => {
            respond(
                stream,
                "200 OK",
                "text/html; charset=utf-8",
                DASHBOARD_HTML.as_bytes(),
                &[],
            )
            .await
        }
        "/stats" => serve_json(stream, request, &stats.snapshot()).await,
        "/clients" => serve_json(stream, request, &stats.clients()).await,
        "/healthz" => {
            let body = format!("ok uptime_secs={}\n", stats.snapshot().server.uptime_secs);
            respond(stream, "200 OK", "text/plain", body.as_bytes(), &[]).await
        }
        _ => respond(stream, "404 Not Found", "text/plain", b"not found\n", &[]).await,
    }
}

/// Serialize `value` and serve it as JSON, honouring conditional GETs with the
/// `ETag` / `If-None-Match` pair so idle dashboards cost nothing.
async fn serve_json(
    stream: &mut TcpStream,
    request: &ParsedHead<'_>,
    value: &impl Serialize,
) -> io::Result<()> {
    let body = match serde_json::to_vec(value) {
        Ok(body) => body,
        Err(_) => b"{}".to_vec(),
    };
    let etag = etag_of(&body);
    if request.if_none_match == Some(etag.as_str()) {
        return respond(
            stream,
            "304 Not Modified",
            "application/json",
            b"",
            &[("ETag", etag.as_str())],
        )
        .await;
    }
    respond(
        stream,
        "200 OK",
        "application/json",
        &body,
        &[("ETag", etag.as_str()), ("Cache-Control", "no-store")],
    )
    .await
}

/// Read the request head (request line + headers) into a bounded buffer, or
/// `None` when the peer sent nothing usable before EOF or overflowed `MAX_HEAD`.
async fn read_head(stream: &mut TcpStream) -> io::Result<Option<Vec<u8>>> {
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 512];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return if buf.is_empty() {
                Ok(None)
            } else {
                Ok(Some(buf))
            };
        }
        let Some(data) = chunk.get(..n) else {
            return Ok(None);
        };
        buf.extend_from_slice(data);
        if has_header_end(&buf) {
            return Ok(Some(buf));
        }
        if buf.len() > MAX_HEAD {
            return Ok(None);
        }
    }
}

fn has_header_end(buf: &[u8]) -> bool {
    buf.windows(4).any(|window| window == b"\r\n\r\n")
}

/// Parse `GET` method, target path and the `Authorization` / `If-None-Match`
/// headers out of a bounded request head.
fn parse_head(buf: &[u8]) -> Option<ParsedHead<'_>> {
    let head = header_bytes(buf);
    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text.lines();
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?;
    let target = parts.next()?;
    let path = target.split('?').next().unwrap_or(target);

    let mut bearer: Option<&str> = None;
    let mut if_none_match: Option<&str> = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("authorization") {
            let value = value.trim();
            if let Some((scheme, credential)) = value.split_once(' ')
                && scheme.eq_ignore_ascii_case("bearer")
            {
                bearer = Some(credential.trim());
            }
        } else if name.trim().eq_ignore_ascii_case("if-none-match") {
            if_none_match = Some(value.trim());
        }
    }

    Some(ParsedHead {
        method,
        path,
        bearer,
        if_none_match,
    })
}

/// The head up to (excluding) the `\r\n\r\n` terminator, or everything.
fn header_bytes(buf: &[u8]) -> &[u8] {
    match buf.windows(4).position(|window| window == b"\r\n\r\n") {
        Some(end) => buf.get(..end).unwrap_or(buf),
        None => buf,
    }
}

/// Compare two strings with the same work for every input length, so token
/// comparisons do not leak length information over timing.
fn ct_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    let mut diff = u8::from(a.len() != b.len());
    let width = a.len().max(b.len());
    for i in 0..width {
        diff |= a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0);
    }
    diff == 0
}

/// A content hash quoted for use as an `ETag` / `If-None-Match` pair.
fn etag_of(body: &[u8]) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    body.hash(&mut hasher);
    format!("\"{:016x}\"", hasher.finish())
}

/// Write a complete `Connection: close` response and shut the socket down.
async fn respond(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
    headers: &[(&str, &str)],
) -> io::Result<()> {
    let mut head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (name, value) in headers {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.shutdown().await
}

/// Dependency-free dashboard. It polls `/stats` and `/clients` once a second
/// and renders values as text only, so nothing the proxy relays can inject
/// markup.
const DASHBOARD_HTML: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>merino stats</title>
<style>
:root { color-scheme: dark; }
body { font: 14px/1.5 system-ui, sans-serif; margin: 0; padding: 24px; background: #111; color: #ddd; }
h1 { font-size: 20px; margin: 0 0 4px; }
.sub { color: #888; margin-bottom: 20px; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; }
.card { background: #1b1b1f; border: 1px solid #2c2c33; border-radius: 8px; padding: 14px 16px; }
.card h2 { font-size: 13px; text-transform: uppercase; letter-spacing: .08em; color: #9a9aa5; margin: 0 0 10px; }
.kv { display: grid; grid-template-columns: auto 1fr; gap: 2px 12px; }
.kv dt { color: #9a9aa5; }
.kv dd { margin: 0; text-align: right; font-variant-numeric: tabular-nums; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; padding: 4px 6px; border-bottom: 1px solid #25252b; }
th { color: #9a9aa5; font-weight: 500; }
.empty { color: #777; font-style: italic; }
</style>
</head>
<body>
<h1>&#128225; merino &mdash; live stats</h1>
<div class="sub">refreshes every second</div>
<div class="grid">
  <div class="card">
    <h2>Server</h2>
    <dl class="kv" id="server"></dl>
  </div>
  <div class="card">
    <h2>Connections</h2>
    <dl class="kv" id="connections"></dl>
  </div>
  <div class="card">
    <h2>DNS cache</h2>
    <dl class="kv" id="dns"></dl>
  </div>
  <div class="card">
    <h2>Traffic</h2>
    <dl class="kv" id="traffic"></dl>
  </div>
  <div class="card">
    <h2>Errors</h2>
    <dl class="kv" id="errors"></dl>
  </div>
  <div class="card">
    <h2>Active per IP</h2>
    <table id="per-ip"><tbody></tbody></table>
  </div>
  <div class="card">
    <h2>Cached names</h2>
    <table id="names"><tbody></tbody></table>
  </div>
  <div class="card" style="grid-column: 1 / -1;">
    <h2>Clients</h2>
    <table id="clients"><tbody></tbody></table>
  </div>
</div>
<script>
function fmt(n, d = 0) {
  const units = ["", "k", "M", "G", "T"];
  let i = 0;
  while (n >= 1000 && i < units.length - 1) { n /= 1000; i++; }
  return n.toFixed(i === 0 ? d : 1) + units[i];
}
function setKV(id, pairs) {
  const dl = document.getElementById(id);
  dl.textContent = "";
  for (const [k, v] of pairs) {
    const dt = document.createElement("dt"); dt.textContent = k + ":";
    const dd = document.createElement("dd"); dd.textContent = String(v);
    dl.append(dt, dd);
  }
}
function setRows(id, headers, rows) {
  const tbody = document.querySelector("#" + id + " tbody");
  tbody.textContent = "";
  if (!rows.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.className = "empty";
    td.colSpan = headers.length;
    td.textContent = "none";
    tr.append(td); tbody.append(tr);
    return;
  }
  for (const row of rows) {
    const tr = document.createElement("tr");
    for (const cell of row) {
      const td = document.createElement("td");
      td.textContent = String(cell);
      tr.append(td);
    }
    tbody.append(tr);
  }
}
async function tick() {
  try {
    const res = await fetch("/stats", { cache: "no-store" });
    const s = await res.json();
    setKV("server", [
      ["version", s.server.version],
      ["uptime", fmt(s.server.uptime_secs) + "s"],
      ["listeners", s.server.listeners.join(", ") || "—"],
    ]);
    setKV("connections", [
      ["active", s.connections.active],
      ["accepted total", s.connections.accepted_total],
      ["refused (per-IP)", s.connections.refused_per_ip_total],
      ["handshake timeouts", s.connections.handshake_timeouts],
      ["auth failures", s.connections.auth_failures],
      ["disconnects", s.connections.disconnects],
    ]);
    setKV("dns", [
      ["enabled", s.dns.enabled],
      ["entries", s.dns.entries + " / " + s.dns.max_entries],
      ["ttl", s.dns.ttl_secs + "s"],
      ["hits", s.dns.hits],
      ["misses", s.dns.misses],
      ["inserts", s.dns.inserts],
      ["evictions", s.dns.evictions],
      ["expired", s.dns.expired_dropped],
    ]);
    setKV("traffic", [
      ["client → target", fmt(s.traffic.bytes_client_to_target) + " B"],
      ["target → client", fmt(s.traffic.bytes_target_to_client) + " B"],
      ["udp datagrams", s.traffic.udp_datagrams],
      ["CONNECT", s.traffic.requests.connect],
      ["BIND", s.traffic.requests.bind],
      ["UDP ASSOCIATE", s.traffic.requests.udp_associate],
    ]);
    setKV("errors", s.errors.length
      ? s.errors.map(e => [e.name, e.count])
      : [["none", 0]]);
    setRows("per-ip", 2, s.connections.active_per_ip.map(r => [r.ip, r.count]));
    setRows("names", 2, s.dns.names.map(n => [n.name, n.expires_in_secs + "s"]));

    const c = await (await fetch("/clients", { cache: "no-store" })).json();
    setRows("clients", 7, c.map(cl => [
      cl.id, cl.peer, cl.state, cl.command || "—",
      fmt(cl.bytes_client_to_target) + "B", fmt(cl.bytes_target_to_client) + "B",
      cl.elapsed_secs + "s",
    ]));
  } catch (e) {
    setKV("errors", [["dashboard error", String(e.message || e)]]);
  }
}
tick();
setInterval(tick, 1000);
</script>
</body>
</html>
"##;
