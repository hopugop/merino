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
/// markup. All assets are inline; no external network requests are made.
const DASHBOARD_HTML: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>merino live dashboard</title>
<style>
:root { color-scheme: dark; --accent: #4fc3f7; }
* { box-sizing: border-box; }
body { font: 14px/1.5 system-ui, sans-serif; margin: 0; padding: 20px; background: #0f1115; color: #dfe3ea; }
header { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; margin-bottom: 16px; }
h1 { font-size: 20px; margin: 0; }
.dot { width: 10px; height: 10px; border-radius: 50%; background: #2e7d32; animation: pulse 2s infinite; }
.dot.off { background: #b71c1c; animation: none; }
@keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: .35; } }
.sub { color: #8a93a3; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 14px; }
.card { background: #161a21; border: 1px solid #242b36; border-radius: 10px; padding: 14px 16px; }
.card h2 { font-size: 12px; text-transform: uppercase; letter-spacing: .1em; color: #7d8797; margin: 0 0 10px; }
.kv { display: grid; grid-template-columns: auto 1fr; gap: 2px 14px; margin: 0; }
.kv dt { color: #8a93a3; }
.kv dd { margin: 0; text-align: right; font-variant-numeric: tabular-nums; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; padding: 3px 6px; border-bottom: 1px solid #1f2630; }
th { color: #8a93a3; font-weight: 500; }
.empty { color: #6b7280; font-style: italic; }
canvas { width: 100%; height: 64px; display: block; }
.spark-meta { display: flex; justify-content: space-between; color: #8a93a3; font-size: 12px; margin-top: 6px; }
</style>
</head>
<body>
<header>
  <span id="dot" class="dot"></span>
  <h1>&#128225; merino &mdash; live dashboard</h1>
  <div class="sub" id="meta">connecting&hellip;</div>
</header>
<div class="grid">
  <div class="card"><h2>Server</h2><dl class="kv" id="server"></dl></div>
  <div class="card"><h2>Connections</h2><dl class="kv" id="connections"></dl></div>
  <div class="card"><h2>DNS cache</h2><dl class="kv" id="dns"></dl></div>
  <div class="card"><h2>Traffic</h2><dl class="kv" id="traffic"></dl></div>
  <div class="card"><h2>Active connections</h2><canvas id="spark" width="600" height="64"></canvas><div class="spark-meta"><span id="spark-min">min 0</span><span id="spark-max">max 0</span></div></div>
  <div class="card"><h2>Errors</h2><dl class="kv" id="errors"></dl></div>
  <div class="card"><h2>Active per IP</h2><table id="per-ip"><tbody></tbody></table></div>
  <div class="card"><h2>Cached names</h2><table id="names"><tbody></tbody></table></div>
  <div class="card" style="grid-column: 1 / -1;"><h2>Clients</h2><table id="clients"><tbody></tbody></table></div>
</div>
<script>
"use strict";
var SPARK_LEN = 60;
var activeHistory = new Array(SPARK_LEN).fill(0);
var last = { up: 0, down: 0, t: 0 };

function fmtBytes(n) {
  var units = ["B", "kB", "MB", "GB", "TB"];
  var i = 0;
  while (n >= 1000 && i < units.length - 1) { n /= 1000; i++; }
  var v;
  if (i < 2) { v = String(Math.round(n)); }
  else if (n < 10) { v = n.toFixed(2); }
  else if (n < 100) { v = n.toFixed(1); }
  else { v = String(Math.round(n)); }
  return v + " " + units[i];
}
function fmtRate(bps) {
  if (bps < 1) { return "0 B/s"; }
  return fmtBytes(bps) + "/s";
}
function fmtUptime(s) {
  var d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600),
      m = Math.floor((s % 3600) / 60), sec = s % 60;
  var parts = [];
  if (d) { parts.push(d + "d"); }
  if (h) { parts.push(h + "h"); }
  if (m) { parts.push(m + "m"); }
  parts.push(sec + "s");
  return parts.join(" ");
}
function setKV(id, pairs) {
  var dl = document.getElementById(id);
  dl.textContent = "";
  for (var i = 0; i < pairs.length; i++) {
    var dt = document.createElement("dt"); dt.textContent = pairs[i][0] + ":";
    var dd = document.createElement("dd"); dd.textContent = String(pairs[i][1]);
    dl.append(dt, dd);
  }
}
function setRows(id, cols, rows) {
  var tbody = document.querySelector("#" + id + " tbody");
  tbody.textContent = "";
  if (!rows.length) {
    var tr = document.createElement("tr");
    var td = document.createElement("td");
    td.className = "empty";
    td.colSpan = cols;
    td.textContent = "none";
    tr.append(td); tbody.append(tr);
    return;
  }
  for (var r = 0; r < rows.length; r++) {
    var rowTr = document.createElement("tr");
    for (var cIdx = 0; cIdx < rows[r].length; cIdx++) {
      var cellTd = document.createElement("td");
      cellTd.textContent = String(rows[r][cIdx]);
      rowTr.append(cellTd);
    }
    tbody.append(rowTr);
  }
}
function drawSpark() {
  var canvas = document.getElementById("spark");
  if (!canvas.getContext) { return; }
  var ctx = canvas.getContext("2d");
  var w = canvas.width, h = canvas.height;
  ctx.clearRect(0, 0, w, h);
  var lo = activeHistory[0], hi = activeHistory[0];
  for (var i = 1; i < activeHistory.length; i++) {
    if (activeHistory[i] < lo) { lo = activeHistory[i]; }
    if (activeHistory[i] > hi) { hi = activeHistory[i]; }
  }
  var pad = (hi - lo) * 0.15;
  var ymin = Math.max(0, lo - pad);
  var ymax = hi + pad;
  if (ymax - ymin < 0.0001) { ymax = ymin + 1; }
  var span = ymax - ymin;
  var colors = window.getComputedStyle(document.body);
  var line = colors.getPropertyValue("--accent").trim() || "#4fc3f7";
  ctx.beginPath();
  for (var j = 0; j < activeHistory.length; j++) {
    var x = (j / (SPARK_LEN - 1)) * w;
    var y = h - 2 - ((activeHistory[j] - ymin) / span) * (h - 4);
    if (j === 0) { ctx.moveTo(x, y); } else { ctx.lineTo(x, y); }
  }
  ctx.strokeStyle = line;
  ctx.lineWidth = 1.5;
  ctx.stroke();
  ctx.lineTo(w, h); ctx.lineTo(0, h); ctx.closePath();
  ctx.fillStyle = "rgba(79, 195, 247, 0.12)";
  ctx.fill();
  document.getElementById("spark-min").textContent = "min " + lo;
  document.getElementById("spark-max").textContent = "max " + hi;
}
async function tick() {
  var now = Date.now();
  var s, clients;
  try {
    var responses = await Promise.all([
      fetch("/stats", { cache: "no-store" }).then(function (r) { return r.json(); }),
      fetch("/clients", { cache: "no-store" }).then(function (r) { return r.json(); })
    ]);
    s = responses[0]; clients = responses[1];
    document.getElementById("dot").className = "dot";
  } catch (e) {
    document.getElementById("dot").className = "dot off";
    return;
  }

  activeHistory.push(s.connections.active);
  activeHistory.shift();
  drawSpark();

  var rateUp = 0, rateDown = 0, delta = 0;
  if (last.t) {
    var dt = Math.max(1, (now - last.t) / 1000);
    rateUp = Math.max(0, s.traffic.bytes_client_to_target - last.up) / dt;
    rateDown = Math.max(0, s.traffic.bytes_target_to_client - last.down) / dt;
    delta = Math.round((now - last.t) / 1000);
  }
  last = { up: s.traffic.bytes_client_to_target, down: s.traffic.bytes_target_to_client, t: now };

  document.getElementById("meta").textContent =
    "uptime " + fmtUptime(s.server.uptime_secs) +
    " \u00b7 updated " + delta + "s ago" +
    " \u00b7 v" + s.server.version;

  setKV("server", [
    ["listeners", s.server.listeners.join(", ") || "—"],
    ["started", new Date(s.server.started_at_unix * 1000).toISOString().replace("T", " ").slice(0, 19) + " UTC"],
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
    ["client → target", fmtBytes(s.traffic.bytes_client_to_target)],
    ["target → client", fmtBytes(s.traffic.bytes_target_to_client)],
    ["rate up", fmtRate(rateUp)],
    ["rate down", fmtRate(rateDown)],
    ["udp datagrams", s.traffic.udp_datagrams],
    ["CONNECT", s.traffic.requests.connect],
    ["BIND", s.traffic.requests.bind],
    ["UDP ASSOCIATE", s.traffic.requests.udp_associate],
  ]);
  setKV("errors", s.errors.length
    ? s.errors.map(function (e) { return [e.name, e.count]; })
    : [["none", 0]]);
  setRows("per-ip", 2, s.connections.active_per_ip.map(function (r) { return [r.ip, r.count]; }));
  setRows("names", 2, s.dns.names.map(function (n) { return [n.name, n.expires_in_secs + "s"]; }));
  setRows("clients", 7, clients.map(function (cl) {
    return [
      cl.id, cl.peer, cl.state, cl.command || "—",
      fmtBytes(cl.bytes_client_to_target), fmtBytes(cl.bytes_target_to_client),
      cl.elapsed_secs + "s"
    ];
  }));
}
tick();
setInterval(tick, 1000);
</script>
</body>
</html>
"##;
