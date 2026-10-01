//! Always-on statistics core shared by the proxy and the optional embedded
//! web service ([`http`]).
//!
//! Counting is deliberately cheap — atomic increments plus two
//! `Mutex`-guarded map touches per connection — so it is always on. The HTTP
//! listener that exposes the numbers is opt-in via `--stats-addr` (see
//! [`serve_stats`]); without it nothing changes for the operator.

pub mod http;
pub use http::serve_stats;

use crate::SockCommand;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// How many entries the snapshot keeps for the per-IP and DNS-name views.
pub(crate) const TOP_LIST_LEN: usize = 20;

/// One active proxied connection, registered in [`Stats`] and freed on drop.
///
/// Mirrors the RAII slot discipline of `IpSlot`: created once per `run_client`
/// call, every exit path (success, error, panic unwind) drops the guard and
/// releases the per-IP + active-count + client-registry state exactly once.
pub struct ActiveGuard {
    stats: Arc<Stats>,
    ip: IpAddr,
    pub(crate) id: u64,
}

impl ActiveGuard {
    /// Registry id of this connection, used to update its stats row.
    pub fn id(&self) -> u64 {
        self.id
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.stats.active.fetch_sub(1, Ordering::Relaxed);
        let mut per_ip = lock(&self.stats.active_per_ip);
        if let Some(count) = per_ip.get_mut(&self.ip) {
            if *count <= 1 {
                per_ip.remove(&self.ip);
            } else {
                *count -= 1;
            }
        }
        drop(per_ip);
        lock(&self.stats.clients).remove(&self.id);
    }
}

/// Per-connection row kept in the live client registry.
struct ClientRecord {
    peer: SocketAddr,
    local: Option<SocketAddr>,
    started_at: Instant,
    command: Option<&'static str>,
    bytes_up: u64,
    bytes_down: u64,
}

/// Aggregate, always-on counters shared by every accept loop and connection.
pub struct Stats {
    started_at: Instant,
    started_at_unix: u64,
    listeners: Mutex<Vec<String>>,
    // Connections.
    active: AtomicUsize,
    active_per_ip: Mutex<HashMap<IpAddr, u64>>,
    accepted_total: AtomicU64,
    refused_per_ip_total: AtomicU64,
    handshake_timeouts: AtomicU64,
    auth_failures: AtomicU64,
    disconnects: AtomicU64,
    // Requests and traffic.
    requests_connect: AtomicU64,
    requests_bind: AtomicU64,
    requests_udp_associate: AtomicU64,
    udp_datagrams: AtomicU64,
    bytes_client_to_target: AtomicU64,
    bytes_target_to_client: AtomicU64,
    // Error replies sent to clients, keyed by `ResponseCode` byte.
    errors_by_code: Mutex<HashMap<u8, u64>>,
    // DNS cache, registered when `--dns-cache-ttl` enables it.
    dns: Mutex<Option<Arc<crate::DnsCache>>>,
    // Live per-connection registry, keyed by connection id.
    clients: Mutex<HashMap<u64, ClientRecord>>,
    next_client_id: AtomicU64,
}

impl Stats {
    pub fn new() -> Self {
        let started_at = Instant::now();
        let started_at_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or(0);
        Self {
            started_at,
            started_at_unix,
            listeners: Mutex::new(Vec::new()),
            active: AtomicUsize::new(0),
            active_per_ip: Mutex::new(HashMap::new()),
            accepted_total: AtomicU64::new(0),
            refused_per_ip_total: AtomicU64::new(0),
            handshake_timeouts: AtomicU64::new(0),
            auth_failures: AtomicU64::new(0),
            disconnects: AtomicU64::new(0),
            requests_connect: AtomicU64::new(0),
            requests_bind: AtomicU64::new(0),
            requests_udp_associate: AtomicU64::new(0),
            udp_datagrams: AtomicU64::new(0),
            bytes_client_to_target: AtomicU64::new(0),
            bytes_target_to_client: AtomicU64::new(0),
            errors_by_code: Mutex::new(HashMap::new()),
            dns: Mutex::new(None),
            clients: Mutex::new(HashMap::new()),
            next_client_id: AtomicU64::new(0),
        }
    }

    /// Record the addresses the proxy bound its SOCKS listeners on.
    pub fn note_listeners(&self, addrs: &[SocketAddr]) {
        let mut listeners = lock(&self.listeners);
        for addr in addrs {
            listeners.push(addr.to_string());
        }
    }

    /// Register the DNS cache so its counters appear in snapshots.
    pub(crate) fn register_dns(&self, cache: Arc<crate::DnsCache>) {
        *lock(&self.dns) = Some(cache);
    }

    pub fn note_accepted(&self) {
        self.accepted_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn note_refused_per_ip(&self) {
        self.refused_per_ip_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn note_handshake_timeout(&self) {
        self.handshake_timeouts.fetch_add(1, Ordering::Relaxed);
    }

    pub fn note_auth_failure(&self) {
        self.auth_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn note_disconnect(&self) {
        self.disconnects.fetch_add(1, Ordering::Relaxed);
    }

    /// Count one request of `command`. When `client_id` is set, the live
    /// client row is tagged with the command too.
    pub fn note_request(&self, client_id: Option<u64>, command: SockCommand) {
        let counter = match command {
            SockCommand::Connect => &self.requests_connect,
            SockCommand::Bind => &self.requests_bind,
            SockCommand::UdpAssosiate => &self.requests_udp_associate,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        let label = match command {
            SockCommand::Connect => "connect",
            SockCommand::Bind => "bind",
            SockCommand::UdpAssosiate => "udp_associate",
        };
        if let Some(id) = client_id {
            self.update_client(id, |record| record.command = Some(label));
        }
    }

    /// Add relayed bytes (client→target, target→client) and to the live row.
    pub fn note_relay(&self, client_id: Option<u64>, up: u64, down: u64) {
        self.bytes_client_to_target.fetch_add(up, Ordering::Relaxed);
        self.bytes_target_to_client
            .fetch_add(down, Ordering::Relaxed);
        if let Some(id) = client_id {
            self.update_client(id, |record| {
                record.bytes_up = record.bytes_up.saturating_add(up);
                record.bytes_down = record.bytes_down.saturating_add(down);
            });
        }
    }

    /// Count one UDP datagram forwarded from a client.
    pub fn note_udp_datagram(&self, bytes: u64) {
        self.udp_datagrams.fetch_add(1, Ordering::Relaxed);
        self.bytes_client_to_target
            .fetch_add(bytes, Ordering::Relaxed);
    }

    /// Count one UDP datagram relayed back to a client.
    pub fn note_udp_reply(&self, bytes: u64) {
        self.bytes_target_to_client
            .fetch_add(bytes, Ordering::Relaxed);
    }

    /// Count a SOCKS error reply sent to a client, keyed by its code byte.
    pub fn note_error(&self, code: u8) {
        let mut errors = lock(&self.errors_by_code);
        *errors.entry(code).or_insert(0) += 1;
    }

    /// Register a client connection and return a guard that frees it on drop.
    pub fn begin_client(
        self: &Arc<Self>,
        peer: SocketAddr,
        local: Option<SocketAddr>,
    ) -> ActiveGuard {
        let id = self.next_client_id.fetch_add(1, Ordering::Relaxed);
        lock(&self.clients).insert(
            id,
            ClientRecord {
                peer,
                local,
                started_at: Instant::now(),
                command: None,
                bytes_up: 0,
                bytes_down: 0,
            },
        );
        self.active.fetch_add(1, Ordering::Relaxed);
        let mut per_ip = lock(&self.active_per_ip);
        *per_ip.entry(peer.ip()).or_insert(0) += 1;
        ActiveGuard {
            stats: Arc::clone(self),
            ip: peer.ip(),
            id,
        }
    }

    /// Read-only view of the live per-connection registry.
    pub fn clients(&self) -> Vec<ClientView> {
        let now = Instant::now();
        let mut out: Vec<ClientView> = lock(&self.clients)
            .iter()
            .map(|(id, record)| ClientView {
                id: *id,
                peer: record.peer,
                local: record.local,
                elapsed_secs: now.duration_since(record.started_at).as_secs(),
                state: if record.command.is_some() {
                    "relaying"
                } else {
                    "negotiating"
                },
                command: record.command,
                bytes_client_to_target: record.bytes_up,
                bytes_target_to_client: record.bytes_down,
            })
            .collect();
        out.sort_by_key(|client| client.id);
        out
    }

    /// Build a point-in-time snapshot of every counter.
    pub fn snapshot(&self) -> Snapshot {
        let now = Instant::now();
        let mut per_ip: Vec<IpCount> = lock(&self.active_per_ip)
            .iter()
            .map(|(ip, count)| IpCount {
                ip: *ip,
                count: *count,
            })
            .collect();
        per_ip.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.ip.cmp(&b.ip)));
        per_ip.truncate(TOP_LIST_LEN);

        Snapshot {
            server: ServerSnapshot {
                version: env!("CARGO_PKG_VERSION"),
                uptime_secs: now.duration_since(self.started_at).as_secs(),
                started_at_unix: self.started_at_unix,
                listeners: lock(&self.listeners).clone(),
            },
            connections: ConnectionsSnapshot {
                active: self.active.load(Ordering::Relaxed),
                active_per_ip: per_ip,
                accepted_total: self.accepted_total.load(Ordering::Relaxed),
                refused_per_ip_total: self.refused_per_ip_total.load(Ordering::Relaxed),
                handshake_timeouts: self.handshake_timeouts.load(Ordering::Relaxed),
                auth_failures: self.auth_failures.load(Ordering::Relaxed),
                disconnects: self.disconnects.load(Ordering::Relaxed),
            },
            dns: self.dns_snapshot(),
            traffic: TrafficSnapshot {
                bytes_client_to_target: self.bytes_client_to_target.load(Ordering::Relaxed),
                bytes_target_to_client: self.bytes_target_to_client.load(Ordering::Relaxed),
                udp_datagrams: self.udp_datagrams.load(Ordering::Relaxed),
                requests: RequestsSnapshot {
                    connect: self.requests_connect.load(Ordering::Relaxed),
                    bind: self.requests_bind.load(Ordering::Relaxed),
                    udp_associate: self.requests_udp_associate.load(Ordering::Relaxed),
                },
            },
            errors: self.errors_snapshot(),
        }
    }

    fn update_client(&self, id: u64, update: impl FnOnce(&mut ClientRecord)) {
        if let Some(record) = lock(&self.clients).get_mut(&id) {
            update(record);
        }
    }

    fn dns_snapshot(&self) -> DnsSnapshot {
        let cache = match lock(&self.dns).as_ref() {
            Some(cache) => Arc::clone(cache),
            None => return DnsSnapshot::disabled(),
        };
        cache.snapshot()
    }

    fn errors_snapshot(&self) -> Vec<ErrorSnapshot> {
        let mut out: Vec<ErrorSnapshot> = lock(&self.errors_by_code)
            .iter()
            .map(|(code, count)| ErrorSnapshot {
                code: *code,
                name: code_name(*code),
                count: *count,
            })
            .collect();
        out.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.code.cmp(&b.code)));
        out
    }
}

impl Default for Stats {
    fn default() -> Self {
        Self::new()
    }
}

/// Lock a mutex, recovering from a poisoned lock the same way the proxy does.
///
/// A panic elsewhere only means some thread died mid-update; refusing to serve
/// statistics over it would be worse.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// RFC 1928 §6 reply-code bytes, as module constants so `code_name` can match
/// on them (an `Enum as u8` cast is not a valid pattern).
const CODE_SUCCESS: u8 = crate::ResponseCode::Success as u8;
const CODE_FAILURE: u8 = crate::ResponseCode::Failure as u8;
const CODE_RULE_FAILURE: u8 = crate::ResponseCode::RuleFailure as u8;
const CODE_NETWORK_UNREACHABLE: u8 = crate::ResponseCode::NetworkUnreachable as u8;
const CODE_HOST_UNREACHABLE: u8 = crate::ResponseCode::HostUnreachable as u8;
const CODE_CONNECTION_REFUSED: u8 = crate::ResponseCode::ConnectionRefused as u8;
const CODE_TTL_EXPIRED: u8 = crate::ResponseCode::TtlExpired as u8;
const CODE_COMMAND_NOT_SUPPORTED: u8 = crate::ResponseCode::CommandNotSupported as u8;
const CODE_ADDR_TYPE_NOT_SUPPORTED: u8 = crate::ResponseCode::AddrTypeNotSupported as u8;

/// RFC 1928 §6 reply code → stable machine name, for the errors view.
fn code_name(code: u8) -> &'static str {
    match code {
        CODE_SUCCESS => "success",
        CODE_FAILURE => "failure",
        CODE_RULE_FAILURE => "rule_failure",
        CODE_NETWORK_UNREACHABLE => "network_unreachable",
        CODE_HOST_UNREACHABLE => "host_unreachable",
        CODE_CONNECTION_REFUSED => "connection_refused",
        CODE_TTL_EXPIRED => "ttl_expired",
        CODE_COMMAND_NOT_SUPPORTED => "command_not_supported",
        CODE_ADDR_TYPE_NOT_SUPPORTED => "addr_type_not_supported",
        _ => "unassigned",
    }
}

/// Point-in-time view of everything the web service exposes.
#[derive(Debug, Serialize)]
pub struct Snapshot {
    pub server: ServerSnapshot,
    pub connections: ConnectionsSnapshot,
    pub dns: DnsSnapshot,
    pub traffic: TrafficSnapshot,
    pub errors: Vec<ErrorSnapshot>,
}

#[derive(Debug, Serialize)]
pub struct ServerSnapshot {
    pub version: &'static str,
    pub uptime_secs: u64,
    pub started_at_unix: u64,
    pub listeners: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ConnectionsSnapshot {
    pub active: usize,
    pub active_per_ip: Vec<IpCount>,
    pub accepted_total: u64,
    pub refused_per_ip_total: u64,
    pub handshake_timeouts: u64,
    pub auth_failures: u64,
    pub disconnects: u64,
}

#[derive(Debug, Serialize)]
pub struct IpCount {
    pub ip: IpAddr,
    pub count: u64,
}

#[derive(Debug, Serialize)]
pub struct DnsSnapshot {
    pub enabled: bool,
    pub ttl_secs: u64,
    pub max_entries: usize,
    pub entries: usize,
    pub hits: u64,
    pub misses: u64,
    pub inserts: u64,
    pub evictions: u64,
    pub expired_dropped: u64,
    pub names: Vec<DnsName>,
}

impl DnsSnapshot {
    fn disabled() -> Self {
        DnsSnapshot {
            enabled: false,
            ttl_secs: 0,
            max_entries: 0,
            entries: 0,
            hits: 0,
            misses: 0,
            inserts: 0,
            evictions: 0,
            expired_dropped: 0,
            names: Vec::new(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct DnsName {
    pub name: String,
    pub expires_in_secs: u64,
}

#[derive(Debug, Serialize)]
pub struct TrafficSnapshot {
    pub bytes_client_to_target: u64,
    pub bytes_target_to_client: u64,
    pub udp_datagrams: u64,
    pub requests: RequestsSnapshot,
}

#[derive(Debug, Serialize)]
pub struct RequestsSnapshot {
    pub connect: u64,
    pub bind: u64,
    pub udp_associate: u64,
}

#[derive(Debug, Serialize)]
pub struct ErrorSnapshot {
    pub code: u8,
    pub name: &'static str,
    pub count: u64,
}

/// One live client, as served by `GET /clients`.
#[derive(Debug, Serialize)]
pub struct ClientView {
    pub id: u64,
    pub peer: SocketAddr,
    pub local: Option<SocketAddr>,
    pub elapsed_secs: u64,
    pub state: &'static str,
    pub command: Option<&'static str>,
    pub bytes_client_to_target: u64,
    pub bytes_target_to_client: u64,
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use crate::SockCommand;

    #[test]
    fn counters_reflect_snapshot() {
        let stats = Arc::new(Stats::new());
        stats.note_accepted();
        stats.note_accepted();
        stats.note_refused_per_ip();
        stats.note_handshake_timeout();
        stats.note_auth_failure();
        stats.note_relay(None, 100, 200);
        stats.note_error(0x05);

        let snap = stats.snapshot();
        assert_eq!(snap.connections.accepted_total, 2);
        assert_eq!(snap.connections.refused_per_ip_total, 1);
        assert_eq!(snap.connections.handshake_timeouts, 1);
        assert_eq!(snap.connections.auth_failures, 1);
        assert_eq!(snap.traffic.bytes_client_to_target, 100);
        assert_eq!(snap.traffic.bytes_target_to_client, 200);
        assert_eq!(snap.errors.len(), 1);
        assert_eq!(snap.errors[0].code, 0x05);
        assert_eq!(snap.errors[0].name, "connection_refused");
        assert!(!snap.dns.enabled);
    }

    #[test]
    fn active_guard_tracks_per_ip_and_clients() {
        let stats = Arc::new(Stats::new());
        let peer: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let guard = stats.begin_client(peer, None);

        assert_eq!(stats.snapshot().connections.active, 1);
        assert_eq!(stats.clients().len(), 1);
        assert_eq!(stats.clients()[0].id, 0);
        let per_ip = stats.snapshot().connections.active_per_ip;
        assert_eq!(per_ip.len(), 1);
        assert_eq!(per_ip[0].count, 1);

        drop(guard);
        assert_eq!(stats.snapshot().connections.active, 0);
        assert!(stats.clients().is_empty());
        assert!(stats.snapshot().connections.active_per_ip.is_empty());
    }

    #[test]
    fn request_counters_map_commands() {
        let stats = Arc::new(Stats::new());
        stats.note_request(None, SockCommand::Connect);
        stats.note_request(None, SockCommand::Bind);
        stats.note_request(None, SockCommand::UdpAssosiate);

        let requests = stats.snapshot().traffic.requests;
        assert_eq!(requests.connect, 1);
        assert_eq!(requests.bind, 1);
        assert_eq!(requests.udp_associate, 1);
    }

    #[test]
    fn note_request_tags_the_live_client_row() {
        let stats = Arc::new(Stats::new());
        let peer: SocketAddr = "10.0.0.1:53".parse().unwrap();
        let guard = stats.begin_client(peer, None);
        stats.note_request(Some(guard.id), SockCommand::Connect);

        let client = &stats.clients()[0];
        assert_eq!(client.command, Some("connect"));
        assert_eq!(client.state, "relaying");

        stats.note_relay(Some(guard.id), 5, 9);
        assert_eq!(stats.clients()[0].bytes_client_to_target, 5);
        assert_eq!(stats.clients()[0].bytes_target_to_client, 9);
    }
}
