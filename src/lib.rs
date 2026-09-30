#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate log;
use snafu::Snafu;

mod actors;
pub use actors::{SocksConnection, SocksServer};

use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket, lookup_host};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;

/// Version of socks
const SOCKS_VERSION: u8 = 0x05;

const RESERVED: u8 = 0x00;

/// Default time budget for establishing the outbound TCP connection to the
/// requested destination.
///
/// This bounds only connection establishment, never the relay that follows, so
/// a long-lived proxied connection is unaffected once it is up. When no timeout
/// is configured this is used instead of the previous 500 ms fallback, which was
/// too short for any destination beyond the local network and was misreported as
/// a connection refusal.
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Default maximum number of client connections handled at once.
///
/// Accepted connections beyond this limit wait in the accept loop until a
/// slot frees, applying kernel-level backpressure instead of spawning an
/// unbounded number of tasks/actors.
pub const DEFAULT_MAX_CONNECTIONS: usize = 1024;

/// Default time budget for the whole SOCKS5 handshake (greeting + auth) before
/// the server gives up on a slow or stalled client. Protects against
/// slowloris-style connections that trickle bytes to hold a task open.
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct User {
    pub username: String,
    password: String,
}

impl User {
    /// Create a new user from a username / password pair
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }
}

pub struct SocksReply {
    // From rfc 1928 (S6),
    // the server evaluates the request, and returns a reply formed as follows:
    //
    //    +----+-----+-------+------+----------+----------+
    //    |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    //    +----+-----+-------+------+----------+----------+
    //    | 1  |  1  | X'00' |  1   | Variable |    2     |
    //    +----+-----+-------+------+----------+----------+
    //
    // Where:
    //
    //      o  VER    protocol version: X'05'
    //      o  REP    Reply field:
    //         o  X'00' succeeded
    //         o  X'01' general SOCKS server failure
    //         o  X'02' connection not allowed by ruleset
    //         o  X'03' Network unreachable
    //         o  X'04' Host unreachable
    //         o  X'05' Connection refused
    //         o  X'06' TTL expired
    //         o  X'07' Command not supported
    //         o  X'08' Address type not supported
    //         o  X'09' to X'FF' unassigned
    //      o  RSV    RESERVED
    //      o  ATYP   address type of following address
    //         o  IP V4 address: X'01'
    //         o  DOMAINNAME: X'03'
    //         o  IP V6 address: X'04'
    //      o  BND.ADDR       server bound address
    //      o  BND.PORT       server bound port in network octet order
    //
    buf: Vec<u8>,
}

impl SocksReply {
    /// Build a reply with an all-zero `BND.ADDR` / `BND.PORT`.
    ///
    /// Used for `CONNECT` and for error replies, where no server-bound address
    /// is meaningful.
    pub fn new(status: ResponseCode) -> Self {
        Self::from_bound(status, None)
    }

    /// Build a reply advertising the server-bound address `bound`, as required
    /// by the first `BIND` and `UDP ASSOCIATE` replies (RFC 1928 §6).
    pub fn with_addr(status: ResponseCode, bound: SocketAddr) -> Self {
        Self::from_bound(status, Some(bound))
    }

    fn from_bound(status: ResponseCode, bound: Option<SocketAddr>) -> Self {
        let mut buf = Vec::with_capacity(22);
        buf.push(SOCKS_VERSION);
        buf.push(status as u8);
        buf.push(RESERVED);
        match bound {
            Some(SocketAddr::V4(addr)) => {
                buf.push(AddrType::V4 as u8);
                buf.extend_from_slice(&addr.ip().octets());
                buf.extend_from_slice(&addr.port().to_be_bytes());
            }
            Some(SocketAddr::V6(addr)) => {
                buf.push(AddrType::V6 as u8);
                buf.extend_from_slice(&addr.ip().octets());
                buf.extend_from_slice(&addr.port().to_be_bytes());
            }
            None => {
                buf.push(AddrType::V4 as u8);
                buf.extend_from_slice(&[0, 0, 0, 0]);
                buf.extend_from_slice(&[0, 0]);
            }
        }
        Self { buf }
    }

    pub async fn send<T>(&self, stream: &mut T) -> io::Result<()>
    where
        T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        stream.write_all(&self.buf[..]).await?;
        Ok(())
    }

    /// The raw wire representation of this reply.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }
}

#[derive(Error, Debug)]
pub enum MerinoError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Socks error: {0}")]
    Socks(#[from] ResponseCode),
}

#[derive(Debug, Snafu)]
/// Possible SOCKS5 Response Codes
pub enum ResponseCode {
    Success = 0x00,
    #[snafu(display("SOCKS5 Server Failure"))]
    Failure = 0x01,
    #[snafu(display("SOCKS5 Rule failure"))]
    RuleFailure = 0x02,
    #[snafu(display("network unreachable"))]
    NetworkUnreachable = 0x03,
    #[snafu(display("host unreachable"))]
    HostUnreachable = 0x04,
    #[snafu(display("connection refused"))]
    ConnectionRefused = 0x05,
    #[snafu(display("TTL expired"))]
    TtlExpired = 0x06,
    #[snafu(display("Command not supported"))]
    CommandNotSupported = 0x07,
    #[snafu(display("Addr Type not supported"))]
    AddrTypeNotSupported = 0x08,
}

impl From<MerinoError> for ResponseCode {
    fn from(e: MerinoError) -> Self {
        match e {
            MerinoError::Socks(e) => e,
            MerinoError::Io(_) => ResponseCode::Failure,
        }
    }
}

/// DST.addr variant types
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddrType {
    /// IP V4 address: X'01'
    V4 = 0x01,
    /// DOMAINNAME: X'03'
    Domain = 0x03,
    /// IP V6 address: X'04'
    V6 = 0x04,
}

impl AddrType {
    /// Parse Byte to Command
    pub fn from(n: usize) -> Option<AddrType> {
        match n {
            1 => Some(AddrType::V4),
            3 => Some(AddrType::Domain),
            4 => Some(AddrType::V6),
            _ => None,
        }
    }

    // /// Return the size of the AddrType
    // fn size(&self) -> u8 {
    //     match self {
    //         AddrType::V4 => 4,
    //         AddrType::Domain => 1,
    //         AddrType::V6 => 16
    //     }
    // }
}

/// SOCK5 CMD Type
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SockCommand {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssosiate = 0x3,
}

impl SockCommand {
    /// Parse Byte to Command
    pub fn from(n: usize) -> Option<SockCommand> {
        match n {
            1 => Some(SockCommand::Connect),
            2 => Some(SockCommand::Bind),
            3 => Some(SockCommand::UdpAssosiate),
            _ => None,
        }
    }
}

/// Client Authentication Methods
pub enum AuthMethods {
    /// No Authentication
    NoAuth = 0x00,
    // GssApi = 0x01,
    /// Authenticate with a username / password
    UserPass = 0x02,
    /// Cannot authenticate
    NoMethods = 0xFF,
}

/// Bind a listener for every address `ip` resolves to.
///
/// `ip` may be an IP literal or a hostname. When a hostname resolves to both
/// IPv4 and IPv6 addresses (for example `localhost` on a dual-stack host),
/// every address is bound so the server accepts connections over both
/// families and on every interface the name maps to. Duplicate addresses are
/// collapsed. Addresses that fail to bind are logged and skipped; an error is
/// returned only when none could be bound.
pub(crate) async fn bind_all(ip: &str, port: u16) -> io::Result<Vec<TcpListener>> {
    let mut seen = HashSet::new();
    let addrs: Vec<SocketAddr> = lookup_host((ip, port))
        .await?
        .filter(|addr| seen.insert(*addr))
        .collect();

    bind_listeners(&addrs).map_err(|e| {
        if addrs.is_empty() {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("no addresses resolved for {ip}"),
            )
        } else {
            e
        }
    })
}

/// Bind a listener for every address, skipping ones that fail.
///
/// Every address is tried even if an earlier one failed; an error is returned
/// only when none could be bound, reporting the last bind failure.
pub(crate) fn bind_listeners(addrs: &[SocketAddr]) -> io::Result<Vec<TcpListener>> {
    let mut listeners = Vec::new();
    let mut last_err = None;
    for addr in addrs {
        match bind_listener(addr) {
            Ok(listener) => {
                if let Ok(bound) = listener.local_addr() {
                    info!("Listening on {bound}");
                }
                listeners.push(listener);
            }
            Err(e) => {
                warn!("Failed to bind {addr}: {e}");
                last_err = Some(e);
            }
        }
    }

    if !listeners.is_empty() {
        return Ok(listeners);
    }
    Err(last_err.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "no addresses supplied to bind",
        )
    }))
}

fn bind_listener(addr: &SocketAddr) -> io::Result<TcpListener> {
    let listener = std::net::TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    TcpListener::from_std(listener)
}

pub struct Merino {
    listeners: Vec<TcpListener>,
    users: Arc<Vec<User>>,
    auth_methods: Arc<Vec<u8>>,
    // Timeout for connections
    timeout: Option<Duration>,
    max_connections: usize,
}

impl Merino {
    /// Create a new Merino instance
    pub async fn new(
        port: u16,
        ip: &str,
        auth_methods: Vec<u8>,
        users: Vec<User>,
        timeout: Option<Duration>,
    ) -> io::Result<Self> {
        Ok(Merino {
            listeners: bind_all(ip, port).await?,
            auth_methods: Arc::new(auth_methods),
            users: Arc::new(users),
            timeout,
            max_connections: DEFAULT_MAX_CONNECTIONS,
        })
    }

    /// Set the maximum number of simultaneous client connections.
    ///
    /// Zero is clamped to one so the accept loop can never deadlock.
    pub fn set_max_connections(&mut self, max: usize) {
        self.max_connections = max.max(1);
    }

    /// Return the first address a listener is bound to
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listeners
            .first()
            .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "no listeners bound"))?
            .local_addr()
    }

    /// Return the address of every listener this server is bound to
    pub fn local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        self.listeners.iter().map(TcpListener::local_addr).collect()
    }

    pub async fn serve(&mut self) {
        info!("Serving Connections...");
        let listeners = std::mem::take(&mut self.listeners);
        let semaphore = Arc::new(Semaphore::new(self.max_connections));
        let mut set = tokio::task::JoinSet::new();
        for listener in listeners {
            let users = self.users.clone();
            let auth_methods = self.auth_methods.clone();
            let timeout = self.timeout;
            let semaphore = semaphore.clone();
            set.spawn(accept_loop(
                listener,
                semaphore,
                users,
                auth_methods,
                timeout,
                |client, client_addr, permit| {
                    tokio::spawn(async move {
                        let _permit = permit;
                        run_client(client, client_addr).await;
                    });
                },
            ));
        }
        while set.join_next().await.is_some() {}
    }
}

/// Accept loop shared by both backends.
///
/// One slot of `semaphore` is acquired *before* each `accept`, so excess
/// connections wait in the kernel backlog instead of spawning unbounded
/// tasks/actors. The accepted client (with its local address recorded) and the
/// permit are handed to `on_accept`, which owns the permit for the lifetime of
/// the connection and decides how to run it — a Tokio task for [`Merino`], an
/// actor for [`SocksServer`].
///
/// A failed `accept` releases the slot and keeps serving; the two backends had
/// drifted on exactly this point before the loop was shared.
pub(crate) async fn accept_loop<F>(
    listener: TcpListener,
    semaphore: Arc<Semaphore>,
    users: Arc<Vec<User>>,
    auth_methods: Arc<Vec<u8>>,
    timeout: Option<Duration>,
    mut on_accept: F,
) where
    F: FnMut(SOCKClient<TcpStream>, SocketAddr, OwnedSemaphorePermit) + Send + 'static,
{
    // One scan for the whole server: the comparison width only changes when the
    // credential list does.
    let credential_width = credential_width(&users);

    loop {
        let permit = match semaphore.clone().acquire_owned().await {
            Ok(permit) => permit,
            // The semaphore is never closed; treat it as a stop signal anyway.
            Err(_) => break,
        };

        match listener.accept().await {
            Ok((stream, client_addr)) => {
                let local_addr = stream.local_addr().ok();
                let mut client = SOCKClient::with_credential_width(
                    stream,
                    users.clone(),
                    auth_methods.clone(),
                    timeout,
                    credential_width,
                );
                client.set_local_addr(local_addr);
                on_accept(client, client_addr, permit);
            }
            Err(e) => {
                warn!("Accept error: {:?}", e);
                drop(permit);
            }
        }
    }
}

/// Whether an I/O error is just the peer going away rather than a proxy fault.
///
/// A client that opens a connection and then hangs up (or is reset) part-way
/// through the SOCKS greeting produces `UnexpectedEof` from `read_exact`, or a
/// reset/broken-pipe on the reply write. These are routine for a public proxy —
/// health checks, scanners, clients that give up — so they must not be logged as
/// server errors.
fn is_disconnect_kind(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
    )
}

fn is_client_disconnect(error: &MerinoError) -> bool {
    matches!(error, MerinoError::Io(io) if is_disconnect_kind(io.kind()))
}

/// Drive a single client connection to completion, replying with an error code
/// and shutting the stream down when the SOCKS negotiation fails.
pub(crate) async fn run_client<T>(mut client: SOCKClient<T>, client_addr: SocketAddr)
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    match client.init().await {
        Ok(_) => {}
        Err(error) => {
            let disconnected = is_client_disconnect(&error);
            if disconnected {
                debug!(
                    "Client disconnected during handshake: {}, client: {:?}",
                    error, client_addr
                );
            } else {
                error!("Error! {:?}, client: {:?}", error, client_addr);
            }

            // A failure the client was already told about during
            // authentication must not be answered twice.
            if !client.replied
                && let Err(e) = SocksReply::new(error.into()).send(&mut client.stream).await
            {
                if is_disconnect_kind(e.kind()) {
                    debug!("Client already gone, reply not sent: {:?}", e);
                } else {
                    warn!("Failed to send error code: {:?}", e);
                }
            }

            if let Err(e) = client.shutdown().await {
                if is_disconnect_kind(e.kind()) {
                    debug!("Client already gone, shutdown skipped: {:?}", e);
                } else {
                    warn!("Failed to shutdown TcpStream: {:?}", e);
                }
            };
        }
    }
}

pub struct SOCKClient<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> {
    stream: T,
    auth_nmethods: u8,
    auth_methods: Arc<Vec<u8>>,
    authed_users: Arc<Vec<User>>,
    socks_version: u8,
    timeout: Option<Duration>,
    handshake_timeout: Duration,
    /// Local address of the client-facing connection, when known. Used as the
    /// interface to bind `BIND` listeners and `UDP ASSOCIATE` sockets on.
    local_addr: Option<SocketAddr>,
    /// True once the client has been answered during authentication, so the
    /// error path in `run_client` does not write a second reply.
    replied: bool,
    /// Longest username/password in `authed_users`, used as the fixed width of
    /// the constant-time credential comparison so its cost does not depend on
    /// how long the client's input is.
    credential_width: usize,
}

impl<T> SOCKClient<T>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    /// Create a new SOCKClient
    pub fn new(
        stream: T,
        authed_users: Arc<Vec<User>>,
        auth_methods: Arc<Vec<u8>>,
        timeout: Option<Duration>,
    ) -> Self {
        let credential_width = credential_width(&authed_users);
        Self::with_credential_width(
            stream,
            authed_users,
            auth_methods,
            timeout,
            credential_width,
        )
    }

    /// Create a client with a caller-supplied constant-time comparison width.
    ///
    /// [`SOCKClient::new`] derives it from the credential list; the accept loop
    /// already knows the width for the whole server, so it passes it in rather
    /// than rescanning the list on every connection.
    pub(crate) fn with_credential_width(
        stream: T,
        authed_users: Arc<Vec<User>>,
        auth_methods: Arc<Vec<u8>>,
        timeout: Option<Duration>,
        credential_width: usize,
    ) -> Self {
        SOCKClient {
            stream,
            auth_nmethods: 0,
            socks_version: 0,
            authed_users,
            auth_methods,
            timeout,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            local_addr: None,
            replied: false,
            credential_width,
        }
    }

    /// Create a new SOCKClient with no auth
    pub fn new_no_auth(stream: T, timeout: Option<Duration>) -> Self {
        // FIXME: use option here
        let authed_users: Arc<Vec<User>> = Arc::new(Vec::new());
        let auth_methods: Arc<Vec<u8>> = Arc::new(vec![AuthMethods::NoAuth as u8]);

        SOCKClient {
            stream,
            auth_nmethods: 0,
            socks_version: 0,
            authed_users,
            auth_methods,
            timeout,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            local_addr: None,
            replied: false,
            credential_width: 0,
        }
    }

    /// Record the local address of the client-facing connection.
    ///
    /// `BIND` and `UDP ASSOCIATE` bind their listeners on the same interface
    /// the client reached the proxy through, so the advertised `BND.ADDR` is
    /// reachable.
    pub fn set_local_addr(&mut self, local_addr: Option<SocketAddr>) {
        self.local_addr = local_addr;
    }

    /// Override the maximum time allowed for the SOCKS5 handshake.
    pub fn set_handshake_timeout(&mut self, timeout: Duration) {
        self.handshake_timeout = timeout;
    }

    /// Mutable getter for inner stream
    pub fn stream_mut(&mut self) -> &mut T {
        &mut self.stream
    }

    /// Check if username + password pair are valid.
    ///
    /// Takes the raw bytes read off the wire so a login needs no allocation;
    /// credentials loaded from the CSV are byte-comparable.
    ///
    /// The comparison is written to avoid early exit on a mismatch and to
    /// inspect every configured user, so the work done does not reveal which
    /// entry (if any) matched or how far a wrong password got.
    fn authed(&self, username: &[u8], password: &[u8]) -> bool {
        let mut found = false;
        for candidate in self.authed_users.iter() {
            let username_ok = ct_eq(
                username,
                candidate.username.as_bytes(),
                self.credential_width,
            );
            let password_ok = ct_eq(
                password,
                candidate.password.as_bytes(),
                self.credential_width,
            );
            found |= username_ok & password_ok;
        }
        found
    }

    /// Shutdown a client
    pub async fn shutdown(&mut self) -> io::Result<()> {
        self.stream.shutdown().await?;
        Ok(())
    }

    /// Drive a connection: negotiate (bounded by the handshake timeout) and
    /// then relay.
    ///
    /// Only the negotiation — greeting, authentication and reading the request
    /// — is subject to [`SOCKClient::set_handshake_timeout`]. The relay itself
    /// is intentionally unbounded so long-lived proxied connections are not
    /// torn down after the handshake budget elapses. A stalled client is
    /// disconnected with a `TTL expired` reply.
    pub async fn init(&mut self) -> Result<(), MerinoError> {
        let req = match timeout(self.handshake_timeout, self.negotiate()).await {
            Ok(result) => result?,
            Err(_) => {
                warn!(
                    "SOCKS handshake timed out after {:?}",
                    self.handshake_timeout
                );
                return Err(MerinoError::Socks(ResponseCode::TtlExpired));
            }
        };

        self.handle_request(req).await?;
        Ok(())
    }

    async fn negotiate(&mut self) -> Result<SOCKSReq, MerinoError> {
        debug!("New connection");
        let mut header = [0u8; 2];
        // Read a byte from the stream and determine the version being requested
        self.stream.read_exact(&mut header).await?;

        self.socks_version = header[0];
        self.auth_nmethods = header[1];

        trace!(
            "Version: {} Auth nmethods: {}",
            self.socks_version, self.auth_nmethods
        );

        match self.socks_version {
            SOCKS_VERSION => {
                // Authenticate w/ client
                self.auth().await?;
                // Read the request (still inside the handshake budget).
                SOCKSReq::from_stream(&mut self.stream).await
            }
            _ => {
                warn!("Init: Unsupported version: SOCKS{}", self.socks_version);
                self.shutdown().await?;
                Err(MerinoError::Socks(ResponseCode::Failure))
            }
        }
    }

    async fn auth(&mut self) -> Result<(), MerinoError> {
        debug!("Authenticating");
        // Get valid auth methods
        let methods = self.get_avalible_methods().await?;
        trace!("methods: {:?}", methods);

        let mut response = [0u8; 2];

        // Set the version in the response
        response[0] = SOCKS_VERSION;

        if methods.contains(&(AuthMethods::UserPass as u8)) {
            // Set the default auth method (NO AUTH)
            response[1] = AuthMethods::UserPass as u8;

            debug!("Sending USER/PASS packet");
            self.stream.write_all(&response).await?;

            let mut header = [0u8; 2];

            // Read a byte from the stream and determine the version being requested
            self.stream.read_exact(&mut header).await?;

            // Username parsing
            let ulen = header[1] as usize;

            let mut username = vec![0; ulen];

            self.stream.read_exact(&mut username).await?;

            // Password Parsing
            let mut plen = [0u8; 1];
            self.stream.read_exact(&mut plen).await?;

            let mut password = vec![0; plen[0] as usize];
            self.stream.read_exact(&mut password).await?;

            // Re-parse the assembled frame through the pure parser so the
            // sub-negotiation version is validated in exactly one place.
            let mut frame = Vec::with_capacity(2 + username.len() + 1 + password.len());
            frame.extend_from_slice(&header);
            frame.extend_from_slice(&username);
            frame.push(plen[0]);
            frame.extend_from_slice(&password);
            let (parsed, _) = parse_userpass(&frame)?;

            // Answer the client here rather than letting `run_client` do it:
            // the USERPASS sub-negotiation reply is 2 bytes wide, unlike the
            // fixed 10-byte SOCKS5 reply. `replied` stops the error path from
            // answering the same failure a second time.
            if parsed.version != 0x01 {
                warn!(
                    "Invalid USERPASS sub-negotiation version: {}",
                    parsed.version
                );
                self.replied = true;
                let response = [1, ResponseCode::Failure as u8];
                self.stream.write_all(&response).await?;
                self.shutdown().await?;
                return Err(MerinoError::Socks(ResponseCode::Failure));
            }

            // Compare the bytes as they arrived: copying them into `String`s
            // first allocates twice per login and buys nothing, because CSV
            // credentials are already byte-comparable.
            if self.authed(parsed.username, parsed.password) {
                debug!(
                    "Access Granted. User: {}",
                    String::from_utf8_lossy(parsed.username)
                );
                let response = [1, ResponseCode::Success as u8];
                self.stream.write_all(&response).await?;
                Ok(())
            } else {
                debug!(
                    "Access Denied. User: {}",
                    String::from_utf8_lossy(parsed.username)
                );
                self.replied = true;
                let response = [1, ResponseCode::Failure as u8];
                self.stream.write_all(&response).await?;

                // Shutdown, then fail rather than returning `Ok(())`: reading
                // a request from an unauthenticated client would let it skip
                // authentication entirely.
                self.shutdown().await?;
                Err(MerinoError::Socks(ResponseCode::Failure))
            }
        } else if methods.contains(&(AuthMethods::NoAuth as u8)) {
            // set the default auth method (no auth)
            response[1] = AuthMethods::NoAuth as u8;
            debug!("Sending NOAUTH packet");
            self.stream.write_all(&response).await?;
            debug!("NOAUTH sent");
            Ok(())
        } else {
            warn!("Client has no suitable Auth methods!");
            response[1] = AuthMethods::NoMethods as u8;
            self.stream.write_all(&response).await?;
            self.shutdown().await?;

            Err(MerinoError::Socks(ResponseCode::Failure))
        }
    }

    /// Read a request from the stream and handle it.
    ///
    /// Kept for API compatibility; [`SOCKClient::init`] performs the same read
    /// as part of the bounded negotiation and then calls `handle_request`
    /// directly. The read is bounded by
    /// [`SOCKClient::set_handshake_timeout`] — the same budget `init` applies —
    /// so callers of this method are not exposed to a client that connects and
    /// never speaks.
    pub async fn handle_client(&mut self) -> Result<usize, MerinoError> {
        let req = match timeout(
            self.handshake_timeout,
            SOCKSReq::from_stream(&mut self.stream),
        )
        .await
        {
            Ok(result) => result?,
            Err(_) => {
                warn!("SOCKS request timed out after {:?}", self.handshake_timeout);
                return Err(MerinoError::Socks(ResponseCode::TtlExpired));
            }
        };

        self.handle_request(req).await
    }

    /// Handle an already-parsed request (connect + relay).
    async fn handle_request(&mut self, req: SOCKSReq) -> Result<usize, MerinoError> {
        debug!("Starting to relay data");

        // Log Request
        let displayed_addr = pretty_print_addr(&req.addr_type, &req.addr);
        info!(
            "New Request: Command: {:?} Addr: {}, Port: {}",
            req.command, displayed_addr, req.port
        );

        // Respond
        match req.command {
            // Use the Proxy to connect to the specified addr/port
            SockCommand::Connect => {
                debug!("Handling CONNECT Command");

                // A name that does not resolve is a property of the requested
                // destination, not a server failure, so it gets its own code.
                // `InvalidInput` is the other arm of `addr_to_socket`: a
                // malformed address, which is a bad request rather than an
                // unreachable host.
                let sock_addr = addr_to_socket(&req.addr_type, &req.addr, req.port)
                    .await
                    .map_err(|e| match e.kind() {
                        io::ErrorKind::InvalidInput => MerinoError::Io(e),
                        _ => dns_failure_error(),
                    })?;

                trace!("Connecting to: {:?}", sock_addr);

                let time_out = self.timeout.unwrap_or(DEFAULT_CONNECT_TIMEOUT);

                let mut target =
                    timeout(
                        time_out,
                        async move { TcpStream::connect(&sock_addr[..]).await },
                    )
                    .await
                    .map_err(|_| connect_timeout_error())?
                    .map_err(connect_error)?;

                trace!("Connected!");

                SocksReply::new(ResponseCode::Success)
                    .send(&mut self.stream)
                    .await?;

                trace!("copy bidirectional");
                match tokio::io::copy_bidirectional(&mut self.stream, &mut target).await {
                    // ignore not connected for shutdown error
                    Err(e) if e.kind() == std::io::ErrorKind::NotConnected => {
                        trace!("already closed");
                        Ok(0)
                    }
                    Err(e) => Err(MerinoError::Io(e)),
                    Ok((_s_to_t, t_to_s)) => Ok(t_to_s as usize),
                }
            }
            // Listen for a single inbound connection and relay it back.
            SockCommand::Bind => self.handle_bind(&req).await,
            // Relay UDP datagrams for the lifetime of the control connection.
            SockCommand::UdpAssosiate => self.handle_udp_associate(&req).await,
        }
    }

    /// Interface the `BIND` / `UDP ASSOCIATE` sockets should be bound to.
    ///
    /// Prefers the local address of the client-facing connection so the
    /// advertised `BND.ADDR` is reachable by the client; falls back to the
    /// unspecified IPv4 address when it is unknown.
    fn local_interface(&self) -> IpAddr {
        self.local_addr
            .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |addr| addr.ip())
    }

    /// Handle a `BIND` request (RFC 1928 §4).
    ///
    /// Binds an ephemeral listener on the proxy interface, replies with its
    /// address, waits for the anticipated inbound connection and then relays
    /// between it and the client until either side closes.
    async fn handle_bind(&mut self, req: &SOCKSReq) -> Result<usize, MerinoError> {
        debug!("Handling BIND Command");

        let listener = TcpListener::bind(SocketAddr::new(self.local_interface(), 0)).await?;
        let bound = listener.local_addr()?;
        info!("BIND listening on {}", bound);

        SocksReply::with_addr(ResponseCode::Success, bound)
            .send(&mut self.stream)
            .await?;

        let time_out = self.timeout.unwrap_or(DEFAULT_CONNECT_TIMEOUT);
        let (mut inbound, peer) = match timeout(time_out, listener.accept()).await {
            Ok(Ok(pair)) => pair,
            Ok(Err(e)) => return Err(MerinoError::Io(e)),
            Err(_) => return Err(connect_timeout_error()),
        };
        trace!("BIND inbound connection from {}", peer);

        // Validate the client's expected peer when it supplied a concrete
        // address; 0.0.0.0 / :: means "any".
        if let Some(expected) = expected_ip(&req.addr_type, &req.addr)
            && expected != peer.ip()
        {
            warn!("BIND peer {} does not match requested {}", peer, expected);
            return Err(MerinoError::Socks(ResponseCode::RuleFailure));
        }

        // Second reply carries the address of the connected peer.
        SocksReply::with_addr(ResponseCode::Success, peer)
            .send(&mut self.stream)
            .await?;

        trace!("BIND relay");
        match tokio::io::copy_bidirectional(&mut self.stream, &mut inbound).await {
            Err(e) if e.kind() == io::ErrorKind::NotConnected => {
                trace!("already closed");
                Ok(0)
            }
            Err(e) => Err(MerinoError::Io(e)),
            Ok((_s_to_t, t_to_s)) => Ok(t_to_s as usize),
        }
    }

    /// Handle a `UDP ASSOCIATE` request (RFC 1928 §7).
    ///
    /// Binds an ephemeral UDP socket on the proxy interface, replies with its
    /// address, then relays datagrams between the client and their destinations
    /// until the TCP control connection closes.
    async fn handle_udp_associate(&mut self, req: &SOCKSReq) -> Result<usize, MerinoError> {
        debug!("Handling UDP ASSOCIATE Command");

        let socket = UdpSocket::bind(SocketAddr::new(self.local_interface(), 0)).await?;
        let bound = socket.local_addr()?;
        info!("UDP ASSOCIATE bound to {}", bound);

        SocksReply::with_addr(ResponseCode::Success, bound)
            .send(&mut self.stream)
            .await?;

        let expected_client = expected_ip(&req.addr_type, &req.addr);
        let mut client_addr: Option<SocketAddr> = None;
        let mut buf = vec![0u8; 65535];
        let mut control = [0u8; 1];

        loop {
            tokio::select! {
                read = self.stream.read(&mut control) => match read {
                    // EOF or a read error on the control channel tears the
                    // association down.
                    Ok(0) | Err(_) => {
                        debug!("UDP control connection closed");
                        break;
                    }
                    // Any data on the control channel is ignored.
                    Ok(_) => continue,
                },
                recv = socket.recv_from(&mut buf) => {
                    let (n, src) = match recv {
                        Ok(pair) => pair,
                        Err(e) => {
                            warn!("UDP recv error: {}", e);
                            break;
                        }
                    };
                    let Some(data) = buf.get(..n) else {
                        // `recv_from` never reports more than the buffer holds.
                        continue;
                    };

                    match client_addr {
                        None => {
                            // The first datagram identifies the client, unless
                            // it contradicts the address the client declared.
                            if let Some(expected) = expected_client
                                && expected != src.ip()
                            {
                                warn!(
                                    "UDP datagram from unexpected source {}, expected {}",
                                    src, expected
                                );
                                continue;
                            }
                            client_addr = Some(src);
                        }
                        Some(client) if client == src => {}
                        Some(client) => {
                            // A reply from a remote destination: re-frame it
                            // with the sender's address and forward to client.
                            let mut out = encode_udp_header(src);
                            out.extend_from_slice(data);
                            if let Err(e) = socket.send_to(&out, client).await {
                                warn!("UDP relay to client failed: {}", e);
                            }
                            continue;
                        }
                    }

                    // Datagram from the client: forward the payload on.
                    let (header, consumed) = match parse_udp_header(data) {
                        Ok(parsed) => parsed,
                        Err(e) => {
                            warn!("Invalid UDP header: {:?}", e);
                            continue;
                        }
                    };
                    if header.frag != 0 {
                        warn!("UDP fragmentation unsupported (FRAG={})", header.frag);
                        continue;
                    }
                    let target =
                        match addr_to_socket(&header.addr_type, header.addr, header.port).await {
                            Ok(addrs) => addrs,
                            Err(e) => {
                                warn!("UDP destination resolution failed: {}", e);
                                continue;
                            }
                        };
                    if let Some(dest) = target.first()
                        && let Some(payload) = data.get(consumed..)
                        && let Err(e) = socket.send_to(payload, *dest).await
                    {
                        warn!("UDP forward to {} failed: {}", dest, e);
                    }
                }
            }
        }

        Ok(0)
    }

    /// Return the avalible methods based on `self.auth_nmethods`
    async fn get_avalible_methods(&mut self) -> io::Result<Vec<u8>> {
        let mut methods: Vec<u8> = Vec::with_capacity(self.auth_nmethods as usize);
        for _ in 0..self.auth_nmethods {
            let mut method = [0u8; 1];
            self.stream.read_exact(&mut method).await?;
            if self.auth_methods.contains(&method[0]) {
                methods.append(&mut method.to_vec());
            }
        }
        Ok(methods)
    }
}

/// Error reported when the bounded outbound connect attempt runs out of time.
///
/// A timeout is not the same as the peer refusing the connection, so it is
/// reported as `TTL expired` (RFC 1928 §6) rather than `connection refused`.
/// This lets a client tell a blackholed or merely slow destination apart from
/// one that is actively rejecting the connection.
fn connect_timeout_error() -> MerinoError {
    MerinoError::Socks(ResponseCode::TtlExpired)
}

/// Error reported when the destination name cannot be resolved.
///
/// A name that does not resolve is `host unreachable` (RFC 1928 §6), which
/// lets a client tell it apart from a generic server failure.
fn dns_failure_error() -> MerinoError {
    MerinoError::Socks(ResponseCode::HostUnreachable)
}

/// Map a failed outbound connect to the closest reply code of RFC 1928 §6.
///
/// Only refusal was distinguished before, so every network error a client
/// could act on — unroutable network, unreachable host, bad local address —
/// came back as the generic `Failure` (`0x01`).
fn connect_error(error: io::Error) -> MerinoError {
    match error.kind() {
        io::ErrorKind::ConnectionRefused => MerinoError::Socks(ResponseCode::ConnectionRefused),
        io::ErrorKind::NetworkUnreachable | io::ErrorKind::NetworkDown => {
            MerinoError::Socks(ResponseCode::NetworkUnreachable)
        }
        io::ErrorKind::HostUnreachable | io::ErrorKind::AddrNotAvailable => {
            MerinoError::Socks(ResponseCode::HostUnreachable)
        }
        _ => MerinoError::Io(error),
    }
}

/// Convert an address and AddrType to a SocketAddr
async fn addr_to_socket(
    addr_type: &AddrType,
    addr: &[u8],
    port: u16,
) -> io::Result<Vec<SocketAddr>> {
    match addr_type {
        AddrType::V6 => {
            let octets = <[u8; 16]>::try_from(addr).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "IPv6 address must be 16 bytes")
            })?;

            Ok(vec![SocketAddr::from(SocketAddrV6::new(
                Ipv6Addr::from(octets),
                port,
                0,
                0,
            ))])
        }
        AddrType::V4 => {
            let octets = <[u8; 4]>::try_from(addr).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "IPv4 address must be 4 bytes")
            })?;

            Ok(vec![SocketAddr::from(SocketAddrV4::new(
                Ipv4Addr::from(octets),
                port,
            ))])
        }
        AddrType::Domain => {
            let mut domain = String::from_utf8_lossy(addr).to_string();
            domain.push(':');
            domain.push_str(&port.to_string());

            Ok(lookup_host(domain).await?.collect())
        }
    }
}

/// Render client-supplied domain bytes for logging.
///
/// Names arrive from the network and are logged verbatim (see
/// `SOCKClient::handle_request`), so anything outside printable ASCII is shown
/// as a `\xNN` escape. Without this a client could push ANSI escapes or forged
/// log lines into an operator's terminal. Only the rendered form is escaped —
/// the bytes on the wire are untouched.
fn sanitize_domain(addr: &[u8]) -> String {
    let mut rendered = String::with_capacity(addr.len());
    for &byte in addr {
        match byte {
            0x20..=0x7e => rendered.push(char::from(byte)),
            _ => rendered.push_str(&format!("\\x{:02x}", byte)),
        }
    }
    rendered
}

/// Convert an AddrType and address to String
pub fn pretty_print_addr(addr_type: &AddrType, addr: &[u8]) -> String {
    match addr_type {
        AddrType::Domain => sanitize_domain(addr),
        AddrType::V4 => match addr {
            [a, b, c, d, ..] => format!("{a}.{b}.{c}.{d}"),
            _ => format!("<invalid ipv4: {} bytes>", addr.len()),
        },
        AddrType::V6 => {
            let Some(octets) = addr
                .get(..16)
                .and_then(|first| <[u8; 16]>::try_from(first).ok())
            else {
                return format!("<invalid ipv6: {} bytes>", addr.len());
            };

            Ipv6Addr::from(octets)
                .segments()
                .iter()
                .map(|segment| format!("{segment:x}"))
                .collect::<Vec<String>>()
                .join(":")
        }
    }
}

/// Extract a concrete IP from a request address, or `None` when the address is
/// a domain or the unspecified address (`0.0.0.0` / `::`), meaning "any".
fn expected_ip(addr_type: &AddrType, addr: &[u8]) -> Option<IpAddr> {
    let ip = match addr_type {
        AddrType::V4 => {
            let octets = addr
                .get(..4)
                .and_then(|first| <[u8; 4]>::try_from(first).ok())?;
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        AddrType::V6 => {
            let octets = addr
                .get(..16)
                .and_then(|first| <[u8; 16]>::try_from(first).ok())?;
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        AddrType::Domain => return None,
    };

    (!ip.is_unspecified()).then_some(ip)
}

/// A parsed RFC 1928 §7 UDP request header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpRequest<'a> {
    pub frag: u8,
    pub addr_type: AddrType,
    pub addr: &'a [u8],
    pub port: u16,
}

/// Parse a SOCKS5 UDP request header
/// (`RSV, RSV, FRAG, ATYP, DST.ADDR, DST.PORT`) from a byte slice.
///
/// Returns the header and the number of bytes consumed; the remaining bytes are
/// the datagram payload.
pub fn parse_udp_header(bytes: &[u8]) -> Result<(UdpRequest<'_>, usize), MerinoError> {
    let [_rsv, _rsv2, frag, atyp, rest @ ..] = bytes else {
        return Err(truncated());
    };
    let addr_type = AddrType::from(usize::from(*atyp))
        .ok_or(MerinoError::Socks(ResponseCode::AddrTypeNotSupported))?;

    let (addr, rest) = take_addr(rest, addr_type)?;
    let (port, rest) = take_port(rest)?;

    Ok((
        UdpRequest {
            frag: *frag,
            addr_type,
            addr,
            port,
        },
        bytes.len() - rest.len(),
    ))
}

/// Encode an RFC 1928 §7 UDP request header for `addr` with `FRAG = 0`.
pub fn encode_udp_header(addr: SocketAddr) -> Vec<u8> {
    let mut buf = Vec::with_capacity(22);
    buf.push(RESERVED);
    buf.push(RESERVED);
    buf.push(0);
    match addr {
        SocketAddr::V4(addr) => {
            buf.push(AddrType::V4 as u8);
            buf.extend_from_slice(&addr.ip().octets());
            buf.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            buf.push(AddrType::V6 as u8);
            buf.extend_from_slice(&addr.ip().octets());
            buf.extend_from_slice(&addr.port().to_be_bytes());
        }
    }
    buf
}

/// Proxy User Request
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SOCKSReq {
    pub version: u8,
    pub command: SockCommand,
    pub addr_type: AddrType,
    pub addr: Vec<u8>,
    pub port: u16,
}

/// Error used by the pure parsers when a message ends before all of its
/// declared fields have been read.
/// Split the first `len` bytes off the front of a frame.
///
/// Everything the parsers take off the wire goes through here, so the bounds
/// check lives in one place instead of at every indexing site.
fn take(bytes: &[u8], len: usize) -> Result<(&[u8], &[u8]), MerinoError> {
    if bytes.len() < len {
        return Err(truncated());
    }
    Ok(bytes.split_at(len))
}

/// Take the address described by `addr_type` off the front of a frame,
/// returning it with the bytes that follow.
fn take_addr(bytes: &[u8], addr_type: AddrType) -> Result<(&[u8], &[u8]), MerinoError> {
    match addr_type {
        AddrType::Domain => match bytes {
            [dlen, rest @ ..] => take(rest, usize::from(*dlen)),
            [] => Err(truncated()),
        },
        AddrType::V4 => take(bytes, 4),
        AddrType::V6 => take(bytes, 16),
    }
}

/// Take a big-endian port off the front of a frame.
fn take_port(bytes: &[u8]) -> Result<(u16, &[u8]), MerinoError> {
    match bytes {
        [hi, lo, rest @ ..] => Ok((u16::from(*hi) << 8 | u16::from(*lo), rest)),
        _ => Err(truncated()),
    }
}

pub(crate) fn truncated() -> MerinoError {
    MerinoError::Io(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "truncated SOCKS message",
    ))
}

/// Longest username or password in the list, or zero when it is empty.
///
/// This is the fixed width used by [`ct_eq`], so it is computed once per
/// server rather than per login.
fn credential_width(users: &[User]) -> usize {
    users
        .iter()
        .map(|user| user.username.len().max(user.password.len()))
        .max()
        .unwrap_or(0)
}

/// Compare two byte strings with the same work for every input length.
///
/// `width` is the longest credential this server stores, so the loop runs a
/// fixed number of iterations whatever the incoming bytes are: timing reveals
/// neither the stored credential length nor where the incoming value first
/// diverges. The length check is folded into the accumulator instead of
/// short-circuiting. A value longer than `width` is rejected by that length
/// mismatch — the wire caps credentials at 255 bytes, so it cannot spuriously
/// match.
///
/// Cost is proportional to `width` rather than to the actual length compared,
/// so the scan is measurably slower than the previous length-short-circuiting
/// version: `benches/parse.rs` measures 1.75x on a 10k-user list (110 -> 193
/// us of lookup) and no change for the small lists this proxy is normally run
/// with. Padding to the 255-byte wire maximum instead was measured at 46x
/// (4.1 ms), so the per-server width is what makes the trade bearable.
fn ct_eq(a: &[u8], b: &[u8], width: usize) -> bool {
    let mut diff = u8::from(a.len() != b.len());
    for i in 0..width {
        diff |= a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0);
    }
    diff == 0
}

/// Parse the SOCKS5 greeting (`VER, NMETHODS, METHODS..`) from a byte slice.
///
/// Returns `(version, nmethods, methods, consumed)`. Only the bytes belonging
/// to the greeting are inspected; trailing pipelined data is left untouched.
pub fn parse_greeting(bytes: &[u8]) -> Result<(u8, u8, Vec<u8>, usize), MerinoError> {
    let [version, nmethods, rest @ ..] = bytes else {
        return Err(truncated());
    };
    let methods = take(rest, usize::from(*nmethods))?.0.to_vec();
    let consumed = 2 + methods.len();

    Ok((*version, *nmethods, methods, consumed))
}

/// A parsed USERPASS sub-negotiation frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserPassRequest<'a> {
    pub version: u8,
    pub username: &'a [u8],
    pub password: &'a [u8],
}

/// Parse a USERPASS sub-negotiation frame
/// (`VER, ULEN, UNAME.., PLEN, PASSWD..`) from a byte slice.
///
/// Returns the parsed request and the number of bytes consumed.
pub fn parse_userpass(bytes: &[u8]) -> Result<(UserPassRequest<'_>, usize), MerinoError> {
    let [version, ulen, rest @ ..] = bytes else {
        return Err(truncated());
    };

    let (username, rest) = take(rest, usize::from(*ulen))?;

    let [plen, rest @ ..] = rest else {
        return Err(truncated());
    };
    let (password, rest) = take(rest, usize::from(*plen))?;

    Ok((
        UserPassRequest {
            version: *version,
            username,
            password,
        },
        bytes.len() - rest.len(),
    ))
}

/// Parse a SOCKS5 request (`VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT`) from a
/// byte slice.
///
/// Returns the request and the number of bytes consumed. The address length is
/// derived from `ATYP`, and the slice must contain exactly that many address
/// bytes plus the two port bytes; anything short yields `truncated()`.
pub fn parse_request(bytes: &[u8]) -> Result<(SOCKSReq, usize), MerinoError> {
    let [version, command, _rsv, atyp, rest @ ..] = bytes else {
        return Err(truncated());
    };
    let command = SockCommand::from(usize::from(*command))
        .ok_or(MerinoError::Socks(ResponseCode::CommandNotSupported))?;
    let addr_type = AddrType::from(usize::from(*atyp))
        .ok_or(MerinoError::Socks(ResponseCode::AddrTypeNotSupported))?;

    let (addr, rest) = take_addr(rest, addr_type)?;
    let (port, rest) = take_port(rest)?;

    Ok((
        SOCKSReq {
            version: *version,
            command,
            addr_type,
            addr: addr.to_vec(),
            port,
        },
        bytes.len() - rest.len(),
    ))
}

impl SOCKSReq {
    /// Parse a SOCKS Req from a TcpStream
    async fn from_stream<T>(stream: &mut T) -> Result<Self, MerinoError>
    where
        T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        // From rfc 1928 (S4), the SOCKS request is formed as follows:
        //
        //    +----+-----+-------+------+----------+----------+
        //    |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        //    +----+-----+-------+------+----------+----------+
        //    | 1  |  1  | X'00' |  1   | Variable |    2     |
        //    +----+-----+-------+------+----------+----------+
        //
        // Where:
        //
        //      o  VER    protocol version: X'05'
        //      o  CMD
        //         o  CONNECT X'01'
        //         o  BIND X'02'
        //         o  UDP ASSOCIATE X'03'
        //      o  RSV    RESERVED
        //      o  ATYP   address type of following address
        //         o  IP V4 address: X'01'
        //         o  DOMAINNAME: X'03'
        //         o  IP V6 address: X'04'
        //      o  DST.ADDR       desired destination address
        //      o  DST.PORT desired destination port in network octet
        //         order
        trace!("Server waiting for connect");
        // Read the fixed request header first so the address type is known.
        let mut header = [0u8; 4];
        stream.read_exact(&mut header).await?;
        trace!("Server received {:?}", header);

        if header[0] != SOCKS_VERSION {
            warn!("from_stream Unsupported version: SOCKS{}", header[0]);
            return Err(MerinoError::Socks(ResponseCode::Failure));
        }

        // Reject unsupported commands / address types before reading the
        // variable-length body, matching the original error replies. The
        // error is returned (not written here) so `run_client` can send the
        // correct reply before shutting the stream down.
        if SockCommand::from(header[1] as usize).is_none() {
            warn!("Invalid Command");
            return Err(MerinoError::Socks(ResponseCode::CommandNotSupported));
        }
        let addr_type = match AddrType::from(header[3] as usize) {
            Some(addr) => addr,
            None => {
                error!("No Addr");
                return Err(MerinoError::Socks(ResponseCode::AddrTypeNotSupported));
            }
        };

        // Assemble the complete frame byte-for-byte, then hand it to the pure
        // parser. Keeping the wire format in one place makes it directly
        // fuzzable and avoids duplicated length arithmetic.
        let mut frame = Vec::with_capacity(22);
        frame.extend_from_slice(&header);

        match addr_type {
            AddrType::Domain => {
                let mut dlen = [0u8; 1];
                stream.read_exact(&mut dlen).await?;
                frame.push(dlen[0]);
                let mut domain = vec![0u8; dlen[0] as usize];
                stream.read_exact(&mut domain).await?;
                frame.extend_from_slice(&domain);
            }
            AddrType::V4 => {
                let mut addr = [0u8; 4];
                stream.read_exact(&mut addr).await?;
                frame.extend_from_slice(&addr);
            }
            AddrType::V6 => {
                let mut addr = [0u8; 16];
                stream.read_exact(&mut addr).await?;
                frame.extend_from_slice(&addr);
            }
        }

        // Read DST.port
        let mut port = [0u8; 2];
        stream.read_exact(&mut port).await?;
        frame.extend_from_slice(&port);

        let (req, _consumed) = parse_request(&frame)?;
        Ok(req)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    // Tests may index for brevity: a panic here is a failed test, not a
    // production hazard.
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    #[test]
    fn addr_type_from_byte() {
        assert_eq!(AddrType::from(1), Some(AddrType::V4));
        assert_eq!(AddrType::from(3), Some(AddrType::Domain));
        assert_eq!(AddrType::from(4), Some(AddrType::V6));
        assert_eq!(AddrType::from(0), None);
        assert_eq!(AddrType::from(2), None);
        assert_eq!(AddrType::from(255), None);
    }

    #[test]
    fn sock_command_from_byte() {
        assert!(matches!(SockCommand::from(1), Some(SockCommand::Connect)));
        assert!(matches!(SockCommand::from(2), Some(SockCommand::Bind)));
        assert!(matches!(
            SockCommand::from(3),
            Some(SockCommand::UdpAssosiate)
        ));
        assert!(SockCommand::from(0).is_none());
        assert!(SockCommand::from(4).is_none());
        assert!(SockCommand::from(255).is_none());
    }

    #[test]
    fn pretty_print_ipv4() {
        assert_eq!(
            pretty_print_addr(&AddrType::V4, &[127, 0, 0, 1]),
            "127.0.0.1"
        );
        assert_eq!(pretty_print_addr(&AddrType::V4, &[8, 8, 4, 4]), "8.8.4.4");
    }

    #[test]
    fn pretty_print_ipv6() {
        let raw = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets();
        assert_eq!(
            pretty_print_addr(&AddrType::V6, &raw),
            "2001:db8:0:0:0:0:0:1"
        );
    }

    #[test]
    fn pretty_print_domain() {
        assert_eq!(
            pretty_print_addr(&AddrType::Domain, b"example.com"),
            "example.com"
        );
    }

    #[test]
    fn pretty_print_domain_escapes_control_bytes() {
        // A client-supplied name must never reach a log verbatim: ANSI escape,
        // CR/LF injection and non-ASCII bytes are all escaped.
        assert_eq!(
            pretty_print_addr(&AddrType::Domain, b"\x1b[31mexample.com"),
            "\\x1b[31mexample.com"
        );
        assert_eq!(
            pretty_print_addr(&AddrType::Domain, b"a\x00b\x0ac\x0dd\xff"),
            "a\\x00b\\x0ac\\x0dd\\xff"
        );
        // Printable ASCII, spaces included, is passed through untouched.
        assert_eq!(pretty_print_addr(&AddrType::Domain, b"a b~!"), "a b~!");
    }

    #[test]
    fn socks_reply_wire_format() {
        let success = SocksReply::new(ResponseCode::Success);
        assert_eq!(success.buf, [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);

        let failure = SocksReply::new(ResponseCode::ConnectionRefused);
        assert_eq!(failure.buf, [0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn method_and_response_codes_match_rfc() {
        assert_eq!(AuthMethods::NoAuth as u8, 0x00);
        assert_eq!(AuthMethods::UserPass as u8, 0x02);
        assert_eq!(AuthMethods::NoMethods as u8, 0xFF);

        assert_eq!(ResponseCode::Success as u8, 0x00);
        assert_eq!(ResponseCode::Failure as u8, 0x01);
        assert_eq!(ResponseCode::RuleFailure as u8, 0x02);
        assert_eq!(ResponseCode::NetworkUnreachable as u8, 0x03);
        assert_eq!(ResponseCode::HostUnreachable as u8, 0x04);
        assert_eq!(ResponseCode::ConnectionRefused as u8, 0x05);
        assert_eq!(ResponseCode::TtlExpired as u8, 0x06);
        assert_eq!(ResponseCode::CommandNotSupported as u8, 0x07);
        assert_eq!(ResponseCode::AddrTypeNotSupported as u8, 0x08);
    }

    #[test]
    fn merino_error_to_response_code() {
        let socks: ResponseCode = MerinoError::Socks(ResponseCode::HostUnreachable).into();
        assert_eq!(socks as u8, ResponseCode::HostUnreachable as u8);

        let io: ResponseCode = MerinoError::Io(io::Error::other("boom")).into();
        assert_eq!(io as u8, ResponseCode::Failure as u8);
    }

    #[test]
    fn client_disconnects_are_classified() {
        for kind in [
            io::ErrorKind::UnexpectedEof,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::BrokenPipe,
        ] {
            assert!(is_disconnect_kind(kind));
            assert!(is_client_disconnect(&MerinoError::Io(io::Error::new(
                kind, "gone"
            ))));
        }

        // Genuine proxy faults and unrelated I/O errors must still be reported.
        assert!(!is_client_disconnect(&MerinoError::Socks(
            ResponseCode::HostUnreachable
        )));
        assert!(!is_client_disconnect(&MerinoError::Io(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "nope"
        ))));
        assert!(!is_disconnect_kind(io::ErrorKind::PermissionDenied));
    }

    #[test]
    fn default_connect_timeout_is_reasonable() {
        // Guards against reintroducing the old 500 ms fallback, which was too
        // short for any destination beyond the local network.
        assert!(DEFAULT_CONNECT_TIMEOUT >= Duration::from_secs(5));
    }

    #[test]
    fn connect_timeout_maps_to_ttl_expired() {
        assert!(matches!(
            connect_timeout_error(),
            MerinoError::Socks(ResponseCode::TtlExpired)
        ));
    }

    #[tokio::test]
    async fn addr_to_socket_ipv4() {
        let addr = addr_to_socket(&AddrType::V4, &[127, 0, 0, 1], 8080)
            .await
            .unwrap();
        assert_eq!(
            addr,
            vec![SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(127, 0, 0, 1),
                8080
            ))]
        );
    }

    #[tokio::test]
    async fn addr_to_socket_ipv6() {
        let raw = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets();
        let addr = addr_to_socket(&AddrType::V6, &raw, 443).await.unwrap();
        assert_eq!(
            addr,
            vec![SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                443,
                0,
                0
            ))]
        );
    }

    #[test]
    fn user_deserializes_from_csv() {
        let data = "username,password\nalice,secret\n";
        let mut rdr = csv::Reader::from_reader(data.as_bytes());
        let users: Vec<User> = rdr.deserialize().map(|r| r.unwrap()).collect();
        assert_eq!(
            users,
            vec![User {
                username: "alice".into(),
                password: "secret".into(),
            }]
        );
    }

    #[test]
    fn parse_greeting_basic() {
        let (version, nmethods, methods, consumed) =
            parse_greeting(&[0x05, 0x02, 0x00, 0x02]).unwrap();
        assert_eq!(version, 0x05);
        assert_eq!(nmethods, 0x02);
        assert_eq!(methods, vec![0x00, 0x02]);
        assert_eq!(consumed, 4);
    }

    #[test]
    fn parse_greeting_leaves_pipelined_bytes() {
        let (_, _, methods, consumed) = parse_greeting(&[0x05, 0x01, 0x00, 0xAA, 0xBB]).unwrap();
        assert_eq!(methods, vec![0x00]);
        assert_eq!(consumed, 3);
    }

    #[test]
    fn parse_greeting_truncated_errors() {
        assert!(parse_greeting(&[]).is_err());
        assert!(parse_greeting(&[0x05]).is_err());
        // claims two methods but supplies one
        assert!(parse_greeting(&[0x05, 0x02, 0x00]).is_err());
    }

    #[test]
    fn parse_userpass_basic() {
        let frame = [0x01, 0x02, b'a', b'b', 0x03, b'x', b'y', b'z'];
        let (parsed, consumed) = parse_userpass(&frame).unwrap();
        assert_eq!(parsed.version, 0x01);
        assert_eq!(parsed.username, b"ab");
        assert_eq!(parsed.password, b"xyz");
        assert_eq!(consumed, frame.len());
    }

    #[test]
    fn parse_userpass_truncated_errors() {
        assert!(parse_userpass(&[]).is_err());
        assert!(parse_userpass(&[0x01, 0x05, b'a']).is_err());
        // no password length byte
        assert!(parse_userpass(&[0x01, 0x01, b'a']).is_err());
        // password length exceeds body
        assert!(parse_userpass(&[0x01, 0x01, b'a', 0x04, b'b']).is_err());
    }

    #[test]
    fn parse_request_ipv4_roundtrip() {
        let frame = [0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x1F, 0x90];
        let (req, consumed) = parse_request(&frame).unwrap();
        assert_eq!(req.version, 0x05);
        assert_eq!(req.command, SockCommand::Connect);
        assert_eq!(req.addr_type, AddrType::V4);
        assert_eq!(req.addr, vec![127, 0, 0, 1]);
        assert_eq!(req.port, 8080);
        assert_eq!(consumed, frame.len());
    }

    #[test]
    fn parse_request_domain_roundtrip() {
        let mut frame = vec![0x05, 0x01, 0x00, 0x03, 11];
        frame.extend_from_slice(b"example.com");
        frame.extend_from_slice(&443u16.to_be_bytes());
        let (req, consumed) = parse_request(&frame).unwrap();
        assert_eq!(req.addr_type, AddrType::Domain);
        assert_eq!(req.addr, b"example.com");
        assert_eq!(req.port, 443);
        assert_eq!(consumed, frame.len());
    }

    #[test]
    fn parse_request_rejects_bad_command_and_addr_type() {
        assert!(matches!(
            parse_request(&[0x05, 0x09, 0x00, 0x01, 0, 0, 0, 0, 0, 0]),
            Err(MerinoError::Socks(ResponseCode::CommandNotSupported))
        ));
        assert!(matches!(
            parse_request(&[0x05, 0x01, 0x00, 0x02, 0, 0, 0, 0]),
            Err(MerinoError::Socks(ResponseCode::AddrTypeNotSupported))
        ));
    }

    #[test]
    fn parse_request_truncated_errors() {
        assert!(parse_request(&[0x05, 0x01, 0x00]).is_err());
        // claims 4-byte IPv4 but supplies 3
        assert!(parse_request(&[0x05, 0x01, 0x00, 0x01, 1, 2, 3]).is_err());
        // full address but no port
        assert!(parse_request(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00]).is_err());
        // domain length exceeds body
        assert!(parse_request(&[0x05, 0x01, 0x00, 0x03, 200, b'a']).is_err());
    }

    #[test]
    fn pretty_print_short_addresses_do_not_panic() {
        assert!(pretty_print_addr(&AddrType::V4, &[1, 2]).contains("invalid"));
        assert!(pretty_print_addr(&AddrType::V6, &[1, 2, 3]).contains("invalid"));
    }

    #[test]
    fn connect_error_maps_network_failures_to_reply_codes() {
        let code_of = |kind: io::ErrorKind| match connect_error(io::Error::from(kind)) {
            MerinoError::Socks(code) => code,
            other => panic!("expected a SOCKS reply code, got {other:?}"),
        };

        assert!(matches!(
            code_of(io::ErrorKind::ConnectionRefused),
            ResponseCode::ConnectionRefused
        ));
        assert!(matches!(
            code_of(io::ErrorKind::NetworkUnreachable),
            ResponseCode::NetworkUnreachable
        ));
        assert!(matches!(
            code_of(io::ErrorKind::NetworkDown),
            ResponseCode::NetworkUnreachable
        ));
        assert!(matches!(
            code_of(io::ErrorKind::HostUnreachable),
            ResponseCode::HostUnreachable
        ));
        assert!(matches!(
            code_of(io::ErrorKind::AddrNotAvailable),
            ResponseCode::HostUnreachable
        ));

        // Anything the client cannot act on stays a generic failure.
        assert!(matches!(
            connect_error(io::Error::from(io::ErrorKind::PermissionDenied)),
            MerinoError::Io(_)
        ));
    }

    #[test]
    fn dns_failure_is_host_unreachable() {
        assert!(matches!(
            dns_failure_error(),
            MerinoError::Socks(ResponseCode::HostUnreachable)
        ));
    }

    #[test]
    fn ct_eq_is_equality() {
        let width = 8;
        assert!(ct_eq(b"secret", b"secret", width));
        assert!(!ct_eq(b"secret", b"secrez", width));
        assert!(!ct_eq(b"secret", b"secret2", width));
        assert!(!ct_eq(b"", b"x", width));
        assert!(ct_eq(b"", b"", width));
        // A value longer than the configured width still cannot match a
        // shorter one by being truncated.
        assert!(!ct_eq(b"secrets!", b"secret", width));
        assert!(!ct_eq(b"secret", b"secrets!", width));
        // Embedded NULs are compared rather than treated as padding.
        assert!(!ct_eq(b"sec\0ret", b"secret", width));
    }

    #[test]
    fn credential_width_is_the_longest_value() {
        assert_eq!(credential_width(&[]), 0);
        assert_eq!(
            credential_width(&[User::new("alice", "secret")]),
            "secret".len()
        );
        assert_eq!(
            credential_width(&[User::new("alice", "secret"), User::new("bob", "hunter2!")]),
            "hunter2!".len()
        );
    }

    #[tokio::test]
    async fn new_no_auth_builds_client() {
        let (_peer, stream) = tokio::io::duplex(64);
        let mut client = SOCKClient::new_no_auth(stream, Some(Duration::from_secs(1)));
        assert_eq!(client.auth_nmethods, 0);
        assert_eq!(client.socks_version, 0);
        assert_eq!(client.auth_methods.as_slice(), &[AuthMethods::NoAuth as u8]);
        let _ = client.stream_mut();
    }

    #[tokio::test]
    async fn addr_to_socket_rejects_short_addresses() {
        assert!(addr_to_socket(&AddrType::V4, &[1, 2, 3], 0).await.is_err());
        assert!(addr_to_socket(&AddrType::V6, &[0u8; 15], 0).await.is_err());
    }

    #[test]
    fn parse_request_truncated_domain_and_v6() {
        // domain ATYP with no length byte
        assert!(parse_request(&[0x05, 0x01, 0x00, 0x03]).is_err());
        // IPv6 ATYP with a short address
        assert!(parse_request(&[0x05, 0x01, 0x00, 0x04, 0, 0, 0, 0]).is_err());
    }

    #[test]
    fn socks_reply_with_ipv4_bound_addr() {
        let reply = SocksReply::with_addr(
            ResponseCode::Success,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 4321)),
        );
        let port = 4321u16.to_be_bytes();
        assert_eq!(
            reply.as_bytes(),
            &[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, port[0], port[1]]
        );
    }

    #[test]
    fn socks_reply_with_ipv6_bound_addr() {
        let reply = SocksReply::with_addr(
            ResponseCode::Success,
            SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                443,
                0,
                0,
            )),
        );
        assert_eq!(reply.as_bytes().len(), 22);
        assert_eq!(reply.as_bytes()[0], 0x05);
        assert_eq!(reply.as_bytes()[1], 0x00);
        assert_eq!(reply.as_bytes()[3], 0x04);
        assert_eq!(
            &reply.as_bytes()[4..20],
            &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );
        assert_eq!(&reply.as_bytes()[20..22], &443u16.to_be_bytes());
    }

    #[test]
    fn parse_udp_header_ipv4() {
        let frame = [0, 0, 0, 0x01, 127, 0, 0, 1, 0x1F, 0x90, b'h', b'i'];
        let (header, consumed) = parse_udp_header(&frame).unwrap();
        assert_eq!(header.frag, 0);
        assert_eq!(header.addr_type, AddrType::V4);
        assert_eq!(header.addr, &[127, 0, 0, 1]);
        assert_eq!(header.port, 8080);
        assert_eq!(consumed, 10);
        assert_eq!(&frame[consumed..], b"hi");
    }

    #[test]
    fn parse_udp_header_domain_and_frag() {
        let mut frame = vec![0, 0, 0x03, 0x03, 11];
        frame.extend_from_slice(b"example.com");
        frame.extend_from_slice(&443u16.to_be_bytes());
        let (header, consumed) = parse_udp_header(&frame).unwrap();
        assert_eq!(header.frag, 0x03);
        assert_eq!(header.addr_type, AddrType::Domain);
        assert_eq!(header.addr, b"example.com");
        assert_eq!(header.port, 443);
        assert_eq!(consumed, frame.len());
    }

    #[test]
    fn parse_udp_header_rejects_truncated_and_bad_type() {
        assert!(parse_udp_header(&[]).is_err());
        assert!(parse_udp_header(&[0, 0, 0]).is_err());
        // ATYP 0x02 is reserved
        assert!(matches!(
            parse_udp_header(&[0, 0, 0, 0x02]),
            Err(MerinoError::Socks(ResponseCode::AddrTypeNotSupported))
        ));
        // claims IPv4 but only 3 address bytes
        assert!(parse_udp_header(&[0, 0, 0, 0x01, 1, 2, 3]).is_err());
        // address present but no port
        assert!(parse_udp_header(&[0, 0, 0, 0x01, 127, 0, 0, 1, 0x00]).is_err());
    }

    #[test]
    fn encode_udp_header_roundtrips() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 9000));
        let encoded = encode_udp_header(addr);
        assert_eq!(encoded[0], 0);
        assert_eq!(encoded[1], 0);
        assert_eq!(encoded[2], 0);
        let (header, consumed) = parse_udp_header(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(header.addr, &[127, 0, 0, 1]);
        assert_eq!(header.port, 9000);
    }

    #[test]
    fn expected_ip_only_accepts_concrete_addresses() {
        assert_eq!(
            expected_ip(&AddrType::V4, &[127, 0, 0, 1]),
            Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
        );
        assert_eq!(expected_ip(&AddrType::V4, &[0, 0, 0, 0]), None);
        assert_eq!(expected_ip(&AddrType::Domain, b"example.com"), None);
        assert_eq!(expected_ip(&AddrType::V4, &[1, 2]), None);
    }

    #[test]
    fn expected_ip_handles_ipv6() {
        let octets = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets();
        assert_eq!(
            expected_ip(&AddrType::V6, &octets),
            Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)))
        );
        assert_eq!(expected_ip(&AddrType::V6, &[0u8; 16]), None);
        assert_eq!(expected_ip(&AddrType::V6, &[0u8; 8]), None);
    }

    #[test]
    fn parse_udp_header_truncates_domain_and_ipv6() {
        // domain ATYP with no length byte
        assert!(parse_udp_header(&[0, 0, 0, 0x03]).is_err());
        // declared domain length exceeds the body
        assert!(parse_udp_header(&[0, 0, 0, 0x03, 200, b'a']).is_err());
        // IPv6 ATYP with a short address
        assert!(parse_udp_header(&[0, 0, 0, 0x04, 1, 2, 3]).is_err());
        assert!(
            parse_udp_header(&[0, 0, 0, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
                .is_err()
        );
    }

    #[test]
    fn encode_udp_header_ipv6_roundtrips() {
        let ip6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let addr = SocketAddr::V6(SocketAddrV6::new(ip6, 4444, 0, 0));
        let encoded = encode_udp_header(addr);
        assert_eq!(&encoded[..4], &[0, 0, 0, 0x04]);
        let (header, consumed) = parse_udp_header(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(header.addr, &ip6.octets()[..]);
        assert_eq!(header.port, 4444);
    }

    #[test]
    fn bind_listeners_reports_empty_input() {
        let err = bind_listeners(&[]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AddrNotAvailable);
    }

    #[tokio::test]
    async fn bind_listeners_reports_last_failure_when_none_succeed() {
        let a = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let b = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addrs = vec![a.local_addr().unwrap(), b.local_addr().unwrap()];
        let err = bind_listeners(&addrs).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
    }

    #[tokio::test]
    async fn bind_listeners_skips_failed_addresses() {
        let taken = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let taken_addr = taken.local_addr().unwrap();
        let listeners = bind_listeners(&[taken_addr, "127.0.0.1:0".parse().unwrap()]).unwrap();
        assert_eq!(listeners.len(), 1);
        assert_ne!(listeners[0].local_addr().unwrap(), taken_addr);
    }

    #[tokio::test]
    async fn handle_client_relays_a_prepared_request() {
        let (mut peer, stream) = tokio::io::duplex(1024);
        let mut client = SOCKClient::new(
            stream,
            Arc::new(Vec::new()),
            Arc::new(vec![AuthMethods::NoAuth as u8]),
            None,
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 16];
            let n = sock.read(&mut buf).await.unwrap_or(0);
            let _ = sock.write_all(&buf[..n]).await;
        });

        let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
        req.extend_from_slice(&target.port().to_be_bytes());
        peer.write_all(&req).await.unwrap();

        let relay = tokio::spawn(async move { client.handle_client().await });

        let mut reply = [0u8; 10];
        peer.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0x00);

        peer.write_all(b"hi").await.unwrap();
        let mut echoed = [0u8; 2];
        peer.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hi");

        drop(peer);
        assert_eq!(relay.await.unwrap().unwrap(), 2);
        echo.abort();
    }

    #[tokio::test]
    async fn auth_failure_replies_once_and_closes() {
        let (mut peer, stream) = tokio::io::duplex(1024);
        let mut client = SOCKClient::new(
            stream,
            Arc::new(vec![User::new("alice", "secret")]),
            Arc::new(vec![AuthMethods::UserPass as u8]),
            None,
        );
        client.set_handshake_timeout(Duration::from_secs(5));

        let handshake = tokio::spawn(async move { client.init().await });

        // Greeting offering USERPASS.
        peer.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
        let mut selection = [0u8; 2];
        peer.read_exact(&mut selection).await.unwrap();
        assert_eq!(selection, [0x05, 0x02]);

        // Wrong password.
        let mut frame = vec![0x01, 5];
        frame.extend_from_slice(b"alice");
        frame.push(6);
        frame.extend_from_slice(b"wrong!");
        peer.write_all(&frame).await.unwrap();

        let mut response = [0u8; 2];
        peer.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [0x01, 0x01]);

        let err = handshake
            .await
            .unwrap()
            .expect_err("a rejected login must fail the handshake");
        assert!(matches!(err, MerinoError::Socks(ResponseCode::Failure)));

        // Even if the client pushes a request past the failed login it is not
        // served, and no second reply follows the failure.
        let mut request = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
        request.extend_from_slice(&80u16.to_be_bytes());
        let _ = peer.write_all(&request).await;

        let mut trailing = Vec::new();
        peer.read_to_end(&mut trailing).await.unwrap();
        assert!(trailing.is_empty(), "unexpected bytes: {trailing:?}");
    }

    #[tokio::test]
    async fn handle_client_times_out_within_the_handshake_budget() {
        let (peer, stream) = tokio::io::duplex(64);
        let mut client = SOCKClient::new(
            stream,
            Arc::new(Vec::new()),
            Arc::new(vec![AuthMethods::NoAuth as u8]),
            None,
        );
        client.set_handshake_timeout(Duration::from_millis(50));

        // The peer never speaks, so the read must be abandoned once the
        // handshake budget runs out instead of hanging forever.
        let err = client
            .handle_client()
            .await
            .expect_err("a silent client must not be served");
        assert!(matches!(err, MerinoError::Socks(ResponseCode::TtlExpired)));
        drop(peer);
    }

    #[tokio::test]
    async fn from_stream_rejects_unsupported_version() {
        let (mut peer, stream) = tokio::io::duplex(64);
        peer.write_all(&[0x04, 0x01, 0x00, 0x01]).await.unwrap();
        let mut stream = stream;
        let err = SOCKSReq::from_stream(&mut stream).await.unwrap_err();
        assert!(matches!(err, MerinoError::Socks(ResponseCode::Failure)));
    }

    #[tokio::test]
    async fn from_stream_parses_ipv6_request() {
        let (mut peer, stream) = tokio::io::duplex(64);
        let mut frame = vec![0x05, 0x01, 0x00, 0x04];
        frame.extend_from_slice(&[0u8; 16]);
        frame.extend_from_slice(&[0x00, 0x50]);
        peer.write_all(&frame).await.unwrap();
        let mut stream = stream;
        let req = SOCKSReq::from_stream(&mut stream).await.unwrap();
        assert_eq!(req.addr_type, AddrType::V6);
        assert_eq!(req.addr.len(), 16);
        assert_eq!(req.port, 80);
    }

    #[tokio::test]
    async fn bind_all_reports_bind_failure() {
        let taken = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = taken.local_addr().unwrap().port();
        let err = bind_all("127.0.0.1", port).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
    }
}
