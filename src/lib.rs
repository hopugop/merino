#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate log;
use snafu::Snafu;

mod actors;
pub use actors::{SocksConnection, SocksServer};

use std::collections::HashSet;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, lookup_host};
use tokio::sync::Semaphore;
use tokio::time::timeout;

/// Version of socks
const SOCKS_VERSION: u8 = 0x05;

const RESERVED: u8 = 0x00;

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
    buf: [u8; 10],
}

impl SocksReply {
    pub fn new(status: ResponseCode) -> Self {
        let buf = [
            // VER
            SOCKS_VERSION,
            // REP
            status as u8,
            // RSV
            RESERVED,
            // ATYP
            1,
            // BND.ADDR
            0,
            0,
            0,
            0,
            // BND.PORT
            0,
            0,
        ];
        Self { buf }
    }

    pub async fn send<T>(&self, stream: &mut T) -> io::Result<()>
    where
        T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        stream.write_all(&self.buf[..]).await?;
        Ok(())
    }

    /// The raw 10-byte wire representation of this reply.
    pub fn as_bytes(&self) -> &[u8; 10] {
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

    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("no addresses resolved for {ip}"),
        ));
    }

    let mut listeners = Vec::new();
    let mut last_err = None;
    for addr in addrs {
        match TcpListener::bind(addr).await {
            Ok(listener) => {
                info!("Listening on {}", listener.local_addr()?);
                listeners.push(listener);
            }
            Err(e) => {
                warn!("Failed to bind {}: {}", addr, e);
                last_err = Some(e);
            }
        }
    }

    if listeners.is_empty() {
        return Err(last_err.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("could not bind any address for {ip}:{port}"),
            )
        }));
    }

    Ok(listeners)
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
            set.spawn(async move {
                loop {
                    let permit = match semaphore.clone().acquire_owned().await {
                        Ok(permit) => permit,
                        Err(_) => break,
                    };
                    match listener.accept().await {
                        Ok((stream, client_addr)) => {
                            let client = SOCKClient::new(
                                stream,
                                users.clone(),
                                auth_methods.clone(),
                                timeout,
                            );
                            tokio::spawn(async move {
                                let _permit = permit;
                                run_client(client, client_addr).await;
                            });
                        }
                        Err(e) => {
                            warn!("Accept error: {:?}", e);
                            drop(permit);
                        }
                    }
                }
            });
        }
        while set.join_next().await.is_some() {}
    }
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
            error!("Error! {:?}, client: {:?}", error, client_addr);

            if let Err(e) = SocksReply::new(error.into()).send(&mut client.stream).await {
                warn!("Failed to send error code: {:?}", e);
            }

            if let Err(e) = client.shutdown().await {
                warn!("Failed to shutdown TcpStream: {:?}", e);
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
        SOCKClient {
            stream,
            auth_nmethods: 0,
            socks_version: 0,
            authed_users,
            auth_methods,
            timeout,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
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
        }
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
    /// The comparison is written to avoid early exit on a mismatch and to
    /// inspect every configured user, so the work done does not reveal which
    /// entry (if any) matched or how far a wrong password got.
    fn authed(&self, user: &User) -> bool {
        let mut found = false;
        for candidate in self.authed_users.iter() {
            let username_ok = ct_eq(user.username.as_bytes(), candidate.username.as_bytes());
            let password_ok = ct_eq(user.password.as_bytes(), candidate.password.as_bytes());
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

            if parsed.version != 0x01 {
                warn!(
                    "Invalid USERPASS sub-negotiation version: {}",
                    parsed.version
                );
                let response = [1, ResponseCode::Failure as u8];
                self.stream.write_all(&response).await?;
                self.shutdown().await?;
                return Err(MerinoError::Socks(ResponseCode::Failure));
            }

            let username = String::from_utf8_lossy(parsed.username).to_string();
            let password = String::from_utf8_lossy(parsed.password).to_string();

            let user = User { username, password };

            // Authenticate passwords
            if self.authed(&user) {
                debug!("Access Granted. User: {}", user.username);
                let response = [1, ResponseCode::Success as u8];
                self.stream.write_all(&response).await?;
            } else {
                debug!("Access Denied. User: {}", user.username);
                let response = [1, ResponseCode::Failure as u8];
                self.stream.write_all(&response).await?;

                // Shutdown
                self.shutdown().await?;
            }

            Ok(())
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
    /// directly.
    pub async fn handle_client(&mut self) -> Result<usize, MerinoError> {
        let req = SOCKSReq::from_stream(&mut self.stream).await?;
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

                let sock_addr = addr_to_socket(&req.addr_type, &req.addr, req.port).await?;

                trace!("Connecting to: {:?}", sock_addr);

                let time_out = if let Some(time_out) = self.timeout {
                    time_out
                } else {
                    Duration::from_millis(500)
                };

                let mut target =
                    timeout(
                        time_out,
                        async move { TcpStream::connect(&sock_addr[..]).await },
                    )
                    .await
                    .map_err(|_| MerinoError::Socks(ResponseCode::ConnectionRefused))?
                    .map_err(|e| match e.kind() {
                        io::ErrorKind::ConnectionRefused => {
                            MerinoError::Socks(ResponseCode::ConnectionRefused)
                        }
                        _ => MerinoError::Io(e),
                    })?;

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
            SockCommand::Bind => Err(MerinoError::Socks(ResponseCode::CommandNotSupported)),
            SockCommand::UdpAssosiate => Err(MerinoError::Socks(ResponseCode::CommandNotSupported)),
        }
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

/// Convert an address and AddrType to a SocketAddr
async fn addr_to_socket(
    addr_type: &AddrType,
    addr: &[u8],
    port: u16,
) -> io::Result<Vec<SocketAddr>> {
    match addr_type {
        AddrType::V6 => {
            if addr.len() < 16 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "IPv6 address must be 16 bytes",
                ));
            }
            let new_addr = (0..8)
                .map(|x| {
                    trace!("{} and {}", x * 2, (x * 2) + 1);
                    (u16::from(addr[x * 2]) << 8) | u16::from(addr[(x * 2) + 1])
                })
                .collect::<Vec<u16>>();

            Ok(vec![SocketAddr::from(SocketAddrV6::new(
                Ipv6Addr::new(
                    new_addr[0],
                    new_addr[1],
                    new_addr[2],
                    new_addr[3],
                    new_addr[4],
                    new_addr[5],
                    new_addr[6],
                    new_addr[7],
                ),
                port,
                0,
                0,
            ))])
        }
        AddrType::V4 => {
            if addr.len() < 4 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "IPv4 address must be 4 bytes",
                ));
            }
            Ok(vec![SocketAddr::from(SocketAddrV4::new(
                Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]),
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

/// Convert an AddrType and address to String
pub fn pretty_print_addr(addr_type: &AddrType, addr: &[u8]) -> String {
    match addr_type {
        AddrType::Domain => String::from_utf8_lossy(addr).to_string(),
        AddrType::V4 => {
            if addr.len() < 4 {
                return format!("<invalid ipv4: {} bytes>", addr.len());
            }
            addr.iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<String>>()
                .join(".")
        }
        AddrType::V6 => {
            if addr.len() < 16 {
                return format!("<invalid ipv6: {} bytes>", addr.len());
            }
            let addr_16 = (0..8)
                .map(|x| (u16::from(addr[x * 2]) << 8) | u16::from(addr[(x * 2) + 1]))
                .collect::<Vec<u16>>();

            addr_16
                .iter()
                .map(|x| format!("{:x}", x))
                .collect::<Vec<String>>()
                .join(":")
        }
    }
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
pub(crate) fn truncated() -> MerinoError {
    MerinoError::Io(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "truncated SOCKS message",
    ))
}

/// Compare two byte strings without an early exit on the first differing byte.
///
/// The length is still observable, but this avoids leaking *where* a username
/// or password first diverges through timing.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Parse the SOCKS5 greeting (`VER, NMETHODS, METHODS..`) from a byte slice.
///
/// Returns `(version, nmethods, methods, consumed)`. Only the bytes belonging
/// to the greeting are inspected; trailing pipelined data is left untouched.
pub fn parse_greeting(bytes: &[u8]) -> Result<(u8, u8, Vec<u8>, usize), MerinoError> {
    if bytes.len() < 2 {
        return Err(truncated());
    }
    let version = bytes[0];
    let nmethods = bytes[1];
    let consumed = 2 + usize::from(nmethods);
    if bytes.len() < consumed {
        return Err(truncated());
    }
    Ok((version, nmethods, bytes[2..consumed].to_vec(), consumed))
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
    if bytes.len() < 2 {
        return Err(truncated());
    }
    let version = bytes[0];
    let ulen = usize::from(bytes[1]);
    let mut pos = 2;
    if bytes.len() < pos + ulen {
        return Err(truncated());
    }
    let username = &bytes[pos..pos + ulen];
    pos += ulen;

    if bytes.len() < pos + 1 {
        return Err(truncated());
    }
    let plen = usize::from(bytes[pos]);
    pos += 1;
    if bytes.len() < pos + plen {
        return Err(truncated());
    }
    let password = &bytes[pos..pos + plen];
    pos += plen;

    Ok((
        UserPassRequest {
            version,
            username,
            password,
        },
        pos,
    ))
}

/// Parse a SOCKS5 request (`VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT`) from a
/// byte slice.
///
/// Returns the request and the number of bytes consumed. The address length is
/// derived from `ATYP`, and the slice must contain exactly that many address
/// bytes plus the two port bytes; anything short yields `truncated()`.
pub fn parse_request(bytes: &[u8]) -> Result<(SOCKSReq, usize), MerinoError> {
    if bytes.len() < 4 {
        return Err(truncated());
    }
    let version = bytes[0];
    let command = SockCommand::from(bytes[1] as usize)
        .ok_or(MerinoError::Socks(ResponseCode::CommandNotSupported))?;
    let addr_type = AddrType::from(bytes[3] as usize)
        .ok_or(MerinoError::Socks(ResponseCode::AddrTypeNotSupported))?;

    let mut pos = 4;
    let addr: Vec<u8> = match addr_type {
        AddrType::Domain => {
            if bytes.len() < pos + 1 {
                return Err(truncated());
            }
            let dlen = usize::from(bytes[pos]);
            pos += 1;
            if bytes.len() < pos + dlen {
                return Err(truncated());
            }
            let addr = bytes[pos..pos + dlen].to_vec();
            pos += dlen;
            addr
        }
        AddrType::V4 => {
            if bytes.len() < pos + 4 {
                return Err(truncated());
            }
            let addr = bytes[pos..pos + 4].to_vec();
            pos += 4;
            addr
        }
        AddrType::V6 => {
            if bytes.len() < pos + 16 {
                return Err(truncated());
            }
            let addr = bytes[pos..pos + 16].to_vec();
            pos += 16;
            addr
        }
    };

    if bytes.len() < pos + 2 {
        return Err(truncated());
    }
    let port = (u16::from(bytes[pos]) << 8) | u16::from(bytes[pos + 1]);
    pos += 2;

    Ok((
        SOCKSReq {
            version,
            command,
            addr_type,
            addr,
            port,
        },
        pos,
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
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
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
    fn ct_eq_is_equality() {
        assert!(ct_eq(b"secret", b"secret"));
        assert!(!ct_eq(b"secret", b"secrez"));
        assert!(!ct_eq(b"secret", b"secret2"));
        assert!(!ct_eq(b"", b"x"));
        assert!(ct_eq(b"", b""));
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

    #[tokio::test]
    async fn handle_client_reads_and_rejects_bind() {
        let (mut peer, stream) = tokio::io::duplex(64);
        let mut client = SOCKClient::new_no_auth(stream, None);
        let frame = [0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0, 80];
        peer.write_all(&frame).await.unwrap();
        let err = client.handle_client().await.unwrap_err();
        assert!(matches!(
            err,
            MerinoError::Socks(ResponseCode::CommandNotSupported)
        ));
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
