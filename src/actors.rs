use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use actix::fut;
use actix::prelude::*;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::{DEFAULT_MAX_CONNECTIONS, SOCKClient, User, bind_all, run_client};

/// One actor per accepted TCP connection.
///
/// The actor owns the [`SOCKClient`] until `started`, where the blocking
/// SOCKS5 negotiation and relay are driven on the actor's arbiters.
pub struct SocksConnection {
    client: Option<SOCKClient<TcpStream>>,
    peer: SocketAddr,
    /// Held for the lifetime of the connection so the server's connection
    /// semaphore releases the slot when the actor stops.
    _permit: Option<OwnedSemaphorePermit>,
}

impl SocksConnection {
    pub fn new(client: SOCKClient<TcpStream>, peer: SocketAddr) -> Self {
        Self {
            client: Some(client),
            peer,
            _permit: None,
        }
    }

    /// Attach the connection-cap permit acquired by the server.
    pub fn set_permit(&mut self, permit: OwnedSemaphorePermit) {
        self._permit = Some(permit);
    }
}

impl Actor for SocksConnection {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        let client = match self.client.take() {
            Some(client) => client,
            None => {
                ctx.stop();
                return;
            }
        };
        let peer = self.peer;
        ctx.spawn(
            fut::wrap_future::<_, SocksConnection>(run_client(client, peer))
                .map(|_, _, ctx: &mut Context<SocksConnection>| ctx.stop()),
        );
    }
}

/// Actor that owns the listening sockets and supervises the accept loops.
///
/// A hostname may resolve to several addresses (an IPv4 and an IPv6 address on
/// the same host, for example); one listener is bound per resolved address and
/// a dedicated accept loop runs for each.
pub struct SocksServer {
    listeners: Vec<TcpListener>,
    bound_addrs: Vec<SocketAddr>,
    users: Arc<Vec<User>>,
    auth_methods: Arc<Vec<u8>>,
    timeout: Option<Duration>,
    max_connections: usize,
}

impl SocksServer {
    /// Bind a listening socket for every address `ip` resolves to and build
    /// the server actor.
    pub async fn bind(
        port: u16,
        ip: &str,
        auth_methods: Vec<u8>,
        users: Vec<User>,
        timeout: Option<Duration>,
    ) -> io::Result<Self> {
        let listeners = bind_all(ip, port).await?;
        let bound_addrs = listeners
            .iter()
            .map(TcpListener::local_addr)
            .collect::<io::Result<Vec<_>>>()?;
        Ok(Self {
            listeners,
            bound_addrs,
            auth_methods: Arc::new(auth_methods),
            users: Arc::new(users),
            timeout,
            max_connections: DEFAULT_MAX_CONNECTIONS,
        })
    }

    /// Set the maximum number of simultaneous client connections.
    ///
    /// Zero is clamped to one so the accept loop can never deadlock. Call
    /// before [`Actor::start`].
    pub fn set_max_connections(&mut self, max: usize) {
        self.max_connections = max.max(1);
    }

    /// Address of the first listener.
    pub fn local_addr(&self) -> SocketAddr {
        self.bound_addrs[0]
    }

    /// Address of every listener this server is bound to.
    pub fn local_addrs(&self) -> &[SocketAddr] {
        &self.bound_addrs
    }
}

impl Actor for SocksServer {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        let users = self.users.clone();
        let auth_methods = self.auth_methods.clone();
        let timeout = self.timeout;
        let semaphore = Arc::new(Semaphore::new(self.max_connections));

        for listener in std::mem::take(&mut self.listeners) {
            let users = users.clone();
            let auth_methods = auth_methods.clone();
            let semaphore = semaphore.clone();
            ctx.spawn(fut::wrap_future::<_, SocksServer>(async move {
                loop {
                    // Acquire a slot before accepting so excess connections
                    // wait in the kernel backlog instead of spawning actors.
                    let permit = match semaphore.clone().acquire_owned().await {
                        Ok(permit) => permit,
                        Err(_) => break,
                    };
                    match listener.accept().await {
                        Ok((stream, peer)) => {
                            let local_addr = stream.local_addr().ok();
                            let mut client = SOCKClient::new(
                                stream,
                                users.clone(),
                                auth_methods.clone(),
                                timeout,
                            );
                            client.set_local_addr(local_addr);
                            SocksConnection::create(move |_| {
                                let mut connection = SocksConnection::new(client, peer);
                                connection.set_permit(permit);
                                connection
                            });
                        }
                        Err(e) => warn!("Accept error: {:?}", e),
                    }
                }
            }));
        }
    }
}

impl Supervised for SocksServer {}
