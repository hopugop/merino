use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use actix::fut;
use actix::prelude::*;
use tokio::net::{TcpListener, TcpStream};

use crate::{SOCKClient, User, bind_all, run_client};

/// One actor per accepted TCP connection.
///
/// The actor owns the [`SOCKClient`] until `started`, where the blocking
/// SOCKS5 negotiation and relay are driven on the actor's arbiters.
pub struct SocksConnection {
    client: Option<SOCKClient<TcpStream>>,
    peer: SocketAddr,
}

impl SocksConnection {
    pub fn new(client: SOCKClient<TcpStream>, peer: SocketAddr) -> Self {
        Self {
            client: Some(client),
            peer,
        }
    }
}

impl Actor for SocksConnection {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        let client = self.client.take().expect("client is taken exactly once");
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
        })
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

        for listener in std::mem::take(&mut self.listeners) {
            let users = users.clone();
            let auth_methods = auth_methods.clone();
            ctx.spawn(fut::wrap_future::<_, SocksServer>(async move {
                loop {
                    match listener.accept().await {
                        Ok((stream, peer)) => {
                            let client = SOCKClient::new(
                                stream,
                                users.clone(),
                                auth_methods.clone(),
                                timeout,
                            );
                            SocksConnection::create(move |_| SocksConnection::new(client, peer));
                        }
                        Err(e) => warn!("Accept error: {:?}", e),
                    }
                }
            }));
        }
    }
}

impl Supervised for SocksServer {}
