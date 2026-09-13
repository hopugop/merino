use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use actix::fut;
use actix::prelude::*;
use tokio::net::{TcpListener, TcpStream};

use crate::{run_client, SOCKClient, User};

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

/// Actor that owns the listening socket and supervises the accept loop.
pub struct SocksServer {
    listener: Option<TcpListener>,
    bound_addr: SocketAddr,
    users: Arc<Vec<User>>,
    auth_methods: Arc<Vec<u8>>,
    timeout: Option<Duration>,
}

impl SocksServer {
    /// Bind the listening socket and build the server actor.
    pub async fn bind(
        port: u16,
        ip: &str,
        auth_methods: Vec<u8>,
        users: Vec<User>,
        timeout: Option<Duration>,
    ) -> io::Result<Self> {
        info!("Listening on {}:{}", ip, port);
        let listener = TcpListener::bind((ip, port)).await?;
        let bound_addr = listener.local_addr()?;
        Ok(Self {
            listener: Some(listener),
            bound_addr,
            auth_methods: Arc::new(auth_methods),
            users: Arc::new(users),
            timeout,
        })
    }

    /// Address the listener is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.bound_addr
    }
}

impl Actor for SocksServer {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        let listener = self.listener.take().expect("server is started once");
        let users = self.users.clone();
        let auth_methods = self.auth_methods.clone();
        let timeout = self.timeout;

        ctx.spawn(
            fut::wrap_future::<_, SocksServer>(async move {
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
            })
            .map(|_, _, ctx: &mut Context<SocksServer>| ctx.stop()),
        );
    }
}

impl Supervised for SocksServer {}
