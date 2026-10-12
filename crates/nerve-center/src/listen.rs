//! Listening sockets: plain TCP on loopback or TLS with the center's
//! identity, and the node endpoints on them (spec §3 pairing, §4 connect).

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

use nerve_proto::{CONNECT_PATH, NODE_HEADER, PAIR_PATH};
use nerve_transport::http::{self, Request, Response};
use nerve_transport::net::BoxIo;

use crate::center::Center;

/// Open connections per listener; more wait for a free slot.
const MAX_CONNECTIONS: usize = 256;
/// The largest pairing request body.
const PAIR_BODY: usize = 16 * 1024;

/// Binds a TCP listener.
pub async fn tcp(addr: &str) -> Result<TcpListener, String> {
    TcpListener::bind(addr)
        .await
        .map_err(|e| format!("cannot listen on {addr}: {e}"))
}

/// A bound listener that hands each accepted connection, after TLS when it
/// has a TLS acceptor, to a handler.
pub struct Server {
    pub listener: TcpListener,
    pub tls: Option<TlsAcceptor>,
}

impl Server {
    /// Binds `addr`. TLS is used unless `plain` is set, and plain is only
    /// allowed on a loopback address.
    pub async fn bind(addr: &str, center: &Center, plain: bool) -> Result<Server, String> {
        Server::from_listener(tcp(addr).await?, center, plain)
    }

    /// Wraps a listener bound earlier (the node port is bound before the
    /// center opens, so the public URL can carry the real port).
    pub fn from_listener(
        listener: TcpListener,
        center: &Center,
        plain: bool,
    ) -> Result<Server, String> {
        let local = listener.local_addr().map_err(|e| e.to_string())?;
        if plain && !local.ip().is_loopback() {
            return Err(format!(
                "{local} is not a loopback address; plain HTTP is only served on loopback"
            ));
        }
        let tls = if plain {
            None
        } else {
            Some(TlsAcceptor::from(center.identity.server_config()?))
        };
        Ok(Server { listener, tls })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.listener
            .local_addr()
            .expect("a bound listener has an address")
    }

    /// Accepts connections until the task is dropped.
    pub async fn run<F, Fut>(self, handler: F)
    where
        F: Fn(BoxIo, SocketAddr) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let handler = Arc::new(handler);
        let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        loop {
            let Ok(permit) = slots.clone().acquire_owned().await else {
                return;
            };
            let (tcp, peer) = match self.listener.accept().await {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("accept failed: {e}");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
            };
            let _ = tcp.set_nodelay(true);
            let tls = self.tls.clone();
            let handler = handler.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let io: BoxIo = match tls {
                    None => Box::new(tcp),
                    Some(acc) => {
                        let hs = tokio::time::timeout(http::HEAD_TIMEOUT, acc.accept(tcp)).await;
                        match hs {
                            Ok(Ok(s)) => Box::new(s),
                            _ => return,
                        }
                    }
                };
                handler(io, peer).await;
            });
        }
    }
}

/// Serves the node endpoints on `server`.
pub async fn serve_nodes(center: Center, server: Server) {
    server
        .run(move |io, _peer| {
            let center = center.clone();
            async move { node_conn(center, io).await }
        })
        .await
}

async fn node_conn(center: Center, mut io: BoxIo) {
    let req = match http::read_request(&mut io, PAIR_BODY).await {
        Ok(r) => r,
        Err(_) => {
            let _ = Response::text(400, "bad request").write(&mut io).await;
            return;
        }
    };
    match (req.method.as_str(), req.path.as_str()) {
        ("POST", PAIR_PATH) => {
            let (status, body) = center.pair(&req.body);
            let _ = Response::json(status, &body).write(&mut io).await;
        }
        ("GET", CONNECT_PATH) if req.is_upgrade() => connect(center, io, req).await,
        _ => {
            let _ = Response::text(404, "not found").write(&mut io).await;
        }
    }
}

async fn connect(center: Center, mut io: BoxIo, req: Request) {
    let node_id = req.header(NODE_HEADER).unwrap_or("").to_string();
    if !center.knows(&node_id) {
        // Anyone can send this, so it is detail; a node removed here and
        // still dialling stops after the answer.
        center.log().record(
            nerve_transport::log::Level::Debug,
            None,
            &format!(
                "a node that is not paired tried to connect (id {})",
                crate::util::clip(&node_id, 64)
            ),
        );
        // §4.1: an unknown node is told so before any handshake, and stops
        // dialling.
        let _ = Response::json(
            401,
            &serde_json::json!({"error": "this node is not paired with this center"}),
        )
        .write(&mut io)
        .await;
        return;
    }
    match nerve_transport::ws::accept(io, &req, nerve_proto::limits::MESSAGE_BYTES as usize).await {
        Ok(ws) => crate::link::run(center, ws, node_id).await,
        Err(e) => center.log().record(
            nerve_transport::log::Level::Debug,
            None,
            &format!("a WebSocket upgrade failed: {e}"),
        ),
    }
}
