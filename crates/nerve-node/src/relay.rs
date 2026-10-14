//! The relay (docs/dev/spec/protocol.md §4.8): a node in a closed network
//! reaches a center through this node. The relayed node sets this node as
//! its proxy; the relay takes its `CONNECT`, checks its token, and tunnels
//! bytes to one of this node's own centers. It never reads a message: TLS,
//! the pin and the relayed node's signature run end to end inside the
//! tunnel, so the relay can cut a node off but neither read nor steer its
//! link. The relayed node's policy is its own, and this node's policy is not
//! asked: no call of a center runs here for a tunnel.
//!
//! Off unless the owner sets `relay.listen`. A tunnel goes only to a center
//! this node is paired with over https, and not to one that revoked or no
//! longer knows it: the relay opens no way to anything else on this machine
//! or its network. A tunnel ends when the owner turns the relay off, takes
//! the node's token away, unpairs the center, or locks the node (`panic`).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

use nerve_policy::NodeConfig;
use nerve_proto::link::CenterUrl;
use nerve_transport::http::{Request, Response, read_request_head};
use nerve_transport::log::span;

use crate::daemon::{Shared, lock};

/// Connections whose `CONNECT` is not decided yet, at once. Past it a new
/// connection is closed at once, so a peer without a token cannot hold the
/// relay's memory or descriptors.
const UNDECIDED: usize = 64;
/// A tunnel that carries no byte either way this long is closed. A link pings
/// every 20 seconds (spec §4.4), so only a dead one stays this quiet.
const IDLE: Duration = Duration::from_secs(90);
/// How long a relay that could not listen waits before it tries again.
const RETRY: Duration = Duration::from_secs(10);
/// The realm of the `Proxy-Authenticate` answer.
const REALM: &str = "nerve relay";

/// The relay's state in the daemon: what it listens on and its tunnels.
pub(crate) struct Relays {
    status: Mutex<String>,
    /// The address it listens on now (port 0 in `relay.listen` is resolved).
    bound: Mutex<Option<SocketAddr>>,
    tunnels: Mutex<HashMap<u64, Tunnel>>,
    next: AtomicU64,
    undecided: Arc<Semaphore>,
}

impl Default for Relays {
    fn default() -> Relays {
        Relays {
            status: Mutex::new("off".into()),
            bound: Mutex::default(),
            tunnels: Mutex::default(),
            next: AtomicU64::new(1),
            undecided: Arc::new(Semaphore::new(UNDECIDED)),
        }
    }
}

/// One tunnel, for `status` and the limits.
#[derive(Debug, Clone)]
struct Tunnel {
    node: String,
    center: String,
    from: SocketAddr,
    since_ms: u64,
}

impl Relays {
    /// What `status` shows of the relay: whether it listens and who is
    /// connected to which center.
    pub fn status(&self, cfg: &NodeConfig) -> Value {
        let mut tunnels: Vec<Tunnel> = lock(&self.tunnels).values().cloned().collect();
        tunnels.sort_by_key(|t| t.since_ms);
        json!({
            "listen": cfg.relay.listen,
            "address": lock(&self.bound).map(|a| a.to_string()),
            "status": lock(&self.status).clone(),
            "max_links": cfg.relay.max_links,
            "max_links_per_node": cfg.relay.max_links_per_node,
            "nodes": cfg.relay.nodes.iter().map(|n| n.name.clone()).collect::<Vec<_>>(),
            "tunnels": tunnels.iter().map(|t| json!({
                "node": t.node,
                "center": t.center,
                "from": t.from.to_string(),
                "since_ms": t.since_ms,
            })).collect::<Vec<_>>(),
        })
    }

    fn set_status(&self, s: impl Into<String>, bound: Option<SocketAddr>) {
        *lock(&self.status) = s.into();
        *lock(&self.bound) = bound;
    }
}

/// A new relay token and the hash `node.toml` keeps of it. 43 characters
/// of `a-z0-9`: over 220 bits, and nothing a proxy URL must escape.
pub fn new_token() -> (String, String) {
    let token = nerve_transport::keys::random_token(43);
    let hash = token_hash(&token);
    (token, hash)
}

/// The lowercase hex SHA-256 of a relay token.
pub fn token_hash(token: &str) -> String {
    nerve_proto::msg::hex(ring::digest::digest(&ring::digest::SHA256, token.as_bytes()).as_ref())
}

/// Runs the relay while the config says so: listens on `relay.listen`
/// unless the node is locked, and listens again when that changes.
pub(crate) async fn run(shared: Arc<Shared>) {
    let mut changed = shared.changed.subscribe();
    let mut stop = shared.stop.subscribe();
    // The address the last bind failed on: the first failure there is an
    // error in the log, its retries are detail, or a port that stays taken
    // fills the log.
    let mut failed_on: Option<String> = None;
    loop {
        if *stop.borrow() {
            break;
        }
        changed.borrow_and_update();
        let cfg = shared.config();
        let want = cfg.relay.listen.clone().filter(|_| !cfg.locked);
        let wait = match want {
            None => {
                shared.relay.set_status("off", None);
                None
            }
            Some(at) => match TcpListener::bind(&at).await {
                Ok(listener) => {
                    failed_on = None;
                    let bound = listener.local_addr().ok();
                    let shown = bound.map_or_else(|| at.clone(), |a| a.to_string());
                    tracing::info!("relay: listening on {shown}");
                    shared
                        .relay
                        .set_status(format!("listening on {shown}"), bound);
                    serve(&shared, listener, &at, &mut changed, &mut stop).await;
                    tracing::info!("relay: stopped listening on {shown}");
                    shared.relay.set_status("off", None);
                    continue;
                }
                Err(e) => {
                    if failed_on.as_deref() == Some(at.as_str()) {
                        tracing::debug!("relay: cannot listen on {at}: {e}");
                    } else {
                        tracing::error!("relay: cannot listen on {at}: {e}");
                    }
                    failed_on = Some(at.clone());
                    shared
                        .relay
                        .set_status(format!("cannot listen on {at}: {e}"), None);
                    Some(RETRY)
                }
            },
        };
        tokio::select! {
            r = changed.changed() => {
                if r.is_err() {
                    break;
                }
            }
            _ = stop.changed() => break,
            _ = async {
                match wait {
                    Some(w) => tokio::time::sleep(w).await,
                    None => std::future::pending().await,
                }
            } => {}
        }
    }
    shared.relay.set_status("off", None);
}

/// Takes connections on `listener` until the relay's address changes, the
/// node is locked, or the daemon stops. Running tunnels go on: each checks
/// the config itself. `changed` is the caller's, which saw the config the
/// listener was made for, so a change made while it bound is not missed.
async fn serve(
    shared: &Arc<Shared>,
    listener: TcpListener,
    at: &str,
    changed: &mut tokio::sync::watch::Receiver<u64>,
    stop: &mut tokio::sync::watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            got = listener.accept() => match got {
                Ok((io, peer)) => {
                    // A connection over the limit is closed unread.
                    let Ok(permit) = shared.relay.undecided.clone().try_acquire_owned() else {
                        tracing::debug!("relay: too many undecided connections; closed one from {peer}");
                        continue;
                    };
                    let _ = io.set_nodelay(true);
                    let shared = shared.clone();
                    tokio::spawn(async move {
                        connection(shared, io, peer, permit).await;
                    });
                }
                // One connection the node cannot take does not end the relay.
                Err(e) => {
                    tracing::debug!("relay: accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            },
            r = changed.changed() => {
                if r.is_err() {
                    return;
                }
                let cfg = shared.config();
                if cfg.locked || cfg.relay.listen.as_deref() != Some(at) {
                    return;
                }
            }
            _ = stop.changed() => return,
        }
    }
}

/// What the relay answers a `CONNECT` it does not grant.
#[derive(Debug, PartialEq, Eq)]
struct Refusal {
    status: u16,
    why: &'static str,
}

const NO_TOKEN: Refusal = Refusal {
    status: 407,
    why: "this relay wants the name and token of a node it knows",
};
const NOT_A_CENTER: Refusal = Refusal {
    status: 403,
    why: "the relay tunnels only to the https centers its node is paired with",
};
const NOT_CONNECT: Refusal = Refusal {
    status: 405,
    why: "the relay takes CONNECT host:port only",
};
const OFF: Refusal = Refusal {
    status: 503,
    why: "the relay is off",
};
const FULL: Refusal = Refusal {
    status: 503,
    why: "the relay carries as many tunnels as it may now",
};

/// A `CONNECT` the relay grants: whose it is and where it goes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Grant {
    node: String,
    token_sha256: String,
    center: String,
    url: CenterUrl,
}

/// Decides a `CONNECT` by the config alone. The token is checked before the
/// target, so a peer without one learns nothing of this node's centers.
fn decide(cfg: &NodeConfig, req: &Request) -> Result<Grant, Refusal> {
    if cfg.locked || cfg.relay.listen.is_none() {
        return Err(OFF);
    }
    if !req.method.eq_ignore_ascii_case("CONNECT") {
        return Err(NOT_CONNECT);
    }
    let (node, token_sha256) = node_of(cfg, req.header("proxy-authorization")).ok_or(NO_TOKEN)?;
    let (host, port) = authority(&req.path).ok_or(NOT_CONNECT)?;
    let (center, url) = target(cfg, &host, port).ok_or(NOT_A_CENTER)?;
    Ok(Grant {
        node,
        token_sha256,
        center,
        url,
    })
}

/// The relay node a `Proxy-Authorization: Basic` names, with the hash of
/// its token, when the token is that node's.
fn node_of(cfg: &NodeConfig, header: Option<&str>) -> Option<(String, String)> {
    use base64::Engine;
    let (scheme, value) = header?.trim().split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let raw = base64::engine::general_purpose::STANDARD
        .decode(value.trim())
        .ok()?;
    let text = String::from_utf8(raw).ok()?;
    let (name, token) = text.split_once(':')?;
    let node = cfg.relay.node(name)?;
    // The hashes are of tokens of over 220 random bits: comparing them
    // plainly tells a guesser nothing about a token.
    (token_hash(token) == node.token_sha256).then(|| (node.name.clone(), node.token_sha256.clone()))
}

/// `host:port` of a `CONNECT`, with `[...]` around an IPv6 address.
fn authority(target: &str) -> Option<(String, u16)> {
    let (host, port) = match target.strip_prefix('[') {
        Some(rest) => {
            let (h, p) = rest.split_once("]:")?;
            (h, p)
        }
        None => target.rsplit_once(':')?,
    };
    if host.is_empty() || host.contains(['/', '@', '[', ']']) {
        return None;
    }
    Some((host.to_string(), port.parse().ok()?))
}

/// The center at `host:port` that a tunnel may go to: one this node is
/// paired with over https that has not revoked it and still knows it. A
/// plain http center is on this machine's loopback; a tunnel there would
/// open it to the network.
fn target(cfg: &NodeConfig, host: &str, port: u16) -> Option<(String, CenterUrl)> {
    cfg.centers
        .iter()
        .filter(|c| !c.revoked && !c.unknown)
        .find_map(|c| {
            let url = CenterUrl::parse(&c.url).ok()?;
            (url.tls && url.port == port && url.host.eq_ignore_ascii_case(host))
                .then(|| (c.name.clone(), url))
        })
}

/// Whether a granted tunnel may go on under `cfg`: the relay is on, the node
/// is not locked, its token is the same and its center still a target.
fn still_granted(cfg: &NodeConfig, g: &Grant) -> bool {
    !cfg.locked
        && cfg.relay.listen.is_some()
        && cfg
            .relay
            .node(&g.node)
            .is_some_and(|n| n.token_sha256 == g.token_sha256)
        && target(cfg, &g.url.host, g.url.port).is_some_and(|(name, _)| name == g.center)
}

/// Counts a tunnel while it lives, for `status` and the limits.
struct Counted<'a> {
    relays: &'a Relays,
    id: u64,
}

impl Drop for Counted<'_> {
    fn drop(&mut self) {
        lock(&self.relays.tunnels).remove(&self.id);
    }
}

/// Counts a new tunnel of `g`, unless the limits are reached.
fn count<'a>(
    relays: &'a Relays,
    cfg: &NodeConfig,
    g: &Grant,
    from: SocketAddr,
) -> Option<Counted<'a>> {
    let mut tunnels = lock(&relays.tunnels);
    let of_node = tunnels.values().filter(|t| t.node == g.node).count();
    if tunnels.len() >= cfg.relay.max_links as usize
        || of_node >= cfg.relay.max_links_per_node as usize
    {
        return None;
    }
    let id = relays.next.fetch_add(1, Ordering::Relaxed);
    tunnels.insert(
        id,
        Tunnel {
            node: g.node.clone(),
            center: g.center.clone(),
            from,
            since_ms: crate::now_ms(),
        },
    );
    Some(Counted { relays, id })
}

async fn refuse(io: &mut TcpStream, r: &Refusal) {
    let mut resp = Response::text(r.status, r.why);
    if r.status == 407 {
        resp = resp.with_header("Proxy-Authenticate", &format!("Basic realm=\"{REALM}\""));
    }
    let _ = resp.write(io).await;
}

/// One connection to the relay: its `CONNECT`, then the tunnel.
async fn connection(
    shared: Arc<Shared>,
    mut io: TcpStream,
    peer: SocketAddr,
    permit: tokio::sync::OwnedSemaphorePermit,
) {
    let req = match read_request_head(&mut io).await {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!("relay: no request from {peer}: {e}");
            return;
        }
    };
    let cfg = shared.config();
    let grant = match decide(&cfg, &req) {
        Ok(g) => g,
        Err(r) => {
            if r == NO_TOKEN {
                tracing::warn!(
                    "relay: refused a tunnel from {peer}: no relay node with that name and token"
                );
            } else {
                tracing::info!(
                    "relay: refused a tunnel from {peer} to {}: {}",
                    clip(&req.path),
                    r.why
                );
            }
            refuse(&mut io, &r).await;
            return;
        }
    };
    let Some(_counted) = count(&shared.relay, &cfg, &grant, peer) else {
        tracing::warn!(
            "relay: refused a tunnel of {} from {peer}: {}",
            grant.node,
            FULL.why
        );
        refuse(&mut io, &FULL).await;
        return;
    };
    // The relay dials as the node's own link does: through its proxy, or
    // another relay, when it has one.
    let dialled = match crate::link::proxy_for(&shared.paths, &cfg, &grant.url).await {
        Ok(proxy) => nerve_transport::net::reach(&grant.url, proxy.as_ref()).await,
        Err(e) => Err(format!("bad proxy: {e}")),
    };
    let center = match dialled {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                "relay: {} from {peer} to center {}: cannot connect: {e}",
                grant.node,
                grant.center
            );
            refuse(
                &mut io,
                &Refusal {
                    status: 502,
                    why: "the relay cannot reach that center now",
                },
            )
            .await;
            return;
        }
    };
    let _ = center.set_nodelay(true);
    let ok = b"HTTP/1.1 200 Connection established\r\n\r\n";
    if io.write_all(ok).await.is_err() {
        return;
    }
    drop(permit);
    tracing::info!(
        "relay: {} from {peer} to center {}: tunnel open",
        grant.node,
        grant.center
    );
    let started = std::time::Instant::now();
    let (up, down, why) = pump(&shared, &grant, io, center).await;
    tracing::info!(
        "relay: {} from {peer} to center {}: tunnel closed after {} ({why}; {up} bytes up, {down} down)",
        grant.node,
        grant.center,
        span(started.elapsed())
    );
}

/// A target as the log shows it: cut, since a peer chooses it.
fn clip(s: &str) -> String {
    let mut out: String = s.chars().take(80).collect();
    if s.chars().count() > 80 {
        out.push('…');
    }
    out
}

/// Carries bytes both ways between the relayed node and the center, unread,
/// until either side ends, the tunnel is quiet for [`IDLE`], or the owner
/// cuts it off. Returns the bytes each way and why it ended.
async fn pump(
    shared: &Arc<Shared>,
    g: &Grant,
    node: TcpStream,
    center: TcpStream,
) -> (u64, u64, &'static str) {
    let last = AtomicU64::new(crate::now_ms());
    let (up, down) = (AtomicU64::new(0), AtomicU64::new(0));
    let (nr, nw) = node.into_split();
    let (cr, cw) = center.into_split();
    let both = async { tokio::join!(copy(nr, cw, &up, &last), copy(cr, nw, &down, &last)) };
    let mut changed = shared.changed.subscribe();
    let mut stop = shared.stop.subscribe();
    // A change between the grant and here is in the config already.
    if *stop.borrow() {
        return (0, 0, "the node stopped");
    }
    if !still_granted(&shared.config(), g) {
        return (0, 0, "cut off by the owner");
    }
    let cut = async {
        loop {
            tokio::select! {
                r = changed.changed() => {
                    if r.is_err() {
                        return "the node stopped";
                    }
                    if !still_granted(&shared.config(), g) {
                        return "cut off by the owner";
                    }
                }
                _ = stop.changed() => return "the node stopped",
            }
        }
    };
    let idle = async {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let quiet = crate::now_ms().saturating_sub(last.load(Ordering::Relaxed));
            if quiet >= IDLE.as_millis() as u64 {
                return;
            }
        }
    };
    let why = tokio::select! {
        _ = both => "ended",
        why = cut => why,
        _ = idle => "quiet too long",
    };
    (
        up.load(Ordering::Relaxed),
        down.load(Ordering::Relaxed),
        why,
    )
}

/// Copies one way until the reader ends, then ends the writer's side.
async fn copy(
    mut from: tokio::net::tcp::OwnedReadHalf,
    mut to: tokio::net::tcp::OwnedWriteHalf,
    count: &AtomicU64,
    last: &AtomicU64,
) {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = match from.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if to.write_all(&buf[..n]).await.is_err() {
            break;
        }
        count.fetch_add(n as u64, Ordering::Relaxed);
        last.store(crate::now_ms(), Ordering::Relaxed);
    }
    let _ = to.shutdown().await;
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;

    use base64::Engine;
    use nerve_conformance::fake_center::{self, FakeCenter};
    use nerve_policy::CenterEntry;
    use nerve_proto::link::PairLink;
    use nerve_transport::tls::{Acceptor, ServerIdentity};

    use super::*;
    use crate::daemon::{Daemon, NodeOptions};
    use crate::paths::NodePaths;

    const WAIT: Duration = Duration::from_secs(15);
    const QUIET: Duration = Duration::from_millis(300);

    /// A center of the jump node. Paused, so the jump node does not dial it
    /// itself: these tests are about the tunnels of other nodes.
    fn center(name: &str, url: String) -> CenterEntry {
        CenterEntry {
            name: name.into(),
            url,
            pin: None,
            center_id: format!("id-{name}"),
            node_id: "n".into(),
            settings: Default::default(),
            paused: true,
            revoked: false,
            unknown: false,
            policy: Default::default(),
        }
    }

    fn basic(name: &str, token: &str) -> String {
        let b = base64::engine::general_purpose::STANDARD.encode(format!("{name}:{token}"));
        format!("Basic {b}")
    }

    fn options(root: &std::path::Path) -> NodeOptions {
        let mut o = NodeOptions::new(NodePaths::new(root.join("config"), root.join("state")));
        o.home = root.join("home");
        std::fs::create_dir_all(&o.home).unwrap();
        o.ctl = false;
        o.full_rights = Some(false);
        o
    }

    /// A jump node with `centers`, its relay on a free port of loopback and
    /// one node `lab` that may use it.
    struct Jump {
        _dir: tempfile::TempDir,
        daemon: Daemon,
        addr: SocketAddr,
        token: String,
    }

    async fn jump(centers: Vec<CenterEntry>, more: impl FnOnce(&mut NodeConfig)) -> Jump {
        let dir = tempfile::tempdir().unwrap();
        let o = options(dir.path());
        let (token, hash) = new_token();
        let mut cfg = NodeConfig {
            centers,
            ..Default::default()
        };
        cfg.relay.listen = Some("127.0.0.1:0".into());
        cfg.relay.nodes.push(nerve_policy::config::RelayNode {
            name: "lab".into(),
            token_sha256: hash,
        });
        more(&mut cfg);
        cfg.save(&o.paths.config_file()).unwrap();
        let daemon = Daemon::start(o).await.unwrap();
        let addr = listening(&daemon).await;
        Jump {
            _dir: dir,
            daemon,
            addr,
            token,
        }
    }

    /// The address the relay of `daemon` listens on, once it does.
    async fn listening(daemon: &Daemon) -> SocketAddr {
        for _ in 0..400 {
            if let Some(a) = daemon.status()["relay"]["address"].as_str() {
                return a.parse().unwrap();
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("the relay never listened: {}", daemon.status()["relay"]);
    }

    /// Sends `CONNECT target` with `auth` and returns the answer's status and
    /// the connection, read up to the end of the answer's head.
    async fn connect(
        relay: SocketAddr,
        target: &str,
        auth: Option<&str>,
    ) -> (u16, String, TcpStream) {
        let mut s = TcpStream::connect(relay).await.unwrap();
        let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
        if let Some(a) = auth {
            req.push_str(&format!("Proxy-Authorization: {a}\r\n"));
        }
        req.push_str("\r\n");
        s.write_all(req.as_bytes()).await.unwrap();
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            match tokio::time::timeout(WAIT, s.read(&mut b)).await.unwrap() {
                Ok(1) => head.push(b[0]),
                _ => break,
            }
        }
        let head = String::from_utf8_lossy(&head).to_string();
        let status = head
            .split(' ')
            .nth(1)
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        (status, head, s)
    }

    /// A listener that echoes what it reads, standing in for a center.
    async fn echo() -> TcpListener {
        TcpListener::bind("127.0.0.1:0").await.unwrap()
    }

    fn serve_echo(l: TcpListener) {
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
    }

    fn port(l: &TcpListener) -> u16 {
        l.local_addr().unwrap().port()
    }

    /// Whether the tunnel `s` ends within `wait`.
    async fn ends(s: &mut TcpStream, wait: Duration) -> bool {
        let mut b = [0u8; 64];
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            match tokio::time::timeout_at(deadline, s.read(&mut b)).await {
                Err(_) => return false,
                Ok(Ok(0)) | Ok(Err(_)) => return true,
                Ok(Ok(_)) => continue,
            }
        }
    }

    async fn round_trip(s: &mut TcpStream, data: &[u8]) {
        s.write_all(data).await.unwrap();
        let mut got = vec![0u8; data.len()];
        tokio::time::timeout(WAIT, s.read_exact(&mut got))
            .await
            .expect("the tunnel carries bytes")
            .unwrap();
        assert_eq!(got, data);
    }

    fn get(head: &str) -> Request {
        Request {
            method: "CONNECT".into(),
            path: head.into(),
            query: String::new(),
            headers: Default::default(),
            body: Vec::new(),
        }
    }

    #[test]
    fn the_target_of_a_connect_is_host_and_port() {
        assert_eq!(
            authority("c.example:8443"),
            Some(("c.example".into(), 8443))
        );
        assert_eq!(authority("[::1]:443"), Some(("::1".into(), 443)));
        assert_eq!(authority("10.0.0.1:443"), Some(("10.0.0.1".into(), 443)));
        for bad in [
            "c.example",
            ":443",
            "c.example:x",
            "[::1]443",
            "u@c.example:443",
            "/x:1",
            "c:99999",
        ] {
            assert_eq!(authority(bad), None, "{bad}");
        }
    }

    /// The token is checked first; then only a center of this node over
    /// https that still knows it is a target; an off or locked relay grants
    /// nothing.
    #[test]
    fn a_connect_is_granted_with_a_token_and_to_a_paired_center_only() {
        let (token, hash) = new_token();
        let (other_token, _) = new_token();
        let mut cfg = NodeConfig::default();
        cfg.relay.listen = Some("127.0.0.1:7490".into());
        cfg.relay.nodes.push(nerve_policy::config::RelayNode {
            name: "lab".into(),
            token_sha256: hash.clone(),
        });
        cfg.centers
            .push(center("home", "https://Center.Example:8443".into()));
        cfg.centers
            .push(center("local", "http://127.0.0.1:7480".into()));
        let mut gone = center("gone", "https://gone.example:8443".into());
        gone.revoked = true;
        cfg.centers.push(gone);
        let mut forgot = center("forgot", "https://forgot.example:8443".into());
        forgot.unknown = true;
        cfg.centers.push(forgot);
        let ask = |cfg: &NodeConfig, target: &str, auth: Option<String>| {
            let mut r = get(target);
            if let Some(a) = auth {
                r.headers.insert("proxy-authorization".into(), a);
            }
            decide(cfg, &r)
        };
        let good = || Some(basic("lab", &token));
        let g = ask(&cfg, "center.example:8443", good()).unwrap();
        assert_eq!((g.node.as_str(), g.center.as_str()), ("lab", "home"));
        assert_eq!(g.token_sha256, hash);
        for auth in [
            None,
            Some(basic("lab", &other_token)),
            Some(basic("other", &token)),
            Some(format!("Bearer {token}")),
            Some("Basic not-base64!".into()),
            Some(basic("lab", "")),
        ] {
            // Not even a center of this node is told apart without a token.
            assert_eq!(
                ask(&cfg, "center.example:8443", auth.clone()),
                Err(NO_TOKEN),
                "{auth:?}"
            );
            assert_eq!(
                ask(&cfg, "elsewhere.example:22", auth.clone()),
                Err(NO_TOKEN),
                "{auth:?}"
            );
        }
        for target in [
            "center.example:443",
            "elsewhere.example:8443",
            "127.0.0.1:7480",
            "localhost:7480",
            "gone.example:8443",
            "forgot.example:8443",
        ] {
            assert_eq!(ask(&cfg, target, good()), Err(NOT_A_CENTER), "{target}");
        }
        assert_eq!(ask(&cfg, "center.example", good()), Err(NOT_CONNECT));
        let mut r = get("center.example:8443");
        r.method = "GET".into();
        assert_eq!(decide(&cfg, &r), Err(NOT_CONNECT));
        let mut locked = cfg.clone();
        locked.locked = true;
        assert_eq!(ask(&locked, "center.example:8443", good()), Err(OFF));
        let mut off = cfg.clone();
        off.relay.listen = None;
        assert_eq!(ask(&off, "center.example:8443", good()), Err(OFF));

        // A granted tunnel holds only while all of that stays.
        assert!(still_granted(&cfg, &g));
        let changed: [&dyn Fn(&mut NodeConfig); 6] = [
            &|c| c.locked = true,
            &|c| c.relay.listen = None,
            &|c| c.relay.nodes.clear(),
            &|c| c.relay.nodes[0].token_sha256 = "b".repeat(64),
            &|c| c.centers.retain(|e| e.name != "home"),
            &|c| c.centers[0].revoked = true,
        ];
        for (i, change) in changed.iter().enumerate() {
            let mut c = cfg.clone();
            change(&mut c);
            assert!(!still_granted(&c, &g), "change {i}");
        }
    }

    /// A node with its token reaches a center of the jump node and nothing
    /// else: no other port of this machine, no plain http center, no center
    /// that revoked the jump node. Status names the tunnel.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_node_with_its_token_reaches_a_paired_center_and_nothing_else() {
        let home = echo().await;
        let (other, local, gone) = (echo().await, echo().await, echo().await);
        let mut revoked = center("gone", format!("https://127.0.0.1:{}", port(&gone)));
        revoked.revoked = true;
        let j = jump(
            vec![
                center("home", format!("https://127.0.0.1:{}", port(&home))),
                center("local", format!("http://127.0.0.1:{}", port(&local))),
                revoked,
            ],
            |_| {},
        )
        .await;
        let good = basic("lab", &j.token);
        let target = format!("127.0.0.1:{}", port(&home));

        let (status, head, _) = connect(j.addr, &target, None).await;
        assert_eq!(status, 407, "{head}");
        assert!(head.contains("Proxy-Authenticate: Basic"), "{head}");
        let (status, _, _) = connect(j.addr, &target, Some(&basic("lab", "wrong"))).await;
        assert_eq!(status, 407);
        for l in [&other, &local, &gone] {
            let (status, head, _) =
                connect(j.addr, &format!("127.0.0.1:{}", port(l)), Some(&good)).await;
            assert_eq!(status, 403, "{head}");
            assert!(tokio::time::timeout(QUIET, l.accept()).await.is_err());
        }
        assert!(
            j.daemon.status()["relay"]["tunnels"]
                .as_array()
                .unwrap()
                .is_empty()
        );

        serve_echo(home);
        let (status, head, mut t) = connect(j.addr, &target, Some(&good)).await;
        assert_eq!(status, 200, "{head}");
        round_trip(&mut t, b"bytes only").await;
        let relay = j.daemon.status()["relay"].clone();
        assert_eq!(relay["status"], format!("listening on {}", j.addr));
        let tunnels = relay["tunnels"].as_array().unwrap();
        assert_eq!(tunnels.len(), 1, "{relay}");
        assert_eq!(
            (tunnels[0]["node"].as_str(), tunnels[0]["center"].as_str()),
            (Some("lab"), Some("home"))
        );
        drop(t);
        j.daemon.stop().await;
    }

    /// The owner cuts tunnels off: taking a node's token away ends that
    /// node's tunnels, unpairing a center ends the tunnels to it, `relay
    /// off` and `panic` end every tunnel and close the listener.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_owner_cuts_tunnels_off() {
        let (home, work) = (echo().await, echo().await);
        let (home_at, work_at) = (
            format!("127.0.0.1:{}", port(&home)),
            format!("127.0.0.1:{}", port(&work)),
        );
        serve_echo(home);
        serve_echo(work);
        let j = jump(
            vec![
                center("home", format!("https://{home_at}")),
                center("work", format!("https://{work_at}")),
            ],
            |_| {},
        )
        .await;
        let (token2, hash2) = new_token();
        j.daemon.owner_edit(|c| {
            c.relay.nodes.push(nerve_policy::config::RelayNode {
                name: "lab2".into(),
                token_sha256: hash2,
            })
        });
        let (lab, lab2) = (basic("lab", &j.token), basic("lab2", &token2));
        let open = |target: &str, auth: &str| {
            let (target, auth) = (target.to_string(), auth.to_string());
            async move {
                let (status, head, mut t) = connect(j.addr, &target, Some(&auth)).await;
                assert_eq!(status, 200, "{head}");
                round_trip(&mut t, b"up").await;
                t
            }
        };

        let mut a = open(&home_at, &lab).await;
        let mut b = open(&home_at, &lab2).await;
        j.daemon
            .owner_edit(|c| c.relay.nodes.retain(|n| n.name != "lab"));
        assert!(ends(&mut a, WAIT).await, "lab's tunnel outlived its token");
        assert!(
            !ends(&mut b, QUIET).await,
            "lab2's tunnel ended with lab's token"
        );
        round_trip(&mut b, b"still").await;
        let (status, _, _) = connect(j.addr, &home_at, Some(&lab)).await;
        assert_eq!(status, 407);

        let mut w = open(&work_at, &lab2).await;
        j.daemon
            .owner_edit(|c| c.centers.retain(|e| e.name != "home"));
        assert!(ends(&mut b, WAIT).await, "a tunnel outlived its center");
        round_trip(&mut w, b"other center").await;

        j.daemon.owner_edit(|c| c.relay.listen = None);
        assert!(ends(&mut w, WAIT).await, "a tunnel outlived the relay");
        let mut closed = false;
        for _ in 0..200 {
            if TcpStream::connect(j.addr).await.is_err() {
                closed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(closed, "the relay still listens");
        assert_eq!(j.daemon.status()["relay"]["status"], "off");

        j.daemon
            .owner_edit(|c| c.relay.listen = Some(j.addr.to_string()));
        assert_eq!(listening(&j.daemon).await, j.addr);
        let mut w = open(&work_at, &lab2).await;
        j.daemon.owner_edit(|c| c.locked = true);
        assert!(ends(&mut w, WAIT).await, "a tunnel outlived panic");
        j.daemon.stop().await;
    }

    /// A relay that cannot listen says why in `status`, and listens once
    /// the owner gives it an address it can have.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_relay_that_cannot_listen_says_so() {
        let taken = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = taken.local_addr().unwrap().to_string();
        let dir = tempfile::tempdir().unwrap();
        let o = options(dir.path());
        let mut cfg = NodeConfig::default();
        cfg.relay.listen = Some(at.clone());
        cfg.save(&o.paths.config_file()).unwrap();
        let daemon = Daemon::start(o).await.unwrap();
        let mut status = String::new();
        for _ in 0..400 {
            status = daemon.status()["relay"]["status"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            if status != "off" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(
            status.starts_with(&format!("cannot listen on {at}: ")),
            "{status}"
        );
        assert_eq!(daemon.status()["relay"]["address"], Value::Null);
        daemon.owner_edit(|c| c.relay.listen = Some("127.0.0.1:0".into()));
        listening(&daemon).await;
        daemon.stop().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_relay_keeps_to_its_limits() {
        let home = echo().await;
        let home_at = format!("127.0.0.1:{}", port(&home));
        serve_echo(home);
        let (token2, hash2) = new_token();
        let j = jump(vec![center("home", format!("https://{home_at}"))], |c| {
            c.relay.max_links = 2;
            c.relay.max_links_per_node = 1;
            c.relay.nodes.push(nerve_policy::config::RelayNode {
                name: "lab2".into(),
                token_sha256: hash2,
            });
        })
        .await;
        let (lab, lab2) = (basic("lab", &j.token), basic("lab2", &token2));
        let (s, _, mut first) = connect(j.addr, &home_at, Some(&lab)).await;
        assert_eq!(s, 200);
        let (s, head, _) = connect(j.addr, &home_at, Some(&lab)).await;
        assert_eq!(s, 503, "a second tunnel of one node: {head}");
        let (s, _, _second) = connect(j.addr, &home_at, Some(&lab2)).await;
        assert_eq!(s, 200);
        round_trip(&mut first, b"x").await;
        drop(first);
        // The slot is free again once the tunnel is gone.
        let mut again = 0;
        for _ in 0..200 {
            again = connect(j.addr, &home_at, Some(&lab)).await.0;
            if again == 200 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(again, 200);
        j.daemon.stop().await;
    }

    /// TLS in front of the fake center, which speaks plain HTTP: the
    /// center end of the TLS link. Returns its port and pin.
    async fn tls_front(to: u16) -> (u16, String) {
        let id = ServerIdentity::generate(&["127.0.0.1".into()]).unwrap();
        let pin = id.pin();
        let acceptor = Acceptor::new(&id).unwrap();
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = port(&l);
        tokio::spawn(async move {
            while let Ok((tcp, _)) = l.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let Ok(mut plain) = TcpStream::connect(("127.0.0.1", to)).await else {
                        return;
                    };
                    let _ = tokio::io::copy_bidirectional(&mut tls, &mut plain).await;
                });
            }
        });
        (at, pin)
    }

    /// A relayed node: its proxy is the jump node at `relay`, with the
    /// relay token of `lab` in the (test) keyring.
    fn relayed(root: &std::path::Path, relay: SocketAddr, token: &str) -> NodeOptions {
        let o = options(root);
        let mut cfg = NodeConfig::default();
        cfg.connection.proxy = Some(format!("http://{relay}"));
        cfg.connection.headers = vec!["Proxy-Authorization".into()];
        #[cfg(unix)]
        {
            cfg.machine.sudo_path = Some(fake_sudo(root, SUDO_PASSWORD).display().to_string());
        }
        cfg.save(&o.paths.config_file()).unwrap();
        let header = [("Proxy-Authorization".to_string(), basic("lab", token))];
        crate::secrets::store_proxy_headers(&o.paths, &header).unwrap();
        o
    }

    #[cfg(unix)]
    const SUDO_PASSWORD: &str = "conformance-right-password";

    /// The conformance suite's fake `sudo`: right password or `Sorry`.
    #[cfg(unix)]
    fn fake_sudo(root: &std::path::Path, right: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let script = root.join("fake-sudo");
        let body = format!(
            "#!/bin/sh\nv=\nwhile [ $# -gt 0 ]; do case \"$1\" in -S|-k) shift ;; -p) p=\"$2\"; shift 2 ;; \
             -v) v=1; shift ;; *) break ;; esac; done\nprintf %s \"$p\" >&2\nIFS= read -r pw\n\
             [ \"$pw\" = '{right}' ] || {{ echo 'Sorry, try again.' >&2; exit 1; }}\n\
             [ -n \"$v\" ] && exit 0\nexec \"$@\"\n"
        );
        std::fs::write(&script, body).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        script
    }

    /// The acceptance of the relay: a node whose only way to the center is a
    /// jump node pairs through it and passes the node part of the
    /// conformance suite there, the profile checks included (on Unix, where
    /// the suite's fake sudo runs).
    #[tokio::test(flavor = "multi_thread")]
    async fn a_relayed_node_passes_the_node_part_through_a_jump_node() {
        let (jump_dir, node_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let running: Arc<Mutex<Vec<Daemon>>> = Arc::default();
        let held = running.clone();
        let (jd, nd) = (jump_dir.path().to_path_buf(), node_dir.path().to_path_buf());
        let report = nerve_conformance::node_part::run(move |link: PairLink| async move {
            let (front, pin) = tls_front(link.center.port).await;
            let url = format!("https://127.0.0.1:{front}");
            // The jump node is paired with the center at that address.
            let o = options(&jd);
            let (token, hash) = new_token();
            let mut cfg = NodeConfig::default();
            cfg.centers.push(center("home", url.clone()));
            cfg.relay.listen = Some("127.0.0.1:0".into());
            cfg.relay.nodes.push(nerve_policy::config::RelayNode {
                name: "lab".into(),
                token_sha256: hash,
            });
            cfg.save(&o.paths.config_file()).unwrap();
            let jump = Daemon::start(o).await?;
            let relay = listening(&jump).await;
            lock(&held).push(jump);
            // The relayed node pairs through it, with the link's code.
            let o = relayed(&nd, relay, &token);
            let link = PairLink {
                center: CenterUrl::parse(&url)?,
                code: link.code,
                pin: Some(pin),
            };
            crate::pair::pair(&o.paths, &link, Some("home")).await?;
            crate::cli::edit(&o.paths, |c| {
                c.centers[0].settings = nerve_policy::config::SettingsGrant::Write;
                Ok(())
            })
            .await?;
            let folder = o.home.join("work");
            std::fs::create_dir_all(&folder).unwrap();
            let folder = std::fs::canonicalize(&folder).unwrap();
            let node = Daemon::start(o).await?;
            lock(&held).push(node);
            // The link goes through the relay: its tunnel is there.
            let mut carried = false;
            for _ in 0..400 {
                let tunnels = lock(&held)[0].status()["relay"]["tunnels"].clone();
                if tunnels[0]["node"] == "lab" && tunnels[0]["center"] == "home" {
                    carried = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            if !carried {
                return Err("the relayed node's link does not go through the relay".into());
            }
            Ok(nerve_conformance::node_part::Setup {
                folder: cfg!(unix).then(|| nerve_policy::paths::to_wire(&folder)),
                #[cfg(unix)]
                sudo_password: Some(SUDO_PASSWORD.into()),
                #[cfg(not(unix))]
                sudo_password: None,
            })
        })
        .await;
        let daemons: Vec<Daemon> = std::mem::take(&mut *lock(&running));
        let tunnels = daemons
            .first()
            .map(|j| j.status()["relay"]["tunnels"].clone());
        for d in daemons {
            d.stop().await;
        }
        assert!(report.ok(), "{report}");
        if cfg!(unix) {
            assert!(
                report.outcomes.iter().any(|o| o.section.starts_with('7')),
                "{report}"
            );
        }
        // After `bye revoked` the node does not dial again, so no tunnel is
        // left open.
        assert_eq!(tunnels, Some(json!([])));
    }

    /// A proxy below the jump node (a chain: the jump node reaches its
    /// centers through it) that keeps every byte it carries and, when told,
    /// flips one in every chunk.
    struct Middle {
        addr: SocketAddr,
        seen: Arc<Mutex<Vec<u8>>>,
        tamper: Arc<AtomicBool>,
        tampered: Arc<AtomicU64>,
    }

    async fn middle() -> Middle {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let m = Middle {
            addr: l.local_addr().unwrap(),
            seen: Arc::default(),
            tamper: Arc::default(),
            tampered: Arc::default(),
        };
        let (seen, tamper, tampered) = (m.seen.clone(), m.tamper.clone(), m.tampered.clone());
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                let (seen, tamper, tampered) = (seen.clone(), tamper.clone(), tampered.clone());
                tokio::spawn(async move {
                    let Ok(req) = read_request_head(&mut s).await else {
                        return;
                    };
                    let Ok(c) = TcpStream::connect(req.path.as_str()).await else {
                        return;
                    };
                    let _ = s
                        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                        .await;
                    let (sr, sw) = s.into_split();
                    let (cr, cw) = c.into_split();
                    let one =
                        |mut from: tokio::net::tcp::OwnedReadHalf,
                         mut to: tokio::net::tcp::OwnedWriteHalf| {
                            let (seen, tamper, tampered) =
                                (seen.clone(), tamper.clone(), tampered.clone());
                            async move {
                                let mut buf = vec![0u8; 16 * 1024];
                                while let Ok(n) = from.read(&mut buf).await {
                                    if n == 0 {
                                        break;
                                    }
                                    lock(&seen).extend_from_slice(&buf[..n]);
                                    if tamper.load(Ordering::SeqCst) {
                                        buf[0] ^= 0x01;
                                        tampered.fetch_add(1, Ordering::SeqCst);
                                    }
                                    if to.write_all(&buf[..n]).await.is_err() {
                                        break;
                                    }
                                }
                                let _ = to.shutdown().await;
                            }
                        };
                    tokio::join!(one(sr, cw), one(cr, sw));
                });
            }
        });
        m
    }

    /// What the jump node passes on is TLS only: a proxy below it sees none
    /// of the link's plain text, and when it flips bits the link does not
    /// come up, with no message of it reaching the center.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_jump_node_can_neither_read_nor_alter_the_link_it_carries() {
        let mut fake = FakeCenter::start(false).await.unwrap();
        let (front, pin) = tls_front(fake.url.port).await;
        let url = format!("https://127.0.0.1:{front}");
        let m = middle().await;
        let j = jump(vec![center("home", url.clone())], |c| {
            c.connection.proxy = Some(format!("http://{}", m.addr));
        })
        .await;
        let node_dir = tempfile::tempdir().unwrap();
        let o = relayed(node_dir.path(), j.addr, &j.token);
        let link = PairLink {
            center: CenterUrl::parse(&url).unwrap(),
            code: fake.code.clone(),
            pin: Some(pin),
        };
        crate::pair::pair(&o.paths, &link, Some("home"))
            .await
            .unwrap();
        let paired = fake.paired().expect("paired");
        // The pairing went the link's way, through the relay and below it.
        assert!(
            !lock(&m.seen).is_empty(),
            "the pairing did not go through the relay"
        );

        // Reading: the link works, and nothing of it is plain on the way.
        let node = Daemon::start(o.clone()).await.unwrap();
        let mut inc = fake
            .next_link(WAIT)
            .await
            .expect("the node dials through the relay");
        assert_eq!(inc.node_header, paired.node_id);
        fake_center::handshake(&mut inc.conn, &fake.center_id, &paired)
            .await
            .expect("handshake");
        inc.conn
            .call("describe", json!({"detail": "full"}), WAIT)
            .await
            .unwrap()
            .expect("describe");
        node.stop().await;
        let seen = String::from_utf8_lossy(&lock(&m.seen)).to_lowercase();
        assert!(seen.len() > 1000, "the link did not go through the middle");
        for plain in [
            paired.node_id.as_str(),
            paired.request.public_key.as_str(),
            fake.code.as_str(),
            "nerve-node",
            "nerve-connect",
            "/nerve/v0/",
            "\"method\"",
            "describe",
            "capabilities",
        ] {
            assert!(
                !seen.contains(&plain.to_lowercase()),
                "{plain} passed in the clear"
            );
        }

        // Altering: a flipped bit ends the link before any message counts.
        m.tamper.store(true, Ordering::SeqCst);
        let node = Daemon::start(o).await.unwrap();
        assert!(
            fake.next_link(Duration::from_secs(5)).await.is_none(),
            "an altered link reached the center"
        );
        assert!(m.tampered.load(Ordering::SeqCst) > 0, "nothing was altered");
        let status = node.status()["centers"][0]["status"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        assert!(status.starts_with("cannot connect"), "{status}");
        node.stop().await;
        j.daemon.stop().await;
    }
}
