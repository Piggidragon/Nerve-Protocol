//! One center's link: dialling with backoff, the handshake, and serving the
//! center's requests (spec §4, §5, §7).

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use tokio::sync::{mpsc, oneshot};
use tokio::task::AbortHandle;

use nerve_policy::audit::Entry;
use nerve_policy::config::{Mode, SettingsGrant};
use nerve_policy::protected::Protected;
use nerve_policy::rules::RuleSet;
use nerve_policy::{Call, CenterEntry, Decision, Env, NodeConfig, SetError, Target};
use nerve_proto::descriptor::{Detail, Effect, Exposure};
use nerve_proto::frame::{Frame, FrameError};
use nerve_proto::link::CenterUrl;
use nerve_proto::msg::{
    self, Bye, ByeReason, Cancel, Challenge, Describe, Get, Hello, Invoke, SessionEnd, Topic,
    Topics, Welcome, method,
};
use nerve_proto::rpc::{Id, Message, params};
use nerve_proto::{ErrorCode, PROTOCOL_VERSION, RpcError, limits};
use nerve_transport::backoff::Backoff;
use nerve_transport::keys::NodeKey;
use nerve_transport::net::Proxy;
use nerve_transport::ws::{self, ConnectError, WsMessage};

use crate::daemon::{CenterState, LinkHandle, Shared, lock};
use crate::descriptor;
use crate::exec::{self, RunCall, RunOptions, Sig, SignalArgs};
use crate::fs::{FsCall, conflict};

/// Each handshake step must arrive within this (spec §4.2).
const HANDSHAKE: Duration = Duration::from_secs(15);
/// Ping after this much quiet; give up after `DEAD` (spec §4.4).
const PING: Duration = Duration::from_secs(20);
const DEAD: Duration = Duration::from_secs(45);

/// How a link (or a dial) ended.
enum Outcome {
    /// Dial again after the backoff.
    Retry,
    /// Do not dial again until the config says so.
    Stop,
}

/// Dials `name` until it is removed, paused, revoked or unknown, or the
/// daemon stops.
pub(crate) async fn run_center(shared: Arc<Shared>, name: String) {
    let cs = shared.center(&name);
    let mut backoff = Backoff::default();
    let mut stop = shared.stop.subscribe();
    let mut changed = shared.changed.subscribe();
    loop {
        if *stop.borrow() {
            return;
        }
        let cfg = shared.config();
        let Some(entry) = cfg.center(&name).cloned() else {
            return;
        };
        if !entry.dials() || cfg.locked {
            return;
        }
        let key = match load_key(&shared, &name) {
            Ok(k) => k,
            Err(e) => {
                cs.set_status(e);
                return;
            }
        };
        let url = match CenterUrl::parse(&entry.url) {
            Ok(u) => u,
            Err(e) => {
                cs.set_status(format!("bad center url: {e}"));
                return;
            }
        };
        let proxy = match proxy_for(&shared, &cfg, &url).await {
            Ok(p) => p,
            Err(e) => {
                cs.set_status(format!("bad proxy: {e}"));
                return;
            }
        };
        cs.set_status("connecting");
        let started = Instant::now();
        let dialled = ws::connect(
            &url,
            entry.pin.as_deref(),
            proxy.as_ref(),
            &key.node_id(),
            limits::MESSAGE_BYTES as usize,
        )
        .await;
        let outcome = match dialled {
            Err(ConnectError::Unknown) => {
                tracing::warn!("center {name} does not know this node (401); dialling stopped");
                cs.set_status("the center does not know this node (401); dialling stopped");
                shared.mark_center(&name, |e| e.unknown = true);
                return;
            }
            Err(ConnectError::Other(e)) => {
                cs.set_status(format!("cannot connect: {e}"));
                Outcome::Retry
            }
            Ok(ws) => session(&shared, &cs, &entry, &key, ws).await,
        };
        if let Outcome::Stop = outcome {
            return;
        }
        backoff.link_ended(started.elapsed());
        let until = tokio::time::Instant::now() + backoff.next_wait();
        // Wait out the backoff, but leave at once when the center goes away.
        loop {
            tokio::select! {
                _ = tokio::time::sleep_until(until) => break,
                _ = stop.changed() => return,
                r = changed.changed() => {
                    if r.is_err() {
                        return;
                    }
                    let cfg = shared.config();
                    if cfg.locked || !cfg.center(&name).is_some_and(CenterEntry::dials) {
                        return;
                    }
                }
            }
        }
    }
}

fn load_key(shared: &Shared, name: &str) -> Result<NodeKey, String> {
    let path = shared.paths.key_file(name);
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read the node key {}: {e}", path.display()))?;
    NodeKey::from_text(text.trim()).map_err(|e| format!("bad node key {}: {e}", path.display()))
}

/// The proxy to dial `url` through, its header values read from the system
/// keyring. An error stops the dial: a configured proxy is never bypassed.
async fn proxy_for(
    shared: &Shared,
    cfg: &NodeConfig,
    url: &CenterUrl,
) -> Result<Option<Proxy>, String> {
    let Some(p) = &cfg.connection.proxy else {
        return Proxy::from_env(&url.host);
    };
    // The keyring may block (the Secret Service asks to unlock), so off the
    // runtime's threads.
    let (paths, names) = (shared.paths.clone(), cfg.connection.headers.clone());
    let headers =
        tokio::task::spawn_blocking(move || crate::secrets::proxy_headers(&paths, &names))
            .await
            .map_err(|e| format!("the keyring read stopped: {e}"))??;
    Proxy::parse(p, headers).map(Some)
}

/// What one read from the link gave.
enum Got {
    Msg(Message),
    /// A message that did not parse; the error reply to send.
    Bad(Message),
    Binary(Vec<u8>),
    /// Anything else that shows the center is alive (ping, pong).
    Alive,
    TooLarge,
    Closed,
}

async fn read<S>(stream: &mut S) -> Got
where
    S: futures_util::Stream<Item = Result<WsMessage, tokio_tungstenite::tungstenite::Error>>
        + Unpin,
{
    match stream.next().await {
        None | Some(Err(_)) => Got::Closed,
        Some(Ok(WsMessage::Text(t))) => {
            if t.len() as u64 > limits::MESSAGE_BYTES {
                return Got::TooLarge;
            }
            match Message::decode(t.as_str()) {
                Ok(m) => Got::Msg(m),
                Err(reply) => Got::Bad(*reply),
            }
        }
        Some(Ok(WsMessage::Binary(b))) => Got::Binary(b.to_vec()),
        Some(Ok(WsMessage::Close(_))) => Got::Closed,
        Some(Ok(_)) => Got::Alive,
    }
}

fn text(m: &Message) -> WsMessage {
    WsMessage::text(m.encode())
}

fn bye(reason: ByeReason) -> WsMessage {
    text(&Message::notification(
        method::BYE,
        serde_json::to_value(Bye { reason }).unwrap_or_default(),
    ))
}

/// Reads the next handshake notification named `want`.
async fn handshake_step<S, T>(stream: &mut S, want: &str) -> Result<T, (Option<ByeReason>, String)>
where
    S: futures_util::Stream<Item = Result<WsMessage, tokio_tungstenite::tungstenite::Error>>
        + Unpin,
    T: serde::de::DeserializeOwned,
{
    let got = tokio::time::timeout(HANDSHAKE, async {
        loop {
            match read(stream).await {
                Got::Alive => continue,
                other => return other,
            }
        }
    })
    .await
    .map_err(|_| (None, format!("no {want} within 15 s")))?;
    match got {
        Got::Msg(Message::Notification {
            method: m,
            params: p,
        }) if m == want => params::<T>(&p).map_err(|e| (Some(ByeReason::ProtocolError), e.message)),
        Got::Msg(Message::Notification {
            method: m,
            params: p,
        }) if m == method::BYE => {
            let reason = params::<Bye>(&p)
                .map(|b| b.reason.as_str().to_string())
                .unwrap_or_default();
            Err((None, format!("the center said bye ({reason})")))
        }
        Got::Closed => Err((None, "the link closed during the handshake".into())),
        _ => Err((
            Some(ByeReason::ProtocolError),
            format!("expected {want} during the handshake"),
        )),
    }
}

type WsStream = tokio_tungstenite::WebSocketStream<nerve_transport::net::BoxIo>;

/// One connected link: handshake, then serve until it ends.
async fn session(
    shared: &Arc<Shared>,
    cs: &Arc<CenterState>,
    entry: &CenterEntry,
    key: &NodeKey,
    ws: WsStream,
) -> Outcome {
    let (mut sink, mut stream) = ws.split();
    let cfg = shared.config();

    // Handshake (spec §4.2): challenge → hello → welcome.
    let hello = async {
        let ch: Challenge = handshake_step(&mut stream, method::CHALLENGE).await?;
        let nonce = msg::unhex(&ch.nonce).filter(|n| n.len() == 32).ok_or((
            Some(ByeReason::ProtocolError),
            "bad challenge nonce".to_string(),
        ))?;
        if ch.center_id != entry.center_id {
            return Err((
                Some(ByeReason::ProtocolError),
                "the center's id is not the paired one".to_string(),
            ));
        }
        let rev = descriptor::for_center(&cfg, entry, crate::now_ms(), shared.confined()).rev;
        let hello = Hello {
            node_id: key.node_id(),
            auth: msg::Auth {
                sig: key.sign_connect(&ch.center_id, &nonce),
            },
            versions: vec![PROTOCOL_VERSION.to_string()],
            software: msg::Software {
                name: descriptor::SOFTWARE.into(),
                version: descriptor::VERSION.into(),
            },
            limits: msg::Limits::default(),
            rev,
        };
        let m = Message::notification(
            method::HELLO,
            serde_json::to_value(hello).unwrap_or_default(),
        );
        sink.send(text(&m))
            .await
            .map_err(|e| (None, format!("send: {e}")))?;
        let w: Welcome = handshake_step(&mut stream, method::WELCOME).await?;
        if w.version != PROTOCOL_VERSION {
            return Err((
                Some(ByeReason::UnsupportedVersion),
                format!("the center chose version {:?}", w.version),
            ));
        }
        Ok(())
    }
    .await;
    if let Err((reason, why)) = hello {
        cs.set_status(format!("handshake failed: {why}"));
        if let Some(r) = reason {
            let _ = sink.send(bye(r)).await;
        }
        let _ = sink.close().await;
        return Outcome::Retry;
    }
    tracing::info!("linked to center {}", entry.name);
    cs.set_status("connected");

    // One writer owns the sink; everyone else queues (spec §5.5).
    let (tx, mut rx) = mpsc::channel::<WsMessage>(limits::SEND_QUEUE);
    let (done_tx, mut done_rx) = oneshot::channel::<()>();
    // Every frame leaves through here, so the sudo password never does.
    let scrubber = shared.clone();
    let writer = tokio::spawn(async move {
        loop {
            tokio::select! {
                m = rx.recv() => match m {
                    Some(m) => if sink.send(scrub(&scrubber, m)).await.is_err() { return; },
                    None => break,
                },
                _ = &mut done_rx => {
                    // Flush what is queued (the bye), then close.
                    while let Ok(m) = rx.try_recv() {
                        if sink.send(scrub(&scrubber, m)).await.is_err() {
                            return;
                        }
                    }
                    break;
                }
            }
        }
        let _ = sink.close().await;
    });

    let handle = Arc::new(LinkHandle::new(tx.clone()));
    *lock(&cs.link) = Some(handle.clone());
    let link = Arc::new(Link {
        shared: shared.clone(),
        cs: cs.clone(),
        name: entry.name.clone(),
        handle,
        tx,
        calls: Mutex::default(),
        commands: Mutex::default(),
        last_status: Mutex::new("online"),
    });

    let outcome = link.serve(&mut stream).await;

    // The link is gone (spec §4.5): calls end, commands die with their
    // process groups.
    *lock(&cs.link) = None;
    let calls: Vec<InFlight> = lock(&link.calls).drain().map(|(_, c)| c).collect();
    for c in calls {
        c.abort.abort();
    }
    let _ = done_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(2), writer).await;
    if matches!(outcome, Outcome::Retry) {
        cs.set_status("link lost; dialling again");
    }
    outcome
}

/// A call in flight: its task, and the harness session it came from.
struct InFlight {
    abort: AbortHandle,
    session: Option<String>,
}

/// A live link's state shared with its calls.
struct Link {
    shared: Arc<Shared>,
    cs: Arc<CenterState>,
    name: String,
    handle: Arc<LinkHandle>,
    tx: mpsc::Sender<WsMessage>,
    /// Calls in flight; whoever removes an entry sends its reply.
    calls: Mutex<HashMap<Id, InFlight>>,
    /// Running `exec.run` calls → what ends them.
    commands: Mutex<HashMap<Id, exec::Ender>>,
    /// The `node` status the center last heard (online, busy or paused).
    last_status: Mutex<&'static str>,
}

impl Link {
    async fn send(&self, m: Message) {
        let _ = self.tx.send(text(&m)).await;
    }

    async fn reply(&self, id: Id, r: Result<Value, RpcError>) {
        self.send(match r {
            Ok(v) => Message::result(id, v),
            Err(e) => Message::error(Some(id), e),
        })
        .await;
    }

    /// The center's entry, or `None` when it was removed meanwhile.
    fn entry(&self) -> Option<(NodeConfig, CenterEntry)> {
        let cfg = self.shared.config();
        let e = cfg.center(&self.name).cloned()?;
        Some((cfg, e))
    }

    async fn serve(
        self: &Arc<Self>,
        stream: &mut futures_util::stream::SplitStream<WsStream>,
    ) -> Outcome {
        let mut stop = self.shared.stop.subscribe();
        let mut changed = self.shared.changed.subscribe();
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        let mut heard = Instant::now();
        let mut pinged = Instant::now();
        let (cfg, entry) = match self.entry() {
            Some(x) => x,
            None => return self.end(ByeReason::Unpaired, Outcome::Stop).await,
        };
        let mut rev =
            descriptor::for_center(&cfg, &entry, crate::now_ms(), self.shared.confined()).rev;
        let mut version = cfg.version;
        loop {
            tokio::select! {
                got = read(stream) => {
                    heard = Instant::now();
                    match got {
                        Got::Msg(m) => {
                            if let Some(o) = self.message(m).await {
                                return o;
                            }
                        }
                        Got::Bad(reply) => self.send(reply).await,
                        Got::Binary(b) => {
                            // No blobs or streams flow center → node in 0.0.1;
                            // only reserved media frames break the link.
                            if let Err(FrameError::MediaReserved) = Frame::decode(&b) {
                                return self.end(ByeReason::ProtocolError, Outcome::Retry).await;
                            }
                        }
                        Got::Alive => {}
                        Got::TooLarge => {
                            return self.end(ByeReason::ProtocolError, Outcome::Retry).await;
                        }
                        Got::Closed => return Outcome::Retry,
                    }
                }
                _ = tick.tick() => {
                    if heard.elapsed() >= DEAD {
                        tracing::info!("center {} went quiet; dropping the link", self.name);
                        return Outcome::Retry;
                    }
                    if heard.elapsed() >= PING && pinged.elapsed() >= PING {
                        pinged = Instant::now();
                        let _ = self.tx.try_send(WsMessage::Ping(Default::default()));
                    }
                    self.check_rev(&mut rev);
                    self.check_status();
                }
                r = changed.changed() => {
                    if r.is_err() {
                        return self.end(ByeReason::Shutdown, Outcome::Stop).await;
                    }
                    let Some((cfg, entry)) = self.entry() else {
                        return self.end(ByeReason::Unpaired, Outcome::Stop).await;
                    };
                    if cfg.locked || entry.paused {
                        self.cs.set_status("paused");
                        return self.end(ByeReason::Paused, Outcome::Stop).await;
                    }
                    if entry.revoked || entry.unknown {
                        return self.end(ByeReason::Unpaired, Outcome::Stop).await;
                    }
                    self.check_rev(&mut rev);
                    if cfg.version != version {
                        version = cfg.version;
                        if entry.settings == SettingsGrant::Write {
                            self.handle.event("settings", "changed", json!({"version": version}));
                        }
                    }
                }
                _ = stop.changed() => {
                    self.handle.event("node", "going_away", json!({"reason": "shutdown"}));
                    self.cs.set_status("stopped");
                    return self.end(ByeReason::Shutdown, Outcome::Stop).await;
                }
            }
        }
    }

    /// Tells the center when its view of the node changed.
    fn check_rev(&self, rev: &mut u64) {
        if let Some((cfg, entry)) = self.entry() {
            let now =
                descriptor::for_center(&cfg, &entry, crate::now_ms(), self.shared.confined()).rev;
            if now != *rev {
                *rev = now;
                self.handle
                    .event("node", "descriptor_changed", json!({"rev": now}));
            }
        }
    }

    /// Sends a `node` state change when the status moved (spec §7.1). Other
    /// links' commands count too, so the 5 s tick catches those.
    fn check_status(&self) {
        let Some((cfg, _)) = self.entry() else {
            return;
        };
        let now = self.status(&cfg);
        let mut last = lock(&self.last_status);
        if *last != now {
            *last = now;
            self.handle.state("node", json!({"status": now}));
        }
    }

    async fn end(&self, reason: ByeReason, o: Outcome) -> Outcome {
        let _ = self.tx.send(bye(reason)).await;
        o
    }

    /// Handles one message; `Some` ends the link.
    async fn message(self: &Arc<Self>, m: Message) -> Option<Outcome> {
        match m {
            Message::Request {
                id,
                method: m,
                params: p,
            } => {
                self.request(id, &m, p).await;
                None
            }
            Message::Notification {
                method: m,
                params: p,
            } => self.notification(&m, p),
            // The node sends no requests of its own.
            Message::Result { .. } | Message::Error { .. } => None,
        }
    }

    fn notification(&self, m: &str, p: Map<String, Value>) -> Option<Outcome> {
        match m {
            method::CANCEL => {
                let Ok(c) = params::<Cancel>(&p) else {
                    return None;
                };
                let Ok(id) = serde_json::from_value::<Id>(c.id) else {
                    return None;
                };
                self.cancel(id, "cancelled");
                None
            }
            // The calls of an ended session end like cancelled ones: a
            // command's process group is killed as on a timeout.
            method::SESSION_END => {
                let Ok(end) = params::<SessionEnd>(&p) else {
                    return None;
                };
                let ids: Vec<Id> = lock(&self.calls)
                    .iter()
                    .filter(|(_, c)| c.session.as_deref() == Some(end.session.as_str()))
                    .map(|(id, _)| id.clone())
                    .collect();
                for id in ids {
                    self.cancel(id, "cancelled: the harness session ended");
                }
                None
            }
            method::BYE => {
                let reason = params::<Bye>(&p).ok().map(|b| b.reason);
                match reason {
                    Some(r) if r.stops_node() => {
                        tracing::warn!("center {} ended the pairing ({})", self.name, r.as_str());
                        self.cs.set_status(format!(
                            "the center said {}; dialling stopped",
                            r.as_str()
                        ));
                        self.shared.mark_center(&self.name, |e| e.revoked = true);
                        Some(Outcome::Stop)
                    }
                    _ => Some(Outcome::Retry),
                }
            }
            // Unknown notifications are ignored (spec §3).
            _ => None,
        }
    }

    /// Stops call `id` and answers it `cancelled`. Aborting its task drops
    /// a running command, which kills its process group (exec::Group).
    fn cancel(&self, id: Id, why: &str) {
        let c = lock(&self.calls).remove(&id);
        if let Some(c) = c {
            c.abort.abort();
            let e = Message::error(Some(id), RpcError::new(ErrorCode::Cancelled, why));
            let _ = self.tx.try_send(text(&e));
        }
    }

    async fn request(self: &Arc<Self>, id: Id, m: &str, p: Map<String, Value>) {
        let r = match m {
            method::DESCRIBE => self.describe(&p),
            method::INVOKE => {
                self.start_invoke(id, p).await;
                return;
            }
            method::GET => self.get(&p),
            method::SUB | method::UNSUB => self.sub(&p, m == method::SUB),
            method::STREAM_OPEN => Err(RpcError::new(
                ErrorCode::Unavailable,
                "this node offers no streams",
            )),
            method::STREAM_CLOSE => Err(RpcError::new(ErrorCode::UnknownMember, "no such stream")),
            other => Err(RpcError::new(
                ErrorCode::MethodNotFound,
                format!("unknown method {other}"),
            )),
        };
        self.reply(id, r).await;
    }

    fn view(&self) -> Result<nerve_proto::descriptor::Descriptor, RpcError> {
        let (cfg, entry) = self
            .entry()
            .ok_or_else(|| RpcError::new(ErrorCode::Unavailable, "this center was removed"))?;
        Ok(descriptor::for_center(
            &cfg,
            &entry,
            crate::now_ms(),
            self.shared.confined(),
        ))
    }

    fn describe(&self, p: &Map<String, Value>) -> Result<Value, RpcError> {
        let d: Describe = params(p)?;
        if d.detail == Detail::Capability && d.cap.is_none() {
            return Err(RpcError::invalid_args("detail capability needs cap"));
        }
        let view = self.view()?;
        let out = view
            .at_detail(d.detail, d.cap.as_deref())
            .ok_or_else(|| RpcError::new(ErrorCode::UnknownCapability, "no such capability"))?;
        serde_json::to_value(out).map_err(|e| RpcError::internal(e.to_string()))
    }

    fn sub(&self, p: &Map<String, Value>, on: bool) -> Result<Value, RpcError> {
        let t: Topics = params(p)?;
        let view = self.view()?;
        let mut topics = Vec::new();
        for s in &t.topics {
            let topic = Topic::parse(s)
                .ok_or_else(|| RpcError::invalid_args(format!("bad topic {s:?}")))?;
            if view.capability(topic.cap()).is_none() {
                return Err(RpcError::new(
                    ErrorCode::UnknownCapability,
                    format!("no capability {}", topic.cap()),
                ));
            }
            topics.push(topic);
        }
        self.handle.sub(topics, on);
        Ok(json!({}))
    }

    fn get(&self, p: &Map<String, Value>) -> Result<Value, RpcError> {
        let g: Get = params(p)?;
        let view = self.view()?;
        if view.capability(&g.cap).is_none() {
            return Err(RpcError::new(
                ErrorCode::UnknownCapability,
                "no such capability",
            ));
        }
        let (cfg, _) = self
            .entry()
            .ok_or_else(|| RpcError::new(ErrorCode::Unavailable, "this center was removed"))?;
        let all: &[&str] = match g.cap.as_str() {
            "node" => &["status"],
            "exec" => &["shell", "confinement"],
            "settings" => &["document", "version", "sudo"],
            _ => &[],
        };
        let keys: Vec<String> = if g.keys.is_empty() {
            all.iter().map(|k| k.to_string()).collect()
        } else {
            g.keys
        };
        let mut out = Map::new();
        for k in keys {
            if !all.contains(&k.as_str()) {
                return Err(RpcError::new(
                    ErrorCode::UnknownMember,
                    format!("{} has no state {k}", g.cap),
                ));
            }
            let v = match k.as_str() {
                "status" => json!(self.status(&cfg)),
                "shell" => json!(exec::shell_command(cfg.machine.shell.as_deref(), "").0),
                "confinement" => json!(self.confinement()),
                "document" => {
                    let doc = lock(&self.shared.store).center_document(&self.name);
                    serde_json::to_value(doc).map_err(|e| RpcError::internal(e.to_string()))?
                }
                "sudo" => json!(if self.shared.sudo_on() { "on" } else { "off" }),
                _ => json!(lock(&self.shared.store).version()),
            };
            out.insert(k, v);
        }
        Ok(Value::Object(out))
    }

    fn status(&self, cfg: &NodeConfig) -> &'static str {
        if cfg.locked {
            "paused"
        } else if self.shared.running.load(Ordering::Relaxed) >= cfg.limits.max_running as usize {
            "busy"
        } else {
            "online"
        }
    }

    fn confinement(&self) -> String {
        let folders = self
            .entry()
            .is_some_and(|(_, e)| e.policy.mode_at(crate::now_ms()) == Mode::Folder);
        if folders && self.shared.confined() {
            self.shared.confinement.describe()
        } else {
            "none".into()
        }
    }

    /// Starts an `invoke` as its own task, so a slow call does not hold up the
    /// link.
    async fn start_invoke(self: &Arc<Self>, id: Id, p: Map<String, Value>) {
        let inv = match params::<Invoke>(&p).and_then(|i| i.check().map(|()| i)) {
            Ok(i) => i,
            Err(e) => return self.reply(id, Err(e)).await,
        };
        let refusal = {
            let calls = lock(&self.calls);
            if calls.len() >= limits::CALLS as usize {
                Some(RpcError::new(ErrorCode::Busy, "too many calls in flight"))
            } else if calls.contains_key(&id) {
                Some(RpcError::new(
                    ErrorCode::InvalidRequest,
                    "this id is already in flight",
                ))
            } else {
                None
            }
        };
        if let Some(e) = refusal {
            return self.reply(id, Err(e)).await;
        }
        let link = self.clone();
        let call_id = id.clone();
        let session = inv.ctx.session.clone();
        // The deadline counts from receipt (spec §5.1).
        let deadline = inv.deadline_ms.map(Duration::from_millis);
        // Held until the handle is in the map, so a call that finishes at
        // once still finds its entry and replies.
        let mut calls = lock(&self.calls);
        let task = tokio::spawn(async move {
            let settings = inv.cap == "settings";
            let work = link.invoke(&call_id, inv);
            let r = match deadline {
                Some(d) => tokio::time::timeout(d, work).await.unwrap_or_else(|_| {
                    Err(RpcError::new(ErrorCode::Timeout, "the deadline passed"))
                }),
                None => work.await,
            };
            let mine = lock(&link.calls).remove(&call_id).is_some();
            if mine {
                link.reply(call_id, r).await;
            }
            if settings {
                // The reply goes first, then `settings/changed`.
                link.shared.bump();
            }
        });
        calls.insert(
            id,
            InFlight {
                abort: task.abort_handle(),
                session,
            },
        );
    }

    async fn invoke(self: &Arc<Self>, id: &Id, inv: Invoke) -> Result<Value, RpcError> {
        let (cfg, entry) = self
            .entry()
            .ok_or_else(|| RpcError::new(ErrorCode::Unavailable, "this center was removed"))?;
        let view = descriptor::for_call(&cfg, &entry, crate::now_ms());
        let cap = view.capability(&inv.cap).ok_or_else(|| {
            RpcError::new(
                ErrorCode::UnknownCapability,
                format!("no capability {}", inv.cap),
            )
        })?;
        let action = cap.actions.get(&inv.action).ok_or_else(|| {
            RpcError::new(
                ErrorCode::UnknownMember,
                format!("{} has no action {}", inv.cap, inv.action),
            )
        })?;
        let effect = action.effect;
        let off = cap.exposure == Exposure::Off
            || entry.policy.cap_setting(&inv.cap, Some(&inv.action))
                == Some(nerve_policy::config::CapSetting::Off);
        if off {
            return Err(RpcError::new(
                ErrorCode::Disabled,
                format!("{}.{} is off", inv.cap, inv.action),
            ));
        }
        match (inv.cap.as_str(), inv.action.as_str()) {
            ("settings", "set") => self.settings_set(&inv.args),
            ("settings", "pause") => self.settings_pause(),
            ("settings", "sudo-offer") => self.sudo_offer(&entry),
            ("settings", "sudo") => self.settings_sudo(&inv.args).await,
            ("exec", "signal") => {
                // Decided and audited like any other action; its rule target
                // is the action itself.
                let target = format!("{}.{}", inv.cap, inv.action);
                self.gate(&entry, &inv, effect, &[], None, None, target)?;
                self.signal(&inv.args)
            }
            ("exec", "run") => self.exec_run(id, &cfg, &entry, effect, &inv).await,
            ("fs", a) => {
                let call = FsCall::parse(a, &inv.args)?;
                // Taken before the gate: whenever the gate judged by the
                // folders, the walk below does too, even if `until` passes
                // in between.
                let by_folders = entry.policy.mode_at(crate::now_ms()) == Mode::Folder;
                self.gate(
                    &entry,
                    &inv,
                    effect,
                    &call.targets(),
                    None,
                    None,
                    call.target_text(),
                )?;
                let protected = self.protected(&entry);
                let deny = RuleSet::new(&entry.policy.deny, &self.shared.home);
                let folders = entry.policy.folders.clone();
                let action = inv.action.clone();
                tokio::task::spawn_blocking(move || {
                    // An entry the direct read would refuse stays out of the
                    // walk, so a folder without `r` inside one with `r` is
                    // sealed to grep, find and list too. A walk still passes
                    // through such a folder to a folder with `r` inside it,
                    // and finds only the files there.
                    let skip = |p: &std::path::Path, through: bool| {
                        protected.check(p, false, &folders).is_some()
                            || deny
                                .find("fs", &action, &nerve_policy::paths::to_wire(p))
                                .is_some()
                            || by_folders
                                && !nerve_policy::folder_reach(&folders, p, false)
                                && !(through && nerve_policy::readable_below(&folders, p))
                    };
                    call.run(&skip)
                })
                .await
                .map_err(|e| RpcError::internal(e.to_string()))?
            }
            _ => Err(RpcError::new(
                ErrorCode::UnknownMember,
                format!("{}.{} is not served", inv.cap, inv.action),
            )),
        }
    }

    fn protected(&self, entry: &CenterEntry) -> Protected {
        self.protected_with(&entry.policy.protected)
    }

    /// This node's protected list with a center's options.
    fn protected_with(&self, opts: &nerve_policy::config::ProtectedOptions) -> Protected {
        Protected::new(
            &self.shared.platform,
            &self.shared.home,
            &self.shared.paths.own(),
            opts,
        )
    }

    /// Runs the policy for one call: it either runs or is refused at once.
    /// Every outcome lands in the audit log.
    #[allow(clippy::too_many_arguments)]
    fn gate(
        &self,
        entry: &CenterEntry,
        inv: &Invoke,
        effect: Effect,
        targets: &[Target],
        command: Option<&str>,
        cwd: Option<&std::path::Path>,
        target: String,
    ) -> Result<(), RpcError> {
        let call = Call {
            cap: &inv.cap,
            action: &inv.action,
            effect,
            targets,
            command,
            cwd,
            now_ms: crate::now_ms(),
        };
        let decision = {
            let protected = self.protected(entry);
            let env = Env {
                home: &self.shared.home,
                protected: &protected,
                confined: self.shared.confined(),
                sudo: self.shared.sudo_on(),
            };
            nerve_policy::decide(&entry.policy, &env, &call)
        };
        let audit = |decision: &str, code: Option<&str>| {
            self.shared.audit(&Entry {
                ts: crate::now_ms(),
                center: self.name.clone(),
                cap: inv.cap.clone(),
                action: inv.action.clone(),
                target: target.clone(),
                decision: decision.into(),
                code: code.map(Into::into),
                session: inv.ctx.session.clone(),
            })
        };
        match decision {
            Decision::Allow => {
                audit("allowed", None);
                Ok(())
            }
            Decision::Disabled(why) => {
                audit("forbidden", Some("disabled"));
                Err(RpcError::new(ErrorCode::Disabled, why))
            }
            Decision::Forbidden(why) => {
                audit("forbidden", Some("forbidden"));
                Err(RpcError::forbidden(why))
            }
        }
    }

    fn settings_set(&self, args: &Map<String, Value>) -> Result<Value, RpcError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Set {
            document: Value,
            if_version: u64,
        }
        let s: Set = params(args)?;
        let r = lock(&self.shared.store).set_center_document(
            &self.name,
            s.document,
            s.if_version,
            // This node offers no sense capabilities in 0.0.1.
            |_| false,
            |opts| self.protected_with(opts),
        );
        settings_result(r)
    }

    /// `settings.pause`: a center may pause itself, never unpause.
    fn settings_pause(&self) -> Result<Value, RpcError> {
        let mut store = lock(&self.shared.store);
        let doc = store
            .center_document(&self.name)
            .ok_or_else(|| RpcError::new(ErrorCode::Unavailable, "this center was removed"))?;
        let mut v = serde_json::to_value(doc).map_err(|e| RpcError::internal(e.to_string()))?;
        v["paused"] = Value::Bool(true);
        let version = store.version();
        let r = store.set_center_document(
            &self.name,
            v,
            version,
            |_| false,
            |opts| self.protected_with(opts),
        );
        settings_result(r).map(|_| json!({}))
    }

    /// `settings.sudo-offer`: a fresh one-shot key for the sealed password,
    /// signed with this node's key for the center. A new offer replaces the
    /// open one.
    fn sudo_offer(&self, entry: &CenterEntry) -> Result<Value, RpcError> {
        let pending =
            nerve_transport::sudo::Pending::new(crate::now_ms()).map_err(RpcError::internal)?;
        let key = load_key(&self.shared, &self.name).map_err(RpcError::internal)?;
        let center_id = entry.center_id.clone();
        let offer = pending.offer().clone();
        let sig = key.sign_sudo_offer(&center_id, &offer);
        lock(&self.shared.sudo_offers).insert(self.name.clone(), pending);
        Ok(json!({"offer": offer.offer, "key": offer.key, "ts": offer.ts, "sig": sig}))
    }

    /// `settings.sudo`: on with a sealed password the node checks with
    /// `sudo -v`, or off.
    async fn settings_sudo(&self, args: &Map<String, Value>) -> Result<Value, RpcError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct SudoArgs {
            on: bool,
            #[serde(default)]
            sealed: Option<nerve_transport::sudo::Sealed>,
        }
        let a: SudoArgs = params(args)?;
        let by = nerve_policy::Writer::Center(&self.name);
        if !a.on {
            if a.sealed.is_some() {
                return Err(RpcError::invalid_args("off takes no sealed password"));
            }
            return settings_result(self.shared.sudo_switch_off(by))
                .map(|_| json!({"sudo": "off"}));
        }
        let sealed = a
            .sealed
            .ok_or_else(|| RpcError::invalid_args("on needs a sealed password"))?;
        // Taken out before it is opened: an offer opens once, right or wrong.
        let pending = lock(&self.shared.sudo_offers)
            .remove(&self.name)
            .ok_or_else(|| {
                RpcError::invalid_args("no open sudo offer; ask settings.sudo-offer for one")
            })?;
        let password = pending
            .open(&sealed, crate::now_ms())
            .map_err(RpcError::invalid_args)?;
        settings_result(self.shared.sudo_switch_on(by, password).await)
            .map(|_| json!({"sudo": "on"}))
    }

    fn signal(&self, args: &Map<String, Value>) -> Result<Value, RpcError> {
        let s: SignalArgs = params(args)?;
        let sig = Sig::parse(&s.signal)
            .ok_or_else(|| RpcError::invalid_args("signal must be term, kill or int"))?;
        let id: Id = serde_json::from_value(s.call)
            .map_err(|_| RpcError::invalid_args("call must be a request id"))?;
        let ender = lock(&self.commands)
            .get(&id)
            .cloned()
            .ok_or_else(|| RpcError::invalid_args(format!("no running command {id}")))?;
        ender.signal(sig);
        Ok(json!({}))
    }

    async fn exec_run(
        self: &Arc<Self>,
        id: &Id,
        cfg: &NodeConfig,
        entry: &CenterEntry,
        effect: Effect,
        inv: &Invoke,
    ) -> Result<Value, RpcError> {
        let rc = RunCall::parse(&inv.args, &self.shared.home)?;
        let target = rc.command.clone();
        self.gate(
            entry,
            inv,
            effect,
            &rc.targets(),
            Some(&rc.command),
            Some(&rc.cwd),
            target,
        )?;
        // The policy let a sudo command through only with the switch on and
        // the sudo allow list naming it. It runs the node's sudo, with the
        // password on stdin once sudo prompts for it, and without Landlock,
        // which would keep sudo from rising.
        let mut rc = rc;
        let mut sudo = None;
        if let Some(args) = nerve_policy::sudo_command(&rc.command) {
            let password = self
                .shared
                .sudo_password()
                .ok_or_else(|| RpcError::forbidden("sudo is off on this node"))?;
            let prompt = exec::sudo_prompt();
            rc.command = exec::sudo_line(&self.shared.sudo_path(), args, &prompt);
            sudo = Some(exec::SudoInput { password, prompt });
        }
        let guard = Running::start(self, id.clone(), cfg.limits.max_running as usize)?;
        let landlock = (sudo.is_none()
            && entry.policy.mode_at(crate::now_ms()) == Mode::Folder
            && self.shared.confined())
        .then(|| exec::landlock_spec(&entry.policy, &self.shared.home, &self.shared.paths.own()));
        let opts = RunOptions {
            shell: cfg.machine.shell.clone(),
            landlock,
            exe: self.shared.exe.clone().unwrap_or_default(),
            output_cap: (cfg.limits.output_cap_bytes as usize).min(exec::OUTPUT_HARD_CAP),
            sudo,
        };
        let r = exec::run(&rc, &opts, |e| guard.started(e)).await;
        drop(guard);
        if let Ok(v) = &r {
            self.handle.event(
                "exec",
                "exit",
                json!({"call": id, "exit_code": v.get("exit_code").cloned().unwrap_or(Value::Null)}),
            );
        }
        r
    }
}

/// `m` without the sudo password (crate::sudo).
fn scrub(shared: &Shared, m: WsMessage) -> WsMessage {
    match m {
        WsMessage::Text(t) => WsMessage::text(shared.scrub(t.to_string())),
        other => other,
    }
}

fn settings_result(r: Result<u64, SetError>) -> Result<Value, RpcError> {
    match r {
        Ok(v) => Ok(json!({"version": v})),
        Err(SetError::Conflict { current }) => Err(conflict(format!(
            "the settings changed (version {current})"
        ))
        .with("version", json!(current))),
        Err(SetError::Forbidden(f)) => Err(RpcError::forbidden(f)),
        Err(SetError::Invalid(e)) => Err(RpcError::invalid_args(e)),
        Err(SetError::Io(e)) => Err(RpcError::internal(e)),
    }
}

/// Counts a running command and remembers its process group, so a control
/// request from below it is refused and `exec.signal` can find it.
struct Running<'a> {
    link: &'a Link,
    id: Id,
    pid: Mutex<Option<u32>>,
}

impl<'a> Running<'a> {
    fn start(link: &'a Link, id: Id, max: usize) -> Result<Running<'a>, RpcError> {
        let n = link.shared.running.fetch_add(1, Ordering::SeqCst);
        if n >= max {
            link.shared.running.fetch_sub(1, Ordering::SeqCst);
            return Err(RpcError::new(
                ErrorCode::Busy,
                format!("{max} commands are running already"),
            ));
        }
        link.check_status();
        Ok(Running {
            link,
            id,
            pid: Mutex::new(None),
        })
    }

    fn started(&self, ender: &exec::Ender) {
        let pid = ender.pid();
        *lock(&self.pid) = Some(pid);
        lock(&self.link.shared.commands).insert(pid, self.link.name.clone());
        lock(&self.link.commands).insert(self.id.clone(), ender.clone());
    }
}

impl Drop for Running<'_> {
    fn drop(&mut self) {
        if let Some(pid) = *lock(&self.pid) {
            lock(&self.link.shared.commands).remove(&pid);
        }
        lock(&self.link.commands).remove(&self.id);
        self.link.shared.running.fetch_sub(1, Ordering::SeqCst);
        self.link.check_status();
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use crate::daemon::{Daemon, NodeOptions};
    use crate::paths::NodePaths;

    /// A node with one center behind a proxy that wants the header `X-Key`,
    /// and listeners standing in for the center and the proxy.
    async fn behind_a_proxy() -> (tempfile::TempDir, NodePaths, TcpListener, TcpListener) {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("config"), d.path().join("state"));
        let center = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut cfg = nerve_policy::NodeConfig::default();
        cfg.centers.push(nerve_policy::CenterEntry {
            name: "home".into(),
            // Only TLS goes through the proxy; the tunnel carries it.
            url: format!("https://127.0.0.1:{}", center.local_addr().unwrap().port()),
            pin: None,
            center_id: "c".into(),
            node_id: "n".into(),
            settings: Default::default(),
            paused: false,
            revoked: false,
            unknown: false,
            policy: Default::default(),
        });
        cfg.connection.proxy = Some(format!(
            "http://127.0.0.1:{}",
            proxy.local_addr().unwrap().port()
        ));
        cfg.connection.headers = vec!["X-Key".into()];
        cfg.save(&paths.config_file()).unwrap();
        let key = nerve_transport::keys::NodeKey::generate().unwrap();
        let key_file = paths.key_file("home");
        nerve_transport::files::create_private_dir(key_file.parent().unwrap()).unwrap();
        nerve_transport::files::write_private(&key_file, key.to_text().as_bytes()).unwrap();
        (d, paths, center, proxy)
    }

    async fn start(d: &tempfile::TempDir, paths: &NodePaths) -> Daemon {
        let mut opts = NodeOptions::new(paths.clone());
        opts.home = d.path().to_path_buf();
        opts.ctl = false;
        Daemon::start(opts).await.unwrap()
    }

    /// The status of the center once it is no longer `connecting`.
    async fn settled_status(daemon: &Daemon) -> String {
        for _ in 0..200 {
            let s = daemon.status()["centers"][0]["status"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            if !["", "not connected", "connecting"].contains(&s.as_str()) {
                return s;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("the link never settled");
    }

    #[tokio::test]
    async fn a_missing_keyring_entry_stops_the_link_and_names_it() {
        let (d, paths, center, proxy) = behind_a_proxy().await;
        let daemon = start(&d, &paths).await;
        let status = settled_status(&daemon).await;
        let entry = crate::secrets::Entry::proxy(&paths).to_string();
        assert!(status.contains(&entry), "{status}");
        assert!(status.contains("proxy set"), "{status}");
        // Fail closed: neither the proxy nor the center was dialled.
        let quiet = Duration::from_millis(300);
        assert!(tokio::time::timeout(quiet, proxy.accept()).await.is_err());
        assert!(tokio::time::timeout(quiet, center.accept()).await.is_err());
        daemon.stop().await;
    }

    #[tokio::test]
    async fn the_link_sends_the_values_from_the_keyring_to_the_proxy() {
        let (d, paths, center, proxy) = behind_a_proxy().await;
        let headers = [("X-Key".to_string(), "s3cret-value".to_string())];
        crate::secrets::store_proxy_headers(&paths, &headers).unwrap();
        let daemon = start(&d, &paths).await;
        let (mut s, _) = tokio::time::timeout(Duration::from_secs(10), proxy.accept())
            .await
            .expect("the node dials the proxy")
            .unwrap();
        let mut buf = vec![0u8; 4096];
        let n = s.read(&mut buf).await.unwrap();
        let req = String::from_utf8_lossy(&buf[..n]).to_string();
        assert!(req.starts_with("CONNECT 127.0.0.1:"), "{req}");
        assert!(req.contains("\r\nX-Key: s3cret-value\r\n"), "{req}");
        s.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            .await
            .unwrap();
        drop(s);
        let status = settled_status(&daemon).await;
        assert!(
            status.contains("403") && !status.contains("s3cret"),
            "{status}"
        );
        // The refused tunnel is no reason to go direct.
        let quiet = Duration::from_millis(300);
        assert!(tokio::time::timeout(quiet, center.accept()).await.is_err());
        daemon.stop().await;
    }
}
