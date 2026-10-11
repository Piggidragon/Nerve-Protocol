//! One center's link: dialling with backoff, the handshake, and serving the
//! center's requests (spec §4, §5, §7).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use tokio::sync::{mpsc, oneshot};
use tokio::task::AbortHandle;

use nerve_policy::approvals::{AnswerError, Ask, By};
use nerve_policy::audit::Entry;
use nerve_policy::config::{Mode, SettingsGrant};
use nerve_policy::protected::Protected;
use nerve_policy::{Call, CenterEntry, Choice, Decision, Env, NodeConfig, Scope, SetError, Target};
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
        let proxy = match proxy_for(&cfg, &url) {
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

fn proxy_for(cfg: &NodeConfig, url: &CenterUrl) -> Result<Option<Proxy>, String> {
    let headers: Vec<(String, String)> = cfg
        .connection
        .headers
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    match &cfg.connection.proxy {
        Some(p) => Proxy::parse(p, headers).map(Some),
        None => Proxy::from_env(&url.host),
    }
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
        let rev = descriptor::for_center(&cfg, entry, crate::now_ms()).rev;
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
    let writer = tokio::spawn(async move {
        loop {
            tokio::select! {
                m = rx.recv() => match m {
                    Some(m) => if sink.send(m).await.is_err() { return; },
                    None => break,
                },
                _ = &mut done_rx => {
                    // Flush what is queued (the bye), then close.
                    while let Ok(m) = rx.try_recv() {
                        if sink.send(m).await.is_err() {
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
    // process groups, open approvals are withdrawn.
    *lock(&cs.link) = None;
    let calls: Vec<AbortHandle> = lock(&link.calls).drain().map(|(_, h)| h).collect();
    for c in calls {
        c.abort();
    }
    shared.withdraw_all(&entry.name, By::Withdrawn);
    let _ = done_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(2), writer).await;
    if matches!(outcome, Outcome::Retry) {
        cs.set_status("link lost; dialling again");
    }
    outcome
}

/// A live link's state shared with its calls.
struct Link {
    shared: Arc<Shared>,
    cs: Arc<CenterState>,
    name: String,
    handle: Arc<LinkHandle>,
    tx: mpsc::Sender<WsMessage>,
    /// Calls in flight; whoever removes an entry sends its reply.
    calls: Mutex<HashMap<Id, AbortHandle>>,
    /// Running `exec.run` calls → their process group.
    commands: Mutex<HashMap<Id, u32>>,
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
        let mut rev = descriptor::for_center(&cfg, &entry, crate::now_ms()).rev;
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
                        self.shared.withdraw_all(&self.name, By::Pause);
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
            let now = descriptor::for_center(&cfg, &entry, crate::now_ms()).rev;
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
                let h = lock(&self.calls).remove(&id);
                if let Some(h) = h {
                    h.abort();
                    let e =
                        Message::error(Some(id), RpcError::new(ErrorCode::Cancelled, "cancelled"));
                    let _ = self.tx.try_send(text(&e));
                }
                None
            }
            method::SESSION_END => {
                if let Ok(s) = params::<SessionEnd>(&p) {
                    lock(&self.cs.grants).end_session(&s.session);
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
        Ok(descriptor::for_center(&cfg, &entry, crate::now_ms()))
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
            "settings" => &["document", "version"],
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
            .is_some_and(|(_, e)| e.policy.mode_at(crate::now_ms()) == Mode::Folders);
        if folders && self.shared.confined() {
            self.shared.confinement.describe()
        } else {
            "none".into()
        }
    }

    /// Starts an `invoke` as its own task, so a slow call (or one waiting for
    /// an approval) does not hold up the link.
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
        calls.insert(id, task.abort_handle());
    }

    async fn invoke(self: &Arc<Self>, id: &Id, inv: Invoke) -> Result<Value, RpcError> {
        let (cfg, entry) = self
            .entry()
            .ok_or_else(|| RpcError::new(ErrorCode::Unavailable, "this center was removed"))?;
        let view = descriptor::for_center(&cfg, &entry, crate::now_ms());
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
            ("approvals", "list") => {
                let list = lock(&self.cs.queue).list();
                Ok(json!({"approvals": list}))
            }
            ("approvals", "answer") => self.answer(&entry, &inv.args),
            ("settings", "set") => self.settings_set(&inv.args),
            ("settings", "pause") => self.settings_pause(),
            ("exec", "signal") => self.signal(&inv.args),
            ("exec", "run") => self.exec_run(id, &cfg, &entry, effect, &inv).await,
            ("fs", a) => {
                let call = FsCall::parse(a, &inv.args)?;
                let preview = format!("{} {}", a, call.target_text());
                self.gate(
                    &entry,
                    &inv,
                    effect,
                    &call.targets(),
                    None,
                    None,
                    call.target_text(),
                    preview,
                )
                .await?;
                let protected = self.protected(&entry);
                let deny = self.deny_paths(&entry);
                let folders = entry.policy.folders.clone();
                tokio::task::spawn_blocking(move || {
                    let skip = |p: &std::path::Path| {
                        protected.check(p, false, &folders).is_some()
                            || deny.iter().any(|d| nerve_policy::paths::within(p, d))
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
        Protected::new(
            &self.shared.home,
            &self.shared.paths.own(),
            &entry.policy.protected,
        )
    }

    fn deny_paths(&self, entry: &CenterEntry) -> Vec<PathBuf> {
        entry
            .policy
            .deny
            .iter()
            .filter_map(|d| nerve_policy::protected::expand(&self.shared.home, d))
            .collect()
    }

    /// Runs the policy for one call: allows it, refuses it, or asks the owner
    /// and waits. Every outcome lands in the audit log.
    #[allow(clippy::too_many_arguments)]
    async fn gate(
        self: &Arc<Self>,
        entry: &CenterEntry,
        inv: &Invoke,
        effect: Effect,
        targets: &[Target],
        command: Option<&str>,
        cwd: Option<&std::path::Path>,
        target: String,
        preview: String,
    ) -> Result<(), RpcError> {
        let now = crate::now_ms();
        let session = inv.ctx.session.clone();
        let call = Call {
            cap: &inv.cap,
            action: &inv.action,
            effect,
            targets,
            command,
            cwd,
            session: session.as_deref(),
            tainted: inv.ctx.tainted,
            now_ms: now,
        };
        let decision = {
            let protected = self.protected(entry);
            let env = Env {
                home: &self.shared.home,
                protected: &protected,
                confined: self.shared.confined(),
            };
            let mut grants = lock(&self.cs.grants);
            nerve_policy::decide(&entry.policy, &env, &call, grants.at(now))
        };
        let audit = |decision: &str, code: Option<&str>, by: Option<&str>| {
            self.shared.audit(&Entry {
                ts: crate::now_ms(),
                center: self.name.clone(),
                cap: inv.cap.clone(),
                action: inv.action.clone(),
                target: target.clone(),
                decision: decision.into(),
                code: code.map(Into::into),
                by: by.map(Into::into),
                session: session.clone(),
            })
        };
        match decision {
            Decision::Allow => {
                audit("allowed", None, None);
                Ok(())
            }
            Decision::Disabled(why) => {
                audit("forbidden", Some("disabled"), None);
                Err(RpcError::new(ErrorCode::Disabled, why))
            }
            Decision::Forbidden(why) => {
                audit("forbidden", Some("forbidden"), None);
                Err(RpcError::forbidden(why))
            }
            Decision::Ask { reasons, choices } => {
                audit("asked", None, None);
                let timing = &entry.policy.approvals;
                let ask = Ask {
                    cap: inv.cap.clone(),
                    action: inv.action.clone(),
                    target: target.clone(),
                    reasons,
                    preview,
                    choices,
                    max_minutes: timing.max_minutes,
                    expires_ms: now + timing.timeout_s * 1000,
                    session: session.clone(),
                };
                let scope = Scope::of(&call);
                let r = self
                    .shared
                    .ask(
                        &self.cs,
                        ask,
                        Duration::from_secs(timing.timeout_s),
                        timing.on_timeout,
                    )
                    .await;
                let by = r.by.as_str();
                if !r.allowed() {
                    audit("denied", Some("denied"), Some(by));
                    return Err(if r.by == By::Pause {
                        RpcError::new(ErrorCode::Unavailable, "the node was paused")
                    } else {
                        RpcError::new(ErrorCode::Denied, "the owner denied this call")
                    });
                }
                let now = crate::now_ms();
                match r.choice() {
                    Some(Choice::Session) if session.is_some() => {
                        let until = now + u64::from(timing.remember_minutes) * 60_000;
                        lock(&self.cs.grants).add(scope, session.clone(), until);
                    }
                    Some(Choice::Time) => {
                        let minutes = r
                            .minutes
                            .unwrap_or(timing.max_minutes)
                            .min(timing.max_minutes);
                        lock(&self.cs.grants).add(scope, None, now + u64::from(minutes) * 60_000);
                    }
                    _ => {}
                }
                audit("allowed", None, Some(by));
                Ok(())
            }
        }
    }

    fn answer(&self, entry: &CenterEntry, args: &Map<String, Value>) -> Result<Value, RpcError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Answer {
            id: String,
            answer: String,
            #[serde(default)]
            minutes: Option<u32>,
        }
        let a: Answer = params(args)?;
        let choice = Choice::parse(&a.answer)
            .ok_or_else(|| RpcError::invalid_args("answer must be once, session, time or deny"))?;
        let r = lock(&self.cs.queue).answer(&a.id, choice, a.minutes, By::Center, entry.approvals);
        match r {
            Ok(_) => Ok(json!({})),
            Err(AnswerError::Forbidden) => Err(RpcError::forbidden(
                "this node takes answers only from its owner",
            )),
            Err(AnswerError::Unknown(_)) => {
                Err(RpcError::invalid_args(format!("no open approval {}", a.id)))
            }
            Err(e) => Err(RpcError::invalid_args(e.to_string())),
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
            crate::now_ms(),
            // This node offers no sense capabilities in 0.0.1.
            |_| false,
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
        let r = store.set_center_document(&self.name, v, version, crate::now_ms(), |_| false);
        settings_result(r).map(|_| json!({}))
    }

    fn signal(&self, args: &Map<String, Value>) -> Result<Value, RpcError> {
        let s: SignalArgs = params(args)?;
        let sig = Sig::parse(&s.signal)
            .ok_or_else(|| RpcError::invalid_args("signal must be term, kill or int"))?;
        let id: Id = serde_json::from_value(s.call)
            .map_err(|_| RpcError::invalid_args("call must be a request id"))?;
        let pid = lock(&self.commands)
            .get(&id)
            .copied()
            .ok_or_else(|| RpcError::invalid_args(format!("no running command {id}")))?;
        exec::kill_group(pid, sig);
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
            format!("$ {}  (in {})", rc.command, rc.cwd.display()),
        )
        .await?;
        let guard = Running::start(self, id.clone(), cfg.limits.max_running as usize)?;
        let landlock = (entry.policy.mode_at(crate::now_ms()) == Mode::Folders
            && self.shared.confined())
        .then(|| exec::landlock_spec(&entry.policy, &self.shared.home));
        let opts = RunOptions {
            shell: cfg.machine.shell.clone(),
            landlock,
            exe: self.shared.exe.clone().unwrap_or_default(),
            output_cap: (cfg.limits.output_cap_bytes as usize).min(exec::OUTPUT_HARD_CAP),
        };
        let r = exec::run(&rc, &opts, |pid| guard.started(pid)).await;
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

    fn started(&self, pid: u32) {
        *lock(&self.pid) = Some(pid);
        lock(&self.link.shared.commands).insert(pid, self.link.name.clone());
        lock(&self.link.commands).insert(self.id.clone(), pid);
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
