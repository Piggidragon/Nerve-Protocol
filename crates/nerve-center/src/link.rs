//! The center's side of one node link (spec §4): the handshake, the one-link
//! rule, requests to the node with their pending replies, and the reader that
//! routes the node's results, events and state.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::sync::{Notify, mpsc, oneshot};
use tokio_tungstenite::WebSocketStream;

use nerve_proto::frame::{Frame, FrameError};
use nerve_proto::msg::{self, ByeReason, Hello, Limits, method};
use nerve_proto::{ErrorCode, Id, Message, PROTOCOL_VERSION, RpcError};
use nerve_transport::log::Level;
use nerve_transport::net::BoxIo;
use nerve_transport::ws::WsMessage;

use crate::center::Center;

/// Each side has this long for its handshake step (§4.2).
pub const HANDSHAKE_STEP: Duration = Duration::from_secs(15);
/// A held link must answer a ping within this when a second one arrives (§4.3).
pub const DUPLICATE_PING: Duration = Duration::from_secs(3);
/// No frame for this long is a dead link (§4.4).
pub const DEAD_AFTER: Duration = Duration::from_secs(45);
/// How long the center waits for a `describe`, `get` or `settings.set`.
pub const SHORT_CALL: Duration = Duration::from_secs(30);

type Reply = Result<Value, RpcError>;

enum Out {
    Frame(WsMessage),
    /// Sends `bye {reason}`, closes, and ends the writer.
    Bye(ByeReason),
}

/// One authenticated, welcomed link.
pub struct Link {
    pub node_id: String,
    /// The node key the hello was signed with: its key, or its old one in
    /// the grace of a rotation (§4.9).
    pub auth_key: String,
    /// Whether both sides speak key rotation.
    pub rotate: bool,
    pub since: Instant,
    pub since_ms: u64,
    pub limits: Limits,
    out: mpsc::Sender<Out>,
    pending: Mutex<HashMap<u64, oneshot::Sender<Reply>>>,
    next_id: AtomicU64,
    closed: AtomicBool,
    /// Woken when the center closes the link, so its reader stops at once
    /// and handles nothing more the peer sends.
    ended: Notify,
    /// When the last frame came, in milliseconds after `since`.
    heard: AtomicU64,
    pong: Notify,
    /// `node` state `status` (online, busy, paused).
    pub status: Mutex<String>,
    /// Sessions that called through this link, for `session.end`.
    pub sessions: Mutex<std::collections::BTreeSet<String>>,
}

impl Link {
    fn new(
        node_id: &str,
        auth_key: String,
        rotate: bool,
        limits: Limits,
        out: mpsc::Sender<Out>,
    ) -> Link {
        Link {
            node_id: node_id.to_string(),
            auth_key,
            rotate,
            since: Instant::now(),
            since_ms: msg::now_ms(),
            limits,
            out,
            pending: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            closed: AtomicBool::new(false),
            ended: Notify::new(),
            heard: AtomicU64::new(0),
            pong: Notify::new(),
            status: Mutex::new("online".into()),
            sessions: Mutex::new(Default::default()),
        }
    }

    /// Notes that a frame came.
    fn touch(&self) {
        self.heard
            .store(self.since.elapsed().as_millis() as u64, Ordering::Relaxed);
    }

    /// How long nothing has come from the node.
    pub fn silent_for(&self) -> Duration {
        self.since
            .elapsed()
            .saturating_sub(Duration::from_millis(self.heard.load(Ordering::Relaxed)))
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Sends a request; `wait` bounds the wait for its reply.
    pub async fn call(&self, method: &str, params: Value, wait: Option<Duration>) -> Reply {
        let (id, rx) = self.start(method, params).await?;
        self.finish(id, rx, wait).await
    }

    /// Sends a request and hands back its id and the receiver of its reply.
    pub async fn start(
        &self,
        method: &str,
        params: Value,
    ) -> Result<(u64, oneshot::Receiver<Reply>), RpcError> {
        if self.is_closed() {
            return Err(lost());
        }
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(id, tx);
        let text = Message::request(id, method, params).encode();
        if self
            .out
            .send(Out::Frame(WsMessage::text(text)))
            .await
            .is_err()
        {
            self.pending.lock().unwrap().remove(&id);
            return Err(lost());
        }
        Ok((id, rx))
    }

    pub async fn finish(
        &self,
        id: u64,
        rx: oneshot::Receiver<Reply>,
        wait: Option<Duration>,
    ) -> Reply {
        let got = match wait {
            None => rx.await,
            Some(w) => match tokio::time::timeout(w, rx).await {
                Ok(r) => r,
                Err(_) => {
                    self.pending.lock().unwrap().remove(&id);
                    self.notify(method::CANCEL, json!({"id": id})).await;
                    return Err(RpcError::new(
                        ErrorCode::Timeout,
                        "the node did not answer in time",
                    ));
                }
            },
        };
        got.unwrap_or_else(|_| Err(lost()))
    }

    /// Stops waiting for request `id` and tells the node to cancel it.
    pub async fn cancel(&self, id: u64) {
        self.pending.lock().unwrap().remove(&id);
        self.notify(method::CANCEL, json!({"id": id})).await;
    }

    pub async fn notify(&self, method: &str, params: Value) {
        let text = Message::notification(method, params).encode();
        let _ = self.out.send(Out::Frame(WsMessage::text(text))).await;
    }

    /// Ends the link with `bye {reason}`.
    pub async fn bye(&self, reason: ByeReason) {
        let _ = self.out.send(Out::Bye(reason)).await;
    }

    /// Whether the link answers a ping within `wait`.
    async fn answers(&self, wait: Duration) -> bool {
        let notified = self.pong.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if self
            .out
            .send(Out::Frame(WsMessage::Ping(b"nerve".to_vec().into())))
            .await
            .is_err()
        {
            return false;
        }
        tokio::time::timeout(wait, notified).await.is_ok()
    }

    pub(crate) fn fail_all(&self) {
        self.closed.store(true, Ordering::SeqCst);
        // A permit stays for a reader that is not waiting right now.
        self.ended.notify_one();
        let pending: Vec<_> = self.pending.lock().unwrap().drain().collect();
        for (_, tx) in pending {
            let _ = tx.send(Err(lost()));
        }
    }

    fn reply(&self, id: &Id, r: Reply) {
        if let Id::Num(n) = id
            && let Some(tx) = self.pending.lock().unwrap().remove(n)
        {
            let _ = tx.send(r);
        }
    }
}

fn lost() -> RpcError {
    RpcError::new(ErrorCode::ConnectionLost, "the link to the node ended")
}

async fn send_text(ws: &mut WebSocketStream<BoxIo>, m: Message) -> Result<(), String> {
    ws.send(WsMessage::text(m.encode()))
        .await
        .map_err(|e| e.to_string())
}

async fn refuse(mut ws: WebSocketStream<BoxIo>, reason: ByeReason) {
    let bye = Message::notification(method::BYE, json!({ "reason": reason }));
    let _ = send_text(&mut ws, bye).await;
    let _ = ws.close(None).await;
}

/// The next text frame, skipping control frames, within `wait`.
async fn next_text(ws: &mut WebSocketStream<BoxIo>, wait: Duration) -> Option<String> {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        match tokio::time::timeout_at(deadline, ws.next()).await {
            Ok(Some(Ok(WsMessage::Text(t)))) => return Some(t.to_string()),
            Ok(Some(Ok(WsMessage::Ping(_) | WsMessage::Pong(_)))) => continue,
            _ => return None,
        }
    }
}

/// Runs a link from the upgraded WebSocket until it ends. `node_id` is the
/// `Nerve-Node` header, already known to belong to a paired node.
pub async fn run(center: Center, mut ws: WebSocketStream<BoxIo>, node_id: String) {
    let Some((public_key, old_key)) = center.node_keys(&node_id) else {
        return refuse(ws, ByeReason::Revoked).await;
    };
    let nonce = nerve_transport::keys::random_bytes(32);
    let challenge = Message::notification(
        method::CHALLENGE,
        json!({"nonce": msg::hex(&nonce), "center_id": center.id()}),
    );
    if send_text(&mut ws, challenge).await.is_err() {
        return;
    }
    let hello = match next_text(&mut ws, HANDSHAKE_STEP).await {
        Some(t) => t,
        None => {
            center.note(
                Level::Debug,
                Some(&node_id),
                "the handshake failed: no hello within 15 s",
            );
            return refuse(ws, ByeReason::ProtocolError).await;
        }
    };
    let hello: Hello = match Message::decode(&hello) {
        Ok(Message::Notification { method: m, params }) if m == method::HELLO => {
            match nerve_proto::rpc::params(&params) {
                Ok(h) => h,
                Err(_) => {
                    center.note(
                        Level::Debug,
                        Some(&node_id),
                        "the handshake failed: the hello cannot be read",
                    );
                    return refuse(ws, ByeReason::ProtocolError).await;
                }
            }
        }
        _ => {
            center.note(
                Level::Debug,
                Some(&node_id),
                "the handshake failed: the first message was not a hello",
            );
            return refuse(ws, ByeReason::ProtocolError).await;
        }
    };
    // The node's key, or its old one while the grace of a rotation runs.
    let signed = |k: &str| {
        hello.node_id == node_id
            && nerve_transport::keys::verify_connect(k, &center.id(), &nonce, &hello.auth.sig)
    };
    let now = msg::now_ms();
    let auth_key = if signed(&public_key) {
        public_key
    } else if let Some(old) = old_key.as_ref().filter(|o| signed(&o.public_key)) {
        if now >= old.until_ms {
            center.note(
                Level::Warn,
                Some(&node_id),
                "a link was refused: the hello is signed with the node's old key, whose grace after its rotation has ended",
            );
            return refuse(ws, ByeReason::ProtocolError).await;
        }
        old.public_key.clone()
    } else {
        center.note(
            Level::Warn,
            Some(&node_id),
            "a link failed authentication: the hello is not signed with the key paired for this node",
        );
        return refuse(ws, ByeReason::ProtocolError).await;
    };
    if !hello.versions.iter().any(|v| v == PROTOCOL_VERSION) {
        center.note(
            Level::Warn,
            Some(&node_id),
            format!(
                "the node speaks protocol versions {:?}; this center speaks {PROTOCOL_VERSION}",
                hello.versions
            ),
        );
        return refuse(ws, ByeReason::UnsupportedVersion).await;
    }

    // One live link per node (§4.3): a held link that still answers means
    // two machines hold this key.
    if let Some(held) = center.link(&node_id) {
        if held.answers(DUPLICATE_PING).await {
            center.alert(
                &node_id,
                "a second link authenticated while the first was alive: the node's key may have been copied",
            );
            return refuse(ws, ByeReason::Duplicate).await;
        }
        held.bye(ByeReason::Replaced).await;
        held.fail_all();
        center.link_replaced(&held);
    }

    // Features go only to a node that named its own (§1.1): an older node
    // refuses a field it does not know in the welcome.
    let features = (!hello.features.is_empty()).then(|| {
        nerve_proto::FEATURES
            .iter()
            .filter(|f| hello.features.iter().any(|h| h == *f))
            .map(|f| f.to_string())
            .collect::<Vec<_>>()
    });
    let rotate = features
        .as_ref()
        .is_some_and(|f| f.iter().any(|f| f == nerve_proto::FEATURE_ROTATE));
    let welcome = Message::notification(
        method::WELCOME,
        serde_json::to_value(msg::Welcome {
            version: PROTOCOL_VERSION.into(),
            limits: Limits::default(),
            features,
        })
        .unwrap_or_default(),
    );
    if send_text(&mut ws, welcome).await.is_err() {
        return;
    }

    let (tx, mut rx) = mpsc::channel::<Out>(nerve_proto::limits::SEND_QUEUE);
    let link = Arc::new(Link::new(&node_id, auth_key, rotate, hello.limits, tx));
    let (mut sink, mut stream) = ws.split();
    let writer = tokio::spawn(async move {
        while let Some(o) = rx.recv().await {
            match o {
                Out::Frame(f) => {
                    if sink.send(f).await.is_err() {
                        break;
                    }
                }
                Out::Bye(reason) => {
                    let bye = Message::notification(method::BYE, json!({ "reason": reason }));
                    let _ = sink.send(WsMessage::text(bye.encode())).await;
                    let _ = sink.close().await;
                    break;
                }
            }
        }
    });
    center.link_up(link.clone(), &hello);
    // A node that links while the center's key rotation is told learns of
    // it now.
    if rotate && let Some(notice) = center.rotation_notice() {
        link.notify(method::CENTER_ROTATE, notice).await;
    }

    let mut clean = false;
    let quiet = center.dead_after();
    // What ended the link, set on every way out of the loop, and for how long
    // nothing had come when it did.
    let why: String;
    let mut silent = Duration::ZERO;
    loop {
        // A link the center closed (its key's grace ended, a newer link
        // replaced it) handles nothing more: frames still in flight from the
        // peer are not the node's any more.
        let next = tokio::select! {
            r = tokio::time::timeout(quiet, stream.next()) => Some(r),
            _ = link.ended.notified() => None,
        };
        let Some(next) = next.filter(|_| !link.is_closed()) else {
            clean = true;
            why = "the center ended the link".into();
            break;
        };
        let frame = match next {
            Err(_) => {
                why = format!(
                    "no frame from the node for {}, not even a ping",
                    crate::util::span(quiet)
                );
                silent = quiet;
                break;
            }
            Ok(None) => {
                why = "the connection closed without a bye".into();
                break;
            }
            Ok(Some(Err(e))) => {
                why = format!("the connection failed: {e}");
                break;
            }
            Ok(Some(Ok(f))) => f,
        };
        link.touch();
        match frame {
            WsMessage::Text(t) => match Message::decode(&t) {
                Ok(m) => {
                    if let Some(end) = handle(&center, &link, m).await {
                        clean = true;
                        why = format!("the node said bye ({})", end.as_str());
                        if end == ByeReason::Unpaired {
                            center.forget(&node_id, "the node unpaired itself (bye unpaired)");
                        }
                        break;
                    }
                }
                Err(reply) => {
                    // A malformed message from a node is answered, not fatal,
                    // so a newer node's mistake does not drop its link.
                    let _ = link
                        .out
                        .send(Out::Frame(WsMessage::text(reply.encode())))
                        .await;
                }
            },
            WsMessage::Binary(b) => {
                // Nodes send no blobs to the center; media frames are refused.
                if let Err(FrameError::MediaReserved) = Frame::decode(&b) {
                    link.bye(ByeReason::ProtocolError).await;
                    why = "the node sent a media frame, which the center does not take".into();
                    break;
                }
            }
            WsMessage::Pong(_) => link.pong.notify_waiters(),
            WsMessage::Close(_) => {
                clean = true;
                why = "the node closed the connection".into();
                break;
            }
            _ => {}
        }
    }
    link.fail_all();
    drop(writer);
    center.link_down(&link, clean, &why, silent);
}

/// Handles one message from the node. Returns the bye reason when the node
/// ended the link.
async fn handle(center: &Center, link: &Arc<Link>, m: Message) -> Option<ByeReason> {
    match m {
        Message::Result { id, result } => link.reply(&id, Ok(result)),
        Message::Error {
            id: Some(id),
            error,
        } => link.reply(&id, Err(error)),
        Message::Error { id: None, error } => {
            center.note(
                Level::Warn,
                Some(&link.node_id),
                format!("the node reported an error: {}", error.message),
            );
        }
        Message::Request { id, method: m, .. } => {
            let e = RpcError::new(
                ErrorCode::Other("method_not_found".into()),
                format!("the center serves no method {m:?}"),
            );
            let mut e = e;
            e.code = -32601;
            let text = Message::error(Some(id), e).encode();
            let _ = link.out.send(Out::Frame(WsMessage::text(text))).await;
        }
        Message::Notification { method: m, params } => match m.as_str() {
            method::EVENT => {
                if let Ok(ev) = nerve_proto::rpc::params::<msg::Event>(&params) {
                    center.on_event(link, ev);
                }
            }
            method::STATE => {
                if let Ok(st) = nerve_proto::rpc::params::<msg::StateChange>(&params)
                    && st.cap == "node"
                    && let Some(s) = st.changed.get("status").and_then(Value::as_str)
                {
                    *link.status.lock().unwrap() = s.to_string();
                    center.changed(crate::center::Change::Nodes);
                }
            }
            method::KEY_ROTATE if link.rotate => {
                let (r, dropped) = center.rotate_node_key(link, &params);
                link.notify(method::KEY_ROTATED, json!(r)).await;
                // A rotation in the grace of another ends the older key's
                // grace, and a link opened with it ends too.
                if let Some(key) = dropped {
                    center.end_link_of_key(&link.node_id, &key);
                }
            }
            method::KEY_RETIRE if link.rotate => {
                let (r, opened_with_it) = center.retire_node_key(link, &params);
                link.notify(method::KEY_RETIRED, json!(r)).await;
                // The key this link was opened with is refused from now on,
                // so the link ends; the node dials again with its key.
                if opened_with_it {
                    link.fail_all();
                    link.bye(ByeReason::Replaced).await;
                }
            }
            method::BYE => {
                let reason = nerve_proto::rpc::params::<msg::Bye>(&params)
                    .map(|b| b.reason)
                    .unwrap_or(ByeReason::Shutdown);
                return Some(reason);
            }
            // Progress is not passed on to MCP clients.
            _ => {}
        },
    }
    None
}
