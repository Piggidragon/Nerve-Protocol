//! The center's side of one node link (spec §4): the handshake, the one-link
//! rule, requests to the node with their pending replies, and the reader that
//! routes the node's results, events and state.

use std::collections::{BTreeMap, HashMap};
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

/// An approval the node holds for this center (`approvals/requested`).
#[derive(Debug, Clone)]
pub struct NodeApproval {
    pub data: Value,
    pub received: Instant,
}

/// One authenticated, welcomed link.
pub struct Link {
    pub node_id: String,
    pub since: Instant,
    pub since_ms: u64,
    pub limits: Limits,
    out: mpsc::Sender<Out>,
    pending: Mutex<HashMap<u64, oneshot::Sender<Reply>>>,
    next_id: AtomicU64,
    closed: AtomicBool,
    pong: Notify,
    /// Approval id to the approval; withdrawn when the link ends.
    pub approvals: Mutex<BTreeMap<String, NodeApproval>>,
    /// `node` state `status` (online, busy, paused).
    pub status: Mutex<String>,
    /// Sessions that called through this link, for `session.end`.
    pub sessions: Mutex<std::collections::BTreeSet<String>>,
}

impl Link {
    fn new(node_id: &str, limits: Limits, out: mpsc::Sender<Out>) -> Link {
        Link {
            node_id: node_id.to_string(),
            since: Instant::now(),
            since_ms: msg::now_ms(),
            limits,
            out,
            pending: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            closed: AtomicBool::new(false),
            pong: Notify::new(),
            approvals: Mutex::new(BTreeMap::new()),
            status: Mutex::new("online".into()),
            sessions: Mutex::new(Default::default()),
        }
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

    fn fail_all(&self) {
        self.closed.store(true, Ordering::SeqCst);
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
    let Some(public_key) = center.public_key(&node_id) else {
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
        None => return refuse(ws, ByeReason::ProtocolError).await,
    };
    let hello: Hello = match Message::decode(&hello) {
        Ok(Message::Notification { method: m, params }) if m == method::HELLO => {
            match nerve_proto::rpc::params(&params) {
                Ok(h) => h,
                Err(_) => return refuse(ws, ByeReason::ProtocolError).await,
            }
        }
        _ => return refuse(ws, ByeReason::ProtocolError).await,
    };
    if hello.node_id != node_id
        || !nerve_transport::keys::verify_connect(
            &public_key,
            &center.id(),
            &nonce,
            &hello.auth.sig,
        )
    {
        tracing::warn!(node = %node_id, "a link failed authentication");
        return refuse(ws, ByeReason::ProtocolError).await;
    }
    if !hello.versions.iter().any(|v| v == PROTOCOL_VERSION) {
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
    }

    let welcome = Message::notification(
        method::WELCOME,
        json!({"version": PROTOCOL_VERSION, "limits": Limits::default()}),
    );
    if send_text(&mut ws, welcome).await.is_err() {
        return;
    }

    let (tx, mut rx) = mpsc::channel::<Out>(nerve_proto::limits::SEND_QUEUE);
    let link = Arc::new(Link::new(&node_id, hello.limits, tx));
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

    let mut clean = false;
    loop {
        let frame = match tokio::time::timeout(DEAD_AFTER, stream.next()).await {
            Err(_) => {
                tracing::info!(node = %node_id, "the link went silent for 45 s");
                break;
            }
            Ok(None) | Ok(Some(Err(_))) => break,
            Ok(Some(Ok(f))) => f,
        };
        match frame {
            WsMessage::Text(t) => match Message::decode(&t) {
                Ok(m) => {
                    if let Some(end) = handle(&center, &link, m).await {
                        clean = true;
                        if end == ByeReason::Unpaired {
                            center.forget(&node_id);
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
                // 0.0.1 sends no blobs to the center; media frames are refused.
                if let Err(FrameError::MediaReserved) = Frame::decode(&b) {
                    link.bye(ByeReason::ProtocolError).await;
                    break;
                }
            }
            WsMessage::Pong(_) => link.pong.notify_waiters(),
            WsMessage::Close(_) => {
                clean = true;
                break;
            }
            _ => {}
        }
    }
    link.fail_all();
    drop(writer);
    center.link_down(&link, clean);
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
            tracing::warn!(node = %link.node_id, "the node reported: {}", error.message);
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
            method::BYE => {
                let reason = nerve_proto::rpc::params::<msg::Bye>(&params)
                    .map(|b| b.reason)
                    .unwrap_or(ByeReason::Shutdown);
                return Some(reason);
            }
            // Progress is not passed on to MCP clients in 0.0.1.
            _ => {}
        },
    }
    None
}
