//! The center's core: paired nodes and their links, pairing, sessions and
//! taint, calls to nodes, the audit feed and
//! the statistics. The MCP server, the node listener and the web UI are thin
//! layers over this.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};
use tokio::sync::broadcast;

use nerve_proto::link::{CenterUrl, PairLink, PairRequest, PairResponse};
use nerve_proto::msg::{self, ByeReason, Event, Hello};
use nerve_proto::{Descriptor, ErrorCode, Exposure, RpcError};
use nerve_transport::tls::ServerIdentity;

use crate::link::{Link, NodeApproval, SHORT_CALL};
use crate::pairing::Codes;
use crate::store::{NodeRecord, Store};
use crate::tools::{self, Route, Tool};
use crate::util::{self, now_ms};

pub const IDENTITY_FILE: &str = "tls.pem";
/// Recent audit decisions kept in memory for the web UI (never on disk).
pub const AUDIT_KEEP: usize = 500;
const ALERTS_KEEP: usize = 50;

/// What changed, for the MCP servers (tool lists) and the web UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    Tools,
    Nodes,
    Approvals,
    Audit,
    Sessions,
}

/// Everything the center needs to start.
#[derive(Debug, Clone)]
pub struct Options {
    pub state_dir: PathBuf,
    /// The center name; kept from the state file when not given.
    pub name: Option<String>,
    /// The URL nodes reach the center at, put into pairing links.
    pub public_url: String,
    /// How long a call waits for an approval before the center gives up on it.
    pub call_wait: Duration,
}

#[derive(Clone)]
pub struct Center(Arc<Inner>);

pub struct Inner {
    dir: PathBuf,
    public_url: CenterUrl,
    pin: Option<String>,
    pub identity: ServerIdentity,
    call_wait: Duration,
    store: Mutex<Store>,
    dirty: AtomicBool,
    codes: Mutex<Codes>,
    links: Mutex<BTreeMap<String, Arc<Link>>>,
    changes: broadcast::Sender<Change>,
    audit: Mutex<VecDeque<Value>>,
    alerts: Mutex<VecDeque<Value>>,
    sessions: Mutex<BTreeMap<String, Arc<Session>>>,
}

/// One harness session: an MCP client (stdio, an attached process, or an
/// HTTP session). Its id goes to the nodes as `ctx.session`.
pub struct Session {
    pub id: String,
    pub transport: String,
    pub client: Mutex<String>,
    pub started_ms: u64,
    tainted: AtomicBool,
    ended: AtomicBool,
    pub calls: AtomicU64,
    /// Nodes this session called, for `session.end`.
    nodes: Mutex<BTreeSet<String>>,
}

impl Session {
    pub fn tainted(&self) -> bool {
        self.tainted.load(Ordering::SeqCst)
    }

    pub fn ended(&self) -> bool {
        self.ended.load(Ordering::SeqCst)
    }
}

/// Why a tool call did not produce a result.
#[derive(Debug)]
pub enum CallError {
    Rpc(RpcError),
    /// An approval was still open when the center stopped waiting: `at` names
    /// where (a node or the center).
    Pending {
        at: String,
        waited: Duration,
    },
}

impl From<RpcError> for CallError {
    fn from(e: RpcError) -> CallError {
        CallError::Rpc(e)
    }
}

impl std::ops::Deref for Center {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.0
    }
}

/// The name a new center gets when no `--name` is given.
pub const DEFAULT_NAME: &str = "nerve-center";

/// This machine's host name, for defaults.
pub fn host_name() -> String {
    #[cfg(unix)]
    {
        let mut buf = [0u8; 256];
        // SAFETY: the buffer is valid for its length and gethostname writes
        // at most that many bytes.
        let r = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
        if r == 0 {
            let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
            if let Ok(s) = std::str::from_utf8(&buf[..end])
                && !s.is_empty()
            {
                return s.to_string();
            }
        }
    }
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "localhost".into())
}

impl Center {
    /// Opens the state folder, creating the identity and the state file on
    /// the first start.
    pub fn open(opts: Options) -> Result<Center, String> {
        let dir = opts.state_dir.clone();
        nerve_transport::files::create_private_dir(&dir)
            .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        let public_url = CenterUrl::parse(&opts.public_url)?;
        let id_path = dir.join(IDENTITY_FILE);
        let identity = match std::fs::read_to_string(&id_path) {
            Ok(t) => {
                ServerIdentity::from_pem(&t).map_err(|e| format!("{}: {e}", id_path.display()))?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let names = vec![public_url.host.clone(), host_name()];
                let id = ServerIdentity::generate(&names)?;
                nerve_transport::files::write_private(&id_path, id.to_pem().as_bytes())
                    .map_err(|e| format!("cannot write {}: {e}", id_path.display()))?;
                id
            }
            Err(e) => return Err(format!("cannot read {}: {e}", id_path.display())),
        };
        let mut store = match Store::load(&dir).map_err(|e| e.to_string())? {
            Some(s) => s,
            None => Store::new(util::random_id(), DEFAULT_NAME.into()),
        };
        if let Some(n) = opts.name {
            store.center_name = n;
        }
        store.prune_stats(now_ms());
        store
            .save(&dir)
            .map_err(|e| format!("cannot write the state file: {e}"))?;
        let pin = public_url.tls.then(|| identity.pin());
        let (changes, _) = broadcast::channel(64);
        Ok(Center(Arc::new(Inner {
            dir,
            public_url,
            pin,
            identity,
            call_wait: opts.call_wait,
            store: Mutex::new(store),
            dirty: AtomicBool::new(false),
            codes: Mutex::new(Codes::default()),
            links: Mutex::new(BTreeMap::new()),
            changes,
            audit: Mutex::new(VecDeque::new()),
            alerts: Mutex::new(VecDeque::new()),
            sessions: Mutex::new(BTreeMap::new()),
        })))
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn id(&self) -> String {
        self.store.lock().unwrap().center_id.clone()
    }

    pub fn name(&self) -> String {
        self.store.lock().unwrap().center_name.clone()
    }

    pub fn public_url(&self) -> &CenterUrl {
        &self.public_url
    }

    pub fn pin(&self) -> Option<&str> {
        self.pin.as_deref()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Change> {
        self.changes.subscribe()
    }

    pub fn changed(&self, c: Change) {
        let _ = self.changes.send(c);
    }

    /// Runs `f` on the stored state and saves it.
    pub fn update<T>(&self, f: impl FnOnce(&mut Store) -> T) -> T {
        let mut s = self.store.lock().unwrap();
        let out = f(&mut s);
        if let Err(e) = s.save(&self.dir) {
            tracing::error!("cannot write the state file: {e}");
        }
        self.dirty.store(false, Ordering::SeqCst);
        out
    }

    /// Runs `f` on the stored state and saves it later (statistics).
    fn update_soon(&self, f: impl FnOnce(&mut Store)) {
        f(&mut self.store.lock().unwrap());
        self.dirty.store(true, Ordering::SeqCst);
    }

    pub fn read<T>(&self, f: impl FnOnce(&Store) -> T) -> T {
        f(&self.store.lock().unwrap())
    }

    /// Writes pending statistics. Called on a timer and on shutdown.
    pub fn flush(&self) {
        if self.dirty.swap(false, Ordering::SeqCst) {
            let mut s = self.store.lock().unwrap();
            s.prune_stats(now_ms());
            if let Err(e) = s.save(&self.dir) {
                tracing::error!("cannot write the state file: {e}");
            }
        }
    }

    pub fn public_key(&self, node_id: &str) -> Option<String> {
        self.read(|s| s.nodes.get(node_id).map(|n| n.public_key.clone()))
    }

    pub fn knows(&self, node_id: &str) -> bool {
        self.read(|s| s.nodes.contains_key(node_id))
    }

    pub fn link(&self, node_id: &str) -> Option<Arc<Link>> {
        self.links
            .lock()
            .unwrap()
            .get(node_id)
            .filter(|l| !l.is_closed())
            .cloned()
    }

    // ---- Pairing (spec §3) ----

    /// A new pairing code and the link that carries it.
    pub fn new_pairing(&self) -> Value {
        let code = self.codes.lock().unwrap().create(Instant::now());
        let link = PairLink {
            center: self.public_url.clone(),
            code: code.clone(),
            pin: self.pin.clone(),
        };
        json!({
            "code": code,
            "link": link.render(),
            "pin": self.pin,
            "center": self.public_url.to_string(),
            "expires_ms": now_ms() + crate::pairing::CODE_TTL.as_millis() as u64,
        })
    }

    /// Answers `POST /nerve/v0/pair`: the status and the body.
    pub fn pair(&self, body: &[u8]) -> (u16, Value) {
        let err = |s: u16, m: &str| (s, json!({ "error": m }));
        let req: PairRequest = match serde_json::from_slice(body) {
            Ok(r) => r,
            Err(e) => return err(400, &format!("bad pairing request: {e}")),
        };
        if !nerve_proto::valid_node_name(&req.name) {
            return err(400, "a node name is 1 to 32 characters of a-z, 0-9 and -");
        }
        if req.platform.is_empty()
            || req.platform.len() > 32
            || req.arch.is_empty()
            || req.arch.len() > 32
        {
            return err(400, "bad platform or arch");
        }
        let pk = match msg::unhex(&req.public_key) {
            Some(b) if b.len() == 32 => b,
            _ => {
                return err(
                    400,
                    "public_key must be 32 bytes as 64 lowercase hex characters",
                );
            }
        };
        let now = Instant::now();
        if self.codes.lock().unwrap().check(&req.code, now).is_err() {
            return err(
                403,
                "the pairing code is unknown, used, expired or out of tries",
            );
        }
        let node_id = nerve_transport::keys::node_id(&pk);
        let out = self.update(|s| {
            if s.nodes.contains_key(&node_id)
                || s.nodes.values().any(|n| n.public_key == req.public_key)
            {
                return Err("this key is already paired");
            }
            if s.node_by_name(&req.name).is_some() {
                return Err("another node already has this name");
            }
            s.nodes.insert(
                node_id.clone(),
                NodeRecord {
                    id: node_id.clone(),
                    name: req.name.clone(),
                    public_key: req.public_key.clone(),
                    platform: req.platform.clone(),
                    arch: req.arch.clone(),
                    paired_ms: now_ms(),
                    last_seen_ms: 0,
                    going_away: None,
                    descriptor: None,
                },
            );
            Ok(PairResponse {
                center_id: s.center_id.clone(),
                center_name: s.center_name.clone(),
                node_id: node_id.clone(),
            })
        });
        match out {
            Ok(resp) => {
                self.codes.lock().unwrap().consume(&req.code);
                tracing::info!(node = %node_id, name = %req.name, "a node paired");
                self.changed(Change::Nodes);
                (200, serde_json::to_value(resp).unwrap_or_default())
            }
            Err(why) => {
                self.codes.lock().unwrap().fail(&req.code);
                err(409, why)
            }
        }
    }

    // ---- Nodes ----

    pub fn rename(&self, node_id: &str, name: &str) -> Result<(), String> {
        if !nerve_proto::valid_node_name(name) {
            return Err("a node name is 1 to 32 characters of a-z, 0-9 and -".into());
        }
        self.update(|s| {
            if s.nodes.values().any(|n| n.name == name && n.id != node_id) {
                return Err("another node already has this name".to_string());
            }
            let n = s.nodes.get_mut(node_id).ok_or("no such node")?;
            n.name = name.to_string();
            Ok(())
        })?;
        self.changed(Change::Nodes);
        self.changed(Change::Tools);
        Ok(())
    }

    /// Removes a node: `bye revoked` on its link, and its record goes.
    pub async fn remove(&self, node_id: &str) -> Result<(), String> {
        if !self.knows(node_id) {
            return Err("no such node".into());
        }
        let link = self.links.lock().unwrap().remove(node_id);
        if let Some(l) = link {
            l.bye(ByeReason::Revoked).await;
        }
        self.forget(node_id);
        Ok(())
    }

    /// Drops a node's record (a remove, or the node's `bye unpaired`).
    pub fn forget(&self, node_id: &str) {
        let had = self.update(|s| {
            s.stats.remove(node_id);
            s.nodes.remove(node_id).is_some()
        });
        if had {
            tracing::info!(node = %node_id, "the node is no longer paired");
            self.changed(Change::Nodes);
            self.changed(Change::Tools);
        }
    }

    pub fn alert(&self, node_id: &str, text: &str) {
        tracing::warn!(node = %node_id, "{text}");
        let mut a = self.alerts.lock().unwrap();
        a.push_back(json!({"ts": now_ms(), "node": node_id, "text": text}));
        while a.len() > ALERTS_KEEP {
            a.pop_front();
        }
        drop(a);
        self.changed(Change::Nodes);
    }

    pub fn alerts(&self) -> Vec<Value> {
        self.alerts.lock().unwrap().iter().cloned().collect()
    }

    pub(crate) fn link_up(&self, link: Arc<Link>, hello: &Hello) {
        let id = link.node_id.clone();
        self.links.lock().unwrap().insert(id.clone(), link.clone());
        let now = now_ms();
        self.update(|s| {
            if let Some(n) = s.nodes.get_mut(&id) {
                n.last_seen_ms = now;
                n.going_away = None;
            }
            s.day(&id, now).links += 1;
        });
        tracing::info!(node = %id, software = %hello.software.version, "a node link is up");
        self.changed(Change::Nodes);
        let c = self.clone();
        tokio::spawn(async move {
            c.refresh(&link).await;
            if c.read(|s| {
                s.nodes
                    .get(&link.node_id)
                    .and_then(|n| n.descriptor.as_ref())
                    .is_some_and(|d| d.capability("audit").is_some())
            }) {
                let _ = link
                    .call(
                        msg::method::SUB,
                        json!({"topics": ["audit/decision"]}),
                        Some(SHORT_CALL),
                    )
                    .await;
            }
        });
    }

    pub(crate) fn link_down(&self, link: &Arc<Link>, clean: bool) {
        let id = &link.node_id;
        {
            let mut links = self.links.lock().unwrap();
            if links.get(id).is_some_and(|l| Arc::ptr_eq(l, link)) {
                links.remove(id);
            }
        }
        let withdrawn = std::mem::take(&mut *link.approvals.lock().unwrap());
        let now = now_ms();
        let online = link.since.elapsed().as_millis() as u64;
        self.update_soon(|s| {
            if let Some(n) = s.nodes.get_mut(id) {
                n.last_seen_ms = now;
            }
            if s.nodes.contains_key(id) {
                let d = s.day(id, now);
                d.online_ms += online;
                if !clean {
                    d.drops += 1;
                }
                if !withdrawn.is_empty() {
                    *d.approvals_by.entry("withdrawn".into()).or_default() +=
                        withdrawn.len() as u64;
                }
            }
        });
        tracing::info!(node = %id, clean, "a node link ended");
        self.changed(Change::Nodes);
        if !withdrawn.is_empty() {
            self.changed(Change::Approvals);
        }
    }

    /// Fetches the full descriptor and keeps it.
    async fn refresh(&self, link: &Arc<Link>) {
        match link
            .call(
                msg::method::DESCRIBE,
                json!({"detail": "full"}),
                Some(SHORT_CALL),
            )
            .await
        {
            Ok(v) => match serde_json::from_value::<Descriptor>(v) {
                Ok(d) => {
                    self.update(|s| {
                        if let Some(n) = s.nodes.get_mut(&link.node_id) {
                            n.descriptor = Some(d);
                        }
                    });
                    self.changed(Change::Tools);
                    self.changed(Change::Nodes);
                }
                Err(e) => {
                    tracing::warn!(node = %link.node_id, "the node sent a descriptor the center cannot read: {e}")
                }
            },
            Err(e) => tracing::warn!(node = %link.node_id, "describe failed: {}", e.message),
        }
    }

    pub(crate) fn on_event(&self, link: &Arc<Link>, ev: Event) {
        let node = link.node_id.clone();
        match (ev.cap.as_str(), ev.name.as_str()) {
            ("node", "descriptor_changed" | "capability_changed") => {
                let c = self.clone();
                let l = link.clone();
                tokio::spawn(async move { c.refresh(&l).await });
            }
            ("node", "going_away") => {
                let why = ev
                    .data
                    .get("reason")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                self.update(|s| {
                    if let Some(n) = s.nodes.get_mut(&node) {
                        n.going_away = Some(util::clip(&why, 200));
                    }
                });
                self.changed(Change::Nodes);
            }
            ("approvals", "requested") => {
                let Some(id) = ev.data.get("id").and_then(Value::as_str) else {
                    return;
                };
                link.approvals.lock().unwrap().insert(
                    id.to_string(),
                    NodeApproval {
                        data: ev.data.clone(),
                        received: Instant::now(),
                    },
                );
                self.update_soon(|s| s.day(&node, now_ms()).approvals_asked += 1);
                self.changed(Change::Approvals);
            }
            ("approvals", "resolved") => {
                let Some(id) = ev.data.get("id").and_then(Value::as_str) else {
                    return;
                };
                let by = ev
                    .data
                    .get("by")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string();
                let gone = link.approvals.lock().unwrap().remove(id);
                let wait = gone
                    .map(|a| a.received.elapsed().as_millis() as u64)
                    .unwrap_or(0);
                self.update_soon(|s| {
                    let d = s.day(&node, now_ms());
                    *d.approvals_by.entry(util::clip(&by, 32)).or_default() += 1;
                    d.approval_wait_ms += wait;
                    d.approval_wait_max_ms = d.approval_wait_max_ms.max(wait);
                });
                self.changed(Change::Approvals);
            }
            ("settings", "changed") => self.changed(Change::Nodes),
            ("audit", "decision") => {
                let name = self.node_name(&node);
                let mut e = ev.data.clone();
                if let Some(o) = e.as_object_mut() {
                    o.insert("node_id".into(), json!(node));
                    o.insert("node".into(), json!(name));
                    o.entry("ts").or_insert(json!(ev.ts));
                }
                let mut a = self.audit.lock().unwrap();
                a.push_back(e);
                while a.len() > AUDIT_KEEP {
                    a.pop_front();
                }
                drop(a);
                self.changed(Change::Audit);
            }
            _ => {}
        }
    }

    pub fn node_name(&self, node_id: &str) -> String {
        self.read(|s| {
            s.nodes
                .get(node_id)
                .map(|n| n.name.clone())
                .unwrap_or_default()
        })
    }

    pub fn node_id_by_name(&self, name: &str) -> Option<String> {
        self.read(|s| s.node_by_name(name).map(|n| n.id.clone()))
    }

    pub fn audit(&self) -> Vec<Value> {
        self.audit.lock().unwrap().iter().cloned().collect()
    }

    /// The nodes as the web UI and `nerve__nodes` show them.
    pub fn nodes_json(&self) -> Value {
        let links: BTreeMap<String, Arc<Link>> = self.links.lock().unwrap().clone();
        let sessions: Vec<Arc<Session>> = self.sessions.lock().unwrap().values().cloned().collect();
        let nodes: Vec<Value> = self.read(|s| {
            s.nodes
                .values()
                .map(|n| {
                    let link = links.get(&n.id).filter(|l| !l.is_closed());
                    let d = n.descriptor.as_ref();
                    let caps: Vec<Value> = d
                        .map(|d| {
                            d.capabilities
                                .iter()
                                .map(|c| json!({"id": c.id, "profile": c.profile, "exposure": c.exposure, "summary": c.summary}))
                                .collect()
                        })
                        .unwrap_or_default();
                    let approvals: Vec<Value> = link
                        .map(|l| l.approvals.lock().unwrap().values().map(|a| a.data.clone()).collect())
                        .unwrap_or_default();
                    let used_by: Vec<&str> = sessions
                        .iter()
                        .filter(|x| x.nodes.lock().unwrap().contains(&n.id))
                        .map(|x| x.id.as_str())
                        .collect();
                    json!({
                        "id": n.id,
                        "name": n.name,
                        "platform": n.platform,
                        "arch": n.arch,
                        "online": link.is_some(),
                        "status": link.map(|l| l.status.lock().unwrap().clone()),
                        "since_ms": link.map(|l| l.since_ms),
                        "last_seen_ms": n.last_seen_ms,
                        "paired_ms": n.paired_ms,
                        "going_away": n.going_away,
                        "summary": d.map(|d| d.summary.clone()).unwrap_or_default(),
                        "software": d.map(|d| d.node.software.version.clone()),
                        "capabilities": caps,
                        "pending_approvals": approvals,
                        "sessions": used_by,
                        "settings_write": d.is_some_and(settings_write),
                        "approvals_answerable": d.is_some_and(approvals_answerable),
                    })
                })
                .collect()
        });
        json!(nodes)
    }

    // ---- Tools ----

    pub fn tools(&self) -> Vec<Tool> {
        self.read(|s| {
            let views: Vec<tools::NodeView> = s
                .nodes
                .values()
                .filter_map(|n| {
                    n.descriptor.as_ref().map(|d| tools::NodeView {
                        id: &n.id,
                        name: &n.name,
                        descriptor: d,
                    })
                })
                .collect();
            tools::build(&views)
        })
    }

    // ---- Sessions ----

    pub fn new_session(&self, transport: &str) -> Arc<Session> {
        let s = Arc::new(Session {
            id: format!("s-{}", nerve_transport::keys::random_token(20)),
            transport: transport.to_string(),
            client: Mutex::new(String::new()),
            started_ms: now_ms(),
            tainted: AtomicBool::new(false),
            ended: AtomicBool::new(false),
            calls: AtomicU64::new(0),
            nodes: Mutex::new(BTreeSet::new()),
        });
        self.sessions
            .lock()
            .unwrap()
            .insert(s.id.clone(), s.clone());
        self.changed(Change::Sessions);
        s
    }

    pub fn session(&self, id: &str) -> Option<Arc<Session>> {
        self.sessions.lock().unwrap().get(id).cloned()
    }

    /// Ends a session: every node it used gets `session.end`, so approvals
    /// given "for this session" stop there too.
    pub async fn end_session(&self, id: &str) -> bool {
        let Some(s) = self.sessions.lock().unwrap().remove(id) else {
            return false;
        };
        s.ended.store(true, Ordering::SeqCst);
        let nodes: Vec<String> = s.nodes.lock().unwrap().iter().cloned().collect();
        for n in nodes {
            if let Some(l) = self.link(&n) {
                l.notify(msg::method::SESSION_END, json!({"session": s.id}))
                    .await;
            }
        }
        self.changed(Change::Sessions);
        true
    }

    pub fn sessions_json(&self) -> Value {
        let list: Vec<Value> = self
            .sessions
            .lock()
            .unwrap()
            .values()
            .map(|s| {
                let nodes: Vec<String> = s
                    .nodes
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|n| self.node_name(n))
                    .collect();
                json!({
                    "id": s.id,
                    "transport": s.transport,
                    "client": s.client.lock().unwrap().clone(),
                    "started_ms": s.started_ms,
                    "tainted": s.tainted(),
                    "calls": s.calls.load(Ordering::SeqCst),
                    "nodes": nodes,
                })
            })
            .collect();
        json!(list)
    }

    pub fn session_count(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }

    /// Answers an approval a node holds, through its `approvals.answer`.
    pub async fn answer_node(
        &self,
        node_id: &str,
        id: &str,
        answer: &str,
        minutes: Option<u64>,
    ) -> Result<(), RpcError> {
        let link = self
            .link(node_id)
            .ok_or_else(|| RpcError::new(ErrorCode::Unavailable, "the node is offline"))?;
        let mut args = json!({"id": id, "answer": answer});
        if let Some(m) = minutes {
            args["minutes"] = json!(m);
        }
        link.call(
            msg::method::INVOKE,
            json!({"cap": "approvals", "action": "answer", "args": args, "ctx": {}}),
            Some(SHORT_CALL),
        )
        .await
        .map(|_| ())
    }

    // ---- Settings (only with the node's `settings = write` grant) ----

    pub async fn node_settings(&self, node_id: &str) -> Result<Value, RpcError> {
        let link = self
            .link(node_id)
            .ok_or_else(|| RpcError::new(ErrorCode::Unavailable, "the node is offline"))?;
        link.call(
            msg::method::GET,
            json!({"cap": "settings", "keys": ["document", "version"]}),
            Some(SHORT_CALL),
        )
        .await
    }

    pub async fn set_node_settings(
        &self,
        node_id: &str,
        document: Value,
        if_version: Value,
    ) -> Result<Value, RpcError> {
        let link = self
            .link(node_id)
            .ok_or_else(|| RpcError::new(ErrorCode::Unavailable, "the node is offline"))?;
        link.call(
            msg::method::INVOKE,
            json!({"cap": "settings", "action": "set", "args": {"document": document, "if_version": if_version}, "ctx": {}}),
            Some(SHORT_CALL),
        )
        .await
    }

    /// Adds a command rule from the audit tab (design §11 9a) to this
    /// center's entry of the node's settings: `allow` puts `pattern` on
    /// `never_ask`, `deny` on `deny`. The node checks and may refuse the
    /// document.
    pub async fn add_command_rule(
        &self,
        node_id: &str,
        list: &str,
        pattern: &str,
    ) -> Result<Value, RpcError> {
        if !matches!(list, "allow" | "deny") {
            return Err(RpcError::invalid_args("the rule is allow or deny"));
        }
        let cur = self.node_settings(node_id).await?;
        let mut doc = cur.get("document").cloned().unwrap_or_else(|| json!({}));
        let version = cur.get("version").cloned().unwrap_or(Value::Null);
        let rules = command_rules(&mut doc).ok_or_else(|| {
            RpcError::invalid_args("the node's settings document has no room for command rules")
        })?;
        put_rule(rules, list == "allow", pattern)?;
        self.set_node_settings(node_id, doc, version).await
    }

    // ---- Calls ----

    /// Runs a tool call on its node: the node's policy decides.
    pub async fn call(
        &self,
        sess: &Arc<Session>,
        route: &Route,
        args: Map<String, Value>,
    ) -> Result<Value, CallError> {
        sess.calls.fetch_add(1, Ordering::SeqCst);
        let started = Instant::now();
        let out = self.call_inner(sess, route, args).await;
        let ms = started.elapsed().as_millis() as u64;
        let code = match &out {
            Ok(_) => None,
            Err(CallError::Rpc(e)) => Some(e.kind().as_str().to_string()),
            Err(CallError::Pending { .. }) => Some("pending".to_string()),
        };
        self.update_soon(|s| {
            if !s.nodes.contains_key(&route.node_id) {
                return;
            }
            let d = s.day(&route.node_id, now_ms());
            let c = d
                .calls
                .entry(format!("{}.{}", route.cap, route.action))
                .or_default();
            c.count += 1;
            c.total_ms += ms;
            c.max_ms = c.max_ms.max(ms);
            if let Some(code) = &code {
                c.errors += 1;
                *d.errors.entry(code.clone()).or_default() += 1;
            }
        });
        if out.is_ok() && tools::taints(route) && !sess.tainted.swap(true, Ordering::SeqCst) {
            self.changed(Change::Sessions);
        }
        out
    }

    async fn call_inner(
        &self,
        sess: &Arc<Session>,
        route: &Route,
        args: Map<String, Value>,
    ) -> Result<Value, CallError> {
        let link = self.link(&route.node_id).ok_or_else(|| {
            RpcError::new(
                ErrorCode::Unavailable,
                format!("the node {} is offline", route.node_name),
            )
        })?;
        let mut ctx = json!({"session": sess.id});
        if sess.tainted() {
            ctx["tainted"] = json!(true);
        }
        sess.nodes.lock().unwrap().insert(route.node_id.clone());
        link.sessions.lock().unwrap().insert(sess.id.clone());
        let started = Instant::now();
        let (id, rx) = link
            .start(
                msg::method::INVOKE,
                json!({"cap": route.cap, "action": route.action, "args": args, "ctx": ctx}),
            )
            .await?;
        tokio::pin!(rx);
        loop {
            tokio::select! {
                r = &mut rx => return r.unwrap_or_else(|_| Err(RpcError::new(ErrorCode::ConnectionLost, "the link to the node ended"))).map_err(CallError::Rpc),
                _ = tokio::time::sleep(self.call_wait) => {
                    // A call that waits for a person at the node is given up
                    // after the wait, so the harness hears why instead of
                    // timing out on its own. Other long calls keep running.
                    let waiting = link.approvals.lock().unwrap().values().any(|a| {
                        a.received >= started
                            && a.data.get("session").and_then(Value::as_str) == Some(sess.id.as_str())
                            && a.data.get("cap").and_then(Value::as_str) == Some(route.cap.as_str())
                            && a.data.get("action").and_then(Value::as_str) == Some(route.action.as_str())
                    });
                    if waiting {
                        link.cancel(id).await;
                        return Err(CallError::Pending { at: format!("the node {}", route.node_name), waited: started.elapsed() });
                    }
                }
            }
        }
    }

    pub fn call_wait(&self) -> Duration {
        self.call_wait
    }

    /// Closes every link with `bye shutdown`.
    pub async fn shutdown(&self) {
        let links: Vec<Arc<Link>> = self.links.lock().unwrap().values().cloned().collect();
        for l in links {
            l.bye(ByeReason::Shutdown).await;
        }
        self.flush();
    }

    /// Statistics: per node (summed over the kept days) and in total.
    pub fn stats_json(&self) -> Value {
        self.read(|s| {
            let mut total = crate::store::DayStats::default();
            let mut nodes = Map::new();
            for (id, ns) in &s.stats {
                let mut sum = crate::store::DayStats::default();
                for d in ns.days.values() {
                    sum.add(d);
                }
                total.add(&sum);
                let name = s
                    .nodes
                    .get(id)
                    .map(|n| n.name.clone())
                    .unwrap_or_else(|| id.clone());
                nodes.insert(name, serde_json::to_value(&sum).unwrap_or_default());
            }
            json!({"retention_days": s.retention_days, "total": total, "nodes": nodes})
        })
    }
}

/// The node gave this center `settings = write`: its descriptor carries the
/// `settings` capability (spec §7.5).
pub fn settings_write(d: &Descriptor) -> bool {
    d.capability("settings")
        .is_some_and(|c| c.exposure != Exposure::Off)
}

/// The node lets this center answer its approvals (`approvals = both`): the
/// `answer` action is offered and not off. A node with `local` may still list
/// the action; then its answer fails with `forbidden` and the UI says so.
pub fn approvals_answerable(d: &Descriptor) -> bool {
    d.capability("approvals")
        .is_some_and(|c| c.exposure != Exposure::Off && c.actions.contains_key("answer"))
}

/// The command rule lists of a center entry's settings document:
/// `policy.commands`, created when missing.
// The settings document is the node's center entry (nerve-policy), with the
// command rules under `policy.commands.{deny,allow,always_ask,never_ask}`. A
// node with another layout refuses the document and the web UI shows why.
fn command_rules(doc: &mut Value) -> Option<&mut Map<String, Value>> {
    let policy = doc
        .as_object_mut()?
        .entry("policy")
        .or_insert_with(|| json!({}));
    let commands = policy
        .as_object_mut()?
        .entry("commands")
        .or_insert_with(|| json!({}));
    commands.as_object_mut()
}

/// Puts `pattern` on the list an audit answer means. The node's `allow` list
/// is an allowlist that blocks every other command, so "Allow" means "run
/// without asking" (`never_ask`). A rule moves: it leaves the opposite list.
fn put_rule(rules: &mut Map<String, Value>, allow: bool, pattern: &str) -> Result<(), RpcError> {
    let (add, drop) = if allow {
        ("never_ask", "deny")
    } else {
        ("deny", "never_ask")
    };
    if let Some(arr) = rules.get_mut(drop).and_then(Value::as_array_mut) {
        arr.retain(|v| v != pattern);
    }
    let arr = rules
        .entry(add)
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or_else(|| RpcError::invalid_args("the node's command rules are not lists"))?;
    if !arr.iter().any(|v| v == pattern) {
        arr.push(json!(pattern));
    }
    Ok(())
}

/// The wildcard rule the audit tab offers for a command: its first word and
/// anything after it.
pub fn wildcard_of(command: &str) -> String {
    match command.split_whitespace().next() {
        Some(w) => format!("{w} *"),
        None => "*".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open(dir: &Path, name: Option<&str>) -> Center {
        nerve_transport::init_crypto();
        Center::open(Options {
            state_dir: dir.to_path_buf(),
            name: name.map(str::to_string),
            public_url: "http://127.0.0.1:7443".into(),
            call_wait: Duration::from_secs(1),
        })
        .unwrap()
    }

    #[test]
    fn a_new_center_is_named_nerve_center_unless_told_otherwise() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(open(dir.path(), None).name(), "nerve-center");
        // The name is kept across restarts and a flag renames it.
        assert_eq!(open(dir.path(), None).name(), "nerve-center");
        assert_eq!(open(dir.path(), Some("lab")).name(), "lab");
        assert_eq!(open(dir.path(), None).name(), "lab");
    }

    #[test]
    fn allow_means_never_ask_and_rules_move_between_lists() {
        let mut d = json!({"policy": {"commands": {"deny": ["git *"], "allow": ["ls"]}}});
        let rules = command_rules(&mut d).unwrap();
        put_rule(rules, true, "git *").unwrap();
        put_rule(rules, true, "git *").unwrap();
        // The allowlist is left alone: one entry there would block the rest.
        assert_eq!(
            d["policy"]["commands"],
            json!({"deny": [], "allow": ["ls"], "never_ask": ["git *"]})
        );
        let rules = command_rules(&mut d).unwrap();
        put_rule(rules, false, "git *").unwrap();
        assert_eq!(d["policy"]["commands"]["deny"], json!(["git *"]));
        assert_eq!(d["policy"]["commands"]["never_ask"], json!([]));
    }

    #[test]
    fn wildcards_and_rule_lists() {
        assert_eq!(wildcard_of("git status --short"), "git *");
        assert_eq!(wildcard_of("  "), "*");
        let mut d = json!({"mode": "ask"});
        command_rules(&mut d)
            .unwrap()
            .insert("allow".into(), json!(["ls"]));
        assert_eq!(d["policy"]["commands"]["allow"], json!(["ls"]));
        assert!(command_rules(&mut json!([])).is_none());
    }
}
