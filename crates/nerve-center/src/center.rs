//! The center's core: paired nodes and their links, pairing, sessions, calls
//! to nodes, the audit feed and the statistics. The MCP server, the node listener and the web UI are thin
//! layers over this.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};
use tokio::sync::broadcast;

use nerve_proto::link::{CenterUrl, PairLink, PairRequest, PairResponse};
use nerve_proto::msg::{self, ByeReason, Event, Hello};
use nerve_proto::{Descriptor, ErrorCode, Exposure, RpcError};
use nerve_transport::log::{Level, Log, Query, call_line};
use nerve_transport::tls::ServerIdentity;

use crate::audit::AuditFeed;
use crate::link::{Link, SHORT_CALL};
use crate::pairing::{Codes, Outcome};
use crate::store::{NodeRecord, Store};
use crate::tools::{self, Route, Tool};
use crate::util::{self, now_ms};

pub const IDENTITY_FILE: &str = "tls.pem";
pub use crate::audit::{AUDIT_KEEP, AUDIT_MAX_BYTES};
const ALERTS_KEEP: usize = 50;

/// What changed, for the MCP servers (tool lists) and the web UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    Tools,
    Nodes,
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
    /// The log to write to: the process's (`nerve_transport::log::install`),
    /// else one of the center's own. The center attaches its file to it.
    pub log: Option<Arc<Log>>,
    /// The level from `--log`, which wins over the stored one for this run.
    pub log_level: Option<Level>,
}

#[derive(Clone)]
pub struct Center(Arc<Inner>);

pub struct Inner {
    dir: PathBuf,
    public_url: CenterUrl,
    pin: Option<String>,
    pub identity: ServerIdentity,
    store: Mutex<Store>,
    dirty: AtomicBool,
    codes: Mutex<Codes>,
    links: Mutex<BTreeMap<String, Arc<Link>>>,
    changes: broadcast::Sender<Change>,
    audit: Mutex<AuditFeed>,
    alerts: Mutex<VecDeque<Value>>,
    sessions: Mutex<BTreeMap<String, Arc<Session>>>,
    log: Arc<Log>,
    /// `--log` was given, so the level in the settings does not hold at the
    /// next start.
    log_level_pinned: bool,
    /// When each node's last link ended, for the wait before the next one.
    down: Mutex<HashMap<String, Instant>>,
    /// Failed pairings, logged now and then (they need no secret to make).
    pair_log: Mutex<Quiet>,
    /// How long a link may be silent, in milliseconds.
    dead_after_ms: AtomicU64,
}

/// A line that may repeat: logged at most once in `QUIET_FOR`, with the count
/// of those left out since.
#[derive(Default)]
struct Quiet {
    last: Option<Instant>,
    skipped: u32,
}

const QUIET_FOR: Duration = Duration::from_secs(10);

impl Quiet {
    /// How many were left out, once `QUIET_FOR` has passed since the last line
    /// without another to carry the count; zero before.
    fn flush(&mut self, now: Instant) -> u32 {
        match self.last {
            Some(t) if now.duration_since(t) >= QUIET_FOR => std::mem::take(&mut self.skipped),
            _ => 0,
        }
    }

    /// Whether to log now, and how many were left out before.
    fn take(&mut self, now: Instant) -> Option<u32> {
        if self.last.is_some_and(|t| now.duration_since(t) < QUIET_FOR) {
            self.skipped += 1;
            return None;
        }
        self.last = Some(now);
        Some(std::mem::take(&mut self.skipped))
    }
}

/// One harness session: an MCP client (stdio, an attached process, or an
/// HTTP session). Its id goes to the nodes as `ctx.session`.
pub struct Session {
    pub id: String,
    pub transport: String,
    pub client: Mutex<String>,
    pub started_ms: u64,
    ended: AtomicBool,
    pub calls: AtomicU64,
    /// Nodes this session called, for `session.end`.
    nodes: Mutex<BTreeSet<String>>,
}

impl Session {
    pub fn ended(&self) -> bool {
        self.ended.load(Ordering::SeqCst)
    }
}

/// Why a tool call did not produce a result.
#[derive(Debug)]
pub enum CallError {
    Rpc(RpcError),
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

/// An `invoke` whose reply has not come. Dropped before it comes (the
/// harness cancelled the call), it tells the node to cancel the request, so
/// a command does not run on for nobody.
struct Waiting {
    link: Option<Arc<Link>>,
    id: u64,
}

impl Drop for Waiting {
    fn drop(&mut self) {
        if let Some(link) = self.link.take()
            && let Ok(rt) = tokio::runtime::Handle::try_current()
        {
            let id = self.id;
            rt.spawn(async move { link.cancel(id).await });
        }
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
        let log = opts.log.unwrap_or_else(|| Log::new(Level::default()));
        log.set_level(opts.log_level.unwrap_or(store.log_level));
        // A log that cannot be written is no reason not to run: the window
        // and stderr still work.
        if let Err(e) = log.attach_file(nerve_transport::log::file_in(&dir)) {
            eprintln!(
                "cannot open the log {}: {e}",
                nerve_transport::log::file_in(&dir).display()
            );
        }
        let pin = public_url.tls.then(|| identity.pin());
        let (changes, _) = broadcast::channel(64);
        Ok(Center(Arc::new(Inner {
            dir,
            public_url,
            pin,
            identity,
            store: Mutex::new(store),
            dirty: AtomicBool::new(false),
            codes: Mutex::new(Codes::default()),
            links: Mutex::new(BTreeMap::new()),
            changes,
            audit: Mutex::new(AuditFeed::default()),
            alerts: Mutex::new(VecDeque::new()),
            sessions: Mutex::new(BTreeMap::new()),
            log,
            log_level_pinned: opts.log_level.is_some(),
            down: Mutex::new(HashMap::new()),
            pair_log: Mutex::new(Quiet::default()),
            dead_after_ms: AtomicU64::new(crate::link::DEAD_AFTER.as_millis() as u64),
        })))
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The log (docs/user/logs.md): what the web UI shows and the file holds.
    pub fn log(&self) -> &Arc<Log> {
        &self.log
    }

    /// Logs `msg`, about the node `node_id` when one is given. Never called
    /// with the state locked: it reads the node's name from it.
    pub fn note(&self, level: Level, node_id: Option<&str>, msg: impl AsRef<str>) {
        // A node that is gone from the state is named by its id.
        let name = node_id.map(|id| match self.node_name(id) {
            n if n.is_empty() => id.to_string(),
            n => n,
        });
        let who = node_id.zip(name.as_deref()).map(|(id, n)| (n, id));
        self.log.record(level, who, msg.as_ref());
    }

    /// How long a link may send nothing before it is closed (spec §4.4).
    pub fn dead_after(&self) -> Duration {
        Duration::from_millis(self.dead_after_ms.load(Ordering::Relaxed))
    }

    /// Shortens the silence a link may keep, so that a test need not wait
    /// 45 s for the center to give up on a node that went quiet.
    #[doc(hidden)]
    pub fn set_dead_after(&self, d: Duration) {
        self.dead_after_ms
            .store(d.as_millis() as u64, Ordering::Relaxed);
    }

    /// Whether the `--log` flag was given, so that the level in the settings
    /// does not hold at the next start.
    pub fn log_level_pinned(&self) -> bool {
        self.log_level_pinned
    }

    /// The level kept for the next start, which `--log` does not change.
    pub fn stored_log_level(&self) -> Level {
        self.read(|s| s.log_level)
    }

    /// Sets the level from now on and keeps it for the next start. With
    /// `--log` the flag holds for this run: only the stored level changes.
    pub fn set_log_level(&self, level: Level) {
        let stored = self.stored_log_level();
        if stored != level {
            self.update(|s| s.log_level = level);
        }
        let old = self.log.level();
        if self.log_level_pinned {
            if stored != level {
                self.log.record(
                    Level::Info,
                    None,
                    &format!("the log level is kept as {level} for the next start; --log holds this run at {old}"),
                );
            }
            return;
        }
        if old == level {
            return;
        }
        // Said at a level that both the old and the new setting keep.
        let wide = old.max(level);
        self.log.set_level(wide);
        self.log.record(
            wide.min(Level::Info),
            None,
            &format!("the log level changes from {old} to {level}"),
        );
        self.log.set_level(level);
    }

    /// What the log view shows: the entries `q` asks for, newest first, the
    /// nodes that can be picked, and the level the log is kept at.
    pub fn log_json(&self, q: &Query) -> Value {
        let entries: Vec<Value> = self
            .log
            .entries(q)
            .into_iter()
            .map(|(seq, e)| {
                let mut v = serde_json::to_value(&e).unwrap_or_default();
                v["seq"] = json!(seq);
                v
            })
            .collect();
        // Every paired node, and those only the log remembers.
        let mut nodes: Vec<Value> = self.read(|s| {
            s.nodes
                .values()
                .map(|n| json!({"id": n.id, "name": n.name, "paired": true}))
                .collect()
        });
        for (id, name) in self.log.nodes() {
            if !nodes.iter().any(|n| n["id"] == id.as_str()) {
                nodes.push(json!({"id": id, "name": name, "paired": false}));
            }
        }
        json!({
            "level": self.log.level(),
            "entries": entries,
            "nodes": nodes,
            "file": self.log.file_path().is_some(),
        })
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
            self.log.record(
                Level::Error,
                None,
                &format!("cannot write the state file: {e}"),
            );
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
                self.log.record(
                    Level::Error,
                    None,
                    &format!("cannot write the state file: {e}"),
                );
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
        let ttl = Duration::from_secs(u64::from(self.read(|st| st.pair_code_minutes)) * 60);
        let code = self.codes.lock().unwrap().create(Instant::now(), ttl);
        // The code is a secret until it is used, so it is not logged.
        self.log.record(
            Level::Info,
            None,
            &format!(
                "a pairing code was made; it is valid for {}",
                util::span(ttl)
            ),
        );
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
            "expires_ms": now_ms() + ttl.as_millis() as u64,
        })
    }

    /// What became of a code from [`Center::new_pairing`], for the web UI:
    /// `open` while it can still pair a machine (a pairing in progress counts,
    /// it may fail), and once a machine used it, that machine as `node`.
    pub fn pairing_status(&self, code: &str) -> Value {
        let outcome = self.codes.lock().unwrap().outcome(code, Instant::now());
        match outcome {
            Outcome::Open => json!({"open": true, "node": null}),
            Outcome::Gone => json!({"open": false, "node": null}),
            Outcome::Paired(id) => {
                let name = self.read(|s| s.nodes.get(&id).map(|n| n.name.clone()));
                json!({"open": false, "node": name.map(|name| json!({"id": id, "name": name}))})
            }
        }
    }

    /// Answers `POST /nerve/v0/pair`: the status and the body.
    pub fn pair(&self, body: &[u8]) -> (u16, Value) {
        // A request without a code that works costs nothing to make, so a
        // refusal before the code is checked is detail, not news.
        let err = |s: u16, m: &str| {
            self.log.record(
                Level::Debug,
                None,
                &format!("a pairing request was refused ({s}): {m}"),
            );
            (s, json!({ "error": m }))
        };
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
        // Taken out in the same step as the check: the code is used up from
        // here on, and given back only if this pairing fails.
        let Ok(taken) = self.codes.lock().unwrap().take(&req.code, now) else {
            // Anyone who reaches the port can send these; one line now and
            // then says it happens.
            let quiet = self.pair_log.lock().unwrap().take(now);
            if let Some(more) = quiet {
                let also = if more > 0 {
                    format!(" ({more} more since the last line)")
                } else {
                    String::new()
                };
                self.log.record(
                    Level::Warn,
                    None,
                    &format!(
                        "pairing refused: the code is unknown, used, expired or out of tries{also}"
                    ),
                );
            }
            return (
                403,
                json!({ "error": "the pairing code is unknown, used, expired or out of tries" }),
            );
        };
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
                    disabled: false,
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
                self.codes
                    .lock()
                    .unwrap()
                    .done(taken, &node_id, Instant::now());
                self.log.record(
                    Level::Info,
                    Some((&req.name, &node_id)),
                    &format!(
                        "the node paired ({}/{}); its code is used up",
                        req.platform, req.arch
                    ),
                );
                self.changed(Change::Nodes);
                (200, serde_json::to_value(resp).unwrap_or_default())
            }
            Err(why) => {
                self.codes.lock().unwrap().fail(taken);
                self.log.record(
                    Level::Warn,
                    None,
                    &format!("pairing refused for the name {}: {why}", req.name),
                );
                (409, json!({ "error": why }))
            }
        }
    }

    // ---- Nodes ----

    pub fn rename(&self, node_id: &str, name: &str) -> Result<(), String> {
        if !nerve_proto::valid_node_name(name) {
            return Err("a node name is 1 to 32 characters of a-z, 0-9 and -".into());
        }
        let old = self.update(|s| {
            if s.nodes.values().any(|n| n.name == name && n.id != node_id) {
                return Err("another node already has this name".to_string());
            }
            let n = s.nodes.get_mut(node_id).ok_or("no such node")?;
            Ok(std::mem::replace(&mut n.name, name.to_string()))
        })?;
        self.note(
            Level::Info,
            Some(node_id),
            format!("the node was renamed from {old}"),
        );
        self.changed(Change::Nodes);
        self.changed(Change::Tools);
        Ok(())
    }

    /// Switches a node off or on for the agent. The link stays as it is;
    /// only the tool list and the call path look at the flag.
    pub fn set_disabled(&self, node_id: &str, disabled: bool) -> Result<(), String> {
        self.update(|s| {
            s.nodes.get_mut(node_id).ok_or("no such node")?.disabled = disabled;
            Ok::<(), String>(())
        })?;
        self.note(
            Level::Info,
            Some(node_id),
            if disabled {
                "the node was disabled: the agent gets none of its tools and calls to it are refused"
            } else {
                "the node was enabled"
            },
        );
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
        self.forget(node_id, "removed by the owner; its link got bye revoked");
        Ok(())
    }

    /// Drops a node's record (a remove, or the node's `bye unpaired`); `why`
    /// goes to the log.
    pub fn forget(&self, node_id: &str, why: &str) {
        let name = self.node_name(node_id);
        let had = self.update(|s| {
            s.stats.remove(node_id);
            s.nodes.remove(node_id).is_some()
        });
        if had {
            self.down.lock().unwrap().remove(node_id);
            self.log.record(
                Level::Info,
                Some((&name, node_id)),
                &format!("the node is no longer paired: {why}"),
            );
            self.changed(Change::Nodes);
            self.changed(Change::Tools);
        }
    }

    pub fn alert(&self, node_id: &str, text: &str) {
        self.note(Level::Warn, Some(node_id), text);
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
        let again = match self.down.lock().unwrap().remove(&id) {
            Some(t) => format!(" again after {}", util::span(t.elapsed())),
            None => String::new(),
        };
        self.note(
            Level::Info,
            Some(&id),
            format!("link up{again} (node software {})", hello.software.version),
        );
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

    /// The node's old link is given up because the node connected again and
    /// the old one did not answer a ping: told as the drop it is, with how long
    /// it had been silent, which the wait before the new link counts from. The
    /// old link stops being the node's here, so its own end, whenever it
    /// comes, is detail. A link that ended while the ping was waited for has
    /// told its drop already, and says nothing more.
    pub(crate) fn link_replaced(&self, old: &Arc<Link>) {
        {
            let mut links = self.links.lock().unwrap();
            let current = links.get(&old.node_id).is_some_and(|l| Arc::ptr_eq(l, old));
            if !current {
                return;
            }
            links.remove(&old.node_id);
        }
        let silent = old.silent_for();
        let gone = Instant::now()
            .checked_sub(silent)
            .unwrap_or_else(Instant::now);
        self.down.lock().unwrap().insert(old.node_id.clone(), gone);
        self.note(
            Level::Warn,
            Some(&old.node_id),
            format!(
                "link dropped: the node connected again and this link did not answer a ping, so it was replaced (it was up for {}, silent for {})",
                util::span(old.since.elapsed()),
                util::span(silent)
            ),
        );
    }

    /// A link ended. `clean` is whether the node said bye; `why` is what ended
    /// it, for the log. `silent` is how long nothing had come from the node,
    /// which the wait before its next link counts from.
    pub(crate) fn link_down(&self, link: &Arc<Link>, clean: bool, why: &str, silent: Duration) {
        let id = &link.node_id;
        // A link the node's newer one replaced is no longer the node's: its end
        // says nothing about the node, which is up.
        let current = {
            let mut links = self.links.lock().unwrap();
            let current = links.get(id).is_some_and(|l| Arc::ptr_eq(l, link));
            if current {
                links.remove(id);
            }
            current
        };
        let now = now_ms();
        let online = link.since.elapsed().as_millis() as u64;
        self.update_soon(|s| {
            if current && let Some(n) = s.nodes.get_mut(id) {
                n.last_seen_ms = now;
            }
            if s.nodes.contains_key(id) {
                let d = s.day(id, now);
                d.online_ms += online;
                if !clean {
                    d.drops += 1;
                }
            }
        });
        if !current {
            self.note(
                Level::Debug,
                Some(id),
                format!(
                    "a link that was replaced ended: {why} (it was up for {})",
                    util::span(link.since.elapsed())
                ),
            );
            self.changed(Change::Nodes);
            return;
        }
        let gone = Instant::now()
            .checked_sub(silent)
            .unwrap_or_else(Instant::now);
        self.down.lock().unwrap().insert(id.clone(), gone);
        let (level, verb) = if clean {
            (Level::Info, "closed")
        } else {
            (Level::Warn, "dropped")
        };
        self.note(
            level,
            Some(id),
            format!(
                "link {verb}: {why} (it was up for {})",
                util::span(link.since.elapsed())
            ),
        );
        self.changed(Change::Nodes);
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
                Ok(d) if d.check_names().is_err() => {
                    let e = d.check_names().unwrap_err();
                    self.note(
                        Level::Warn,
                        Some(&link.node_id),
                        format!("the node sent a description with a bad name, so the center ignores it: {e}"),
                    );
                }
                Ok(d) => {
                    self.update(|s| {
                        if let Some(n) = s.nodes.get_mut(&link.node_id) {
                            n.descriptor = Some(d);
                        }
                    });
                    self.changed(Change::Tools);
                    self.changed(Change::Nodes);
                }
                Err(e) => self.note(
                    Level::Warn,
                    Some(&link.node_id),
                    format!("the node sent a description the center cannot read: {e}"),
                ),
            },
            // A link that ended meanwhile says so on its own.
            Err(e) => self.note(
                if e.kind() == ErrorCode::ConnectionLost {
                    Level::Debug
                } else {
                    Level::Warn
                },
                Some(&link.node_id),
                format!("asking the node for its description failed: {}", e.message),
            ),
        }
    }

    pub(crate) fn on_event(&self, link: &Arc<Link>, ev: Event) {
        let node = link.node_id.clone();
        match (ev.cap.as_str(), ev.name.as_str()) {
            ("node", "descriptor_changed" | "capability_changed") => {
                self.note(
                    Level::Debug,
                    Some(&node),
                    "the node's description changed; fetching it again",
                );
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
                self.note(
                    Level::Info,
                    Some(&node),
                    format!("the node is going away: {}", util::clip(&why, 200)),
                );
                self.changed(Change::Nodes);
            }
            ("settings", "changed") => {
                let version = ev.data.get("version").and_then(Value::as_u64);
                self.note(
                    Level::Info,
                    Some(&node),
                    match version {
                        Some(v) => format!("the node's settings changed (version {v})"),
                        None => "the node's settings changed".to_string(),
                    },
                );
                self.changed(Change::Nodes);
            }
            ("audit", "decision") => {
                let name = self.node_name(&node);
                let mut e = ev.data.clone();
                if let Some(o) = e.as_object_mut() {
                    o.insert("node_id".into(), json!(node));
                    o.insert("node".into(), json!(name));
                    o.entry("ts").or_insert(json!(ev.ts));
                }
                self.audit.lock().unwrap().push(e);
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
        self.audit.lock().unwrap().list()
    }

    /// The nodes as the web UI and `nodes` show them.
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
                        "disabled": n.disabled,
                        "summary": d.map(|d| d.summary.clone()).unwrap_or_default(),
                        "software": d.map(|d| d.node.software.version.clone()),
                        "capabilities": caps,
                        "sessions": used_by,
                        "settings_write": d.is_some_and(settings_write),
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
                // A disabled node offers the agent nothing.
                .filter(|n| !n.disabled)
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
            ended: AtomicBool::new(false),
            calls: AtomicU64::new(0),
            nodes: Mutex::new(BTreeSet::new()),
        });
        self.sessions
            .lock()
            .unwrap()
            .insert(s.id.clone(), s.clone());
        self.log.record(
            Level::Info,
            None,
            &format!("a harness session started over {transport} ({})", s.id),
        );
        self.changed(Change::Sessions);
        s
    }

    pub fn session(&self, id: &str) -> Option<Arc<Session>> {
        self.sessions.lock().unwrap().get(id).cloned()
    }

    /// Ends a session: every node it used gets `session.end`.
    pub async fn end_session(&self, id: &str) -> bool {
        let Some(s) = self.sessions.lock().unwrap().remove(id) else {
            return false;
        };
        s.ended.store(true, Ordering::SeqCst);
        self.log.record(
            Level::Info,
            None,
            &format!(
                "the harness session {} ended after {} calls",
                s.id,
                s.calls.load(Ordering::SeqCst)
            ),
        );
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

    // ---- Settings (only with the node's `settings = write` grant) ----

    pub async fn node_settings(&self, node_id: &str) -> Result<Value, RpcError> {
        let link = self
            .link(node_id)
            .ok_or_else(|| RpcError::new(ErrorCode::Unavailable, "the node is offline"))?;
        link.call(
            msg::method::GET,
            json!({"cap": "settings", "keys": ["document", "version", "sudo"]}),
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
        let r = self.send_settings(node_id, document, if_version).await;
        self.log_change(node_id, "settings saved", "save the settings", &r);
        r
    }

    async fn send_settings(
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

    /// Logs what a change to a node's settings from the web UI came to: `done`
    /// when the node took it, else that it refused to `wanted`.
    fn log_change(&self, node_id: &str, done: &str, wanted: &str, r: &Result<Value, RpcError>) {
        match r {
            Ok(v) => {
                let version = v
                    .get("version")
                    .map(|v| format!(" (version {v})"))
                    .unwrap_or_default();
                self.note(
                    Level::Info,
                    Some(node_id),
                    format!("{done} from the web UI{version}"),
                );
            }
            Err(e) => self.note(
                Level::Warn,
                Some(node_id),
                format!(
                    "the node did not {wanted} from the web UI ({}): {}",
                    e.kind().as_str(),
                    util::clip(&e.message, 300)
                ),
            ),
        }
    }

    /// A one-shot offer to seal the node's sudo password for (docs/dev/spec/protocol.md
    /// §7.4.1). The center checks that the paired node signed it for this
    /// center, so a client seals only for that node.
    pub async fn node_sudo_offer(&self, node_id: &str) -> Result<Value, RpcError> {
        let link = self
            .link(node_id)
            .ok_or_else(|| RpcError::new(ErrorCode::Unavailable, "the node is offline"))?;
        let public = self
            .public_key(node_id)
            .ok_or_else(|| RpcError::new(ErrorCode::Unavailable, "the node is not paired"))?;
        let v = link
            .call(
                msg::method::INVOKE,
                json!({"cap": "settings", "action": "sudo-offer", "args": {}, "ctx": {}}),
                Some(SHORT_CALL),
            )
            .await?;
        let offer: nerve_transport::sudo::Offer = serde_json::from_value(json!({
            "offer": v["offer"], "key": v["key"], "ts": v["ts"],
        }))
        .map_err(|e| RpcError::internal(format!("the node's sudo offer: {e}")))?;
        let sig = v["sig"].as_str().unwrap_or_default();
        if !nerve_transport::keys::verify_sudo_offer(&public, &self.id(), &offer, sig) {
            return Err(RpcError::internal(
                "the node's sudo offer is not signed with its paired key",
            ));
        }
        Ok(json!({"offer": offer.offer, "key": offer.key, "ts": offer.ts}))
    }

    /// Switches the node's sudo on (with a password sealed for one of its
    /// offers) or off. The center only relays the sealed box; it cannot
    /// open it and keeps no copy.
    pub async fn set_node_sudo(
        &self,
        node_id: &str,
        on: bool,
        sealed: Option<Value>,
    ) -> Result<Value, RpcError> {
        let link = self
            .link(node_id)
            .ok_or_else(|| RpcError::new(ErrorCode::Unavailable, "the node is offline"))?;
        let mut args = json!({"on": on});
        if let Some(sealed) = sealed {
            args["sealed"] = sealed;
        }
        let r = link
            .call(
                msg::method::INVOKE,
                json!({"cap": "settings", "action": "sudo", "args": args, "ctx": {}}),
                Some(SHORT_CALL),
            )
            .await;
        // The password is sealed for the node; the center never sees it.
        let (done, wanted) = if on {
            ("sudo switched on", "switch sudo on")
        } else {
            ("sudo switched off", "switch sudo off")
        };
        self.log_change(node_id, done, wanted, &r);
        r
    }

    /// Adds `rule` to one list of this center's policy on the node, from the
    /// audit tab (design §11 9a): `allow`, `deny`, or `sudo` for the sudo
    /// allow list. A button only adds; it never takes a rule off the other
    /// list. The node checks and may refuse the document.
    pub async fn add_rule(&self, node_id: &str, list: &str, rule: &str) -> Result<Value, RpcError> {
        let key = policy_list(list)?;
        let cur = self.node_settings(node_id).await?;
        let mut doc = cur.get("document").cloned().unwrap_or_else(|| json!({}));
        let version = cur.get("version").cloned().unwrap_or(Value::Null);
        put_rule(&mut doc, key, rule)?;
        let r = self.send_settings(node_id, doc, version).await;
        let done = format!("rule added to the {list} list ({rule})");
        self.log_change(
            node_id,
            &done,
            &format!("add a rule to the {list} list"),
            &r,
        );
        r
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
        };
        // A call that worked is in the node's audit log, not here.
        if let Err(CallError::Rpc(e)) = &out {
            self.log_failed_call(route, e, started.elapsed());
        }
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
        out
    }

    async fn call_inner(
        &self,
        sess: &Arc<Session>,
        route: &Route,
        args: Map<String, Value>,
    ) -> Result<Value, CallError> {
        // Checked first: nothing is sent to a disabled node, not even the
        // session mark. A call can still arrive here from a tool list that
        // was read before the switch.
        if self.read(|s| s.nodes.get(&route.node_id).is_some_and(|n| n.disabled)) {
            return Err(RpcError::new(
                ErrorCode::Unavailable,
                format!("the node {} is disabled in the center", route.node_name),
            )
            .into());
        }
        let link = self.link(&route.node_id).ok_or_else(|| {
            RpcError::new(
                ErrorCode::Unavailable,
                format!("the node {} is offline", route.node_name),
            )
        })?;
        let ctx = json!({"session": sess.id});
        sess.nodes.lock().unwrap().insert(route.node_id.clone());
        link.sessions.lock().unwrap().insert(sess.id.clone());
        let (id, rx) = link
            .start(
                msg::method::INVOKE,
                json!({"cap": route.cap, "action": route.action, "args": args, "ctx": ctx}),
            )
            .await?;
        let mut waiting = Waiting {
            link: Some(link),
            id,
        };
        let r = rx.await;
        waiting.link = None;
        r.unwrap_or_else(|_| {
            Err(RpcError::new(
                ErrorCode::ConnectionLost,
                "the link to the node ended",
            ))
        })
        .map_err(CallError::Rpc)
    }

    /// Logs a call that was refused or that failed, with the reason.
    fn log_failed_call(&self, route: &Route, e: &RpcError, took: Duration) {
        // A node the owner switched off answers `unavailable`.
        let disabled_here = e.kind() == ErrorCode::Unavailable
            && self.read(|s| s.nodes.get(&route.node_id).is_some_and(|n| n.disabled));
        let what = format!("{}.{}", route.cap, route.action);
        let (level, line) = call_line(&what, e, took, disabled_here);
        self.note(level, Some(&route.node_id), line);
    }

    /// Closes every link with `bye shutdown`.
    pub async fn shutdown(&self) {
        let links: Vec<Arc<Link>> = self.links.lock().unwrap().values().cloned().collect();
        self.log.record(
            Level::Info,
            None,
            &format!(
                "the center is stopping; closing {}",
                plural(links.len() as u32, "node link")
            ),
        );
        for l in links {
            l.bye(ByeReason::Shutdown).await;
        }
        self.flush();
    }

    /// Notes the pairing codes that ran out unused. The center calls this now
    /// and then, so a log line is at most a few seconds behind the expiry.
    pub fn sweep_codes(&self) {
        // The wrong codes left out of a burst are counted when it is over.
        let left_out = self.pair_log.lock().unwrap().flush(Instant::now());
        if left_out > 0 {
            self.log.record(
                Level::Warn,
                None,
                &format!(
                    "{} left out since the last line: the code was unknown, used, expired or out of tries",
                    plural(left_out, "pairing refusal")
                ),
            );
        }
        let lost = self.codes.lock().unwrap().sweep(Instant::now());
        if lost.expired > 0 {
            self.log.record(
                Level::Info,
                None,
                &format!(
                    "{} expired without being used",
                    plural(lost.expired, "pairing code")
                ),
            );
        }
        if lost.out_of_tries > 0 {
            self.log.record(
                Level::Warn,
                None,
                &format!(
                    "{} ran out of tries on wrong codes",
                    plural(lost.out_of_tries, "pairing code")
                ),
            );
        }
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

fn plural(n: u32, one: &str) -> String {
    if n == 1 {
        format!("{n} {one}")
    } else {
        format!("{n} {one}s")
    }
}

/// The node gave this center `settings = write`: its descriptor carries the
/// `settings` capability (spec §7.4).
pub fn settings_write(d: &Descriptor) -> bool {
    d.capability("settings")
        .is_some_and(|c| c.exposure != Exposure::Off)
}

/// The key of the policy list a button writes to. The settings document is
/// the node's center entry (nerve-policy): `policy.allow`, `policy.deny` and
/// `policy.sudo_allow`. A node with another layout refuses the document and
/// the web UI shows why.
fn policy_list(list: &str) -> Result<&'static str, RpcError> {
    match list {
        "allow" => Ok("allow"),
        "deny" => Ok("deny"),
        "sudo" => Ok("sudo_allow"),
        _ => Err(RpcError::invalid_args("the list is allow, deny or sudo")),
    }
}

/// Puts `rule` on `policy.<key>` of a settings document, unless it is there.
fn put_rule(doc: &mut Value, key: &str, rule: &str) -> Result<(), RpcError> {
    let no_room = || RpcError::invalid_args("the node's settings document has no room for rules");
    let list = doc
        .as_object_mut()
        .ok_or_else(no_room)?
        .entry("policy")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(no_room)?
        .entry(key)
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or_else(|| RpcError::invalid_args("the node's rules are not lists"))?;
    if !list.iter().any(|v| v == rule) {
        list.push(json!(rule));
    }
    Ok(())
}

/// The list and the rule an audit button means: the entry's `cap`, `action`
/// and `target`, the list (`allow`, `deny`, or `sudo` for a sudo command) and
/// whether it is the wildcard form.
pub fn audit_rule(
    list: &str,
    cap: &str,
    action: &str,
    target: &str,
    wildcard: bool,
) -> Result<String, String> {
    // A cut target is no longer the call's, so no rule can be made from it.
    if nerve_policy::audit::is_cut_target(target) {
        return Err("the target was cut to its start, so a rule cannot name it".into());
    }
    match list {
        "allow" | "deny" => nerve_policy::rules::rule_for(cap, action, target, wildcard),
        "sudo" if (cap, action) == ("exec", "run") => {
            nerve_policy::rules::sudo_rule_for(target, wildcard)
        }
        "sudo" => Err("the sudo list is for sudo commands".into()),
        _ => Err("the list is allow, deny or sudo".into()),
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
            log: None,
            log_level: None,
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

    /// One code is good for one pairing, also when several nodes send it at
    /// the same moment.
    #[test]
    fn one_code_pairs_one_node_however_many_send_it_at_once() {
        let dir = tempfile::tempdir().unwrap();
        let center = open(dir.path(), None);
        let code = center.new_pairing()["code"].as_str().unwrap().to_string();
        let start = std::sync::Barrier::new(8);
        let statuses: Vec<u16> = std::thread::scope(|s| {
            let tries: Vec<_> = (0..8u8)
                .map(|i| {
                    let (center, code, start) = (&center, &code, &start);
                    s.spawn(move || {
                        let body = json!({
                            "code": code,
                            "name": format!("node-{i}"),
                            "platform": "linux",
                            "arch": "x86_64",
                            "public_key": msg::hex(&[i + 1; 32]),
                        });
                        start.wait();
                        center.pair(body.to_string().as_bytes()).0
                    })
                })
                .collect();
            tries.into_iter().map(|t| t.join().unwrap()).collect()
        });
        let paired = statuses.iter().filter(|s| **s == 200).count();
        assert_eq!(paired, 1, "statuses {statuses:?}");
        assert_eq!(center.read(|st| st.nodes.len()), 1);
        assert!(
            statuses.iter().all(|s| matches!(s, 200 | 403)),
            "{statuses:?}"
        );
    }

    // ---- The log ----

    use nerve_transport::log::Entry;

    /// Every entry of the log, oldest first.
    fn lines(c: &Center) -> Vec<Entry> {
        let all = Query {
            limit: usize::MAX,
            ..Query::default()
        };
        c.log()
            .entries(&all)
            .into_iter()
            .rev()
            .map(|(_, e)| e)
            .collect()
    }

    fn said(c: &Center, level: Level, part: &str) -> Vec<Entry> {
        lines(c)
            .into_iter()
            .filter(|e| e.level == level && e.msg.contains(part))
            .collect()
    }

    fn pair_body(code: &str, name: &str, key: u8) -> Vec<u8> {
        json!({
            "code": code, "name": name, "platform": "linux", "arch": "x86_64",
            "public_key": msg::hex(&[key; 32]),
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn pairing_is_logged_and_no_code_is() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        let made = c.new_pairing();
        let code = made["code"].as_str().unwrap().to_string();
        let link = made["link"].as_str().unwrap().to_string();
        // Wrong codes in a row make one line, not one each.
        for _ in 0..3 {
            assert_eq!(c.pair(&pair_body("wrongwrong12", "box-1", 1)).0, 403);
        }
        assert_eq!(c.pair(&pair_body(&code, "box-1", 7)).0, 200);
        // A right code that cannot pair: told, with the name that was asked for.
        let second = c.new_pairing()["code"].as_str().unwrap().to_string();
        assert_eq!(c.pair(&pair_body(&second, "box-2", 7)).0, 409);
        let id = nerve_transport::keys::node_id(&[7; 32]);

        assert_eq!(
            said(
                &c,
                Level::Info,
                "a pairing code was made; it is valid for 10 min"
            )
            .len(),
            2
        );
        assert_eq!(
            said(&c, Level::Warn, "pairing refused: the code is unknown").len(),
            1
        );
        let paired = said(&c, Level::Info, "the node paired (linux/x86_64)");
        assert_eq!(paired.len(), 1);
        assert_eq!(paired[0].node.as_deref(), Some("box-1"));
        assert_eq!(paired[0].node_id.as_deref(), Some(id.as_str()));
        assert_eq!(
            said(
                &c,
                Level::Warn,
                "pairing refused for the name box-2: this key is already paired"
            )
            .len(),
            1
        );
        // Neither a code, the link that carries one, nor a wrong code is in
        // the window or in the file.
        let file = std::fs::read_to_string(dir.path().join("log.jsonl")).unwrap();
        let window = serde_json::to_string(&lines(&c)).unwrap();
        for secret in [&code, &second, &link, "wrongwrong12"] {
            assert!(
                !file.contains(secret) && !window.contains(secret),
                "{secret}"
            );
        }
    }

    #[test]
    fn a_code_that_runs_out_unused_is_logged_once() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        let short = Duration::from_millis(1);
        c.codes.lock().unwrap().create(Instant::now(), short);
        c.codes.lock().unwrap().create(Instant::now(), short);
        std::thread::sleep(Duration::from_millis(10));
        c.sweep_codes();
        c.sweep_codes();
        let expired = said(&c, Level::Info, "expired without being used");
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].msg, "2 pairing codes expired without being used");
        // A code taken by wrong tries is a warning.
        c.codes
            .lock()
            .unwrap()
            .create(Instant::now(), Duration::from_secs(60));
        for _ in 0..crate::pairing::TRIES {
            assert_eq!(c.pair(&pair_body("wrongwrong12", "box-1", 1)).0, 403);
        }
        c.sweep_codes();
        assert_eq!(
            said(
                &c,
                Level::Warn,
                "1 pairing code ran out of tries on wrong codes"
            )
            .len(),
            1
        );
    }

    /// The wrong codes a burst leaves out of the log are counted once it is
    /// over, not only if another one comes later.
    #[test]
    fn a_burst_of_wrong_codes_is_counted_when_it_stops() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        for _ in 0..5 {
            assert_eq!(c.pair(&pair_body("wrongwrong12", "box-1", 1)).0, 403);
        }
        assert_eq!(said(&c, Level::Warn, "pairing refused").len(), 1);
        // Inside the window the count waits.
        c.sweep_codes();
        assert!(said(&c, Level::Warn, "left out").is_empty());
        // Past it, the next sweep says how many there were, once.
        c.pair_log.lock().unwrap().last = Instant::now().checked_sub(QUIET_FOR * 2);
        c.sweep_codes();
        c.sweep_codes();
        let left = said(&c, Level::Warn, "left out");
        assert_eq!(left.len(), 1);
        assert!(
            left[0]
                .msg
                .starts_with("4 pairing refusals left out since the last line"),
            "{}",
            left[0].msg
        );
        // A single refusal after the quiet is a line of its own, with no count.
        assert_eq!(c.pair(&pair_body("wrongwrong12", "box-1", 1)).0, 403);
        let lines = said(&c, Level::Warn, "pairing refused");
        assert_eq!(lines.len(), 2);
        assert!(!lines[1].msg.contains("more since"), "{}", lines[1].msg);
    }

    /// With `--log` the flag holds for the run; a level saved meanwhile is kept
    /// for the next start and does not change this one.
    #[test]
    fn a_level_saved_under_the_flag_is_kept_for_the_next_start_only() {
        let dir = tempfile::tempdir().unwrap();
        open(dir.path(), None).set_log_level(Level::Debug);
        let c = Center::open(Options {
            state_dir: dir.path().to_path_buf(),
            name: None,
            public_url: "http://127.0.0.1:7443".into(),
            log: None,
            log_level: Some(Level::Warn),
        })
        .unwrap();
        assert_eq!(
            (c.log().level(), c.stored_log_level()),
            (Level::Warn, Level::Debug)
        );
        // Saving the stored level again changes nothing.
        c.set_log_level(Level::Debug);
        assert_eq!(
            (c.log().level(), c.stored_log_level()),
            (Level::Warn, Level::Debug)
        );
        // Another one is stored; this run stays where the flag put it.
        c.set_log_level(Level::Error);
        assert_eq!(
            (c.log().level(), c.stored_log_level()),
            (Level::Warn, Level::Error)
        );
        drop(c);
        assert_eq!(open(dir.path(), None).log().level(), Level::Error);
    }

    #[tokio::test]
    async fn changes_to_a_node_are_logged_under_its_name_and_id() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        let code = c.new_pairing()["code"].as_str().unwrap().to_string();
        assert_eq!(c.pair(&pair_body(&code, "box-1", 7)).0, 200);
        let id = nerve_transport::keys::node_id(&[7; 32]);
        c.rename(&id, "web-1").unwrap();
        c.set_disabled(&id, true).unwrap();
        c.set_disabled(&id, false).unwrap();
        c.remove(&id).await.unwrap();

        let about: Vec<(Level, Option<String>, String)> = lines(&c)
            .into_iter()
            .filter(|e| e.node_id.as_deref() == Some(id.as_str()))
            .map(|e| (e.level, e.node, e.msg))
            .collect();
        let name = |n: &str| Some(n.to_string());
        assert_eq!(
            about[1],
            (
                Level::Info,
                name("web-1"),
                "the node was renamed from box-1".into()
            )
        );
        assert_eq!(about[2].1, name("web-1"));
        assert!(about[2].2.starts_with("the node was disabled"), "{about:?}");
        assert_eq!(about[3].2, "the node was enabled");
        // Removed, it is named as it was.
        assert_eq!(about.len(), 5);
        assert_eq!(about[4].1, name("web-1"));
        assert!(about[4].2.contains("removed by the owner"), "{about:?}");
        // The log still names a node the center forgot, for the view's list.
        let v = c.log_json(&Query {
            limit: 10,
            ..Query::default()
        });
        assert_eq!(
            v["nodes"],
            json!([{"id": id, "name": "web-1", "paired": false}])
        );
    }

    #[test]
    fn the_log_level_is_a_setting_and_the_flag_wins() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        // Info unless set; debug is not kept.
        assert_eq!(c.log().level(), Level::Info);
        c.log().record(Level::Debug, None, "detail one");
        assert!(said(&c, Level::Debug, "detail").is_empty());
        c.set_log_level(Level::Debug);
        c.log().record(Level::Debug, None, "detail two");
        assert_eq!(said(&c, Level::Debug, "detail two").len(), 1);
        assert_eq!(
            said(&c, Level::Info, "the log level changes from info to debug").len(),
            1
        );
        // It lasts: the next start keeps it.
        drop(c);
        let c = open(dir.path(), None);
        assert_eq!(c.log().level(), Level::Debug);
        assert!(!c.log_level_pinned());
        // Lowering is told too, while the old level still keeps it.
        c.set_log_level(Level::Error);
        assert_eq!(
            said(&c, Level::Info, "the log level changes from debug to error").len(),
            1
        );
        c.log().record(Level::Warn, None, "not kept");
        assert!(said(&c, Level::Warn, "not kept").is_empty());
        drop(c);
        // `--log` wins for the run and leaves the stored level as it was.
        let c = Center::open(Options {
            state_dir: dir.path().to_path_buf(),
            name: None,
            public_url: "http://127.0.0.1:7443".into(),
            log: None,
            log_level: Some(Level::Warn),
        })
        .unwrap();
        assert_eq!(c.log().level(), Level::Warn);
        assert!(c.log_level_pinned());
        assert_eq!(c.read(|s| s.log_level), Level::Error);
        // The window is the file's: what an earlier run logged is still there.
        assert!(!said(&c, Level::Debug, "detail two").is_empty());
    }

    #[test]
    fn a_failed_call_says_what_it_was_and_why() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        let code = c.new_pairing()["code"].as_str().unwrap().to_string();
        assert_eq!(c.pair(&pair_body(&code, "box-1", 7)).0, 200);
        let id = nerve_transport::keys::node_id(&[7; 32]);
        let route = Route {
            node_id: id.clone(),
            node_name: "box-1".into(),
            cap: "fs".into(),
            action: "read".into(),
            profile: "fs".into(),
            effect: nerve_proto::Effect::Read,
        };
        let took = Duration::from_millis(1500);
        let refusal = RpcError::forbidden("no allow rule matches /etc/hostname");
        c.log_failed_call(&route, &refusal, took);
        c.log_failed_call(
            &route,
            &RpcError::new(ErrorCode::Timeout, "the node did not answer in time"),
            Duration::from_secs(30),
        );
        c.log_failed_call(&route, &RpcError::internal("boom"), took);
        // Not a refusal, though the code is `unavailable`: the owner disabled it.
        c.set_disabled(&id, true).unwrap();
        c.log_failed_call(
            &route,
            &RpcError::new(
                ErrorCode::Unavailable,
                "the node box-1 is disabled in the center",
            ),
            took,
        );

        let got: Vec<(Level, String)> = lines(&c)
            .into_iter()
            .filter(|e| e.msg.starts_with("fs.read"))
            .map(|e| (e.level, e.msg))
            .collect();
        assert_eq!(
            got,
            [
                (
                    Level::Info,
                    "fs.read was refused (forbidden): no allow rule matches /etc/hostname"
                        .to_string()
                ),
                (
                    Level::Warn,
                    "fs.read failed (timeout) after 30 s: the node did not answer in time"
                        .to_string()
                ),
                (
                    Level::Error,
                    "fs.read failed (internal) after 1 s: boom".to_string()
                ),
                (
                    Level::Info,
                    "fs.read was refused (unavailable): the node box-1 is disabled in the center"
                        .to_string()
                ),
            ]
        );
    }

    #[test]
    fn a_button_only_adds_a_rule_to_its_list() {
        let mut d = json!({"policy": {"deny": ["exec.run:git push*"], "allow": ["exec.run:ls"]}});
        put_rule(&mut d, "allow", "exec.run:git *").unwrap();
        put_rule(&mut d, "allow", "exec.run:git *").unwrap();
        put_rule(&mut d, "deny", "exec.run:git *").unwrap();
        put_rule(&mut d, "sudo_allow", "sudo apt update").unwrap();
        // Nothing leaves the other list; a repeat adds nothing.
        assert_eq!(
            d["policy"],
            json!({
                "allow": ["exec.run:ls", "exec.run:git *"],
                "deny": ["exec.run:git push*", "exec.run:git *"],
                "sudo_allow": ["sudo apt update"],
            })
        );
        // A document without a policy gets one.
        let mut d = json!({});
        put_rule(&mut d, "deny", "camera").unwrap();
        assert_eq!(d["policy"]["deny"], json!(["camera"]));
        assert!(put_rule(&mut json!([]), "deny", "x").is_err());
        assert!(put_rule(&mut json!({"policy": {"deny": 1}}), "deny", "x").is_err());
        assert_eq!(policy_list("sudo").unwrap(), "sudo_allow");
        assert!(policy_list("permit").is_err());
    }

    #[test]
    fn audit_buttons_write_rules_for_every_action() {
        let rule = |list, cap, action, target, wild| audit_rule(list, cap, action, target, wild);
        assert_eq!(
            rule("allow", "exec", "run", "git status", false).unwrap(),
            "exec.run:git status"
        );
        assert_eq!(
            rule("allow", "exec", "run", "git status", true).unwrap(),
            "exec.run:git *"
        );
        assert_eq!(
            rule("deny", "exec", "run", "rm -rf /tmp/x", true).unwrap(),
            "exec.run:rm *"
        );
        assert_eq!(
            rule("allow", "fs", "read", "/home/u/a.txt", false).unwrap(),
            "fs.read:/home/u/a.txt"
        );
        assert_eq!(
            rule("deny", "fs", "write", "/home/u/a.txt", true).unwrap(),
            "fs.write:/home/u/*"
        );
        assert_eq!(
            rule("allow", "camera", "snap", "camera.snap", false).unwrap(),
            "camera.snap"
        );
        assert_eq!(
            rule("deny", "camera", "snap", "camera.snap", true).unwrap(),
            "camera"
        );
        assert_eq!(
            rule("sudo", "exec", "run", "sudo apt update", false).unwrap(),
            "sudo apt update"
        );
        assert_eq!(
            rule("sudo", "exec", "run", "sudo apt update", true).unwrap(),
            "sudo apt *"
        );
        for (list, cap, action, target) in [
            ("permit", "exec", "run", "ls"),
            ("allow", "exec", "run", "  "),
            ("allow", "fs", "read", ""),
            ("allow", "fs", "read", "relative/path"),
            ("sudo", "exec", "run", "ls"),
            ("sudo", "fs", "read", "/a"),
            ("allow", "", "run", "ls"),
        ] {
            assert!(
                rule(list, cap, action, target, false).is_err(),
                "{list} {cap}.{action} {target:?}"
            );
        }
        // A target the audit cut is not the command any more.
        let cut = nerve_policy::audit::cut_target(&"x".repeat(600)).into_owned();
        for list in ["allow", "deny", "sudo"] {
            assert!(rule(list, "exec", "run", &cut, false).is_err(), "{list}");
            assert!(rule(list, "exec", "run", &cut, true).is_err(), "{list}");
        }
    }
}
