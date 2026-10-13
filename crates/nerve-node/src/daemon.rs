//! The node daemon (`nerve-node run`): one link task per paired center and
//! the control socket the CLI talks to.

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

#[cfg(unix)]
use nerve_policy::SetError;
use nerve_policy::audit::{AuditLog, Change, Entry, diff};
use nerve_policy::{NodeConfig, SettingsStore};
use nerve_proto::Message;
use nerve_proto::msg::{Topic, method};
use nerve_sandbox::Confinement;
use nerve_transport::log::{Level, Log};
use nerve_transport::ws::WsMessage;

use crate::descriptor::IMPLICIT;
use crate::paths::{NodePaths, home_dir};

/// How a daemon runs.
#[derive(Debug, Clone)]
pub struct NodeOptions {
    pub paths: NodePaths,
    /// The `nerve-node` binary that hosts the exec shim. Without it commands
    /// run unconfined (and `folder` mode refuses them).
    pub exe: Option<PathBuf>,
    /// The owner's home: the default `cwd` and the root of the protected list.
    pub home: PathBuf,
    /// Serve the control socket (the CLI's way in).
    pub ctl: bool,
    /// The log to write to: the process's, when `nerve_transport::log::install`
    /// ran. The daemon adds the file in the state folder and sets the level
    /// from `node.toml`.
    pub log: Option<Arc<Log>>,
}

impl NodeOptions {
    pub fn new(paths: NodePaths) -> NodeOptions {
        NodeOptions {
            paths,
            exe: None,
            home: home_dir(),
            ctl: true,
            log: nerve_transport::log::global(),
        }
    }
}

/// Locks a std mutex, shrugging off poisoning: every holder keeps its state
/// consistent before anything can panic.
pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// The sending side of one live link, shared with the calls running on it.
pub(crate) struct LinkHandle {
    pub tx: mpsc::Sender<WsMessage>,
    subs: Mutex<Subs>,
}

#[derive(Default)]
struct Subs {
    topics: BTreeSet<Topic>,
    /// `seq` per capability, counting from 1 on this link.
    seq: HashMap<String, u64>,
}

impl LinkHandle {
    pub fn new(tx: mpsc::Sender<WsMessage>) -> LinkHandle {
        LinkHandle {
            tx,
            subs: Mutex::default(),
        }
    }

    pub fn sub(&self, topics: Vec<Topic>, on: bool) {
        let mut s = lock(&self.subs);
        for t in topics {
            if on {
                s.topics.insert(t);
            } else {
                s.topics.remove(&t);
            }
        }
    }

    fn next_seq(s: &mut Subs, cap: &str) -> u64 {
        let n = s.seq.entry(cap.to_string()).or_insert(0);
        *n += 1;
        *n
    }

    /// Sends `cap/name` if it is implicit or subscribed. Events never wait
    /// for room: when the send queue is full the event is dropped and logged.
    pub fn event(&self, cap: &str, name: &str, data: Value) {
        let mut s = lock(&self.subs);
        let wanted = IMPLICIT.contains(&cap)
            || s.topics.contains(&Topic::Event(cap.into(), name.into()))
            || s.topics.contains(&Topic::All(cap.into()));
        if !wanted {
            return;
        }
        let seq = Self::next_seq(&mut s, cap);
        let m = Message::notification(
            method::EVENT,
            json!({"cap": cap, "name": name, "seq": seq, "ts": crate::now_ms(), "data": data}),
        );
        if self.tx.try_send(WsMessage::text(m.encode())).is_err() {
            tracing::warn!("event {cap}/{name} dropped: the link's send queue is full");
        }
    }

    /// Sends a `state` change if subscribed (implicit for the implicit caps).
    pub fn state(&self, cap: &str, changed: Value) {
        let mut s = lock(&self.subs);
        let wanted = IMPLICIT.contains(&cap)
            || s.topics.contains(&Topic::State(cap.into()))
            || s.topics.contains(&Topic::All(cap.into()));
        if !wanted {
            return;
        }
        let seq = Self::next_seq(&mut s, cap);
        let m = Message::notification(
            method::STATE,
            json!({"cap": cap, "seq": seq, "ts": crate::now_ms(), "changed": changed}),
        );
        let _ = self.tx.try_send(WsMessage::text(m.encode()));
    }
}

/// What the node keeps per center across links.
pub(crate) struct CenterState {
    pub link: Mutex<Option<Arc<LinkHandle>>>,
    pub status: Mutex<String>,
}

impl CenterState {
    pub fn set_status(&self, s: impl Into<String>) {
        *lock(&self.status) = s.into();
    }

    pub fn link(&self) -> Option<Arc<LinkHandle>> {
        lock(&self.link).clone()
    }
}

/// Everything the daemon's tasks share.
/// How long a looked-up account is used before it is looked up again.
const ACCOUNT_FRESH: std::time::Duration = std::time::Duration::from_secs(5);

pub(crate) struct Shared {
    pub paths: NodePaths,
    /// Whether this is the installed service (crate::service::is_service_node).
    pub service: bool,
    pub exe: Option<PathBuf>,
    pub home: PathBuf,
    /// Which protected list applies, and where its system folders are.
    pub platform: nerve_policy::protected::Platform,
    pub confinement: Confinement,
    pub store: Mutex<SettingsStore>,
    /// Ticks whenever the config may have changed; links re-check their
    /// center, the supervisor its link tasks.
    pub changed: watch::Sender<u64>,
    pub centers: Mutex<HashMap<String, Arc<CenterState>>>,
    /// pid → center of every command running now.
    pub commands: Mutex<HashMap<u32, String>>,
    /// Commands running now, over all centers (`limits.max_running`).
    pub running: AtomicUsize,
    pub stop: watch::Sender<bool>,
    /// The log, to keep the sudo password out of it.
    pub log: Option<Arc<Log>>,
    /// The checked sudo password while the switch is on (crate::sudo).
    pub sudo: Mutex<Option<crate::sudo::Secret>>,
    /// Open sudo offers by center; each is opened at most once.
    pub sudo_offers: Mutex<HashMap<String, nerve_transport::sudo::Pending>>,
    /// The account sudo's password was checked for (crate::sudo): the
    /// switch holds only for that account.
    pub sudo_for: Mutex<Option<String>>,
    /// The last account looked up for `machine.user`, and when: every call
    /// of a center needs it, and a lookup starts two programs.
    pub account_cache: Mutex<Option<(String, std::time::Instant, Option<crate::service::Account>)>>,
}

impl Shared {
    pub fn config(&self) -> NodeConfig {
        lock(&self.store).config().clone()
    }

    /// The account a command and the sudo switch run as (crate::account);
    /// `None` runs them as the node's own user.
    pub fn command_account(
        &self,
        cfg: &NodeConfig,
    ) -> Result<Option<crate::service::Account>, String> {
        let cached = |name: &str| {
            if let Some((n, at, a)) = lock(&self.account_cache).as_ref()
                && n == name
                && at.elapsed() < ACCOUNT_FRESH
            {
                return Ok(a.clone());
            }
            let a = crate::account::lookup(name)?;
            *lock(&self.account_cache) =
                Some((name.to_string(), std::time::Instant::now(), a.clone()));
            Ok(a)
        };
        crate::account::for_commands(
            cfg.machine.user.as_deref(),
            nerve_transport::net::euid(),
            self.service,
            crate::account::can_switch(),
            cached,
        )
    }

    /// The `~` of the rules and the protected list: the home of the account
    /// the commands run as, else the node's own.
    pub fn rules_home(&self, cfg: &NodeConfig) -> PathBuf {
        match self.command_account(cfg) {
            Ok(Some(a)) => a.home,
            _ => self.home.clone(),
        }
    }

    pub fn bump(&self) {
        self.changed.send_modify(|v| *v += 1);
    }

    /// Reads the config file again because the owner asked (SIGHUP, the
    /// control socket). Nothing else rereads it: the node keeps its config
    /// in memory, and a file it did not sign is refused.
    pub fn reload(&self) -> Result<bool, String> {
        let r = lock(&self.store).reload();
        match &r {
            Ok(true) => {
                // A signed file may say sudo on without a password held.
                self.settle_sudo();
                self.bump();
                tracing::info!("node.toml was read again and has changed");
            }
            Ok(false) => tracing::debug!("node.toml was read again; nothing changed"),
            Err(e) => tracing::warn!("reload refused, the old config stays: {e}"),
        }
        r
    }

    /// Whether commands may run confined (Landlock and the shim's host).
    pub fn confined(&self) -> bool {
        self.confinement.available() && self.exe.is_some()
    }

    pub fn center(&self, name: &str) -> Arc<CenterState> {
        lock(&self.centers)
            .entry(name.to_string())
            .or_insert_with(|| {
                Arc::new(CenterState {
                    link: Mutex::new(None),
                    status: Mutex::new("not connected".into()),
                })
            })
            .clone()
    }

    /// Sends an event to `center`'s link.
    pub fn emit(&self, center: &str, cap: &str, name: &str, data: Value) {
        if let Some(l) = lock(&self.centers).get(center).and_then(|c| c.link()) {
            l.event(cap, name, data);
        }
    }

    /// Records a decision in the local log and tells the center (if it
    /// subscribed to `audit/decision`).
    pub fn audit(&self, e: &Entry) {
        let mut e = e.clone();
        e.target = self.scrub(e.target);
        e.decision = self.scrub(e.decision);
        let e = &e;
        if let Err(err) = lock(&self.store).audit().decision(e) {
            tracing::error!("the audit log cannot be written: {err}");
        }
        self.emit(&e.center, "audit", "decision", e.event_data());
    }

    /// Marks bookkeeping on a center (revoked, unknown) and tells everyone.
    pub fn mark_center(&self, name: &str, f: impl FnOnce(&mut nerve_policy::CenterEntry)) {
        let r = lock(&self.store).mark(|c| {
            if let Some(e) = c.center_mut(name) {
                f(e);
            }
        });
        if let Err(e) = r {
            tracing::error!("cannot save the config: {e}");
        }
        self.bump();
    }

    // Only the Unix control socket asks this; Windows has none yet.
    /// Whether `pid` runs below a command the node started for a center: such
    /// a process must not change the node's settings.
    #[cfg_attr(not(unix), allow(dead_code))]
    pub fn below_command(&self, pid: Option<u32>) -> bool {
        let commands = lock(&self.commands);
        if commands.is_empty() {
            return false;
        }
        match pid {
            Some(pid) => commands
                .keys()
                .any(|&c| nerve_transport::ctl::descends_from(pid, c)),
            // Without the peer's pid the node cannot tell; refuse while
            // commands run.
            None => true,
        }
    }

    pub fn status(&self) -> Value {
        let cfg = self.config();
        let now = crate::now_ms();
        let centers: Vec<Value> = cfg
            .centers
            .iter()
            .map(|c| {
                let cs = lock(&self.centers).get(&c.name).cloned();
                let status = match &cs {
                    Some(cs) => lock(&cs.status).clone(),
                    None => "not connected".to_string(),
                };
                json!({
                    "name": c.name,
                    "url": c.url,
                    "status": status,
                    "mode": c.policy.mode_at(now).as_str(),
                    "until": c.policy.until,
                    "settings": c.settings,
                    "paused": c.paused,
                    "revoked": c.revoked,
                    "unknown": c.unknown,
                })
            })
            .collect();
        json!({
            "version": cfg.version,
            "locked": cfg.locked,
            "confinement": self.confinement.describe(),
            "running": self.running.load(Ordering::Relaxed),
            "sudo": if self.sudo_on() { "on" } else { "off" },
            "centers": centers,
        })
    }
}

/// A running node daemon.
pub struct Daemon {
    shared: Arc<Shared>,
    supervisor: JoinHandle<()>,
    ctl: Option<JoinHandle<()>>,
}

impl Daemon {
    /// Starts the daemon: loads the config, serves the control socket, dials
    /// every center that is not paused, revoked or unknown.
    pub async fn start(opts: NodeOptions) -> Result<Daemon, String> {
        Daemon::start_with(opts, crate::rights::full_rights()).await
    }

    /// [`Daemon::start`] for a process whose rights are `full_rights`: root,
    /// or an elevated token on Windows. A test cannot be root.
    async fn start_with(opts: NodeOptions, full_rights: bool) -> Result<Daemon, String> {
        nerve_transport::init_crypto();
        let paths = opts.paths.clone();
        // Both exist before the first command runs, so Landlock can leave
        // them out by their real paths.
        for dir in [&paths.state_dir, &paths.config_dir] {
            nerve_transport::files::create_private_dir(dir)
                .map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        let mut store = SettingsStore::open(
            paths.config_file(),
            paths.config_key(),
            AuditLog::new(paths.audit_log()),
        )?;
        let cfg = store.config().clone();
        if let Some(log) = &opts.log {
            log.set_level(cfg.log.level);
            // The node runs without a log file it cannot open; stderr and the
            // service manager still have the lines.
            if let Err(e) = log.attach_file(paths.log_file()) {
                eprintln!("cannot open the log {}: {e}", paths.log_file().display());
            }
        }
        store.on_change(|by, version, changes| {
            nerve_transport::log::emit(Level::Info, None, &describe_change(by, version, changes));
        });
        if let Some(warning) = crate::rights::check(full_rights, cfg.machine.allow_root)? {
            tracing::warn!("{warning}");
        }
        #[cfg(unix)]
        if opts.ctl
            && nerve_transport::ctl::call(&paths.ctl_socket(), "status", json!({}))
                .await
                .is_ok()
        {
            return Err("a node daemon already runs for this state directory".into());
        }
        let (changed, _) = watch::channel(0);
        let (stop, _) = watch::channel(false);
        let service = crate::service::is_service_node(&paths);
        #[cfg(unix)]
        if service && nerve_transport::net::euid() != 0 && !crate::account::can_switch() {
            tracing::warn!(
                "this is the installed node, started without CAP_SETUID and CAP_SETGID: it runs no command; start it as the service: `sudo systemctl start nerve-node`"
            );
        }
        let shared = Arc::new(Shared {
            paths: paths.clone(),
            service,
            exe: opts.exe,
            home: opts.home,
            platform: crate::paths::platform(),
            confinement: Confinement::detect(),
            store: Mutex::new(store),
            changed,
            centers: Mutex::default(),
            commands: Mutex::default(),
            running: AtomicUsize::new(0),
            stop,
            log: opts.log,
            sudo: Mutex::new(None),
            sudo_offers: Mutex::default(),
            sudo_for: Mutex::default(),
            account_cache: Mutex::default(),
        });
        // The password lives in memory only: a file that says on starts off.
        shared.settle_sudo();
        let ctl = if opts.ctl {
            Some(start_ctl(shared.clone()).await?)
        } else {
            None
        };
        let supervisor = tokio::spawn(supervise(shared.clone()));
        tracing::info!(
            "node daemon running (nerve-node {}, {} centers, confinement {}, log level {})",
            crate::descriptor::VERSION,
            cfg.centers.len(),
            shared.confinement.describe(),
            cfg.log.level
        );
        Ok(Daemon {
            shared,
            supervisor,
            ctl,
        })
    }

    pub fn paths(&self) -> &NodePaths {
        &self.shared.paths
    }

    /// The log the daemon writes to, if it was given one.
    pub fn log(&self) -> Option<&Arc<Log>> {
        self.shared.log.as_ref()
    }

    /// The config as the daemon holds it now.
    pub fn config(&self) -> NodeConfig {
        self.shared.config()
    }

    /// What `nerve-node status` shows.
    pub fn status(&self) -> Value {
        self.shared.status()
    }

    /// Reads the config file again (what SIGHUP does). Only a file the node
    /// signed is applied; any other is refused and the old config stays.
    pub fn reload(&self) -> Result<bool, String> {
        self.shared.reload()
    }

    /// Ends every link with `bye shutdown` and stops.
    pub async fn stop(self) {
        tracing::info!("node daemon stopping");
        self.shared.stop.send_replace(true);
        let _ = tokio::time::timeout(Duration::from_secs(5), self.supervisor).await;
        if let Some(c) = self.ctl {
            c.abort();
            let _ = std::fs::remove_file(self.shared.paths.ctl_socket());
        }
        tracing::info!("node daemon stopped");
    }

    /// Runs until SIGINT or SIGTERM; SIGHUP reloads the config.
    pub async fn run(opts: NodeOptions) -> Result<(), String> {
        let d = Daemon::start(opts).await?;
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let mut term = signal(SignalKind::terminate()).map_err(|e| e.to_string())?;
            let mut hup = signal(SignalKind::hangup()).map_err(|e| e.to_string())?;
            loop {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => break,
                    _ = term.recv() => break,
                    _ = hup.recv() => {
                        let _ = d.reload();
                    }
                }
            }
        }
        #[cfg(not(unix))]
        let _ = tokio::signal::ctrl_c().await;
        d.stop().await;
        Ok(())
    }
}

/// Keeps one link task per center that should be linked. It works from the
/// config in memory: the file is not reread here, so a file changed behind
/// the node's back changes nothing (only the owner's reload reads it).
async fn supervise(shared: Arc<Shared>) {
    let mut tasks: HashMap<String, JoinHandle<()>> = HashMap::new();
    let mut changed = shared.changed.subscribe();
    let mut stop = shared.stop.subscribe();
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        shared.settle_sudo();
        let cfg = shared.config();
        // The level follows the config, whoever changed it and however.
        if let Some(log) = &shared.log {
            log.set_level(cfg.log.level);
        }
        tasks.retain(|_, t| !t.is_finished());
        if !cfg.locked {
            for c in cfg.centers.iter().filter(|c| c.dials()) {
                if !tasks.contains_key(&c.name) {
                    let t = tokio::spawn(crate::link::run_center(shared.clone(), c.name.clone()));
                    tasks.insert(c.name.clone(), t);
                }
            }
        }
        lock(&shared.centers).retain(|n, _| cfg.center(n).is_some());
        changed.borrow_and_update();
        tokio::select! {
            _ = tick.tick() => {}
            _ = changed.changed() => {}
            _ = stop.changed() => break,
        }
    }
    // Each link task sends its `bye shutdown` and ends.
    for (_, t) in tasks {
        let _ = tokio::time::timeout(Duration::from_secs(3), t).await;
    }
}

#[cfg(unix)]
async fn start_ctl(shared: Arc<Shared>) -> Result<JoinHandle<()>, String> {
    let path = shared.paths.ctl_socket();
    if let Some(dir) = path.parent() {
        nerve_transport::files::create_private_dir(dir)
            .map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    // Fails early when another daemon holds the socket.
    let listener = nerve_transport::ctl::bind(&path)
        .await
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let s = shared.clone();
    let task = tokio::spawn(async move {
        let r = nerve_transport::ctl::serve_on(listener, move |req, peer| {
            let s = s.clone();
            async move {
                match req.method.as_str() {
                    // Checking the password runs `sudo -v`, so it cannot
                    // block inside `control`.
                    "sudo.on" => sudo_on(&s, req.params, peer.pid).await,
                    m => control(&s, m, req.params, peer.pid),
                }
            }
        })
        .await;
        if let Err(e) = r {
            tracing::error!("the control socket stopped: {e}");
        }
    });
    // The socket is bound already, so a CLI started right after finds the
    // daemon.
    Ok(task)
}

#[cfg(not(unix))]
async fn start_ctl(_shared: Arc<Shared>) -> Result<JoinHandle<()>, String> {
    // Not done in 0.0.1: a named pipe. The CLI writes the signed file itself,
    // and the running node takes it at its next start.
    Ok(tokio::spawn(async {}))
}

/// Methods that change something: refused from below a center's command.
/// `owner.check` changes nothing itself: the CLI asks it before `install`,
/// `setup`, `update` and `uninstall`, which change the node.
#[cfg(unix)]
const MUTATING: &[&str] = &[
    "config.write",
    "config.accept",
    "reload",
    "sudo.on",
    "sudo.off",
    "owner.check",
];

/// `sudo.on {password}`: the CLI on this machine turns the switch on. The
/// socket is the owner's only, so the password travels in the clear here.
#[cfg(unix)]
async fn sudo_on(
    shared: &Arc<Shared>,
    params: Value,
    pid: Option<u32>,
) -> nerve_transport::ctl::Reply {
    use nerve_transport::ctl::Reply;
    if shared.below_command(pid) {
        return Reply::Err(
            "refused: this request comes from a command the node runs for a center".into(),
        );
    }
    let Some(password) = params.get("password").and_then(Value::as_str) else {
        return Reply::Err("password is missing".into());
    };
    match shared
        .sudo_switch_on(nerve_policy::Writer::Local, password.to_string())
        .await
    {
        Ok(v) => Reply::Ok(json!({"sudo": "on", "version": v})),
        Err(e) => Reply::Err(e.to_string()),
    }
}

/// One control-socket request.
#[cfg(unix)]
pub(crate) fn control(
    shared: &Arc<Shared>,
    method: &str,
    params: Value,
    pid: Option<u32>,
) -> nerve_transport::ctl::Reply {
    use nerve_transport::ctl::Reply;
    if MUTATING.contains(&method) && shared.below_command(pid) {
        return Reply::Err(
            "refused: this request comes from a command the node runs for a center".into(),
        );
    }
    let str_of = |k: &str| params.get(k).and_then(Value::as_str).map(str::to_string);
    match method {
        "status" => Reply::Ok(shared.status()),
        "owner.check" => Reply::Ok(json!({})),
        "sudo.status" => Reply::Ok(json!({"sudo": if shared.sudo_on() { "on" } else { "off" }})),
        "sudo.off" => match shared.sudo_switch_off(nerve_policy::Writer::Local) {
            Ok(v) => Reply::Ok(json!({"sudo": "off", "version": v})),
            Err(e) => Reply::Err(e.to_string()),
        },
        "config.read" => {
            let s = lock(&shared.store);
            Reply::Ok(json!({"config": s.config().to_toml(), "version": s.version()}))
        }
        "config.write" => {
            let Some(text) = str_of("config") else {
                return Reply::Err("config is missing".into());
            };
            let new = match NodeConfig::parse(&text) {
                Ok(c) => c,
                Err(e) => return Reply::Err(e),
            };
            let if_version = params.get("if_version").and_then(Value::as_u64);
            let mut store = lock(&shared.store);
            if new.machine.sudo != store.config().machine.sudo {
                return Reply::Err(
                    "machine.sudo changes only through nerve-node sudo on|off".into(),
                );
            }
            let r = store.set_local(new, if_version);
            drop(store);
            match r {
                Ok(v) => {
                    shared.bump();
                    Reply::Ok(json!({"version": v}))
                }
                Err(SetError::Conflict { current }) => {
                    Reply::Err(format!("conflict: the config changed (version {current})"))
                }
                Err(e) => Reply::Err(e.to_string()),
            }
        }
        "config.accept" => {
            let r = lock(&shared.store).accept();
            match r {
                Ok(v) => {
                    shared.settle_sudo();
                    shared.bump();
                    Reply::Ok(json!({"version": v}))
                }
                Err(e) => Reply::Err(e.to_string()),
            }
        }
        "reload" => match shared.reload() {
            Ok(changed) => Reply::Ok(json!({"changed": changed})),
            Err(e) => Reply::Err(e),
        },
        other => Reply::Err(format!("unknown method {other}")),
    }
}

/// Settings whose values are not told in the log, only that they changed.
fn is_quiet_key(key: &str) -> bool {
    key.starts_with("connection") || key.ends_with(".pin") || key.ends_with("_id")
}

/// A value as the log tells it: a word or a number plainly, anything longer
/// cut.
fn show_value(v: &Value) -> String {
    let text = match v {
        Value::Null => "unset".to_string(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    clip(&text, 80)
}

fn clip(text: &str, max: usize) -> String {
    match text.char_indices().nth(max) {
        Some((end, _)) => format!("{}…", &text[..end]),
        None => text.to_string(),
    }
}

/// The entries of a list setting. A list that is empty is not in the file, so
/// an unset one is an empty list.
fn list_of(v: &Value) -> Option<&[Value]> {
    match v {
        Value::Array(a) => Some(a),
        Value::Null => Some(&[]),
        _ => None,
    }
}

/// What a changed leaf of the settings says: both values of a plain setting,
/// what a list gained and lost, and for a secret-bearing one only its name.
fn describe_leaf(key: &str, old: &Value, new: &Value) -> String {
    if is_quiet_key(key) {
        return format!("{key} changed");
    }
    let is_list = |v: &Value| matches!(v, Value::Array(_));
    if is_list(old) || is_list(new) {
        let (Some(o), Some(n)) = (list_of(old), list_of(new)) else {
            return format!("{key} changed");
        };
        let mut out = key.to_string();
        for v in n.iter().filter(|v| !o.contains(v)) {
            out.push_str(&format!(" +{}", show_value(v)));
        }
        for v in o.iter().filter(|v| !n.contains(v)) {
            out.push_str(&format!(" -{}", show_value(v)));
        }
        return out;
    }
    match (old, new) {
        (Value::Object(_), _) | (_, Value::Object(_)) => format!("{key} changed"),
        (o, n) => format!("{key}: {} -> {}", show_value(o), show_value(n)),
    }
}

/// A change to the settings, for the log: who, the version it made, and each
/// setting that differs. The paired centers are a list, so one is looked into
/// by its name; a center that came or went is told by its name alone.
fn describe_change(by: &str, version: u64, changes: &[Change]) -> String {
    let named = |v: &Value| -> std::collections::BTreeMap<String, Value> {
        v.as_array()
            .into_iter()
            .flatten()
            .filter_map(|c| Some((c.get("name")?.as_str()?.to_string(), c.clone())))
            .collect()
    };
    let mut told = Vec::new();
    for c in changes {
        if c.key != "center" {
            told.push(describe_leaf(&c.key, &c.old, &c.new));
            continue;
        }
        let (old, new) = (named(&c.old), named(&c.new));
        for (name, n) in &new {
            match old.get(name) {
                None => told.push(format!("center {name} was added")),
                Some(o) => {
                    for d in diff(o, n) {
                        told.push(describe_leaf(
                            &format!("center.{name}.{}", d.key),
                            &d.old,
                            &d.new,
                        ));
                    }
                }
            }
        }
        for name in old.keys().filter(|n| !new.contains_key(*n)) {
            told.push(format!("center {name} was removed"));
        }
    }
    format!(
        "settings changed by {by} (version {version}): {}",
        told.join("; ")
    )
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    async fn daemon() -> (tempfile::TempDir, Daemon) {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("config"), d.path().join("state"));
        let mut opts = NodeOptions::new(paths);
        opts.home = d.path().to_path_buf();
        (d, Daemon::start(opts).await.unwrap())
    }

    fn options(d: &tempfile::TempDir, log: &Arc<Log>) -> NodeOptions {
        let paths = NodePaths::new(d.path().join("config"), d.path().join("state"));
        let mut opts = NodeOptions::new(paths);
        opts.home = d.path().to_path_buf();
        opts.ctl = false;
        opts.log = Some(log.clone());
        opts
    }

    fn warnings(log: &Log) -> Vec<String> {
        let q = nerve_transport::log::Query {
            limit: usize::MAX,
            ..Default::default()
        };
        log.entries(&q)
            .into_iter()
            .filter(|(_, e)| e.level == Level::Warn)
            .map(|(_, e)| e.msg)
            .collect()
    }

    /// A node with full rights (root, or an elevated token) is refused
    /// without `machine.allow_root`, and warned about in the log with it.
    #[tokio::test]
    async fn full_rights_are_refused_without_allow_root_and_warned_about_with_it() {
        use tracing_subscriber::layer::SubscriberExt;
        let log = Log::new(Level::Info);
        let sub = tracing_subscriber::Registry::default().with(log.layer());
        let _guard = tracing::subscriber::set_default(sub);
        let d = tempfile::tempdir().unwrap();

        let err = Daemon::start_with(options(&d, &log), true).await.err();
        assert_eq!(err.as_deref(), Some(crate::rights::REFUSED));
        assert!(warnings(&log).is_empty());

        let paths = NodePaths::new(d.path().join("config"), d.path().join("state"));
        for dir in [&paths.state_dir, &paths.config_dir] {
            nerve_transport::files::create_private_dir(dir).unwrap();
        }
        let mut store = SettingsStore::open(
            paths.config_file(),
            paths.config_key(),
            AuditLog::new(paths.audit_log()),
        )
        .unwrap();
        store
            .update(|c| {
                c.machine.allow_root = true;
                Ok(())
            })
            .unwrap();
        let daemon = Daemon::start_with(options(&d, &log), true).await.unwrap();
        let w = warnings(&log);
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("full rights") && w[0].contains("You are responsible"));
        // The warning also reaches the node's log file.
        let file = std::fs::read_to_string(paths.log_file()).unwrap();
        assert!(file.contains("You are responsible"), "{file}");
        daemon.stop().await;

        // A node without full rights is not asked anything.
        let log = Log::new(Level::Info);
        let d = tempfile::tempdir().unwrap();
        let daemon = Daemon::start_with(options(&d, &log), false).await.unwrap();
        assert!(warnings(&log).is_empty());
        daemon.stop().await;
    }

    #[tokio::test]
    async fn refuses_settings_from_below_a_command() {
        let (_d, daemon) = daemon().await;
        let s = daemon.shared.clone();
        let me = std::process::id();
        let read = control(&s, "config.read", json!({}), Some(me));
        let nerve_transport::ctl::Reply::Ok(v) = read else {
            panic!("config.read failed")
        };
        let write = json!({"config": v["config"], "if_version": v["version"]});
        // This process stands in for a command the node started.
        lock(&s.commands).insert(me, "home".into());
        let r = control(&s, "config.write", write.clone(), Some(me));
        assert!(matches!(r, nerve_transport::ctl::Reply::Err(e) if e.starts_with("refused")));
        let r = control(&s, "status", json!({}), Some(me));
        assert!(matches!(r, nerve_transport::ctl::Reply::Ok(_)));
        // What install, setup, update and uninstall ask first.
        let r = control(&s, "owner.check", json!({}), Some(me));
        assert!(matches!(r, nerve_transport::ctl::Reply::Err(e) if e.starts_with("refused")));
        lock(&s.commands).clear();
        let r = control(&s, "config.write", write, Some(me));
        assert!(matches!(r, nerve_transport::ctl::Reply::Ok(_)));
        let r = control(&s, "owner.check", json!({}), Some(me));
        assert!(matches!(r, nerve_transport::ctl::Reply::Ok(_)));
        daemon.stop().await;
    }

    #[tokio::test]
    async fn second_daemon_is_refused_and_ctl_answers() {
        let (d, daemon) = daemon().await;
        let paths = daemon.paths().clone();
        let v = nerve_transport::ctl::call(&paths.ctl_socket(), "status", json!({}))
            .await
            .unwrap();
        assert_eq!(v["locked"], false);
        let mut opts = NodeOptions::new(paths.clone());
        opts.home = d.path().to_path_buf();
        assert!(Daemon::start(opts).await.is_err());
        daemon.stop().await;
        assert!(!paths.ctl_socket().exists());
    }
}

#[cfg(test)]
mod change_tests {
    use super::*;

    /// What the log says when `old` becomes `new`, as the settings store
    /// would report it.
    fn told(old: &str, new: &str) -> String {
        let json = |t: &str| {
            let mut v = serde_json::to_value(NodeConfig::parse(t).unwrap()).unwrap();
            v.as_object_mut().unwrap().remove("version");
            v
        };
        describe_change("local", 7, &diff(&json(old), &json(new)))
    }

    const CENTER: &str = r#"
[[center]]
name = "lab"
url = "https://lab.example:7443"
pin = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
center_id = "c1"
node_id = "n1"
"#;

    #[test]
    fn a_change_to_the_settings_is_told_by_what_changed() {
        let with = |policy: &str| format!("{CENTER}[center.policy]\n{policy}\n");
        // A plain value, both ways round.
        assert_eq!(
            told(&with("mode = \"allowlist\""), &with("mode = \"folder\"")),
            "settings changed by local (version 7): center.lab.policy.mode: allowlist -> folder"
        );
        // A list says what it gained and lost; an empty list is not in the file.
        assert_eq!(
            told(&with(""), &with("allow = [\"fs.read:~/notes/*\"]")),
            "settings changed by local (version 7): center.lab.policy.allow +fs.read:~/notes/*"
        );
        assert_eq!(
            told(
                &with("allow = [\"a\", \"b\"]"),
                &with("allow = [\"b\", \"c\"]")
            ),
            "settings changed by local (version 7): center.lab.policy.allow +c -a"
        );
        assert_eq!(
            told(&with("deny = [\"x\"]"), &with("")),
            "settings changed by local (version 7): center.lab.policy.deny -x"
        );
        // Several at once, and a machine setting.
        assert_eq!(
            told(
                &format!("{CENTER}[machine]\nsudo = \"off\"\n"),
                &format!("[machine]\nsudo = \"on\"\n{CENTER}[center.policy]\nuntil = 5\n")
            ),
            "settings changed by local (version 7): center.lab.policy.until: unset -> 5; machine.sudo: off -> on"
        );
    }

    #[test]
    fn a_center_that_comes_or_goes_is_named_and_nothing_else_of_it() {
        assert_eq!(
            told("", CENTER),
            "settings changed by local (version 7): center lab was added"
        );
        assert_eq!(
            told(CENTER, ""),
            "settings changed by local (version 7): center lab was removed"
        );
        let text = told(CENTER, &CENTER.replace("c1", "c2").replace("AAAA", "BBBB"));
        // Its id and pin are told as changed, never shown.
        assert_eq!(
            text,
            "settings changed by local (version 7): center.lab.center_id changed; center.lab.pin changed"
        );
    }

    #[test]
    fn the_proxy_is_never_shown() {
        let a = "[connection]\nproxy = \"http://one.example:3128\"\nheaders = [\"X-Key\"]\n";
        let b = "[connection]\nproxy = \"http://two.example:3128\"\nheaders = [\"X-Other\"]\n";
        let text = told(a, b);
        assert_eq!(
            text,
            "settings changed by local (version 7): connection.headers changed; connection.proxy changed"
        );
        assert!(!text.contains("example") && !text.contains("X-"), "{text}");
    }

    #[test]
    fn a_long_value_is_cut() {
        let long = "x".repeat(300);
        let text = describe_leaf("a.b", &Value::Null, &Value::String(long));
        assert_eq!(text.chars().count(), "a.b: unset -> ".len() + 81);
        assert!(text.ends_with('…'));
    }
}
