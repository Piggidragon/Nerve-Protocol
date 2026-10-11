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
use nerve_policy::audit::{AuditLog, Entry};
use nerve_policy::{NodeConfig, SettingsStore};
use nerve_proto::Message;
use nerve_proto::msg::{Topic, method};
use nerve_sandbox::Confinement;
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
}

impl NodeOptions {
    pub fn new(paths: NodePaths) -> NodeOptions {
        NodeOptions {
            paths,
            exe: None,
            home: home_dir(),
            ctl: true,
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
pub(crate) struct Shared {
    pub paths: NodePaths,
    pub exe: Option<PathBuf>,
    pub home: PathBuf,
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
    /// The checked sudo password while the switch is on (crate::sudo).
    pub sudo: Mutex<Option<crate::sudo::Secret>>,
    /// Open sudo offers by center; each is opened at most once.
    pub sudo_offers: Mutex<HashMap<String, nerve_transport::sudo::Pending>>,
}

impl Shared {
    pub fn config(&self) -> NodeConfig {
        lock(&self.store).config().clone()
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
            }
            Ok(false) => {}
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
            tracing::warn!("cannot write the audit log: {err}");
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
            tracing::warn!("cannot save the config: {e}");
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
                    "user_until": c.policy.user_until,
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
        nerve_transport::init_crypto();
        let paths = opts.paths.clone();
        // Both exist before the first command runs, so Landlock can leave
        // them out by their real paths.
        for dir in [&paths.state_dir, &paths.config_dir] {
            nerve_transport::files::create_private_dir(dir)
                .map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        let store = SettingsStore::open(
            paths.config_file(),
            paths.config_key(),
            AuditLog::new(paths.audit_log()),
        )?;
        let cfg = store.config().clone();
        #[cfg(unix)]
        if nerve_transport::net::euid() == 0 && !cfg.machine.allow_root {
            return Err(
                "refusing to run as root; set machine.allow_root = true to allow it".into(),
            );
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
        let shared = Arc::new(Shared {
            paths: paths.clone(),
            exe: opts.exe,
            home: opts.home,
            confinement: Confinement::detect(),
            store: Mutex::new(store),
            changed,
            centers: Mutex::default(),
            commands: Mutex::default(),
            running: AtomicUsize::new(0),
            stop,
            sudo: Mutex::new(None),
            sudo_offers: Mutex::default(),
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
            "node daemon running ({} centers, confinement {})",
            cfg.centers.len(),
            shared.confinement.describe()
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
        self.shared.stop.send_replace(true);
        let _ = tokio::time::timeout(Duration::from_secs(5), self.supervisor).await;
        if let Some(c) = self.ctl {
            c.abort();
            let _ = std::fs::remove_file(self.shared.paths.ctl_socket());
        }
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
            tracing::warn!("the control socket stopped: {e}");
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
#[cfg(unix)]
const MUTATING: &[&str] = &[
    "config.write",
    "config.accept",
    "reload",
    "sudo.on",
    "sudo.off",
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
        lock(&s.commands).clear();
        let r = control(&s, "config.write", write, Some(me));
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
