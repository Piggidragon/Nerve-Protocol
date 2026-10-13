//! The node as a service (docs/user/service.md): `install`, `update` and
//! `uninstall`, on Linux with systemd. The service runs `nerve-node run`
//! under a user of its own, `nerve`, which owns the node's config and state
//! folders. The owner's commands reach that node with `sudo nerve-node …`:
//! a command root runs on folders that belong to another user runs as that
//! user ([`become_owner`]), so whatever it writes stays the node's.
//!
//! What these commands do to the machine beyond the node's files (the user,
//! systemd, running a program) goes through [`System`], so the tests run
//! every step on temporary folders.

use std::io::Write;
use std::path::{Path, PathBuf};

use nerve_policy::audit::AuditLog;

use crate::paths::NodePaths;

/// The user the service runs as.
pub const USER: &str = "nerve";
/// The comment `install` gives that user. A `nerve` user without it was not
/// made by `install`: install does not take it over, uninstall leaves it.
pub const USER_MARK: &str = "Nerve node";
/// The systemd unit.
pub const UNIT_NAME: &str = "nerve-node.service";
/// The largest program `update` downloads.
const PROGRAM_MAX: usize = 256 * 1024 * 1024;
/// The largest `SHA256SUMS` `update` downloads.
const SUMS_MAX: usize = 64 * 1024;

/// Where an installed node lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    /// The systemd unit file.
    pub unit: PathBuf,
    /// The program the service runs.
    pub bin: PathBuf,
    /// The home of the service's user: a command's working folder when the
    /// call names none, and the `~` of the protected list. It holds the
    /// state folder.
    pub home: PathBuf,
    pub paths: NodePaths,
    /// Where `update` finds the programs of the latest release and their
    /// `SHA256SUMS`.
    pub release: String,
}

impl Layout {
    /// The places on this machine.
    pub fn system() -> Layout {
        Layout {
            unit: PathBuf::from("/etc/systemd/system").join(UNIT_NAME),
            bin: "/usr/local/bin/nerve-node".into(),
            home: "/var/lib/nerve".into(),
            paths: NodePaths::new("/etc/nerve", "/var/lib/nerve/state"),
            release: concat!(env!("CARGO_PKG_REPOSITORY"), "/releases/latest/download").into(),
        }
    }

    /// Whether `install` put the node here: its unit is in place.
    pub fn installed(&self) -> bool {
        cfg!(target_os = "linux") && self.unit.is_file()
    }

    /// The service unit. The node runs as its own user with the folders
    /// given; stopping the service ends every command it runs, and a node
    /// that fails is started again.
    pub fn unit_text(&self) -> String {
        format!(
            "# Written by `nerve-node install`; `nerve-node uninstall` removes it.
[Unit]
Description=Nerve node
Documentation={repo}
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User={USER}
Group={USER}
Environment=HOME={home}
ExecStart={bin} --config-dir {config} --state-dir {state} run
ExecReload=kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
UMask=0077

[Install]
WantedBy=multi-user.target
",
            repo = env!("CARGO_PKG_REPOSITORY"),
            home = self.home.display(),
            bin = self.bin.display(),
            config = self.paths.config_dir.display(),
            state = self.paths.state_dir.display(),
        )
    }
}

/// A user account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub uid: u32,
    pub gid: u32,
    /// The comment field, where [`USER_MARK`] goes.
    pub comment: String,
}

/// What install, update and uninstall do to the machine besides writing the
/// node's files.
pub trait System {
    fn is_root(&self) -> bool;
    /// Whether systemd runs this machine.
    fn has_systemd(&self) -> bool;
    fn account(&self, name: &str) -> Result<Option<Account>, String>;
    /// Makes a system user with a group of the same name, the home given
    /// (not created) and no login, marked with [`USER_MARK`].
    fn add_account(&self, name: &str, home: &Path) -> Result<(), String>;
    /// Removes the user and its group.
    fn remove_account(&self, name: &str) -> Result<(), String>;
    fn systemctl(&self, args: &[&str]) -> Result<(), String>;
    /// Gives `path` and everything below it to `uid`:`gid`.
    fn give(&self, path: &Path, uid: u32, gid: u32) -> Result<(), String>;
    /// Waits until the node the service started answers on its control
    /// socket.
    fn wait_running(&self, paths: &NodePaths) -> Result<(), String>;
    /// What `<program> --version` prints, run as `account`.
    fn version_of(&self, program: &Path, account: &Account) -> Result<String, String>;
}

/// This machine.
pub struct Host;

impl System for Host {
    fn is_root(&self) -> bool {
        nerve_transport::net::euid() == 0
    }

    fn has_systemd(&self) -> bool {
        Path::new("/run/systemd/system").is_dir()
    }

    fn account(&self, name: &str) -> Result<Option<Account>, String> {
        let o = std::process::Command::new("getent")
            .args(["passwd", name])
            .output()
            .map_err(|e| format!("getent: {e}"))?;
        // 2: no such key.
        if o.status.code() == Some(2) {
            return Ok(None);
        }
        if !o.status.success() {
            return Err(format!("getent passwd {name}: {}", failure(&o)));
        }
        let line = String::from_utf8_lossy(&o.stdout);
        let f: Vec<&str> = line.trim().split(':').collect();
        let num = |i: usize| f.get(i).and_then(|v| v.parse::<u32>().ok());
        match (num(2), num(3)) {
            (Some(uid), Some(gid)) => Ok(Some(Account {
                uid,
                gid,
                comment: f.get(4).unwrap_or(&"").to_string(),
            })),
            _ => Err(format!("getent passwd {name}: cannot read {line:?}")),
        }
    }

    fn add_account(&self, name: &str, home: &Path) -> Result<(), String> {
        let shell = ["/usr/sbin/nologin", "/sbin/nologin"]
            .into_iter()
            .find(|s| Path::new(s).exists())
            .unwrap_or("/bin/false");
        run(
            "useradd",
            &[
                "--system",
                "--user-group",
                "--home-dir",
                &home.display().to_string(),
                "--no-create-home",
                "--shell",
                shell,
                "--comment",
                USER_MARK,
                name,
            ],
        )
    }

    fn remove_account(&self, name: &str) -> Result<(), String> {
        run("userdel", &[name])?;
        // userdel takes the group along where the system makes one group per
        // user; elsewhere it stays behind.
        let group = std::process::Command::new("getent")
            .args(["group", name])
            .output()
            .is_ok_and(|o| o.status.success());
        if group {
            run("groupdel", &[name])?;
        }
        Ok(())
    }

    fn systemctl(&self, args: &[&str]) -> Result<(), String> {
        run("systemctl", args)
    }

    fn give(&self, path: &Path, uid: u32, gid: u32) -> Result<(), String> {
        chown_tree(path, uid, gid)
    }

    fn wait_running(&self, paths: &NodePaths) -> Result<(), String> {
        #[cfg(unix)]
        {
            use std::io::{BufRead, BufReader};
            let ask = || -> std::io::Result<bool> {
                let mut s = std::os::unix::net::UnixStream::connect(paths.ctl_socket())?;
                s.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;
                s.write_all(b"{\"method\":\"status\",\"params\":{}}\n")?;
                let mut line = String::new();
                BufReader::new(s).read_line(&mut line)?;
                Ok(line.contains("\"ok\""))
            };
            for _ in 0..60 {
                if ask().unwrap_or(false) {
                    return Ok(());
                }
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
            Err(format!(
                "the service started, but the node does not answer on {}; `journalctl -u {UNIT_NAME}` says why",
                paths.ctl_socket().display()
            ))
        }
        #[cfg(not(unix))]
        {
            let _ = paths;
            Err(LINUX_ONLY.into())
        }
    }

    fn version_of(&self, program: &Path, account: &Account) -> Result<String, String> {
        let mut c = std::process::Command::new(program);
        c.arg("--version");
        // A downloaded program runs as the service's user, not as root.
        #[cfg(unix)]
        if self.is_root() {
            use std::os::unix::process::CommandExt;
            c.uid(account.uid).gid(account.gid);
        }
        #[cfg(not(unix))]
        let _ = account;
        let o = c
            .output()
            .map_err(|e| format!("{}: {e}", program.display()))?;
        if !o.status.success() {
            return Err(format!("{} --version: {}", program.display(), failure(&o)));
        }
        Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())
    }
}

const LINUX_ONLY: &str = "works on Linux with systemd only; elsewhere run `nerve-node run` under your own service manager";

/// Runs a system tool; its error output is the error.
fn run(program: &str, args: &[&str]) -> Result<(), String> {
    let o = std::process::Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("{program}: {e}"))?;
    if o.status.success() {
        Ok(())
    } else {
        Err(format!("{program} {}: {}", args.join(" "), failure(&o)))
    }
}

fn failure(o: &std::process::Output) -> String {
    let err = String::from_utf8_lossy(&o.stderr).trim().to_string();
    if err.is_empty() {
        o.status.to_string()
    } else {
        err
    }
}

/// The steps a command did, shown as they are done and audited at its end.
struct Steps<'a> {
    done: Vec<String>,
    out: &'a mut dyn Write,
}

impl Steps<'_> {
    fn did(&mut self, step: impl Into<String>) {
        let step = step.into();
        let _ = writeln!(self.out, "{step}");
        self.done.push(step);
    }
}

/// Whether `what` can run here: Linux, root and systemd.
fn supported(sys: &dyn System, what: &str) -> Result<(), String> {
    if !cfg!(target_os = "linux") {
        return Err(format!("{what} {LINUX_ONLY}"));
    }
    if !sys.is_root() {
        return Err(format!("{what} needs root: run `sudo nerve-node {what}`"));
    }
    if !sys.has_systemd() {
        return Err(format!(
            "{what} needs systemd, which does not run this machine; run `nerve-node run` under your own service manager"
        ));
    }
    Ok(())
}

/// Writes the command's audit entry, when the state folder is there to hold
/// it. Root writes it, so the files are given back to the folder's owner.
fn audit(
    sys: &dyn System,
    paths: &NodePaths,
    event: &str,
    steps: &[String],
    r: &Result<(), String>,
    out: &mut dyn Write,
) {
    if !paths.state_dir.is_dir() {
        return;
    }
    let log = AuditLog::new(paths.audit_log());
    let given = |()| -> Result<(), String> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let m = std::fs::metadata(&paths.state_dir).map_err(|e| e.to_string())?;
            for f in [log.path().to_path_buf(), log.old_path()] {
                if f.exists() {
                    sys.give(&f, m.uid(), m.gid())?;
                }
            }
        }
        #[cfg(not(unix))]
        let _ = sys;
        Ok(())
    };
    let written = log
        .node(event, steps, r.as_ref().err().map(String::as_str))
        .map_err(|e| e.to_string())
        .and_then(given);
    if let Err(e) = written {
        let _ = writeln!(out, "the audit log cannot be written: {e}");
    }
}

/// `install`: the user, the folders, the program, the unit, the running
/// service, in that order. Running it again puts back what is missing and
/// restarts the service.
pub fn install(
    layout: &Layout,
    sys: &dyn System,
    exe: &Path,
    out: &mut dyn Write,
) -> Result<(), String> {
    supported(sys, "install")?;
    let mut steps = Steps {
        done: Vec::new(),
        out,
    };
    let r = install_steps(layout, sys, exe, &mut steps);
    audit(sys, &layout.paths, "install", &steps.done, &r, steps.out);
    r?;
    let _ = writeln!(
        steps.out,
        "Next: `sudo nerve-node setup` names the node and pairs it with its first center."
    );
    Ok(())
}

fn install_steps(
    layout: &Layout,
    sys: &dyn System,
    exe: &Path,
    steps: &mut Steps,
) -> Result<(), String> {
    let account = match sys.account(USER)? {
        Some(a) if a.comment == USER_MARK => {
            steps.did(format!("the user {USER} is there already"));
            a
        }
        Some(_) => {
            return Err(format!(
                "a user {USER} exists already, and nerve-node install did not make it; the node needs a user of its own"
            ));
        }
        None => {
            sys.add_account(USER, &layout.home)?;
            let a = sys
                .account(USER)?
                .ok_or_else(|| format!("useradd made no user {USER}"))?;
            steps.did(format!("made the user {USER} (uid {})", a.uid));
            a
        }
    };
    // The folders may be left from an earlier install, whose user had
    // another uid: everything in them is given to this one.
    for dir in [
        &layout.home,
        &layout.paths.config_dir,
        &layout.paths.state_dir,
    ] {
        nerve_transport::files::create_private_dir(dir)
            .map_err(|e| format!("{}: {e}", dir.display()))?;
        set_mode(dir, 0o700)?;
        sys.give(dir, account.uid, account.gid)?;
    }
    steps.did(format!(
        "{} and {} belong to {USER}",
        layout.paths.config_dir.display(),
        layout.paths.state_dir.display()
    ));
    let real = |p: &Path| std::fs::canonicalize(p).ok();
    if real(exe).is_some() && real(exe) == real(&layout.bin) {
        steps.did(format!(
            "the program is at {} already",
            layout.bin.display()
        ));
    } else {
        let program = std::fs::read(exe).map_err(|e| format!("{}: {e}", exe.display()))?;
        write_file(&layout.bin, &program, 0o755)?;
        steps.did(format!("put the program at {}", layout.bin.display()));
    }
    write_file(&layout.unit, layout.unit_text().as_bytes(), 0o644)?;
    steps.did(format!("wrote the service unit {}", layout.unit.display()));
    sys.systemctl(&["daemon-reload"])?;
    sys.systemctl(&["enable", UNIT_NAME])?;
    sys.systemctl(&["restart", UNIT_NAME])?;
    sys.wait_running(&layout.paths)?;
    steps.did(format!(
        "the service {UNIT_NAME} runs as {USER} and starts with the machine"
    ));
    Ok(())
}

/// `uninstall`: stops and removes the service, then the folders (deleted
/// with `purge`, else kept and given to root), the user and the program.
pub fn uninstall(
    layout: &Layout,
    sys: &dyn System,
    purge: bool,
    out: &mut dyn Write,
) -> Result<(), String> {
    supported(sys, "uninstall")?;
    let mut steps = Steps {
        done: Vec::new(),
        out,
    };
    let r = uninstall_steps(layout, sys, purge, &mut steps);
    // With --purge the log went with the state folder.
    audit(sys, &layout.paths, "uninstall", &steps.done, &r, steps.out);
    if r.is_ok() && steps.done.is_empty() {
        let _ = writeln!(
            steps.out,
            "nothing to uninstall: no service, user {USER} or program of the node is here"
        );
    }
    r
}

fn uninstall_steps(
    layout: &Layout,
    sys: &dyn System,
    purge: bool,
    steps: &mut Steps,
) -> Result<(), String> {
    if layout.unit.exists() {
        sys.systemctl(&["disable", "--now", UNIT_NAME])?;
        steps.did(format!("stopped the service {UNIT_NAME}"));
        std::fs::remove_file(&layout.unit)
            .map_err(|e| format!("{}: {e}", layout.unit.display()))?;
        sys.systemctl(&["daemon-reload"])?;
        // Only clears a failed state systemd still shows.
        let _ = sys.systemctl(&["reset-failed", UNIT_NAME]);
        steps.did(format!(
            "removed the service unit {}",
            layout.unit.display()
        ));
    }
    let folders = [
        &layout.paths.config_dir,
        &layout.home,
        &layout.paths.state_dir,
    ];
    if purge {
        for dir in folders {
            if dir.exists() {
                std::fs::remove_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
                steps.did(format!("deleted {}", dir.display()));
            }
        }
    } else if folders.iter().any(|d| d.exists()) {
        // Their user goes; a uid nobody has must not own the keys, since
        // the next user to get it would.
        for dir in folders.iter().filter(|d| d.exists()) {
            sys.give(dir, 0, 0)?;
        }
        steps.did(format!(
            "kept {} and {} (they belong to root now; `uninstall --purge` deletes them)",
            layout.paths.config_dir.display(),
            layout.paths.state_dir.display()
        ));
    }
    match sys.account(USER)? {
        Some(a) if a.comment == USER_MARK => {
            sys.remove_account(USER)?;
            steps.did(format!("removed the user {USER}"));
        }
        Some(_) => {
            let _ = writeln!(
                steps.out,
                "left the user {USER} as it is: nerve-node install did not make it"
            );
        }
        None => {}
    }
    if layout.bin.exists() {
        std::fs::remove_file(&layout.bin).map_err(|e| format!("{}: {e}", layout.bin.display()))?;
        steps.did(format!("removed the program {}", layout.bin.display()));
    }
    Ok(())
}

/// A version as `nerve-node --version` prints it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Version(u64, u64, u64);

impl Version {
    fn parse(said: &str) -> Option<Version> {
        let v = said.trim().strip_prefix("nerve-node ")?;
        let mut parts = v.split('.').map(|p| p.parse::<u64>().ok());
        let v = Version(parts.next()??, parts.next()??, parts.next()??);
        parts.next().is_none().then_some(v)
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

/// `update`: the new program (the latest release, checked against its
/// `SHA256SUMS`, or a file the owner gives) replaces the installed one, and
/// the service restarts. The config, the keys and the audit log are not
/// touched. A program that does not run here, or is older than the
/// installed one, is refused; one that does not start is replaced by the
/// old one again.
pub async fn update(
    layout: &Layout,
    sys: &dyn System,
    from: Option<&Path>,
    out: &mut dyn Write,
) -> Result<(), String> {
    supported(sys, "update")?;
    if !layout.installed() || !layout.bin.is_file() {
        return Err(
            "the node is not installed as a service here; `sudo nerve-node install` installs it"
                .into(),
        );
    }
    let mut steps = Steps {
        done: Vec::new(),
        out,
    };
    let r = update_steps(layout, sys, from, &mut steps).await;
    audit(sys, &layout.paths, "update", &steps.done, &r, steps.out);
    r
}

async fn update_steps(
    layout: &Layout,
    sys: &dyn System,
    from: Option<&Path>,
    steps: &mut Steps<'_>,
) -> Result<(), String> {
    let account = sys
        .account(USER)?
        .filter(|a| a.comment == USER_MARK)
        .ok_or_else(|| {
            format!("the user {USER} is missing; `sudo nerve-node install` makes it again")
        })?;
    let new = match from {
        Some(f) => {
            let b = std::fs::read(f).map_err(|e| format!("{}: {e}", f.display()))?;
            steps.did(format!("read the new program from {}", f.display()));
            b
        }
        None => {
            let asset = asset_name()?;
            let b = fetch_release(&layout.release, &asset).await?;
            steps.did(format!(
                "downloaded {asset} from {} and checked it against its SHA256SUMS",
                layout.release
            ));
            b
        }
    };
    let old = std::fs::read(&layout.bin).map_err(|e| format!("{}: {e}", layout.bin.display()))?;
    if new == old {
        steps.did("the installed program is that one already; nothing to update");
        return Ok(());
    }
    // Staged beside the program, so the rename that puts it in place does
    // not cross file systems.
    let staged = layout.bin.with_file_name(".nerve-node.new");
    write_file(&staged, &new, 0o755)?;
    let checked = (|| {
        let said = sys.version_of(&staged, &account)?;
        let new_v = Version::parse(&said)
            .ok_or_else(|| format!("the new program is not nerve-node: it says {said:?}"))?;
        let old_v = sys
            .version_of(&layout.bin, &account)
            .ok()
            .and_then(|s| Version::parse(&s));
        if let Some(o) = old_v
            && new_v < o
        {
            return Err(format!(
                "the new program is nerve-node {new_v}, older than the installed {o}; nothing changed"
            ));
        }
        Ok((old_v, new_v))
    })();
    let (old_v, new_v) = match checked {
        Ok(v) => v,
        Err(e) => {
            let _ = std::fs::remove_file(&staged);
            return Err(e);
        }
    };
    std::fs::rename(&staged, &layout.bin).map_err(|e| format!("{}: {e}", layout.bin.display()))?;
    let old_v = old_v.map_or_else(|| "?".to_string(), |v| v.to_string());
    steps.did(format!("replaced nerve-node {old_v} with {new_v}"));
    let started = sys
        .systemctl(&["restart", UNIT_NAME])
        .and_then(|()| sys.wait_running(&layout.paths));
    if let Err(e) = started {
        write_file(&layout.bin, &old, 0o755)?;
        let back = sys
            .systemctl(&["restart", UNIT_NAME])
            .and_then(|()| sys.wait_running(&layout.paths));
        steps.did(format!("put nerve-node {old_v} back"));
        return Err(match back {
            Ok(()) => format!("the new program did not start ({e}); the old one runs again"),
            Err(e2) => format!(
                "the new program did not start ({e}), and the old one does not either ({e2})"
            ),
        });
    }
    steps.did(format!("restarted the service {UNIT_NAME}"));
    Ok(())
}

/// The release file of this machine's program.
fn asset_name() -> Result<String, String> {
    match std::env::consts::ARCH {
        arch @ ("x86_64" | "aarch64") => Ok(format!("nerve-node-{arch}-linux")),
        other => Err(format!(
            "the releases have no program for {other}; build one (docs/dev/building.md) and give it with --from"
        )),
    }
}

/// Downloads `asset` from the release at `base` and checks it against the
/// release's `SHA256SUMS`.
async fn fetch_release(base: &str, asset: &str) -> Result<Vec<u8>, String> {
    nerve_transport::init_crypto();
    let sums = download(&format!("{base}/SHA256SUMS"), SUMS_MAX).await?;
    let want = String::from_utf8_lossy(&sums)
        .lines()
        .find_map(|l| {
            let (hash, name) = l.split_once(char::is_whitespace)?;
            let name = name.trim_start();
            let name = name.strip_prefix('*').unwrap_or(name);
            (name == asset).then(|| hash.to_ascii_lowercase())
        })
        .ok_or_else(|| format!("the release's SHA256SUMS lists no {asset}"))?;
    let program = download(&format!("{base}/{asset}"), PROGRAM_MAX).await?;
    let got: String = ring::digest::digest(&ring::digest::SHA256, &program)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if got != want {
        return Err(format!(
            "the downloaded {asset} does not match its line in SHA256SUMS; nothing changed"
        ));
    }
    Ok(program)
}

/// `GET url`, following redirects (never from https to http), through the
/// proxy `HTTPS_PROXY` names. Errors name the host, not the whole address,
/// which may hold a signed query.
async fn download(url: &str, max: usize) -> Result<Vec<u8>, String> {
    let mut url = url.to_string();
    let mut tls = None;
    for _ in 0..6 {
        let (at, target) = split_url(&url)?;
        if tls == Some(true) && !at.tls {
            return Err(format!("{} redirects from https to http", at.host));
        }
        tls = Some(at.tls);
        let proxy = if at.tls {
            nerve_transport::net::Proxy::from_env(&at.host)?
        } else {
            None
        };
        let mut io = nerve_transport::net::open(&at, None, proxy.as_ref()).await?;
        let r = nerve_transport::http::get(&mut io, &at.authority(), &target, max)
            .await
            .map_err(|e| format!("{}: {e}", at.host))?;
        match r.status {
            200 => return Ok(r.body),
            301 | 302 | 303 | 307 | 308 => {
                let to = r
                    .location
                    .ok_or_else(|| format!("{} redirects without a Location", at.host))?;
                url = if to.contains("://") {
                    to
                } else if to.starts_with('/') {
                    format!(
                        "{}://{}{to}",
                        if at.tls { "https" } else { "http" },
                        at.authority()
                    )
                } else {
                    return Err(format!("{} redirects to a relative place", at.host));
                };
            }
            s => return Err(format!("{} answered HTTP {s}", at.host)),
        }
    }
    Err("too many redirects".into())
}

/// The server and the request target (path and query) of an http(s) URL.
fn split_url(url: &str) -> Result<(nerve_proto::link::CenterUrl, String), String> {
    let scheme_end = url.find("://").ok_or("not an http(s) address")?;
    let rest = &url[scheme_end + 3..];
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let mut target = rest[end..].to_string();
    if !target.starts_with('/') {
        target.insert(0, '/');
    }
    let at =
        nerve_proto::link::CenterUrl::parse(&format!("{}{}", &url[..scheme_end + 3], &rest[..end]))
            .map_err(|_| "not an http(s) address".to_string())?;
    Ok((at, target))
}

/// Writes `data` to `path` through a temporary file beside it and a rename,
/// with `mode`.
fn write_file(path: &Path, data: &[u8], mode: u32) -> Result<(), String> {
    let at = |e: std::io::Error| format!("{}: {e}", path.display());
    let dir = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir).map_err(at)?;
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let tmp = dir.join(format!(
        ".{name}.{}.tmp",
        nerve_transport::keys::random_token(8)
    ));
    let r = (|| {
        std::fs::write(&tmp, data)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
        }
        #[cfg(not(unix))]
        let _ = mode;
        std::fs::rename(&tmp, path)
    })();
    if r.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    r.map_err(at)
}

fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .map_err(|e| format!("{}: {e}", path.display()))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        Ok(())
    }
}

fn chown(path: &Path, uid: u32, gid: u32) -> Result<(), String> {
    #[cfg(unix)]
    {
        std::os::unix::fs::lchown(path, Some(uid), Some(gid))
            .map_err(|e| format!("{}: {e}", path.display()))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, uid, gid);
        Ok(())
    }
}

/// Gives `path` and everything below it to `uid`:`gid`. Links are changed
/// themselves and never followed.
fn chown_tree(path: &Path, uid: u32, gid: u32) -> Result<(), String> {
    chown(path, uid, gid)?;
    let meta = std::fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if meta.is_dir() {
        let entries = std::fs::read_dir(path).map_err(|e| format!("{}: {e}", path.display()))?;
        for e in entries {
            let e = e.map_err(|e| format!("{}: {e}", path.display()))?;
            chown_tree(&e.path(), uid, gid)?;
        }
    }
    Ok(())
}

/// A command root runs on a node whose folders belong to another user (the
/// installed node's `nerve`) runs as that user, so that what it writes stays
/// readable to the node. Called before anything else runs in the process:
/// it changes the user of the calling thread only where the C library does
/// not change every thread's.
pub fn become_owner(paths: &NodePaths) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if nerve_transport::net::euid() != 0 {
            return Ok(());
        }
        let Some(m) = [&paths.config_dir, &paths.state_dir]
            .iter()
            .find_map(|d| std::fs::metadata(d).ok())
        else {
            return Ok(());
        };
        if m.uid() == 0 {
            return Ok(());
        }
        // SAFETY: plain calls with no pointers but the empty group list;
        // groups first, the user last, while root may still change both.
        let failed = unsafe {
            libc::setgroups(0, std::ptr::null()) != 0
                || libc::setgid(m.gid()) != 0
                || libc::setuid(m.uid()) != 0
        };
        if failed {
            return Err(format!(
                "cannot run as the owner (uid {}) of {}: {}",
                m.uid(),
                paths.config_dir.display(),
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = paths;
        Ok(())
    }
}

/// A command on the installed node from a user who is neither root nor the
/// node's own stops here and says how to run it, instead of failing on a
/// folder it may not open.
pub fn check_access(paths: &NodePaths) -> Result<(), String> {
    let layout = Layout::system();
    if *paths != layout.paths || !layout.installed() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let me = nerve_transport::net::euid();
        let owner = std::fs::metadata(&paths.config_dir).map(|m| m.uid());
        if me != 0 && owner.is_ok_and(|o| o != me) {
            return Err(format!(
                "the node is installed as a service, and its files belong to the user {USER}: run `sudo nerve-node …`"
            ));
        }
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// A machine in a temporary folder: the user is the test's own, and
    /// systemctl and the node's start are recorded.
    struct Fake {
        user: RefCell<Option<Account>>,
        calls: RefCell<Vec<String>>,
        /// The folders given to another user, and to whom.
        given: RefCell<Vec<(PathBuf, u32)>>,
        /// Whether a node started by the service answers.
        starts: std::cell::Cell<bool>,
    }

    impl Fake {
        fn new() -> Fake {
            Fake {
                user: RefCell::new(None),
                calls: RefCell::new(Vec::new()),
                given: RefCell::new(Vec::new()),
                starts: std::cell::Cell::new(true),
            }
        }

        fn calls(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }
    }

    fn me() -> Account {
        // SAFETY: plain getters.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        Account {
            uid,
            gid,
            comment: USER_MARK.into(),
        }
    }

    impl System for Fake {
        fn is_root(&self) -> bool {
            true
        }
        fn has_systemd(&self) -> bool {
            true
        }
        fn account(&self, name: &str) -> Result<Option<Account>, String> {
            assert_eq!(name, USER);
            Ok(self.user.borrow().clone())
        }
        fn add_account(&self, name: &str, home: &Path) -> Result<(), String> {
            self.calls
                .borrow_mut()
                .push(format!("useradd {name} {}", home.display()));
            *self.user.borrow_mut() = Some(me());
            Ok(())
        }
        fn remove_account(&self, name: &str) -> Result<(), String> {
            self.calls.borrow_mut().push(format!("userdel {name}"));
            *self.user.borrow_mut() = None;
            Ok(())
        }
        fn systemctl(&self, args: &[&str]) -> Result<(), String> {
            self.calls
                .borrow_mut()
                .push(format!("systemctl {}", args.join(" ")));
            Ok(())
        }
        /// The test may give files to itself only; giving them to anyone
        /// else is recorded.
        fn give(&self, path: &Path, uid: u32, gid: u32) -> Result<(), String> {
            if uid == me().uid {
                chown_tree(path, uid, gid)
            } else {
                self.given.borrow_mut().push((path.to_path_buf(), uid));
                Ok(())
            }
        }
        fn wait_running(&self, _paths: &NodePaths) -> Result<(), String> {
            if self.starts.get() {
                Ok(())
            } else {
                Err("the node does not answer".into())
            }
        }
        /// A program here is a text file whose first line is what it says.
        fn version_of(&self, program: &Path, account: &Account) -> Result<String, String> {
            assert_eq!(account.comment, USER_MARK);
            let text = std::fs::read_to_string(program).map_err(|e| e.to_string())?;
            Ok(text.lines().next().unwrap_or_default().to_string())
        }
    }

    fn layout(root: &Path) -> Layout {
        Layout {
            unit: root.join("etc/systemd/system").join(UNIT_NAME),
            bin: root.join("usr/local/bin/nerve-node"),
            home: root.join("var/lib/nerve"),
            paths: NodePaths::new(root.join("etc/nerve"), root.join("var/lib/nerve/state")),
            release: "http://127.0.0.1:1/none".into(),
        }
    }

    /// Installs a "program" saying `version` from a file in `root`.
    fn installed(root: &Path, sys: &Fake, version: &str) -> Layout {
        let l = layout(root);
        let exe = root.join("download/nerve-node");
        std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
        std::fs::write(&exe, format!("nerve-node {version}\n")).unwrap();
        let mut out = Vec::new();
        install(&l, sys, &exe, &mut out).unwrap();
        l
    }

    fn audit_events(l: &Layout) -> Vec<serde_json::Value> {
        AuditLog::new(l.paths.audit_log())
            .read()
            .unwrap()
            .into_iter()
            .filter(|v| v["kind"] == "node")
            .collect()
    }

    fn mode(p: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn install_puts_the_service_under_its_own_user() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = layout(d.path());
        let exe = d.path().join("download/nerve-node");
        std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
        std::fs::write(&exe, "nerve-node 1.0.0\n").unwrap();
        let mut out = Vec::new();
        install(&l, &sys, &exe, &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("made the user nerve"), "{out}");
        assert!(out.contains("sudo nerve-node setup"), "{out}");
        // The user, made once with the home the unit names.
        assert_eq!(
            sys.calls(),
            [
                format!("useradd nerve {}", l.home.display()),
                "systemctl daemon-reload".into(),
                format!("systemctl enable {UNIT_NAME}"),
                format!("systemctl restart {UNIT_NAME}"),
            ]
        );
        // The program, the unit, and the folders, private to the user.
        assert_eq!(std::fs::read(&l.bin).unwrap(), b"nerve-node 1.0.0\n");
        assert_eq!(mode(&l.bin), 0o755);
        let unit = std::fs::read_to_string(&l.unit).unwrap();
        assert_eq!(unit, l.unit_text());
        assert!(unit.contains("\nUser=nerve\n"), "{unit}");
        assert!(
            unit.contains(&format!(
                "\nExecStart={} --config-dir {} --state-dir {} run\n",
                l.bin.display(),
                l.paths.config_dir.display(),
                l.paths.state_dir.display()
            )),
            "{unit}"
        );
        for dir in [&l.home, &l.paths.config_dir, &l.paths.state_dir] {
            assert_eq!(mode(dir), 0o700, "{dir:?}");
        }
        // Audited, with each step.
        let a = audit_events(&l);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0]["event"], "install");
        assert!(a[0].get("error").is_none());
        assert_eq!(a[0]["steps"].as_array().unwrap().len(), 5, "{}", a[0]);
        // Again: the user is reused, the program replaced, the service restarted.
        std::fs::write(&exe, "nerve-node 1.0.1\n").unwrap();
        let mut out = Vec::new();
        install(&l, &sys, &exe, &mut out).unwrap();
        assert_eq!(std::fs::read(&l.bin).unwrap(), b"nerve-node 1.0.1\n");
        assert_eq!(
            sys.calls()
                .iter()
                .filter(|c| c.starts_with("useradd"))
                .count(),
            1
        );
        assert!(
            String::from_utf8(out)
                .unwrap()
                .contains("the user nerve is there already")
        );
        assert_eq!(audit_events(&l).len(), 2);
    }

    #[test]
    fn install_refuses_a_user_it_did_not_make_and_needs_root() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        *sys.user.borrow_mut() = Some(Account {
            comment: "someone".into(),
            ..me()
        });
        let l = layout(d.path());
        let e = install(&l, &sys, Path::new("/bin/true"), &mut Vec::new()).unwrap_err();
        assert!(e.contains("did not make it"), "{e}");
        assert!(!l.bin.exists() && !l.unit.exists());
        assert!(sys.calls().is_empty());

        struct NotRoot;
        impl System for NotRoot {
            fn is_root(&self) -> bool {
                false
            }
            fn has_systemd(&self) -> bool {
                true
            }
            fn account(&self, _: &str) -> Result<Option<Account>, String> {
                unreachable!()
            }
            fn add_account(&self, _: &str, _: &Path) -> Result<(), String> {
                unreachable!()
            }
            fn remove_account(&self, _: &str) -> Result<(), String> {
                unreachable!()
            }
            fn systemctl(&self, _: &[&str]) -> Result<(), String> {
                unreachable!()
            }
            fn give(&self, _: &Path, _: u32, _: u32) -> Result<(), String> {
                unreachable!()
            }
            fn wait_running(&self, _: &NodePaths) -> Result<(), String> {
                unreachable!()
            }
            fn version_of(&self, _: &Path, _: &Account) -> Result<String, String> {
                unreachable!()
            }
        }
        for (what, e) in [
            (
                "install",
                install(&l, &NotRoot, Path::new("/bin/true"), &mut Vec::new()),
            ),
            ("uninstall", uninstall(&l, &NotRoot, false, &mut Vec::new())),
        ] {
            assert_eq!(
                e.unwrap_err(),
                format!("{what} needs root: run `sudo nerve-node {what}`")
            );
        }
    }

    #[test]
    fn uninstall_leaves_no_service_user_or_program_and_keeps_the_folders() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.0.0");
        std::fs::write(l.paths.config_file(), "version = 3\n").unwrap();
        let mut out = Vec::new();
        uninstall(&l, &sys, false, &mut out).unwrap();
        assert!(!l.unit.exists() && !l.bin.exists());
        assert!(sys.user.borrow().is_none());
        assert!(
            sys.calls().ends_with(&[
                format!("systemctl disable --now {UNIT_NAME}"),
                "systemctl daemon-reload".into(),
                format!("systemctl reset-failed {UNIT_NAME}"),
                "userdel nerve".into(),
            ]),
            "{:?}",
            sys.calls()
        );
        // The config and state stay, and the audit log has both commands.
        assert_eq!(
            std::fs::read_to_string(l.paths.config_file()).unwrap(),
            "version = 3\n"
        );
        let events: Vec<_> = audit_events(&l)
            .iter()
            .map(|v| v["event"].clone())
            .collect();
        assert_eq!(events, ["install", "uninstall"]);
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("uninstall --purge"), "{out}");
        // No uid that may come to another user owns them: they are root's.
        let given = sys.given.borrow().clone();
        assert_eq!(
            given,
            [
                (l.paths.config_dir.clone(), 0),
                (l.home.clone(), 0),
                (l.paths.state_dir.clone(), 0)
            ]
        );
    }

    #[test]
    fn uninstall_purge_deletes_the_folders_and_leaves_a_foreign_user() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.0.0");
        uninstall(&l, &sys, true, &mut Vec::new()).unwrap();
        for p in [
            &l.unit,
            &l.bin,
            &l.home,
            &l.paths.config_dir,
            &l.paths.state_dir,
        ] {
            assert!(!p.exists(), "{p:?}");
        }
        assert!(sys.user.borrow().is_none());
        let mut out = Vec::new();
        uninstall(&l, &sys, true, &mut out).unwrap();
        assert!(
            String::from_utf8(out)
                .unwrap()
                .starts_with("nothing to uninstall"),
        );
        // A nerve user that install did not make stays.
        *sys.user.borrow_mut() = Some(Account {
            comment: "someone".into(),
            ..me()
        });
        let mut out = Vec::new();
        uninstall(&l, &sys, true, &mut out).unwrap();
        assert!(sys.user.borrow().is_some());
        assert!(
            String::from_utf8(out)
                .unwrap()
                .contains("left the user nerve")
        );
    }

    /// What update must not touch: the config, a key and the audit log so far.
    fn kept(l: &Layout) -> Vec<(PathBuf, Vec<u8>)> {
        [
            l.paths.config_file(),
            l.paths.key_file("lab"),
            l.paths.config_key(),
            l.paths.audit_log(),
        ]
        .into_iter()
        .map(|p| {
            let b = std::fs::read(&p).unwrap();
            (p, b)
        })
        .collect()
    }

    fn with_files(l: &Layout) {
        std::fs::write(l.paths.config_file(), "version = 7\n").unwrap();
        std::fs::create_dir_all(l.paths.key_file("lab").parent().unwrap()).unwrap();
        std::fs::write(l.paths.key_file("lab"), "key").unwrap();
        std::fs::write(l.paths.config_key(), "mac key").unwrap();
    }

    #[tokio::test]
    async fn update_replaces_the_program_and_keeps_config_keys_and_audit() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.0.0");
        with_files(&l);
        let before = kept(&l);
        let new = d.path().join("new");
        std::fs::write(&new, "nerve-node 1.2.0\n").unwrap();
        let mut out = Vec::new();
        update(&l, &sys, Some(&new), &mut out).await.unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(
            out.contains("replaced nerve-node 1.0.0 with 1.2.0"),
            "{out}"
        );
        assert_eq!(std::fs::read(&l.bin).unwrap(), b"nerve-node 1.2.0\n");
        assert_eq!(mode(&l.bin), 0o755);
        assert_eq!(
            sys.calls().last().unwrap(),
            &format!("systemctl restart {UNIT_NAME}")
        );
        // Everything else as it was; the audit log only grew.
        for (p, b) in before {
            let now = std::fs::read(&p).unwrap();
            if p == l.paths.audit_log() {
                assert!(now.starts_with(&b), "{p:?}");
            } else {
                assert_eq!(now, b, "{p:?}");
            }
        }
        let a = audit_events(&l);
        assert_eq!(a.last().unwrap()["event"], "update");
        assert!(!l.bin.with_file_name(".nerve-node.new").exists());
        // The same program again changes nothing.
        let calls = sys.calls().len();
        let mut out = Vec::new();
        update(&l, &sys, Some(&new), &mut out).await.unwrap();
        assert!(
            String::from_utf8(out)
                .unwrap()
                .contains("nothing to update")
        );
        assert_eq!(sys.calls().len(), calls);
    }

    #[tokio::test]
    async fn update_refuses_an_older_or_foreign_program_and_puts_back_one_that_does_not_start() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let l = installed(d.path(), &sys, "1.2.0");
        let new = d.path().join("new");
        for (text, why) in [
            ("nerve-node 1.1.9\n", "older than the installed 1.2.0"),
            ("something else\n", "is not nerve-node"),
        ] {
            std::fs::write(&new, text).unwrap();
            let e = update(&l, &sys, Some(&new), &mut Vec::new())
                .await
                .unwrap_err();
            assert!(e.contains(why), "{e}");
            assert_eq!(std::fs::read(&l.bin).unwrap(), b"nerve-node 1.2.0\n");
            assert!(!l.bin.with_file_name(".nerve-node.new").exists());
        }
        std::fs::write(&new, "nerve-node 2.0.0\n").unwrap();
        sys.starts.set(false);
        let e = update(&l, &sys, Some(&new), &mut Vec::new())
            .await
            .unwrap_err();
        assert!(e.contains("did not start"), "{e}");
        assert_eq!(std::fs::read(&l.bin).unwrap(), b"nerve-node 1.2.0\n");
        let a = audit_events(&l);
        let last = a.last().unwrap();
        assert_eq!(last["event"], "update");
        assert!(last["error"].as_str().unwrap().contains("did not start"));
        assert!(
            last["steps"]
                .to_string()
                .contains("put nerve-node 1.2.0 back")
        );
    }

    #[tokio::test]
    async fn update_needs_an_installed_node() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let e = update(&layout(d.path()), &sys, None, &mut Vec::new())
            .await
            .unwrap_err();
        assert!(e.contains("not installed"), "{e}");
    }

    /// A release on a local server: `SHA256SUMS` and the program, the
    /// program behind a redirect as GitHub has it.
    async fn release(program: &'static [u8], sums: String) -> String {
        use nerve_transport::http::{Response, read_request};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let asset = asset_name().unwrap();
        tokio::spawn(async move {
            while let Ok((mut io, _)) = listener.accept().await {
                let req = read_request(&mut io, 0).await.unwrap();
                let r = if req.path == "/rel/SHA256SUMS" {
                    Response::text(200, &sums)
                } else if req.path == format!("/rel/{asset}") {
                    Response::new(302, "text/plain", "").with_header("Location", "/blob?sig=x")
                } else if req.path == "/blob" && req.query_param("sig").as_deref() == Some("x") {
                    Response::new(200, "application/octet-stream", program)
                } else {
                    Response::text(404, "no")
                };
                let _ = r.write(&mut io).await;
            }
        });
        format!("http://127.0.0.1:{port}/rel")
    }

    fn sha(b: &[u8]) -> String {
        ring::digest::digest(&ring::digest::SHA256, b)
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    #[tokio::test]
    async fn update_downloads_the_release_and_checks_it() {
        let d = tempfile::tempdir().unwrap();
        let sys = Fake::new();
        let mut l = installed(d.path(), &sys, "1.0.0");
        let program: &[u8] = b"nerve-node 1.3.0\n";
        let asset = asset_name().unwrap();
        l.release = release(
            program,
            format!("{}  other\n{} *{asset}\n", sha(b"x"), sha(program)),
        )
        .await;
        let mut out = Vec::new();
        update(&l, &sys, None, &mut out).await.unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("checked it against its SHA256SUMS"), "{out}");
        assert_eq!(std::fs::read(&l.bin).unwrap(), program);

        // A program that does not match its line is refused.
        let mut l2 = installed(&d.path().join("two"), &sys, "1.0.0");
        l2.release = release(program, format!("{}  {asset}\n", sha(b"other"))).await;
        let e = update(&l2, &sys, None, &mut Vec::new()).await.unwrap_err();
        assert!(e.contains("does not match"), "{e}");
        assert_eq!(std::fs::read(&l2.bin).unwrap(), b"nerve-node 1.0.0\n");
        // So is a release that does not list it.
        l2.release = release(program, format!("{}  other\n", sha(program))).await;
        let e = update(&l2, &sys, None, &mut Vec::new()).await.unwrap_err();
        assert!(e.contains("lists no"), "{e}");
    }

    #[test]
    fn versions_and_addresses() {
        assert_eq!(
            Version::parse("nerve-node 0.10.2\n"),
            Some(Version(0, 10, 2))
        );
        assert!(Version(0, 10, 0) > Version(0, 9, 9));
        for bad in [
            "nerve-center 1.0.0",
            "nerve-node 1.0",
            "nerve-node 1.0.0.1",
            "nerve-node x",
        ] {
            assert_eq!(Version::parse(bad), None, "{bad}");
        }
        let (at, target) = split_url("https://example.com/a/b?x=1").unwrap();
        assert_eq!(
            (at.host.as_str(), at.port, at.tls),
            ("example.com", 443, true)
        );
        assert_eq!(target, "/a/b?x=1");
        let (at, target) = split_url("http://127.0.0.1:8080?q").unwrap();
        assert_eq!((at.port, target.as_str()), (8080, "/?q"));
        assert!(split_url("ftp://x/y").is_err());
    }
}
