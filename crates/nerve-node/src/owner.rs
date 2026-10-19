//! The owners of the installed node and their way in without root
//! (docs/user/service.md, "Who may change the node").
//!
//! `install` makes the user who ran it an owner: on Linux a member of the
//! group [`GROUP`], on Windows a SID in the service's registry value
//! [`OWNERS_VALUE`]. Who is one is looked up at each request, by name, never
//! from the caller's token, so a new owner counts at once, without a new
//! login.
//!
//! The running node serves an owner endpoint beside its control socket: on
//! Linux [`socket`] (open to everyone, in the unit's runtime folder), on
//! Windows the pipe [`pipe_name`] (open to the owners, SYSTEM and the
//! administrators). It takes one request, `cli {args, cwd}`: the node
//! checks the caller and the command, then runs its own program with those
//! arguments as its own user, as `sudo nerve-node …` runs after
//! [`crate::service::become_owner`], with the caller's input and output
//! passed through the connection and [`OWNER_ENV`] naming the caller for the
//! audit. So the commands keep every check of the CLI, and the CLI of an
//! owner sends its command there by itself ([`forward_if_needed`]).
//!
//! What it does not stop: a command of a center that runs as an owner's
//! account and gets a process outside the node's process tree and sandbox
//! (the account's own `systemd --user`, a tmux server, the task scheduler)
//! is that owner. The app warns when commands run as its user
//! (docs/user/desktop.md).

use std::io::Write;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::cli::{Cli, Cmd, FolderCmd, SudoCmd};
use crate::paths::NodePaths;

/// The group of the installed node's owners on Linux.
pub const GROUP: &str = "nerve-admin";

/// Set by the node for a command it runs for an owner: the owner's name,
/// for the audit ([`crate::cli`]'s invoker) and the settings that stay
/// root's ([`root_only_change`]).
pub const OWNER_ENV: &str = "NERVE_OWNER";

/// The installed unit's runtime folder (`RuntimeDirectory=`), where the
/// owner socket is.
pub const RUNTIME_DIR: &str = "/run/nerve-node";

/// The owner socket's file name in [`RUNTIME_DIR`].
pub const SOCKET_NAME: &str = "owner.sock";

/// The registry value under the service's key that lists the owners' SIDs
/// on Windows (`Parameters`, REG_MULTI_SZ). It goes with the service.
pub const OWNERS_VALUE: &str = "Owners";

/// The owner socket of the installed node on Linux.
pub fn socket() -> PathBuf {
    Path::new(RUNTIME_DIR).join(SOCKET_NAME)
}

/// The owner pipe of the node at `paths` on Windows.
pub fn pipe_name(paths: &NodePaths) -> String {
    format!("{}-owner", paths.ctl_pipe())
}

/// The settings that decide which account and which programs a command
/// runs as. Through them an owner would get the rights of another account
/// or of root, so they stay root's: the node refuses them from an owner.
pub const ROOT_ONLY: [&str; 4] = [
    "machine.user",
    "machine.allow_root",
    "machine.sudo_path",
    "machine.shell",
];

/// The first of [`ROOT_ONLY`] that differs between `old` and `new`.
pub fn root_only_change(
    old: &nerve_policy::NodeConfig,
    new: &nerve_policy::NodeConfig,
) -> Option<&'static str> {
    let (o, n) = (&old.machine, &new.machine);
    [
        o.user != n.user,
        o.allow_root != n.allow_root,
        o.sudo_path != n.sudo_path,
        o.shell != n.shell,
    ]
    .iter()
    .position(|d| *d)
    .map(|i| ROOT_ONLY[i])
}

/// The owner a command runs for, when the node runs it for one.
pub fn owner_running() -> Option<String> {
    std::env::var(OWNER_ENV).ok().filter(|o| !o.is_empty())
}

/// Refuses a change of the settings that stay root's when this command runs
/// for an owner ([`OWNER_ENV`]).
pub fn check_change(
    old: &nerve_policy::NodeConfig,
    new: &nerve_policy::NodeConfig,
) -> Result<(), String> {
    if owner_running().is_none() {
        return Ok(());
    }
    match root_only_change(old, new) {
        Some(key) => Err(format!(
            "{key} decides which account or program commands run as, so only {} changes it: {}",
            admin(),
            with_rights("config set …")
        )),
        None => Ok(()),
    }
}

/// Who may do what an owner may not.
fn admin() -> &'static str {
    if cfg!(windows) {
        "an administrator"
    } else {
        "root"
    }
}

/// How to run `command` with the rights it needs.
fn with_rights(command: &str) -> String {
    let program = crate::edition::get().program;
    if cfg!(windows) {
        format!("run `{program} {command}` in a terminal opened with \"Run as administrator\"")
    } else {
        format!("run `sudo {program} {command}`")
    }
}

/// Why the node does not run `cmd` for an owner, if it does not: what
/// changes the program, the service, the accounts or the machine settings
/// stays root's (or an administrator's).
pub fn refused(cmd: &Cmd) -> Option<String> {
    let (what, why) = match cmd {
        Cmd::Run => ("run", "it starts a node of its own"),
        Cmd::Install => ("install", "it installs the program and the service"),
        Cmd::Update { .. } => ("update", "it replaces the program"),
        Cmd::Uninstall { .. } => ("uninstall", "it removes the program and the service"),
        Cmd::Service(_) => (
            "service",
            "the service manager decides who may start and stop the service",
        ),
        Cmd::Setup { .. } => (
            "setup",
            "it chooses the account commands run as, and can make one",
        ),
        Cmd::Sudo(SudoCmd::On) => ("sudo on", "it lets commands run as root"),
        Cmd::Backup { .. } => (
            "backup",
            "its file is written as you, which only root can do for the node",
        ),
        Cmd::Restore { .. } => (
            "restore",
            "it replaces the node's machine settings and its accounts' too",
        ),
        _ => return None,
    };
    Some(format!(
        "`{what}` needs {}: {why}; {}",
        admin(),
        with_rights(&format!("{what} …"))
    ))
}

/// Whether the CLI sends `cli`'s command to the owner endpoint: the node is
/// installed, the command works on its folders, and this process may not
/// open them (neither root, an administrator, nor the node's own user).
fn wanted(cli: &Cli) -> bool {
    if cli.cmd.is_service() || matches!(cli.cmd, Cmd::Run) {
        return false;
    }
    let paths = NodePaths::from_args(cli.config_dir.clone(), cli.state_dir.clone());
    let layout = crate::service::Layout::system();
    paths == layout.paths && crate::service::check_access(&paths).is_err()
}

/// Runs `cli`'s command through the owner endpoint when this process may not
/// open the installed node's folders ([`wanted`]): the exit code, or `None`
/// when the command runs here.
pub fn forward_if_needed(cli: &Cli) -> Option<i32> {
    if !wanted(cli) {
        return None;
    }
    let args = match forwarded_args(
        cli,
        std::env::args_os().skip(1),
        std::env::current_dir().ok(),
    ) {
        Ok(a) => a,
        Err(e) => return Some(fail(cli.json, &e)),
    };
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => return Some(fail(cli.json, &format!("cannot start the runtime: {e}"))),
    };
    let cwd = std::env::current_dir()
        .ok()
        .map(|d| d.display().to_string());
    let paths = NodePaths::from_args(None, None);
    Some(rt.block_on(forward(&paths, args, cwd, cli.json)))
}

/// Says `e` as `main` says an error; exit code 1.
fn fail(json: bool, e: &str) -> i32 {
    if json {
        let _ = writeln!(std::io::stdout(), "{}", json!({ "error": e }));
    }
    eprintln!("nerve-node: {e}");
    1
}

/// The arguments the node gets: those given, without `--config-dir` and
/// `--state-dir` (the node names its own folders), and a folder given by a
/// relative path made whole with `cwd`, as the node's program does not run
/// in this folder.
pub fn forwarded_args(
    cli: &Cli,
    given: impl IntoIterator<Item = std::ffi::OsString>,
    cwd: Option<PathBuf>,
) -> Result<Vec<String>, String> {
    let relative = match &cli.cmd {
        Cmd::Folder(
            FolderCmd::Add { path, .. } | FolderCmd::Set { path, .. } | FolderCmd::Rm { path, .. },
        ) if path.is_relative() => Some(path.clone()),
        _ => None,
    };
    let mut out = Vec::new();
    let mut skip = false;
    let mut made_whole = false;
    for a in given {
        if std::mem::take(&mut skip) {
            continue;
        }
        let Some(s) = a.to_str() else {
            return Err(format!(
                "{} is not UTF-8, which the node's owner path takes only",
                a.to_string_lossy()
            ));
        };
        if s == "--config-dir" || s == "--state-dir" {
            skip = true;
            continue;
        }
        if s.starts_with("--config-dir=") || s.starts_with("--state-dir=") {
            continue;
        }
        if let Some(r) = &relative
            && !made_whole
            && Path::new(s) == r
        {
            let cwd = cwd
                .as_ref()
                .ok_or("give the folder by its full path: this folder cannot be read")?;
            out.push(cwd.join(r).display().to_string());
            made_whole = true;
            continue;
        }
        out.push(s.to_string());
    }
    Ok(out)
}

/// What the CLI of someone who is no owner, or of an owner while the node
/// does not run, is told.
fn not_reached(e: &str) -> String {
    if e == nerve_transport::ctl::NOT_RUNNING {
        return format!(
            "the node is installed as a service and does not run; while it is stopped only {} changes it: start it with `{} service start`, or {}",
            admin(),
            crate::edition::get().program,
            with_rights("…")
        );
    }
    e.to_string()
}

/// Sends `args` to the owner endpoint of the node at `paths`, passes this
/// process's input to it and its output here; the command's exit code.
async fn forward(paths: &NodePaths, args: Vec<String>, cwd: Option<String>, json: bool) -> i32 {
    let conn = match connect(paths).await {
        Ok(c) => c,
        Err(e) => return fail(json, &not_reached(&e)),
    };
    match session(conn, args, cwd).await {
        Ok(code) => code,
        Err(e) => fail(json, &e),
    }
}

/// The client's side of one `cli` request on `conn`.
async fn session<S>(conn: S, args: Vec<String>, cwd: Option<String>) -> Result<i32, String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite,
{
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    let (r, mut w) = tokio::io::split(conn);
    let request = json!({"method": "cli", "params": {"args": args, "cwd": cwd}});
    w.write_all(format!("{request}\n").as_bytes())
        .await
        .map_err(|e| format!("cannot reach the node: {e}"))?;
    let mut lines = tokio::io::BufReader::new(r).lines();
    let first = lines
        .next_line()
        .await
        .map_err(|e| format!("cannot reach the node: {e}"))?
        .ok_or("the node closed without answering")?;
    let first: Value =
        serde_json::from_str(&first).map_err(|_| "the node closed without answering")?;
    if let Some(e) = first["error"].as_str() {
        return Err(e.to_string());
    }
    // The input goes on its own thread: a read of a terminal blocks, and the
    // command may never ask for it.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Value>(16);
    std::thread::spawn(move || read_input(std::io::stdin(), &tx));
    let feeding = async move {
        while let Some(v) = rx.recv().await {
            let line = format!("{v}\n");
            if w.write_all(line.as_bytes()).await.is_err() {
                break;
            }
        }
        // Kept open: the node ends the session.
        std::future::pending::<()>().await;
    };
    let reading = async {
        while let Ok(Some(line)) = lines.next_line().await {
            let Ok(v) = serde_json::from_str::<Value>(&line) else {
                continue;
            };
            if let Some(s) = v["out"].as_str() {
                let mut o = std::io::stdout();
                let _ = o.write_all(s.as_bytes());
                let _ = o.flush();
            } else if let Some(s) = v["err"].as_str() {
                let _ = std::io::stderr().write_all(s.as_bytes());
            } else if let Some(code) = v["exit"].as_i64() {
                return Ok(code as i32);
            }
        }
        Err("the node ended the command before it said how it ended".to_string())
    };
    tokio::select! {
        r = reading => r,
        () = feeding => unreachable!("the input never ends the session"),
    }
}

/// Reads `input` until its end and sends it as `{"in": text}` lines, then
/// `{"eof": true}`.
fn read_input(mut input: impl std::io::Read, tx: &tokio::sync::mpsc::Sender<Value>) {
    let mut buf = [0u8; 8192];
    let mut pending = Vec::new();
    loop {
        match input.read(&mut buf) {
            Ok(0) | Err(_) => {
                let _ = tx.blocking_send(json!({"eof": true}));
                return;
            }
            Ok(n) => {
                pending.extend_from_slice(&buf[..n]);
                let text = take_text(&mut pending);
                if !text.is_empty() && tx.blocking_send(json!({ "in": text })).is_err() {
                    return;
                }
            }
        }
    }
}

/// The text at the start of `pending`, taken out of it: all of it but a
/// character cut at its end, which waits for its next bytes. Bytes that are
/// no UTF-8 become U+FFFD.
pub fn take_text(pending: &mut Vec<u8>) -> String {
    let cut = match std::str::from_utf8(pending) {
        Ok(_) => pending.len(),
        // An incomplete character at the end (no error length) waits.
        Err(e) if e.error_len().is_none() => e.valid_up_to(),
        Err(_) => pending.len(),
    };
    let rest = pending.split_off(cut);
    let text = String::from_utf8_lossy(pending).into_owned();
    *pending = rest;
    text
}

#[cfg(unix)]
async fn connect(_paths: &NodePaths) -> Result<tokio::net::UnixStream, String> {
    let at = std::env::var_os("NERVE_OWNER_SOCKET").map_or_else(socket, PathBuf::from);
    tokio::net::UnixStream::connect(&at)
        .await
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
                nerve_transport::ctl::NOT_RUNNING.to_string()
            }
            _ => format!("cannot reach the node at {}: {e}", at.display()),
        })
}

#[cfg(windows)]
async fn connect(
    paths: &NodePaths,
) -> Result<tokio::net::windows::named_pipe::NamedPipeClient, String> {
    win::connect(paths).await
}

#[cfg(not(any(unix, windows)))]
async fn connect(_paths: &NodePaths) -> Result<tokio::io::DuplexStream, String> {
    Err(nerve_transport::ctl::NOT_RUNNING.into())
}

/// Who is an owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Owners {
    /// Linux: the members of this group, looked up at each request.
    Group(String),
    /// These uids (a test's; root always is one on Linux).
    Uids(Vec<u32>),
    /// Windows: these SIDs, as text.
    Sids(Vec<String>),
}

/// Where the node takes its owners' commands, and who they are.
#[derive(Debug, Clone)]
pub struct Endpoint {
    /// The socket (Linux) or the pipe's name (Windows).
    pub at: PathBuf,
    pub owners: Owners,
    /// The program the node runs for them: its own.
    pub program: PathBuf,
}

impl Endpoint {
    /// The installed node's, when the node at `paths` is it: on Linux in the
    /// runtime folder systemd made for it (`RUNTIME_DIRECTORY`), on Windows
    /// the pipe for the owners `install` wrote. `None` for a node run by
    /// hand, and on Windows when the service names no owner.
    pub fn of_service(paths: &NodePaths) -> Option<Endpoint> {
        if !crate::service::is_service_node(paths) {
            return None;
        }
        #[cfg(target_os = "linux")]
        {
            let dir = std::env::var_os("RUNTIME_DIRECTORY")?;
            // Several folders are separated by ':'; the unit names one.
            let dir = PathBuf::from(dir.to_string_lossy().split(':').next()?);
            Some(Endpoint {
                at: dir.join(SOCKET_NAME),
                owners: Owners::Group(GROUP.into()),
                program: "/proc/self/exe".into(),
            })
        }
        #[cfg(windows)]
        {
            let sids = crate::win_host::owners().ok()?;
            if sids.is_empty() {
                return None;
            }
            Some(Endpoint {
                at: pipe_name(paths).into(),
                owners: Owners::Sids(sids),
                program: std::env::current_exe().ok()?,
            })
        }
        #[cfg(not(any(target_os = "linux", windows)))]
        None
    }
}

/// Whether the account `uid` is in `group`, as the account database says
/// now; root always is.
#[cfg(unix)]
pub fn in_group(uid: u32, group: &str) -> bool {
    if uid == 0 {
        return true;
    }
    let Some(gid) = group_id(group) else {
        return false;
    };
    crate::account::name_of(uid)
        .and_then(|n| crate::account::lookup(&n).ok().flatten())
        .is_some_and(|a| a.uid == uid && a.groups.contains(&gid))
}

/// The id of `group`, from `getent group`.
#[cfg(unix)]
pub fn group_id(group: &str) -> Option<u32> {
    let o = std::process::Command::new("getent")
        .args(["group", group])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !o.status.success() {
        return None;
    }
    String::from_utf8_lossy(&o.stdout)
        .lines()
        .next()?
        .split(':')
        .nth(2)?
        .parse()
        .ok()
}

/// Whether the process `pid` runs with `no_new_privs`, which every confined
/// command of the node keeps, whatever it starts or leaves.
#[cfg(target_os = "linux")]
fn keeps_no_new_privs(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/status")).is_ok_and(|s| {
        s.lines().any(|l| {
            l.strip_prefix("NoNewPrivs:")
                .is_some_and(|v| v.trim() == "1")
        })
    })
}

/// Why the node refuses an owner request from a process of a center's
/// command.
const FROM_A_COMMAND: &str = "refused: this request comes from a command the node runs for a center, or a program it started";

/// One request on the owner endpoint from `who` (`None`: no owner):
/// `status` answers anyone that the node runs; `cli` runs a command for an
/// owner. `from_command` says whether the caller is a process of a
/// center's command, as far as the node can tell.
pub(crate) async fn answer(
    shared: &std::sync::Arc<crate::daemon::Shared>,
    program: &Path,
    req: nerve_transport::ctl::CtlRequest,
    who: Option<String>,
    from_command: bool,
) -> nerve_transport::ctl::Reply {
    use nerve_transport::ctl::Reply;
    match req.method.as_str() {
        // What the control socket says without its token: `service
        // restart` of an owner waits for it.
        "status" => Reply::Ok(json!({"running": true})),
        "cli" => {
            if from_command {
                return Reply::Err(FROM_A_COMMAND.into());
            }
            let Some(who) = who else {
                return Reply::Err(not_an_owner());
            };
            run_for(&shared.paths, program, &who, &req.params).await
        }
        other => Reply::Err(format!("unknown method {other}")),
    }
}

/// What someone who is no owner is told.
fn not_an_owner() -> String {
    if cfg!(windows) {
        format!(
            "you are not an owner of the installed node: {}",
            with_rights("…")
        )
    } else {
        format!(
            "you are not in the group {GROUP} of the installed node's owners: {} (an owner's account is added with `sudo usermod -aG {GROUP} NAME`)",
            with_rights("…")
        )
    }
}

/// Runs the command `params` names (`args`, `cwd`) for the owner `who`: the
/// node's own program, as the node's user, on the node's folders.
async fn run_for(
    paths: &NodePaths,
    program: &Path,
    who: &str,
    params: &Value,
) -> nerve_transport::ctl::Reply {
    use clap::Parser;
    use nerve_transport::ctl::Reply;
    let Some(args) = params["args"].as_array().and_then(|a| {
        a.iter()
            .map(|v| v.as_str().map(str::to_string))
            .collect::<Option<Vec<String>>>()
    }) else {
        return Reply::Err("args is missing".into());
    };
    // Parsed as the program will: a command that stays root's is refused
    // here, before anything runs. One that does not parse runs, and the
    // program says what is wrong with it.
    let name = crate::edition::get().program;
    if let Ok(cli) = Cli::try_parse_from(std::iter::once(name.to_string()).chain(args.clone())) {
        if cli.config_dir.is_some() || cli.state_dir.is_some() {
            return Reply::Err("the node runs its commands on its own folders".into());
        }
        if let Some(why) = refused(&cli.cmd) {
            return Reply::Err(why);
        }
    }
    let words: Vec<&str> = args
        .iter()
        .map(String::as_str)
        .take_while(|a| !a.starts_with('-'))
        .take(2)
        .collect();
    tracing::info!("{who} runs `{name} {}` as an owner", words.join(" "));
    let cwd = params["cwd"].as_str().map(PathBuf::from);
    let mut child = match spawn(paths, program, who, &args, cwd.as_deref()) {
        Ok(c) => c,
        Err(e) => return Reply::Err(format!("cannot run {name}: {e}")),
    };
    let (out_tx, out_rx) = tokio::sync::mpsc::channel::<Value>(64);
    let (in_tx, in_rx) = tokio::sync::mpsc::channel::<Value>(16);
    let stdin = child.stdin.take();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    tokio::spawn(async move {
        let pumped = async {
            tokio::join!(
                pump(stdout, "out", out_tx.clone()),
                pump(stderr, "err", out_tx.clone())
            );
            child.wait().await
        };
        let fed = feed(in_rx, stdin);
        tokio::pin!(fed);
        let status = tokio::select! {
            s = pumped => s,
            // The caller went: the command ends with it.
            () = &mut fed => return,
        };
        let code = status.ok().and_then(|s| s.code()).unwrap_or(1);
        let _ = out_tx.send(json!({ "exit": code })).await;
    });
    Reply::Session {
        ok: json!({}),
        out: out_rx,
        inbound: in_tx,
    }
}

/// Starts the program for `who`: its output and input piped, ended when
/// dropped. The caller's folder is its working folder when the node may
/// enter it, else the root.
fn spawn(
    paths: &NodePaths,
    program: &Path,
    who: &str,
    args: &[String],
    cwd: Option<&Path>,
) -> std::io::Result<tokio::process::Child> {
    let make = |dir: &Path| {
        let mut c = tokio::process::Command::new(program);
        c.arg("--config-dir")
            .arg(&paths.config_dir)
            .arg("--state-dir")
            .arg(&paths.state_dir)
            .args(args)
            .current_dir(dir)
            .env(OWNER_ENV, who)
            // Who asked is the owner, not whoever these name.
            .env_remove("SUDO_USER")
            .env_remove("PKEXEC_UID")
            .env_remove(crate::cli::DESKTOP_USER_SID)
            .env_remove("NERVE_CONFIG_DIR")
            .env_remove("NERVE_STATE_DIR")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        #[cfg(windows)]
        c.creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW);
        c
    };
    let root = if cfg!(windows) {
        paths.state_dir.clone()
    } else {
        PathBuf::from("/")
    };
    match cwd.filter(|d| d.is_absolute()) {
        // A folder the node may not enter fails the start: then the root.
        Some(d) => make(d).spawn().or_else(|_| make(&root).spawn()),
        None => make(&root).spawn(),
    }
}

/// Sends what `from` gives as `{kind: text}` values until it ends.
async fn pump<R: tokio::io::AsyncRead + Unpin>(
    from: Option<R>,
    kind: &'static str,
    to: tokio::sync::mpsc::Sender<Value>,
) {
    use tokio::io::AsyncReadExt;
    let Some(mut from) = from else {
        return;
    };
    let mut buf = vec![0u8; 8192];
    let mut pending = Vec::new();
    loop {
        match from.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                pending.extend_from_slice(&buf[..n]);
                let text = take_text(&mut pending);
                if !text.is_empty() && to.send(json!({ kind: text })).await.is_err() {
                    return;
                }
            }
        }
    }
    if !pending.is_empty() {
        let _ = to
            .send(json!({ kind: String::from_utf8_lossy(&pending) }))
            .await;
    }
}

/// Passes the caller's `{"in": text}` to the program's input and closes it
/// at `{"eof": true}`; ends when the caller goes.
async fn feed(
    mut from: tokio::sync::mpsc::Receiver<Value>,
    mut stdin: Option<tokio::process::ChildStdin>,
) {
    use tokio::io::AsyncWriteExt;
    while let Some(v) = from.recv().await {
        if let Some(text) = v["in"].as_str() {
            if let Some(s) = stdin.as_mut()
                && s.write_all(text.as_bytes()).await.is_err()
            {
                stdin = None;
            }
        } else if v["eof"] == true {
            stdin = None;
        }
    }
}

/// Serves the owner endpoint of the node `shared` until the task is
/// aborted. On Linux the socket is open to everyone, in a folder everyone
/// may enter: who may run a command is decided by the account the kernel
/// names for the caller, so an owner added a moment ago counts in a session
/// that began before.
#[cfg(unix)]
pub(crate) async fn serve(
    shared: std::sync::Arc<crate::daemon::Shared>,
    endpoint: Endpoint,
) -> Result<tokio::task::JoinHandle<()>, String> {
    let listener = nerve_transport::ctl::bind_open(&endpoint.at)
        .await
        .map_err(|e| format!("{}: {e}", endpoint.at.display()))?;
    let task = tokio::spawn(async move {
        let program = endpoint.program.clone();
        let owners = endpoint.owners.clone();
        let r = nerve_transport::ctl::serve_anyone(listener, move |req, peer| {
            let s = shared.clone();
            let program = program.clone();
            let owners = owners.clone();
            async move {
                // Asked only for a command: the lookup runs programs.
                let (who, from_command) = if req.method == "cli" {
                    (owner_name(&owners, peer.uid), from_a_command(&s, peer.pid))
                } else {
                    (None, false)
                };
                answer(&s, &program, req, who, from_command).await
            }
        })
        .await;
        if let Err(e) = r {
            tracing::error!("the owner socket stopped: {e}");
        }
    });
    Ok(task)
}

/// The owner's name when the account `uid` is one.
#[cfg(unix)]
fn owner_name(owners: &Owners, uid: u32) -> Option<String> {
    let owner = match owners {
        Owners::Group(g) => in_group(uid, g),
        Owners::Uids(u) => uid == 0 || u.contains(&uid),
        Owners::Sids(_) => false,
    };
    owner.then(|| crate::account::name_of(uid).unwrap_or_else(|| format!("uid {uid}")))
}

/// Whether the caller `pid` is a process of a center's command: below one
/// the node runs, or with `no_new_privs`, which a confined command keeps
/// wherever its processes go. An unknown caller is one.
#[cfg(unix)]
fn from_a_command(shared: &crate::daemon::Shared, pid: Option<u32>) -> bool {
    let Some(pid) = pid else {
        return true;
    };
    #[cfg(target_os = "linux")]
    if keeps_no_new_privs(pid) {
        return true;
    }
    shared.below_command(Some(pid))
}

#[cfg(windows)]
pub(crate) use win::serve;

#[cfg(windows)]
mod win {
    use std::os::windows::io::AsRawHandle;
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient, NamedPipeServer};
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY, HANDLE,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, RevertToSelf, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::Storage::FileSystem::SECURITY_IDENTIFICATION;
    use windows_sys::Win32::System::Pipes::ImpersonateNamedPipeClient;
    use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

    use super::{Endpoint, NodePaths, Owners, answer, not_an_owner, pipe_name};
    use crate::pipe::{Descriptor, client_pid, instance};

    /// The owner pipe's DACL in SDDL: SYSTEM, the administrators and the
    /// owners. No AppContainer gets in: no entry names a package.
    pub fn dacl_text(owners: &[String]) -> String {
        let mut s = String::from("D:P(A;;GA;;;SY)(A;;GA;;;BA)");
        for o in owners {
            s.push_str(&format!("(A;;GA;;;{o})"));
        }
        s
    }

    /// The SID of the client of the connected `pipe`, read at
    /// identification level after its request was read.
    fn client_sid(pipe: HANDLE) -> Option<String> {
        // SAFETY: a connected pipe the server read from; the thread's
        // token is opened while impersonating, then reverted at once.
        unsafe {
            if ImpersonateNamedPipeClient(pipe) == 0 {
                return None;
            }
            let mut token: HANDLE = std::ptr::null_mut();
            let opened = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token);
            RevertToSelf();
            if opened == 0 {
                return None;
            }
            let mut buf = vec![0u8; 256];
            let mut len = 0u32;
            let ok = GetTokenInformation(
                token,
                TokenUser,
                buf.as_mut_ptr().cast(),
                buf.len() as u32,
                &mut len,
            );
            CloseHandle(token);
            if ok == 0 {
                return None;
            }
            let user = &*buf.as_ptr().cast::<TOKEN_USER>();
            let len = windows_sys::Win32::Security::GetLengthSid(user.User.Sid) as usize;
            let sid = std::slice::from_raw_parts(user.User.Sid.cast::<u8>(), len).to_vec();
            crate::win_host::sid_text(&sid).ok()
        }
    }

    /// Who is on the other end of an owner connection.
    #[derive(Clone, Copy)]
    struct Caller {
        pid: Option<u32>,
        pipe: usize,
    }

    /// Serves the owner pipe until the task is aborted; the first instance
    /// is made before this returns.
    pub(crate) async fn serve(
        shared: Arc<crate::daemon::Shared>,
        endpoint: Endpoint,
    ) -> Result<tokio::task::JoinHandle<()>, String> {
        let Owners::Sids(owners) = endpoint.owners.clone() else {
            return Err("the owner pipe takes owners by SID".into());
        };
        let name = endpoint.at.display().to_string();
        let sd = Descriptor::from_sddl(&dacl_text(&owners))
            .map_err(|e| format!("the owner pipe: cannot make its DACL: {e}"))?;
        let first =
            instance(&name, &sd, true).map_err(|e| format!("the owner pipe {name}: {e}"))?;
        Ok(tokio::spawn(accept(shared, endpoint, owners, sd, first)))
    }

    async fn accept(
        shared: Arc<crate::daemon::Shared>,
        endpoint: Endpoint,
        owners: Vec<String>,
        sd: Descriptor,
        mut listening: NamedPipeServer,
    ) {
        let name = endpoint.at.display().to_string();
        let places = Arc::new(tokio::sync::Semaphore::new(
            nerve_transport::ctl::MAX_CONNECTIONS,
        ));
        loop {
            if listening.connect().await.is_err() {
                let _ = listening.disconnect();
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
            let next = loop {
                match instance(&name, &sd, false) {
                    Ok(n) => break n,
                    Err(_) => tokio::time::sleep(Duration::from_secs(1)).await,
                }
            };
            let conn = std::mem::replace(&mut listening, next);
            let Ok(place) = places.clone().try_acquire_owned() else {
                continue;
            };
            let caller = Caller {
                pid: client_pid(&conn),
                pipe: conn.as_raw_handle() as usize,
            };
            let s = shared.clone();
            let program = endpoint.program.clone();
            let owners = owners.clone();
            tokio::spawn(async move {
                let _place = place;
                let handler = Arc::new(move |req: nerve_transport::ctl::CtlRequest, c: Caller| {
                    let s = s.clone();
                    let program = program.clone();
                    let owners = owners.clone();
                    async move {
                        let (who, from_command) = if req.method == "cli" {
                            // The pipe lives while its request is answered.
                            let sid = client_sid(c.pipe as HANDLE);
                            let who = sid
                                .filter(|s| owners.contains(s) || is_admin_sid(s))
                                .map(|s| crate::win_user::name_of_sid(&s).unwrap_or(s));
                            (who, crate::win::from_a_command(c.pid))
                        } else {
                            (None, false)
                        };
                        answer(&s, &program, req, who, from_command).await
                    }
                });
                let _ = nerve_transport::ctl::serve_stream(conn, caller, handler).await;
            });
        }
    }

    /// SYSTEM, whom the DACL lets in besides the owners and the
    /// administrators; an administrator's own SID is not known by itself
    /// here, so an elevated administrator who is no owner is refused as one.
    fn is_admin_sid(sid: &str) -> bool {
        sid == "S-1-5-18"
    }

    /// Opens the owner pipe of the node at `paths`, for identification only,
    /// and only when the node's account (or SYSTEM, the administrators) owns
    /// it.
    pub(super) async fn connect(paths: &NodePaths) -> Result<NamedPipeClient, String> {
        let name = pipe_name(paths);
        let mut busy = 0;
        let client = loop {
            match ClientOptions::new()
                .security_qos_flags(SECURITY_IDENTIFICATION)
                .open(&name)
            {
                Ok(c) => break c,
                Err(e) if e.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32) => {
                    return Err(nerve_transport::ctl::NOT_RUNNING.into());
                }
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) && busy < 50 => {
                    busy += 1;
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(e) if e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) => {
                    return Err(not_an_owner());
                }
                Err(e) => return Err(format!("cannot reach the running node: {e}")),
            }
        };
        crate::pipe::check_owner(paths, &client, &name)?;
        Ok(client)
    }
}

#[cfg(windows)]
pub use win::dacl_text;

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn cli(args: &[&str]) -> Cli {
        Cli::try_parse_from(std::iter::once("nerve-node").chain(args.iter().copied())).unwrap()
    }

    /// What changes the program, the service, the accounts or the machine
    /// settings is refused; settings, pairing and rules are not.
    #[test]
    fn the_commands_that_stay_roots_are_refused() {
        for args in [
            &["run"][..],
            &["install"],
            &["update"],
            &["uninstall", "--purge"],
            &["service", "restart"],
            &["setup"],
            &["setup", "--create-user", "x", "--account-only"],
            &["sudo", "on"],
            &["backup", "/tmp/b"],
            &["restore", "/tmp/b"],
        ] {
            assert!(refused(&cli(args).cmd).is_some(), "{args:?}");
        }
        for args in [
            &["status"][..],
            &["center", "ls"],
            &["center", "add", "nerve://pair?x", "--yes"],
            &["rule", "add", "allow", "ls"],
            &["mode", "set", "folder"],
            &["config", "set", "log.level", "debug"],
            &["sudo", "off"],
            &["sudo", "status"],
            &["audit", "--last", "5"],
            &["log", "--follow"],
            &["panic"],
            &["unlock"],
            &["proxy", "rm"],
        ] {
            assert_eq!(refused(&cli(args).cmd), None, "{args:?}");
        }
    }

    /// The settings that pick the account and the programs of the commands
    /// are root's; the others are not.
    #[test]
    fn the_settings_that_pick_the_account_are_roots() {
        let old = nerve_policy::NodeConfig::default();
        let changed = |f: &dyn Fn(&mut nerve_policy::NodeConfig)| {
            let mut new = old.clone();
            f(&mut new);
            root_only_change(&old, &new)
        };
        assert_eq!(
            changed(&|c| c.machine.user = Some("bob".into())),
            Some("machine.user")
        );
        assert_eq!(
            changed(&|c| c.machine.allow_root = !c.machine.allow_root),
            Some("machine.allow_root")
        );
        assert_eq!(
            changed(&|c| c.machine.sudo_path = Some("/tmp/sudo".into())),
            Some("machine.sudo_path")
        );
        assert_eq!(
            changed(&|c| c.machine.shell = Some("/tmp/sh".into())),
            Some("machine.shell")
        );
        assert_eq!(changed(&|c| c.locked = true), None);
    }

    /// The folders' flags go (the node gives its own), and a relative folder
    /// is made whole with the caller's folder, once.
    #[test]
    fn forwarded_arguments_name_no_folders_of_the_callers() {
        let os = |a: &[&str]| a.iter().map(std::ffi::OsString::from).collect::<Vec<_>>();
        let given = ["--config-dir", "/etc/nerve", "--json", "status"];
        let c = cli(&given);
        assert_eq!(
            forwarded_args(&c, os(&given), None).unwrap(),
            ["--json", "status"]
        );
        let given = [
            "--state-dir=/var/lib/nerve/state",
            "folder",
            "add",
            "src",
            "+r",
        ];
        let c = cli(&given);
        assert_eq!(
            forwarded_args(&c, os(&given), Some("/home/a".into())).unwrap(),
            ["folder", "add", "/home/a/src", "+r"]
        );
        // Without a folder to make it whole, it is refused.
        assert!(forwarded_args(&c, os(&given), None).is_err());
        // A whole one goes as it is.
        let given = ["folder", "rm", "/srv/x"];
        assert_eq!(
            forwarded_args(&cli(&given), os(&given), None).unwrap(),
            given
        );
    }

    /// A character cut between two reads waits for its other bytes.
    #[test]
    fn text_is_cut_between_characters_only() {
        let mut p = "aé".as_bytes().to_vec();
        let last = p.pop().unwrap();
        assert_eq!(take_text(&mut p), "a");
        p.push(last);
        assert_eq!(take_text(&mut p), "é");
        assert!(p.is_empty());
        let mut bad = vec![b'x', 0xff, b'y'];
        assert_eq!(take_text(&mut bad), "x\u{fffd}y");
    }
}
