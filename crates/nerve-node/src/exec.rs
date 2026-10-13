//! The `exec` capability (spec §7.3): shell commands, each in its own
//! process group so the whole tree can be signalled and is killed when the
//! call ends or the link drops. Windows has no process groups; there each
//! command runs in a job object of its own (crate::job), and only when
//! Windows makes none does the node record the processes below the shell
//! while it runs (crate::tree), best effort.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde::Deserialize;
use serde_json::{Map, Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

use nerve_policy::NodeConfig;
use nerve_policy::config::{Access, CenterPolicy, Folder};
use nerve_policy::paths::{to_wire, within};
use nerve_policy::protected::{Platform, Protected};
use nerve_policy::{Target, protected::expand};
use nerve_proto::rpc::params;
use nerve_proto::{ErrorCode, RpcError};
use nerve_sandbox::{LandlockSpec, SHIM_ARG, ShimSpec};

use crate::fs::WirePath;

/// The most of stdout and of stderr a result carries, whatever the config
/// says, so the result fits the 4 MiB message limit.
pub const OUTPUT_HARD_CAP: usize = 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunArgs {
    command: String,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    timeout_ms: Option<u64>,
}

/// A parsed `exec.run`.
#[derive(Debug, Clone)]
pub struct RunCall {
    pub command: String,
    pub cwd: PathBuf,
    pub timeout: Option<Duration>,
}

impl RunCall {
    /// `cwd` defaults to `home`, the home of the account the command runs
    /// as. On the installed node the folder is looked at as that account
    /// (crate::account::FsAs).
    pub fn parse(args: &Map<String, Value>, home: &Path) -> Result<RunCall, RpcError> {
        let a: RunArgs = params(args)?;
        if a.command.trim().is_empty() {
            return Err(RpcError::invalid_args("command is empty"));
        }
        let cwd = match a.cwd {
            Some(c) => WirePath::parse(&c)?.real,
            None => home.to_path_buf(),
        };
        if !cwd.is_dir() {
            return Err(crate::fs::bad_path(format!(
                "{} is not a directory",
                to_wire(&cwd)
            )));
        }
        Ok(RunCall {
            command: a.command,
            cwd,
            timeout: a.timeout_ms.filter(|t| *t > 0).map(Duration::from_millis),
        })
    }

    /// The working directory is judged as a read; the command itself by the
    /// command rules and the folders that allow running.
    pub fn targets(&self) -> Vec<Target> {
        vec![Target {
            path: self.cwd.clone(),
            write: false,
        }]
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignalArgs {
    pub call: Value,
    pub signal: String,
}

/// The shell program and its arguments for `command`.
pub fn shell_command(shell: Option<&str>, command: &str) -> (String, Vec<String>) {
    let default = if cfg!(windows) {
        "powershell.exe"
    } else {
        "/bin/sh"
    };
    let sh = shell.unwrap_or(default).to_string();
    let lower = sh.to_lowercase();
    let flag = if lower.contains("powershell") || lower.contains("pwsh") {
        vec!["-NoProfile".to_string(), "-Command".to_string()]
    } else if lower.ends_with("cmd.exe") || lower == "cmd" {
        vec!["/C".to_string()]
    } else {
        vec!["-c".to_string()]
    };
    let mut args = flag;
    args.push(command.into());
    (sh, args)
}

/// A Windows command line for `program` and `args`, quoted as the Rust
/// standard library quotes one for `CreateProcessW` (the rules of the
/// Microsoft C runtime): a command started with another account's token
/// (crate::win_user) gets the same arguments as one the node starts as
/// itself.
pub fn windows_command_line(program: &str, args: &[String]) -> String {
    let mut line = format!("\"{program}\"");
    for a in args {
        line.push(' ');
        let quote = a.is_empty() || a.contains([' ', '\t']);
        if quote {
            line.push('"');
        }
        // Backslashes count only before a quote: doubled there, and one
        // more escapes the quote itself.
        let mut backslashes = 0;
        for c in a.chars() {
            if c == '\\' {
                backslashes += 1;
            } else {
                if c == '"' {
                    line.extend(std::iter::repeat_n('\\', backslashes + 1));
                }
                backslashes = 0;
            }
            line.push(c);
        }
        if quote {
            line.extend(std::iter::repeat_n('\\', backslashes));
            line.push('"');
        }
    }
    line
}

/// An account's environment (`NAME=value` entries) pointed at its profile
/// folder `home`. While the account is not signed in its registry is not
/// loaded, and Windows builds the environment from the default profile,
/// without the folders of the account's own: those are set as a sign-in
/// sets them, and any other value below the default profile is moved to
/// `home`. The entries come sorted by name, as Windows wants them.
pub fn rehome_env(vars: Vec<String>, home: &str) -> Vec<String> {
    let name = |v: &str| {
        v.split_once('=')
            .map_or(String::new(), |(n, _)| n.to_uppercase())
    };
    let Some(profile) = vars.iter().find_map(|v| {
        let (n, val) = v.split_once('=')?;
        n.eq_ignore_ascii_case("USERPROFILE")
            .then(|| val.to_string())
    }) else {
        return vars;
    };
    if profile.eq_ignore_ascii_case(home) || profile.is_empty() {
        return vars;
    }
    let (drive, path) = match home.get(..2) {
        Some(d) if d.ends_with(':') => (d, &home[2..]),
        _ => ("", home),
    };
    let own = [
        ("USERPROFILE", home.to_string()),
        ("HOMEDRIVE", drive.to_string()),
        ("HOMEPATH", path.to_string()),
        ("APPDATA", format!("{home}\\AppData\\Roaming")),
        ("LOCALAPPDATA", format!("{home}\\AppData\\Local")),
        ("TEMP", format!("{home}\\AppData\\Local\\Temp")),
        ("TMP", format!("{home}\\AppData\\Local\\Temp")),
    ];
    let mut out: Vec<String> = vars
        .into_iter()
        .filter(|v| !own.iter().any(|(n, _)| *n == name(v)))
        .map(|v| {
            let Some((n, val)) = v.split_once('=') else {
                return v;
            };
            let below = val
                .get(..profile.len())
                .is_some_and(|p| p.eq_ignore_ascii_case(&profile))
                && matches!(val[profile.len()..].chars().next(), None | Some('\\'));
            if below {
                format!("{n}={home}{}", &val[profile.len()..])
            } else {
                v
            }
        })
        .collect();
    out.extend(own.iter().map(|(n, v)| format!("{n}={v}")));
    out.sort_by_key(|v| name(v));
    out
}

/// What the `exec.run` action says about the shell, so a model writes the
/// syntax of the shell that runs it: Windows PowerShell 5.1 is the default
/// on Windows, and cmd's `a & b` is a parser error there.
pub fn shell_summary(shell: Option<&str>) -> String {
    let (sh, mut args) = shell_command(shell, "");
    args.pop();
    let line = format!("`{sh} {}`", args.join(" "));
    let lower = sh.to_lowercase();
    if lower.contains("pwsh") {
        format!("Runs a command in PowerShell 7 ({line}): PowerShell syntax, not cmd or sh.")
    } else if lower.contains("powershell") {
        format!(
            "Runs a command in Windows PowerShell 5.1 ({line}): PowerShell syntax, not cmd or sh. \
             Chain commands with `;`; `&&` and `a & b` are parser errors there."
        )
    } else if args == ["/C"] {
        format!("Runs a command in cmd ({line}): cmd syntax.")
    } else {
        format!("Runs a command with {line}.")
    }
}

/// Command output as text. UTF-8 is taken as it is, also when the cap cut
/// its last character (`cut`); other bytes are decoded by `other`, the code
/// page the shell wrote in (Windows PowerShell 5.1 writes the console code
/// page, not UTF-8), and what neither reads is replaced.
pub fn output_text(bytes: &[u8], cut: bool, other: impl Fn(&[u8]) -> Option<String>) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(e) if cut && e.error_len().is_none() => String::from_utf8_lossy(bytes).into_owned(),
        Err(_) => other(bytes).unwrap_or_else(|| String::from_utf8_lossy(bytes).into_owned()),
    }
}

/// [`output_text`] with this platform's other encoding: the console code
/// page on Windows, none elsewhere.
fn decode(bytes: &[u8], cut: bool) -> String {
    #[cfg(windows)]
    let other = |b: &[u8]| crate::win::code_page_text(crate::win::console_code_page(), b);
    #[cfg(not(windows))]
    let other = |_: &[u8]| None;
    output_text(bytes, cut, other)
}

/// The Landlock rules for a command of a center in `folders` mode: it reads
/// the system and its `r` folders, writes its `w` folders, runs programs from
/// the system and its `x` folders. The three flags are independent, so each
/// set takes the folders with its own flag and nothing else: a folder with
/// only `w` is in `write` alone, and the write rule carries no read right
/// (the command can put files there but not list or read them), and a folder
/// with only `x` can run its programs but not be listed: Landlock refuses to
/// run a file it may not read, so the `exec` rule carries ReadFile and the
/// files there can be read by name. The node's own folders
/// (`own`: its config, keys and state) are in none of these sets, whatever
/// the folders say ([`leave_out`]).
///
/// Each folder is resolved again here, since it may have become a link
/// after it was added and Landlock follows a link in a rule's path: one
/// that now leads into a protected entry the folders do not release with
/// its flags is left out and the reason logged (`Protected::real_folder`).
/// The others go in by their real path, the place that was judged.
///
/// A folder that holds a protected entry gives none of it either: it is
/// replaced by its other entries, level by level down to the protected one,
/// as the own folders are ([`leave_protected_out`]). The write set leaves
/// out the entries protected for writes as well. The system folders are not
/// cut: what a command reads there is the system's to guard.
///
/// A folder whose resolution crosses a link at or inside a place where
/// commands may write (`writable`, configured paths, `~` expanded: the `w`
/// folders of every center, since another center's command may be the one
/// that wrote) is left out ([`led_away`]): a command may have put that link,
/// and the rule would grant the folder's flags wherever it leads.
pub fn landlock_spec(
    policy: &CenterPolicy,
    home: &Path,
    own: &[PathBuf],
    writable: &[PathBuf],
) -> LandlockSpec {
    // Landlock is Linux's, so the list is the Unix one.
    let protected = Protected::new(&Platform::Unix, home, own, &policy.protected);
    // The boundary is judged by resolved places, so a writable folder
    // reached by one spelling catches a folder configured by another.
    let bounds: Vec<PathBuf> = writable.iter().map(|w| real(w)).collect();
    let real: Vec<(Access, PathBuf)> = policy
        .folders
        .iter()
        .filter_map(|x| {
            let path = expand(home, &x.path)?;
            let folder = Folder {
                path: path.display().to_string(),
                access: x.access,
            };
            let real = protected
                .real_folder(&folder, &policy.folders)
                .and_then(|real| match led_away(&path, &bounds) {
                    Some(why) => Err(why),
                    None => Ok(real),
                });
            match real {
                Ok(real) => Some((x.access, real)),
                Err(why) => {
                    tracing::warn!("folder {} left out of the command's sandbox: {why}", x.path);
                    None
                }
            }
        })
        .collect();
    let folders = |f: &dyn Fn(Access) -> bool, write: bool| -> Vec<PathBuf> {
        let granted: Vec<PathBuf> = real
            .iter()
            .filter(|(a, _)| f(*a))
            .map(|(_, p)| p.clone())
            .collect();
        leave_protected_out(&granted, &protected, write)
    };
    LandlockSpec {
        read: leave_out(
            &[nerve_sandbox::system_dirs(), folders(&|a| a.read, false)].concat(),
            own,
        ),
        write: leave_out(
            &[
                nerve_sandbox::system_writable(),
                folders(&|a| a.write, true),
            ]
            .concat(),
            own,
        ),
        exec: leave_out(
            &[nerve_sandbox::system_dirs(), folders(&|a| a.execute, false)].concat(),
            own,
        ),
        connect: None,
    }
}

/// Where a command of `folders` mode may connect to socket files while the
/// node's keys are in the keyring: anywhere but the folders in `own`, which
/// then hold the session bus the keyring answers on
/// (crate::paths::keyring_places). With the files the rule is not set, and
/// commands connect where they did.
pub fn connect_rule(own: &[PathBuf]) -> Vec<PathBuf> {
    leave_out(&[PathBuf::from("/")], own)
}

/// The configured folders where commands may write: the `w` folders of every
/// center in `cfg` (`~` expanded with `home`), whatever the center's mode. A
/// command of one center can replace a folder of another that lies inside
/// one of them, so `landlock_spec` judges the folders against all of these.
pub fn write_folders(cfg: &NodeConfig, home: &Path) -> Vec<PathBuf> {
    cfg.centers
        .iter()
        .flat_map(|c| &c.policy.folders)
        .filter(|f| f.access.write)
        .filter_map(|f| expand(home, &f.path))
        .collect()
}

/// Why resolving `path` leads out of its own place: a link on the way lies at
/// or inside a place where commands may write (`writable`, resolved). `path`
/// is walked component by component; once the resolved prefix is at or inside
/// a `writable` place, a component that resolves elsewhere than its plain
/// name is a link a command may have put there, and the folder is left out.
/// Above that boundary the links are the owner's and are followed, the
/// boundary's own component (the write folder itself may be a link of the
/// owner's) among them. Places are judged resolved, so a writable folder
/// reached by one spelling catches a folder configured by another.
fn led_away(path: &Path, writable: &[PathBuf]) -> Option<String> {
    use std::path::Component;
    let comps: Vec<_> = path.components().collect();
    // The root is the first step.
    let roots = comps
        .iter()
        .take_while(|c| matches!(c, Component::Prefix(_) | Component::RootDir))
        .count()
        .max(1);
    let mut inside = false;
    for i in roots..=comps.len() {
        let here = real(&comps[..i].iter().collect::<PathBuf>());
        // The place this component names without following a link of its
        // own: the resolved parent plus the component's name.
        let plain = if i == roots {
            here.clone()
        } else {
            real(&comps[..i - 1].iter().collect::<PathBuf>()).join(comps[i - 1].as_os_str())
        };
        if inside && !(within(&here, &plain) && within(&plain, &here)) {
            return Some(format!(
                "it leads to {} through a link inside a folder where commands may write",
                here.display()
            ));
        }
        if !inside && writable.iter().any(|w| within(&here, w)) {
            inside = true;
        }
    }
    None
}

/// `p` resolved; `p` itself when it cannot be resolved.
fn real(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

/// `paths` without the folders in `own`. A Landlock rule grants a folder and
/// everything below it and nothing can carve a hole into it, so a path inside
/// an own folder is dropped, and a path that holds one is replaced by its
/// other entries, level by level down to the own folder. What the command
/// loses there: listing those levels, and making new entries right in them.
///
/// Paths are compared resolved, because Landlock follows a symlink in a
/// rule's path; an entry that is a symlink to or around an own folder is
/// dropped as well.
pub fn leave_out(paths: &[PathBuf], own: &[PathBuf]) -> Vec<PathBuf> {
    let own: Vec<PathBuf> = own.iter().map(|o| real(o)).collect();
    let mut out = Vec::new();
    for p in paths {
        let r = real(p);
        if own.iter().any(|o| within(&r, o)) {
            continue;
        }
        if own.iter().any(|o| within(o, &r)) {
            let inside = |p: &Path| own.iter().any(|o| within(p, o));
            let holds = |p: &Path| own.iter().any(|o| within(o, p));
            split(&r, &inside, &holds, &mut out);
        } else {
            out.push(p.clone());
        }
    }
    out
}

/// `paths` without the protected entries (with `write`, also those
/// protected for writes) that lie strictly inside one of them: such a path
/// is replaced by its other entries, level by level down to the protected
/// one, like an own folder in [`leave_out`]. A path at or inside an entry
/// stays whole: it is a folder the owner released there, and
/// `Protected::real_folder` has judged it for its flags.
pub fn leave_protected_out(paths: &[PathBuf], protected: &Protected, write: bool) -> Vec<PathBuf> {
    let inside = |p: &Path| protected.in_entry(p, write);
    let holds = |p: &Path| protected.holds_entry(p, write);
    let mut out = Vec::new();
    for p in paths {
        let r = std::fs::canonicalize(p).unwrap_or_else(|_| p.clone());
        if !inside(&r) && holds(&r) {
            split(&r, &inside, &holds, &mut out);
        } else {
            out.push(p.clone());
        }
    }
    out
}

/// Pushes the entries of `dir` (which holds a folder to leave out) that hold
/// none, and goes down into the ones that do. `inside` says whether a
/// resolved path is such a folder or inside one, `holds` whether one lies
/// below it.
fn split(
    dir: &Path,
    inside: &dyn Fn(&Path) -> bool,
    holds: &dyn Fn(&Path) -> bool,
    out: &mut Vec<PathBuf>,
) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let path = e.path();
        let link = e.file_type().is_ok_and(|t| t.is_symlink());
        let real = std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
        let held = holds(&real);
        if inside(&real) || (held && link) {
            continue;
        }
        if held {
            split(&real, inside, holds, out);
        } else {
            out.push(path);
        }
    }
}

/// How one command runs.
#[derive(Debug, Clone)]
pub struct RunOptions {
    pub shell: Option<String>,
    /// Confine with these rules through the shim (`exe __exec-shim`).
    pub landlock: Option<LandlockSpec>,
    /// The `nerve-node` binary that hosts the shim.
    pub exe: PathBuf,
    pub output_cap: usize,
    /// Set only for a `sudo` command the sudo allow list names (already rewritten with
    /// [`sudo_line`]): the password goes to sudo's stdin once sudo shows the
    /// prompt. Every other command runs with no_new_privs (Linux), so a
    /// `sudo` the rules did not see (`ls; sudo x`) cannot gain privileges.
    pub sudo: Option<SudoInput>,
    /// The account the command runs as (the installed node, every mode,
    /// crate::account); `None` runs it as the node's own user.
    pub account: Option<crate::service::Account>,
    /// The node's own folders, which the account must not reach.
    pub own: Vec<PathBuf>,
}

/// What a sudo command needs: the password and the prompt sudo was told to
/// show before it reads one ([`sudo_prompt`]).
#[derive(Debug, Clone)]
pub struct SudoInput {
    pub password: String,
    pub prompt: String,
}

/// How long a sudo command's stdin stays open for a prompt that has not come
/// while sudo has not started the command either.
const PROMPT_WAIT: Duration = Duration::from_secs(10);
/// How often the node looks whether sudo started the command.
const PROMPT_POLL: Duration = Duration::from_millis(25);
/// Stderr a sudo prints before its prompt is short; past this much the
/// prompt is not looked for any more.
const PROMPT_SCAN_MAX: usize = 64 * 1024;

/// Quotes `s` for a POSIX shell.
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// A fresh prompt for one sudo command: random, so output that only happens
/// to look like a prompt is not answered with the password. Letters, digits
/// and `-` only, which sudo prints as they are.
pub fn sudo_prompt() -> String {
    format!("nerve-sudo-{}:", nerve_transport::keys::random_token(16))
}

/// The command line that runs `args` (what followed `sudo`) through
/// `sudo_path`, reading the password from stdin. `-k` makes sudo ignore a
/// cached credential; sudo still asks for nothing for a NOPASSWD entry or as
/// root, so the node writes the password only after sudo printed `prompt`
/// (`run`), and a command sudo starts without asking never gets it. The
/// shell `exec`s sudo, so the process the node started is sudo itself and
/// its first child is the command.
///
/// Windows has no sudo program: the line is what followed `sudo`, which
/// the shell runs with the account's administrator token (`run`,
/// crate::winsudo).
pub fn sudo_line(sudo_path: &str, args: &str, prompt: &str) -> String {
    if cfg!(windows) {
        return args.to_string();
    }
    format!(
        "exec {} -S -k -p {} {args}",
        sh_quote(sudo_path),
        sh_quote(prompt)
    )
}

/// Checks `password` with `sudo -S -k -v`, which runs nothing and caches
/// nothing; its output is discarded. It runs as `account`, the account the
/// commands run as (crate::account), so sudo checks that account's
/// password; `None` runs it as the node's own user.
pub async fn sudo_check(
    sudo_path: &str,
    password: &str,
    account: Option<&crate::service::Account>,
) -> Result<(), String> {
    let mut cmd = Command::new(sudo_path);
    cmd.args(["-S", "-k", "-v", "-p", ""])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    #[cfg(target_os = "linux")]
    {
        let switch = account
            .map(|a| crate::account::Switch::new(a, None, &[]))
            .transpose()
            .map_err(|e| e.to_string())?;
        // SAFETY: plain system calls on memory moved into the closure.
        unsafe {
            cmd.pre_exec(move || match &switch {
                Some(s) => s.apply(),
                None if nerve_transport::net::euid() != 0 => crate::account::drop_caps(),
                None => Ok(()),
            });
        }
    }
    if let Some(a) = account {
        cmd.env("HOME", &a.home)
            .env("USER", &a.name)
            .env("LOGNAME", &a.name);
    }
    let as_whom = account.map_or(String::new(), |a| format!(" as {}", a.name));
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("cannot run {sudo_path}{as_whom}: {e}"))?;
    let mut stdin = child.stdin.take().expect("piped");
    // sudo may exit before reading (no such user in sudoers); the exit
    // status says what matters.
    let _ = stdin.write_all(format!("{password}\n").as_bytes()).await;
    drop(stdin);
    match tokio::time::timeout(Duration::from_secs(30), child.wait()).await {
        Ok(Ok(s)) if s.success() => Ok(()),
        Ok(Ok(_)) => Err(format!(
            "the sudo password is wrong (sudo -v{as_whom} refused it)"
        )),
        Ok(Err(e)) => Err(format!("waiting for sudo: {e}")),
        Err(_) => Err("sudo -v did not answer within 30 s".into()),
    }
}

/// What ends one running command, for its call and `exec.signal`: its
/// process group on Unix; on Windows its job (crate::job), or, when Windows
/// made none, the processes recorded below its shell (crate::tree). It is the
/// call's, so a pid that Windows gave to another process after the shell
/// exited leads nowhere.
#[derive(Clone)]
pub struct Ender {
    pid: u32,
    /// The account the command runs as, when it is not the node's: the
    /// node signals it as that account.
    #[cfg(unix)]
    uid: Option<u32>,
    #[cfg(windows)]
    ending: crate::job::Ending<crate::win::Job, Option<std::sync::Arc<crate::tree::Watch>>>,
}

impl Ender {
    /// The shell's pid.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Whether the command runs in a job of its own.
    #[cfg(windows)]
    pub fn has_job(&self) -> bool {
        self.ending.has_job()
    }

    /// Signals the command's processes. On Windows every signal ends them.
    pub fn signal(&self, sig: Sig) {
        #[cfg(windows)]
        {
            let _ = sig;
            self.ending.end(|w| {
                if let Some(w) = w {
                    w.kill();
                }
            });
        }
        #[cfg(unix)]
        kill_group(self.pid, sig, self.uid);
        #[cfg(not(any(unix, windows)))]
        kill_group(self.pid, sig);
    }
}

/// Kills the command's whole process group when dropped: a cancelled call, a
/// dropped link and a finished command all leave nothing behind.
struct Group(Option<Ender>);

impl Group {
    #[cfg(unix)]
    fn start(pid: Option<u32>, uid: Option<u32>) -> Group {
        Group(pid.map(|pid| Ender { pid, uid }))
    }

    #[cfg(not(any(unix, windows)))]
    fn start(pid: Option<u32>) -> Group {
        Group(pid.map(|pid| Ender { pid }))
    }

    /// `job` is the shell's job; without one the processes below the shell
    /// are recorded while it runs.
    #[cfg(windows)]
    fn start(pid: Option<u32>, job: Option<std::sync::Arc<crate::win::Job>>) -> Group {
        use crate::job::Ending;
        Group(pid.map(|pid| Ender {
            pid,
            ending: match job {
                Some(j) => Ending::Job(j),
                None => Ending::Walk(crate::tree::watch(pid)),
            },
        }))
    }
}

impl Drop for Group {
    fn drop(&mut self) {
        if let Some(e) = &self.0 {
            e.signal(Sig::Kill);
            #[cfg(windows)]
            if let crate::job::Ending::Walk(Some(w)) = &e.ending {
                w.forget();
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sig {
    Term,
    Kill,
    Int,
}

impl Sig {
    pub fn parse(s: &str) -> Option<Sig> {
        match s {
            "term" => Some(Sig::Term),
            "kill" => Some(Sig::Kill),
            "int" => Some(Sig::Int),
            _ => None,
        }
    }
}

/// Signals the process group led by `pid`, as `uid` when the command runs
/// as another account.
#[cfg(unix)]
fn kill_group(pid: u32, sig: Sig, uid: Option<u32>) {
    let s = match sig {
        Sig::Term => libc::SIGTERM,
        Sig::Kill => libc::SIGKILL,
        Sig::Int => libc::SIGINT,
    };
    #[cfg(target_os = "linux")]
    if let Some(uid) = uid {
        crate::account::kill_as(uid, pid, s);
        return;
    }
    #[cfg(not(target_os = "linux"))]
    let _ = uid;
    // SAFETY: kill with a negative pid signals that process group only.
    unsafe {
        libc::kill(-(pid as libc::pid_t), s);
    }
}

#[cfg(not(any(unix, windows)))]
fn kill_group(_pid: u32, _sig: Sig) {}

/// Reads up to `cap` bytes and drains the rest, so the command never blocks
/// on a full pipe. Returns the bytes and whether some were dropped.
async fn capped(mut r: impl AsyncRead + Unpin, cap: usize) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 16 * 1024];
    let mut cut = false;
    loop {
        match r.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let room = cap.saturating_sub(out.len());
                if n > room {
                    cut = true;
                }
                out.extend_from_slice(&buf[..n.min(room)]);
            }
        }
    }
    (out, cut)
}

/// A sudo command's stderr, like [`capped`], and its stdin: the password is
/// written only once sudo has printed `sudo.prompt`, then stdin is closed.
/// When sudo asks for nothing (NOPASSWD, root) it starts the command right
/// away; stdin is then closed without the password as soon as sudo has a
/// child process, the process ends, or [`PROMPT_WAIT`] passes. The prompt is
/// left out of the stderr returned.
async fn sudo_stderr(
    mut err: tokio::process::ChildStderr,
    stdin: tokio::process::ChildStdin,
    sudo: &SudoInput,
    pid: Option<u32>,
    cap: usize,
) -> (Vec<u8>, bool) {
    let prompt = sudo.prompt.as_bytes();
    let mut stdin = Some(stdin);
    let mut seen = Vec::new();
    let mut buf = vec![0u8; 16 * 1024];
    let until = tokio::time::Instant::now() + PROMPT_WAIT;
    while stdin.is_some() {
        match tokio::time::timeout(PROMPT_POLL, err.read(&mut buf)).await {
            Ok(Ok(0) | Err(_)) => {
                // Everything that held stderr is gone; so is the command.
                stdin = None;
            }
            Ok(Ok(n)) => {
                seen.extend_from_slice(&buf[..n]);
                if seen.windows(prompt.len()).any(|w| w == prompt) {
                    let mut s = stdin.take().expect("still open");
                    // A sudo that fails early closes the pipe; its exit code tells.
                    let _ = s.write_all(format!("{}\n", sudo.password).as_bytes()).await;
                } else if seen.len() > PROMPT_SCAN_MAX {
                    stdin = None;
                }
            }
            Err(_) => {
                if pid.is_some_and(has_child) || tokio::time::Instant::now() >= until {
                    stdin = None;
                }
            }
        }
    }
    let (rest, cut) = capped(err, cap).await;
    seen.extend_from_slice(&rest);
    let mut out = Vec::with_capacity(seen.len().min(cap));
    let mut i = 0;
    while i < seen.len() {
        if seen[i..].starts_with(prompt) {
            i += prompt.len();
        } else {
            out.push(seen[i]);
            i += 1;
        }
    }
    let cut = cut || out.len() > cap;
    out.truncate(cap);
    (out, cut)
}

/// Whether some process has `pid` as its parent: sudo forks the command it
/// runs, so a child means sudo is past asking for a password. A shell that
/// did not `exec` sudo has sudo as its child at once; stdin then closes
/// early and a sudo that asks fails, which leaks nothing.
#[cfg(target_os = "linux")]
fn has_child(pid: u32) -> bool {
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return false;
    };
    dir.flatten().any(|e| {
        let name = e.file_name();
        let Some(name) = name
            .to_str()
            .filter(|n| n.bytes().all(|b| b.is_ascii_digit()))
        else {
            return false;
        };
        // `pid (comm) state ppid ...`; comm may hold spaces and parentheses.
        std::fs::read_to_string(format!("/proc/{name}/stat")).is_ok_and(|s| {
            s.rsplit_once(')')
                .and_then(|(_, rest)| rest.split_whitespace().nth(1)?.parse::<u32>().ok())
                == Some(pid)
        })
    })
}

#[cfg(not(target_os = "linux"))]
fn has_child(_pid: u32) -> bool {
    // Only Linux runs a sudo program; elsewhere the wait or the end decides.
    false
}

/// Runs `call`. `started` hears what ends the command once it runs (for
/// `exec.signal`, and its pid for the control socket's ancestry check).
pub async fn run(
    call: &RunCall,
    opts: &RunOptions,
    started: impl FnOnce(&Ender),
) -> Result<Value, RpcError> {
    let (program, args) = shell_command(opts.shell.as_deref(), &call.command);
    let shim = opts.landlock.as_ref().map(|l| ShimSpec {
        program: program.clone().into(),
        args: args.clone(),
        parent: std::process::id(),
        landlock: Some(l.clone()),
    });
    #[cfg(windows)]
    if let Some(a) = &opts.account {
        return run_as(call, opts, a, &program, &args, started).await;
    }
    // Only the installed node can start a command with the administrator
    // token of the account commands run as (crate::winsudo).
    #[cfg(windows)]
    if opts.sudo.is_some() {
        return Err(RpcError::new(
            ErrorCode::Unavailable,
            crate::winsudo::INSTALLED_ONLY,
        ));
    }
    let mut cmd = match &shim {
        Some(_) => {
            let mut c = Command::new(&opts.exe);
            c.arg(SHIM_ARG).stdin(Stdio::piped());
            c
        }
        None => {
            let mut c = Command::new(&program);
            c.args(&args).stdin(if opts.sudo.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            });
            c
        }
    };
    // A command of another account takes its ids, drops the service's
    // capabilities and enters its folder in the child (crate::account);
    // any other drops the capabilities.
    #[cfg(target_os = "linux")]
    {
        let switch = match &opts.account {
            Some(a) => Some(
                crate::account::Switch::new(a, Some(&call.cwd), &opts.own)
                    .map_err(|e| RpcError::invalid_args(e.to_string()))?,
            ),
            None => None,
        };
        // Root as the account (the owner chose it, warned) gets root's
        // rights back at exec, which no_new_privs would keep from it.
        let nnp = opts.sudo.is_none() && opts.account.as_ref().is_none_or(|a| a.uid != 0);
        // SAFETY: plain system calls on memory moved into the closure.
        unsafe {
            cmd.pre_exec(move || {
                match &switch {
                    Some(s) => s.apply()?,
                    None if nerve_transport::net::euid() != 0 => crate::account::drop_caps()?,
                    None => {}
                }
                if nnp && libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    if let Some(a) = &opts.account {
        return Err(RpcError::new(
            ErrorCode::Unavailable,
            format!("cannot run commands as {}: Linux and Windows only", a.name),
        ));
    }
    match &opts.account {
        Some(a) => {
            cmd.env("HOME", &a.home)
                .env("USER", &a.name)
                .env("LOGNAME", &a.name);
        }
        None => {
            cmd.current_dir(&call.cwd);
        }
    }
    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    cmd.process_group(0);
    // The shell starts suspended and runs only once it is in its job, so
    // nothing it starts escapes the job. No console is needed for this, so
    // a node that runs as a service does the same.
    #[cfg(windows)]
    let job = crate::job::make();
    #[cfg(windows)]
    if job.is_some() {
        cmd.creation_flags(crate::job::SUSPENDED);
    }
    let mut child = cmd.spawn().map_err(|e| {
        RpcError::new(
            ErrorCode::Unavailable,
            match &opts.account {
                #[cfg(target_os = "linux")]
                Some(a) if e.raw_os_error() == Some(crate::account::IN_REACH) => format!(
                    "cannot start as {}: that account can open the node's own folders, where its keys are",
                    a.name
                ),
                Some(a) => format!(
                    "cannot start as {} in {}: {e}",
                    a.name,
                    to_wire(&call.cwd)
                ),
                None => format!("cannot start: {e}"),
            },
        )
    })?;
    #[cfg(windows)]
    let job = match job {
        Some(job) => Some(
            crate::job::adopt(job, &mut child)
                .map_err(|e| RpcError::new(ErrorCode::Unavailable, e))?,
        ),
        None => None,
    };
    #[cfg(windows)]
    let group = Group::start(child.id(), job);
    #[cfg(unix)]
    let group = Group::start(child.id(), opts.account.as_ref().map(|a| a.uid));
    #[cfg(not(any(unix, windows)))]
    let group = Group::start(child.id());
    let mut sudo_stdin = None;
    if let Some(spec) = shim {
        let mut stdin = child.stdin.take().expect("piped");
        let json = serde_json::to_vec(&spec).map_err(|e| RpcError::internal(e.to_string()))?;
        stdin
            .write_all(&json)
            .await
            .map_err(|e| RpcError::internal(format!("cannot hand the shim its spec: {e}")))?;
        drop(stdin);
    } else if let Some(sudo) = &opts.sudo {
        sudo_stdin = Some((child.stdin.take().expect("piped"), sudo));
    }
    let pid = child.id();
    if let Some(e) = &group.0 {
        started(e);
    }
    let stdout = child.stdout.take().expect("piped");
    let stderr = child.stderr.take().expect("piped");
    let cap = opts.output_cap.min(OUTPUT_HARD_CAP);
    let err = async {
        match sudo_stdin {
            Some((stdin, sudo)) => sudo_stderr(stderr, stdin, sudo, pid, cap).await,
            None => capped(stderr, cap).await,
        }
    };
    let work = async {
        let (o, e, st) = tokio::join!(capped(stdout, cap), err, child.wait());
        (o, e, st)
    };
    let (out, err, status, timed_out) = match call.timeout {
        Some(t) => match tokio::time::timeout(t, work).await {
            Ok((o, e, s)) => (o, e, Some(s), false),
            Err(_) => ((Vec::new(), false), (Vec::new(), false), None, true),
        },
        None => {
            let (o, e, s) = work.await;
            (o, e, Some(s), false)
        }
    };
    drop(group);
    if timed_out {
        return Err(RpcError::new(
            ErrorCode::Timeout,
            "the command ran past timeout_ms and was killed",
        ));
    }
    let status = status
        .expect("set unless timed out")
        .map_err(|e| RpcError::internal(format!("waiting for the command: {e}")))?;
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut result = json!({
        "exit_code": status.code(),
        "stdout": decode(&out.0, out.1),
        "stderr": decode(&err.0, err.1),
        "truncated": out.1 || err.1,
    });
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(s) = status.signal() {
            let name = match s {
                libc::SIGTERM => "term".to_string(),
                libc::SIGKILL => "kill".to_string(),
                libc::SIGINT => "int".to_string(),
                n => format!("signal {n}"),
            };
            result["signal"] = name.into();
        }
    }
    Ok(result)
}

/// [`run`] as another account on Windows (crate::win_user): the shell
/// starts suspended with the account's token in the call's folder, is put
/// in a job of its own and runs only then. It does not start when its
/// account can open the node's own folders, nor without a job: the node
/// may not end another account's processes one by one, only the job. A
/// sudo command starts with the account's administrator token instead
/// (crate::winsudo), which can open every folder.
#[cfg(windows)]
async fn run_as(
    call: &RunCall,
    opts: &RunOptions,
    account: &crate::service::Account,
    program: &str,
    args: &[String],
    started: impl FnOnce(&Ender),
) -> Result<Value, RpcError> {
    let unavailable = |m: String| RpcError::new(ErrorCode::Unavailable, m);
    let token = crate::win_user::token_for(account)
        .map_err(|e| unavailable(format!("cannot start as {}: {e}", account.name)))?;
    let elevated = match &opts.sudo {
        Some(s) => Some(
            crate::win_user::sudo_token(&account.name, &s.password).map_err(|e| {
                unavailable(format!(
                    "cannot start as {} with its administrator rights: {e}",
                    account.name
                ))
            })?,
        ),
        None => None,
    };
    let reach = match elevated {
        Some(_) => Ok(None),
        None => crate::win_user::reach(&token, &opts.own),
    };
    match reach {
        Ok(None) => {}
        Ok(Some(_)) => {
            return Err(unavailable(format!(
                "cannot start as {}: that account can open the node's own folders, where its keys are",
                account.name
            )));
        }
        Err(e) => {
            return Err(unavailable(format!(
                "cannot start as {}: cannot check what it can open ({e})",
                account.name
            )));
        }
    }
    let job = crate::win::Job::new().map_err(|e| {
        unavailable(format!(
            "the command was not run: Windows made no job object for it ({e})"
        ))
    })?;
    let line = windows_command_line(program, args);
    let child = crate::win_user::spawn(
        elevated.as_ref().unwrap_or(token.as_ref()),
        &line,
        Some(&call.cwd),
        Some(&account.home),
    )
    .map_err(|e| {
        unavailable(format!(
            "cannot start as {} in {}: {e}",
            account.name,
            to_wire(&call.cwd)
        ))
    })?;
    if let Err(e) = job.assign(child.process()) {
        child.kill();
        return Err(unavailable(crate::job::assign_error(
            crate::win::in_job(child.process()),
            &e,
        )));
    }
    let job = std::sync::Arc::new(job);
    if let Err(e) = child.resume() {
        job.terminate();
        return Err(unavailable(format!(
            "the command was not run: its shell could not be resumed ({e})"
        )));
    }
    let group = Group::start(Some(child.pid), Some(job));
    if let Some(e) = &group.0 {
        started(e);
    }
    let wait = child
        .waiter()
        .map_err(|e| RpcError::internal(format!("waiting for the command: {e}")))?;
    let crate::win_user::Spawned { stdout, stderr, .. } = child;
    let cap = opts.output_cap.min(OUTPUT_HARD_CAP);
    let work = async {
        tokio::join!(
            capped(tokio::fs::File::from_std(stdout), cap),
            capped(tokio::fs::File::from_std(stderr), cap),
            async {
                tokio::task::spawn_blocking(wait)
                    .await
                    .map_err(std::io::Error::other)
                    .and_then(|r| r)
            }
        )
    };
    let (out, err, code) = match call.timeout {
        Some(t) => match tokio::time::timeout(t, work).await {
            Ok(r) => r,
            Err(_) => {
                drop(group);
                return Err(RpcError::new(
                    ErrorCode::Timeout,
                    "the command ran past timeout_ms and was killed",
                ));
            }
        },
        None => work.await,
    };
    drop(group);
    let code = code.map_err(|e| RpcError::internal(format!("waiting for the command: {e}")))?;
    Ok(json!({
        "exit_code": code as i32,
        "stdout": decode(&out.0, out.1),
        "stderr": decode(&err.0, err.1),
        "truncated": out.1 || err.1,
    }))
}

/// The command lines a command of another account gets on Windows.
#[cfg(test)]
mod command_line_tests {
    use super::windows_command_line;

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn arguments_are_quoted_as_the_standard_library_quotes_them() {
        assert_eq!(
            windows_command_line(
                "powershell.exe",
                &args(&["-NoProfile", "-Command", r#"echo "a b" \x\"#])
            ),
            r#""powershell.exe" -NoProfile -Command "echo \"a b\" \x\\""#
        );
        // Without a space no quotes, and a quote is escaped all the same,
        // with the backslashes before it doubled.
        assert_eq!(
            windows_command_line("cmd.exe", &args(&["/C", r#"a\"b"#, ""])),
            r#""cmd.exe" /C a\\\"b """#
        );
        assert_eq!(
            windows_command_line(r"C:\Program Files\x.exe", &args(&["a\tb", r"c\"])),
            "\"C:\\Program Files\\x.exe\" \"a\tb\" c\\"
        );
    }

    /// The environment Windows builds from the default profile names the
    /// account's own; one that names it already stays as it is.
    #[test]
    fn the_environment_names_the_accounts_profile() {
        let default = args(&[
            "=C:=C:\\",
            r"Path=C:\Windows\system32",
            r"USERPROFILE=C:\Users\Default",
            r"TEMP=C:\WINDOWS\TEMP",
            r"OneDrive=c:\users\default\OneDrive",
            r"OTHER=C:\Users\DefaultAppPool",
        ]);
        assert_eq!(
            super::rehome_env(default, r"D:\Users\bob"),
            args(&[
                "=C:=C:\\",
                r"APPDATA=D:\Users\bob\AppData\Roaming",
                r"HOMEDRIVE=D:",
                r"HOMEPATH=\Users\bob",
                r"LOCALAPPDATA=D:\Users\bob\AppData\Local",
                r"OneDrive=D:\Users\bob\OneDrive",
                r"OTHER=C:\Users\DefaultAppPool",
                r"Path=C:\Windows\system32",
                r"TEMP=D:\Users\bob\AppData\Local\Temp",
                r"TMP=D:\Users\bob\AppData\Local\Temp",
                r"USERPROFILE=D:\Users\bob",
            ])
        );
        let own = args(&[r"HOMEPATH=\x", r"USERPROFILE=C:\Users\bob"]);
        assert_eq!(super::rehome_env(own.clone(), r"C:\Users\bob"), own);
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use nerve_policy::config::Access;

    fn opts(cap: usize) -> RunOptions {
        RunOptions {
            shell: None,
            landlock: None,
            exe: PathBuf::from("/nonexistent"),
            output_cap: cap,
            sudo: None,
            account: None,
            own: Vec::new(),
        }
    }

    fn call(cmd: &str) -> RunCall {
        RunCall {
            command: cmd.into(),
            cwd: std::env::temp_dir(),
            timeout: Some(Duration::from_secs(10)),
        }
    }

    #[tokio::test]
    async fn runs_and_caps() {
        let r = run(&call("echo hi; echo err >&2; exit 3"), &opts(1024), |_| {})
            .await
            .unwrap();
        assert_eq!(r["exit_code"], 3);
        assert_eq!(r["stdout"], "hi\n");
        assert_eq!(r["stderr"], "err\n");
        assert_eq!(r["truncated"], false);
        let r = run(&call("head -c 5000 /dev/zero"), &opts(100), |_| {})
            .await
            .unwrap();
        assert_eq!(r["stdout"].as_str().unwrap().len(), 100);
        assert_eq!(r["truncated"], true);
    }

    fn sudo_input(password: &str) -> Option<SudoInput> {
        Some(SudoInput {
            password: password.into(),
            prompt: "nerve-sudo-test:".into(),
        })
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn only_a_sudo_command_may_gain_privileges() {
        // Like sudo, the probe asks with the prompt before it reads.
        let probe = "printf %s nerve-sudo-test: >&2; read l; echo got=$l; \
                     grep NoNewPrivs /proc/self/status";
        let r = run(&call(probe), &opts(1024), |_| {}).await.unwrap();
        let out = r["stdout"].as_str().unwrap();
        assert!(out.contains("got=\n"), "{out}");
        assert!(out.contains("NoNewPrivs:\t1"), "{out}");
        let mut o = opts(1024);
        o.sudo = sudo_input("pw");
        let r = run(&call(probe), &o, |_| {}).await.unwrap();
        let out = r["stdout"].as_str().unwrap();
        assert!(out.contains("got=pw\n"), "{out}");
        assert!(!out.contains("NoNewPrivs:\t1"), "{out}");
        assert_eq!(r["stderr"], "", "the prompt is left out: {r}");
    }

    /// Writes an executable script at `path` from another process. Written
    /// here, its descriptor would leak into a command that another test
    /// thread forks meanwhile, and running the script would fail with "Text
    /// file busy" until that command execs.
    #[cfg(target_os = "linux")]
    fn write_script(path: &Path, text: &str) {
        use std::io::Write;
        let mut c = std::process::Command::new("sh")
            .args(["-c", "cat > \"$0\" && chmod 755 \"$0\""])
            .arg(path)
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        c.stdin.take().unwrap().write_all(text.as_bytes()).unwrap();
        assert!(c.wait().unwrap().success(), "cannot write {path:?}");
    }

    /// A fake sudo at `dir/sudo`: with `asks` it prints its `-p` prompt to
    /// stderr and reads the password like `sudo -S`, else it asks for none
    /// (NOPASSWD, root). Either way it runs the command as its child.
    #[cfg(target_os = "linux")]
    fn fake_sudo(dir: &Path, asks: bool) -> String {
        let ask = if asks {
            "printf %s \"$p\" >&2\nIFS= read -r pw\n[ \"$pw\" = right-pw ] || exit 1\n"
        } else {
            ""
        };
        let sudo = dir.join("sudo");
        write_script(
            &sudo,
            &format!(
                "#!/bin/sh\nwhile [ $# -gt 0 ]; do case \"$1\" in -S|-k) shift ;; \
                 -p) p=\"$2\"; shift 2 ;; *) break ;; esac; done\n{ask}\"$@\"\n"
            ),
        );
        sudo.display().to_string()
    }

    /// `sudo on` checks the password of the account the commands run as:
    /// sudo -v runs as that account, so sudo asks for its password.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn the_sudo_check_runs_as_the_chosen_account() {
        let d = tempfile::tempdir().unwrap();
        let seen = d.path().join("seen");
        let sudo = d.path().join("sudo");
        // Like sudo -v: takes the password of the user it runs as.
        write_script(
            &sudo,
            &format!(
                "#!/bin/sh\nIFS= read -r pw\necho \"$USER $(id -u)\" > '{}'\n[ \"$pw\" = \"pw-of-$USER\" ]\n",
                seen.display()
            ),
        );
        let sudo = sudo.display().to_string();
        // SAFETY: plain getters.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        let chosen = crate::service::Account {
            name: "chosen".into(),
            uid,
            gid,
            comment: String::new(),
            home: d.path().to_path_buf(),
            groups: vec![gid],
        };
        sudo_check(&sudo, "pw-of-chosen", Some(&chosen))
            .await
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(&seen).unwrap(),
            format!("chosen {uid}\n")
        );
        let e = sudo_check(&sudo, "pw-of-nerve", Some(&chosen))
            .await
            .unwrap_err();
        assert!(e.contains("sudo -v as chosen refused it"), "{e}");
    }

    /// A sudo that asks for no password: the command it starts finds no
    /// password on its stdin, only its end.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_sudo_that_does_not_ask_leaves_the_command_no_password() {
        let d = tempfile::tempdir().unwrap();
        let sudo = fake_sudo(d.path(), false);
        let mut o = opts(1024);
        o.sudo = sudo_input("right-pw");
        let prompt = o.sudo.as_ref().unwrap().prompt.clone();
        let c = call(&sudo_line(&sudo, "cat", &prompt));
        let started = std::time::Instant::now();
        let r = run(&c, &o, |_| {}).await.unwrap();
        assert_eq!(r["exit_code"], 0, "{r}");
        assert_eq!(r["stdout"], "", "the command read the password: {r}");
        // Closed once sudo started the command, not after PROMPT_WAIT.
        assert!(
            started.elapsed() < PROMPT_WAIT / 2,
            "{:?}",
            started.elapsed()
        );
    }

    /// A sudo that asks gets the password after its prompt; the command
    /// after it finds stdin at its end.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_sudo_that_asks_gets_the_password() {
        let d = tempfile::tempdir().unwrap();
        let sudo = fake_sudo(d.path(), true);
        let mut o = opts(1024);
        o.sudo = sudo_input("right-pw");
        let prompt = o.sudo.as_ref().unwrap().prompt.clone();
        let c = call(&sudo_line(&sudo, "cat", &prompt));
        let r = run(&c, &o, |_| {}).await.unwrap();
        assert_eq!(r["exit_code"], 0, "{r}");
        assert_eq!(r["stdout"], "", "{r}");
        assert_eq!(r["stderr"], "", "the prompt is left out: {r}");
    }

    #[cfg(not(windows))]
    #[test]
    fn sudo_line_quotes_the_program() {
        assert_eq!(
            sudo_line("/opt/my sudo", "apt update", "p:"),
            "exec '/opt/my sudo' -S -k -p 'p:' apt update"
        );
        assert_eq!(sudo_line("a'b", "x", "p"), "exec 'a'\\''b' -S -k -p 'p' x");
        let p = sudo_prompt();
        assert!(p.starts_with("nerve-sudo-") && p.ends_with(':'), "{p}");
        assert!(!p.contains('%'), "sudo would expand it: {p}");
        assert_ne!(p, sudo_prompt());
    }

    /// Windows has no sudo program: the shell runs what followed `sudo`,
    /// started with the administrator token.
    #[cfg(windows)]
    #[test]
    fn sudo_line_is_the_command_on_windows() {
        assert_eq!(sudo_line("sudo", "net session", "p:"), "net session");
    }

    #[tokio::test]
    async fn timeout_kills_the_group() {
        let mut c = call("sleep 30 & sleep 30; wait");
        c.timeout = Some(Duration::from_millis(200));
        let mut pid = 0;
        let e = run(&c, &opts(1024), |p| pid = p.pid()).await.unwrap_err();
        assert_eq!(e.kind(), ErrorCode::Timeout);
        tokio::time::sleep(Duration::from_millis(100)).await;
        // SAFETY: signal 0 only checks whether the group exists.
        let alive = unsafe { libc::kill(-(pid as libc::pid_t), 0) } == 0;
        assert!(!alive, "the process group outlived the call");
    }

    /// With the keys in the keyring a command connects to socket files anywhere
    /// but the node's own folders, the session bus's among them: no rule holds
    /// those.
    #[test]
    fn the_connect_rule_leaves_the_own_folders_out() {
        let d = tempfile::tempdir().unwrap();
        let w = std::fs::canonicalize(d.path()).unwrap();
        for dir in ["run/user/1000", "run/user/1001", "run/lock"] {
            std::fs::create_dir_all(w.join(dir)).unwrap();
        }
        let bus = w.join("run/user/1000");
        let got = connect_rule(std::slice::from_ref(&bus));
        assert!(got.contains(&w.join("run/user/1001")), "{got:?}");
        assert!(got.contains(&w.join("run/lock")), "{got:?}");
        assert!(!got.iter().any(|p| bus.starts_with(p)), "{got:?}");
        assert!(!got.iter().any(|p| p.starts_with(&bus)), "{got:?}");
    }

    #[test]
    fn leaves_the_nodes_folders_out_of_every_set() {
        let d = tempfile::tempdir().unwrap();
        let w = std::fs::canonicalize(d.path()).unwrap();
        for dir in ["a", "deep/cfg/keys", "deep/sib", "other"] {
            std::fs::create_dir_all(w.join(dir)).unwrap();
        }
        std::fs::write(w.join("file.txt"), "x").unwrap();
        std::os::unix::fs::symlink(w.join("deep"), w.join("link")).unwrap();
        std::os::unix::fs::symlink(w.join("deep/cfg"), w.join("other/to-cfg")).unwrap();
        let own = [w.join("deep/cfg")];
        let mut got = leave_out(&[w.clone(), w.join("other")], &own);
        got.sort();
        got.dedup();
        // The folder that holds `cfg` is replaced by its other entries, down
        // to `cfg`; the symlink around it is gone; a folder beside it stays
        // whole (a symlink deeper inside is no rule, and Landlock judges what
        // it resolves to).
        let want: Vec<PathBuf> = ["a", "deep/sib", "file.txt", "other"]
            .iter()
            .map(|p| w.join(p))
            .collect();
        assert_eq!(got, want);
        assert!(leave_out(&[w.join("deep/cfg/keys")], &own).is_empty());
        assert!(leave_out(&[w.join("link/cfg")], &own).is_empty());
        // A symlink given as a folder is judged by where it leads.
        let mut via_link = leave_out(&[w.join("link")], &own);
        via_link.sort();
        assert_eq!(via_link, [w.join("deep/sib")]);

        let policy = CenterPolicy {
            folders: vec![nerve_policy::config::Folder {
                path: w.display().to_string(),
                access: Access::ALL,
            }],
            ..Default::default()
        };
        let spec = landlock_spec(&policy, &w, &own, &[]);
        for set in [&spec.read, &spec.write, &spec.exec] {
            assert!(set.contains(&w.join("a")), "{set:?}");
            assert!(!set.iter().any(|p| own[0].starts_with(p)), "{set:?}");
        }
    }

    /// A folder that is, or since became, a link into a protected entry is
    /// left out of every set, unless the folders release that place with its
    /// flags. The protected entry is the `.ssh` of a home in a temp dir.
    #[test]
    fn leaves_a_link_into_a_protected_entry_out() {
        let d = tempfile::tempdir().unwrap();
        let home = std::fs::canonicalize(d.path()).unwrap().join("home");
        let ssh = home.join(".ssh");
        let work = home.join("work");
        std::fs::create_dir_all(&ssh).unwrap();
        std::fs::create_dir_all(work.join("plain")).unwrap();
        std::os::unix::fs::symlink(&ssh, work.join("link")).unwrap();
        let folder = |p: &Path, access: &str| nerve_policy::config::Folder {
            path: p.display().to_string(),
            access: Access::parse(access).unwrap(),
        };
        let mut policy = CenterPolicy {
            folders: vec![
                folder(&work.join("link"), "rwx"),
                folder(&work.join("plain"), "rwx"),
            ],
            ..Default::default()
        };
        let reaches = |spec: &LandlockSpec, p: &Path| {
            [&spec.read, &spec.write, &spec.exec]
                .iter()
                .any(|set| set.iter().any(|s| s.starts_with(p)))
        };
        let spec = landlock_spec(&policy, &home, &[], &[]);
        assert!(!reaches(&spec, &ssh), "{spec:?}");
        assert!(!reaches(&spec, &work.join("link")), "{spec:?}");
        for set in [&spec.read, &spec.write, &spec.exec] {
            assert!(set.contains(&work.join("plain")), "{set:?}");
        }
        // The plain folder becomes a link after it was added.
        std::fs::remove_dir(work.join("plain")).unwrap();
        std::os::unix::fs::symlink(&ssh, work.join("plain")).unwrap();
        let spec = landlock_spec(&policy, &home, &[], &[]);
        assert!(!reaches(&spec, &ssh), "{spec:?}");
        assert!(!reaches(&spec, &work.join("plain")), "{spec:?}");
        // The owner released `.ssh` for reading: a link there reads it.
        policy.folders = vec![folder(&ssh, "r"), folder(&work.join("link"), "r")];
        let spec = landlock_spec(&policy, &home, &[], &[]);
        assert!(spec.read.contains(&ssh), "{spec:?}");
        assert!(!spec.write.iter().any(|s| s.starts_with(&ssh)), "{spec:?}");
    }

    /// A folder that holds a protected entry gives none of it: Landlock
    /// cannot deny inside a rule, so the folder is replaced by its other
    /// entries, level by level down to the protected one, in each set. The
    /// protected entries are those of a home in a temp dir.
    #[test]
    fn a_folder_around_a_protected_entry_leaves_it_out() {
        let d = tempfile::tempdir().unwrap();
        let home = std::fs::canonicalize(d.path()).unwrap().join("home");
        let ssh = home.join(".ssh");
        for dir in [".ssh", "other", ".local/bin"] {
            std::fs::create_dir_all(home.join(dir)).unwrap();
        }
        std::os::unix::fs::symlink(&ssh, home.join("to-ssh")).unwrap();
        let folder = |p: &Path, access: &str| nerve_policy::config::Folder {
            path: p.display().to_string(),
            access: Access::parse(access).unwrap(),
        };
        let real = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
        // No rule is the entry, inside it, around it, or a link into it.
        let grants = |set: &[PathBuf], p: &Path| {
            set.iter()
                .any(|s| p.starts_with(s) || s.starts_with(p) || real(s).starts_with(p))
        };
        let mut policy = CenterPolicy {
            folders: vec![folder(&home, "rwx")],
            ..Default::default()
        };
        let spec = landlock_spec(&policy, &home, &[], &[]);
        for set in [&spec.read, &spec.write, &spec.exec] {
            assert!(!grants(set, &ssh), "{set:?}");
            assert!(set.contains(&home.join("other")), "{set:?}");
        }
        // `.local/bin` is protected for writes only.
        let bin = home.join(".local/bin");
        assert!(!grants(&spec.write, &bin), "{:?}", spec.write);
        assert!(spec.read.contains(&bin), "{:?}", spec.read);
        // The owner's own folder at the entry still gives it what it says.
        policy.folders.push(folder(&ssh, "r"));
        let spec = landlock_spec(&policy, &home, &[], &[]);
        assert!(spec.read.contains(&ssh), "{:?}", spec.read);
        assert!(!grants(&spec.write, &ssh), "{:?}", spec.write);
        assert!(!grants(&spec.exec, &ssh), "{:?}", spec.exec);
    }

    /// Every combination of the three flags puts a folder in exactly the
    /// sets of its flags: `w` without `r` is in `write` only.
    #[test]
    fn each_folder_flag_puts_it_in_its_own_set() {
        // A home beside the folder, so that the folder holds none of its
        // protected entries.
        let (d, h) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let w = std::fs::canonicalize(d.path()).unwrap();
        for bits in 0..8u8 {
            let access = Access {
                read: bits & 1 != 0,
                write: bits & 2 != 0,
                execute: bits & 4 != 0,
            };
            let policy = CenterPolicy {
                folders: vec![nerve_policy::config::Folder {
                    path: w.display().to_string(),
                    access,
                }],
                ..Default::default()
            };
            let spec = landlock_spec(&policy, h.path(), &[], &[]);
            let label = access.to_chmod();
            assert_eq!(spec.read.contains(&w), access.read, "read set of {label}");
            assert_eq!(
                spec.write.contains(&w),
                access.write,
                "write set of {label}"
            );
            assert_eq!(
                spec.exec.contains(&w),
                access.execute,
                "exec set of {label}"
            );
        }
    }

    /// Whether a rule of `spec` for a folder is `p`, holds it, lies inside it
    /// or leads there. The system's own rules are left aside.
    fn spec_reaches(spec: &LandlockSpec, p: &Path) -> bool {
        let system = [
            nerve_sandbox::system_dirs(),
            nerve_sandbox::system_writable(),
        ]
        .concat();
        [&spec.read, &spec.write, &spec.exec]
            .into_iter()
            .flatten()
            .filter(|s| !system.contains(s))
            .any(|s| {
                let r = real(s);
                p.starts_with(&r) || r.starts_with(p)
            })
    }

    fn folder(p: &Path, access: &str) -> Folder {
        Folder {
            path: p.display().to_string(),
            access: Access::parse(access).unwrap(),
        }
    }

    /// A home in a temp dir with `work`, a `work/bin` and, beside them, the
    /// `docs` that no folder names.
    fn nested_home(d: &tempfile::TempDir) -> (PathBuf, PathBuf, PathBuf) {
        let home = std::fs::canonicalize(d.path()).unwrap().join("home");
        for dir in ["work/bin", "docs"] {
            std::fs::create_dir_all(home.join(dir)).unwrap();
        }
        (home.clone(), home.join("work"), home.join("docs"))
    }

    /// A command with `w` on `work` replaces `work/bin`, a folder of its own,
    /// by a link to a place no folder names (issue #74): the next command's
    /// rules must not grant the flags of `bin` there, whether the folder is
    /// one of the same center, the only one of another, or deeper down.
    #[test]
    fn a_link_put_in_place_of_a_nested_folder_gets_no_rule() {
        let d = tempfile::tempdir().unwrap();
        let (home, work, docs) = nested_home(&d);
        let bin = work.join("bin");
        let both = CenterPolicy {
            folders: vec![folder(&work, "rw"), folder(&bin, "rx")],
            ..Default::default()
        };
        // Another center holds only `bin`; `work` is writable by the first.
        let only_bin = CenterPolicy {
            folders: vec![folder(&bin, "rx")],
            ..Default::default()
        };
        let writable = [work.clone()];

        // Plain, `bin` is a rule of its own.
        let spec = landlock_spec(&both, &home, &[], &writable);
        assert!(spec.read.contains(&bin), "{spec:?}");
        assert!(spec.exec.contains(&bin), "{spec:?}");
        let spec = landlock_spec(&only_bin, &home, &[], &writable);
        assert!(spec.read.contains(&bin), "{spec:?}");

        std::fs::remove_dir(&bin).unwrap();
        std::os::unix::fs::symlink(&docs, &bin).unwrap();
        for policy in [&both, &only_bin] {
            let spec = landlock_spec(policy, &home, &[], &writable);
            assert!(!spec_reaches(&spec, &docs), "{spec:?}");
            assert!(
                !spec.read.contains(&bin) && !spec.exec.contains(&bin),
                "{spec:?}"
            );
        }
        // `work` itself stays, with its own flags.
        let spec = landlock_spec(&both, &home, &[], &writable);
        assert!(spec.write.contains(&work), "{spec:?}");
        assert!(spec.read.contains(&work), "{spec:?}");

        // A link further down the folder's path is the same.
        std::fs::remove_file(&bin).unwrap();
        std::fs::create_dir_all(docs.join("sub/deep")).unwrap();
        std::fs::create_dir_all(work.join("a/sub/deep")).unwrap();
        let deep = work.join("a/sub/deep");
        let policy = CenterPolicy {
            folders: vec![folder(&work, "rw"), folder(&deep, "r")],
            ..Default::default()
        };
        let spec = landlock_spec(&policy, &home, &[], &writable);
        assert!(spec.read.contains(&deep), "{spec:?}");
        std::fs::remove_dir_all(work.join("a")).unwrap();
        std::fs::create_dir_all(work.join("a")).unwrap();
        std::os::unix::fs::symlink(docs.join("sub"), work.join("a/sub")).unwrap();
        let spec = landlock_spec(&policy, &home, &[], &writable);
        assert!(!spec_reaches(&spec, &docs), "{spec:?}");
        assert!(spec.read.contains(&work), "{spec:?}");
    }

    /// The links of the owner stay what they were: a folder behind a link
    /// outside every write folder is followed, and so is a write folder that
    /// is a link itself, with a folder inside it.
    #[test]
    fn a_link_of_the_owner_is_followed_outside_the_write_folders() {
        let d = tempfile::tempdir().unwrap();
        let (home, work, docs) = nested_home(&d);
        let bin = work.join("bin");
        // No write folder: the folder is the only one, and its link is followed.
        std::os::unix::fs::symlink(&docs, home.join("to-docs")).unwrap();
        let policy = CenterPolicy {
            folders: vec![folder(&home.join("to-docs"), "r")],
            ..Default::default()
        };
        let spec = landlock_spec(&policy, &home, &[], &[]);
        assert!(spec.read.contains(&docs), "{spec:?}");
        // Beside the write folder, not inside it.
        let spec = landlock_spec(&policy, &home, &[], std::slice::from_ref(&work));
        assert!(spec.read.contains(&docs), "{spec:?}");

        // The write folder is the owner's link to `work`, and a command
        // writes through it: the folder inside it is where it really is.
        std::os::unix::fs::symlink(&work, home.join("w")).unwrap();
        let policy = CenterPolicy {
            folders: vec![
                folder(&home.join("w"), "rw"),
                folder(&home.join("w/bin"), "r"),
            ],
            ..Default::default()
        };
        let spec = landlock_spec(&policy, &home, &[], &[home.join("w")]);
        assert!(spec.read.contains(&work), "{spec:?}");
        assert!(spec.read.contains(&bin), "{spec:?}");
        // The write folder spelled by its real path catches the same folder.
        let spec = landlock_spec(&policy, &home, &[], std::slice::from_ref(&work));
        assert!(spec.read.contains(&bin), "{spec:?}");
        // The write folder is named by the link, the folder by the real path.
        let policy = CenterPolicy {
            folders: vec![folder(&bin, "r")],
            ..Default::default()
        };
        std::fs::remove_dir(&bin).unwrap();
        std::os::unix::fs::symlink(&docs, &bin).unwrap();
        let spec = landlock_spec(&policy, &home, &[], &[home.join("w")]);
        assert!(!spec_reaches(&spec, &docs), "{spec:?}");
    }

    /// The write folders that bound the others are those of every center
    /// in the config, `~` expanded, whatever the center's mode.
    #[test]
    fn the_write_folders_of_every_center_bound_the_others() {
        let d = tempfile::tempdir().unwrap();
        let (home, work, docs) = nested_home(&d);
        let entry = |name: &str, mode, folders: Vec<Folder>| nerve_policy::CenterEntry {
            name: name.into(),
            url: "https://center.example".into(),
            pin: None,
            center_id: name.into(),
            node_id: name.into(),
            settings: Default::default(),
            paused: false,
            revoked: false,
            unknown: false,
            policy: CenterPolicy {
                mode,
                folders,
                ..Default::default()
            },
        };
        let mut cfg = NodeConfig::default();
        cfg.centers.push(entry(
            "writer",
            nerve_policy::Mode::Allowlist,
            vec![folder(&work, "rw"), folder(Path::new("~/docs"), "r")],
        ));
        cfg.centers.push(entry(
            "reader",
            nerve_policy::Mode::Folder,
            vec![folder(&work.join("bin"), "rx")],
        ));
        assert_eq!(write_folders(&cfg, &home), std::slice::from_ref(&work));

        // The writer's command swaps the reader's only folder.
        std::fs::remove_dir(work.join("bin")).unwrap();
        std::os::unix::fs::symlink(&docs, work.join("bin")).unwrap();
        let reader = &cfg.centers[1].policy;
        let spec = landlock_spec(reader, &home, &[], &write_folders(&cfg, &home));
        assert!(!spec_reaches(&spec, &docs), "{spec:?}");
        // Judged by its own folders alone, the link would be followed.
        let spec = landlock_spec(reader, &home, &[], &[]);
        assert!(spec.read.contains(&docs), "{spec:?}");
    }

    #[test]
    fn parses_args() {
        let home = std::env::temp_dir();
        let a = json!({"command": "ls"}).as_object().unwrap().clone();
        let c = RunCall::parse(&a, &home).unwrap();
        assert_eq!(c.cwd, home);
        let bad = json!({"command": "ls", "shell": "x"})
            .as_object()
            .unwrap()
            .clone();
        assert!(RunCall::parse(&bad, &home).is_err());
        assert_eq!(shell_command(None, "ls").1, ["-c", "ls"]);
    }
}

/// The shell's text and the output decoding: plain logic, on every platform.
#[cfg(test)]
mod text_tests {
    use super::*;

    /// A stand-in for code page 850 with the two letters the tests use.
    fn cp850(b: &[u8]) -> Option<String> {
        b.iter()
            .map(|c| match c {
                0x81 => Some('ü'),
                0xE1 => Some('ß'),
                c if c.is_ascii() => Some(*c as char),
                _ => None,
            })
            .collect()
    }

    /// Windows PowerShell 5.1 wrote a German error in the console code page:
    /// it comes back with its umlauts, not as replacement characters.
    #[test]
    fn output_in_another_code_page_is_decoded_with_it() {
        let oem = b"Gr\x81\xE1e: Fehler beim Ausf\x81hren";
        assert_eq!(
            output_text(oem, false, cp850),
            "Grüße: Fehler beim Ausführen"
        );
        // UTF-8 stays UTF-8, and the code page is not asked.
        assert_eq!(output_text("Grüße".as_bytes(), false, |_| None), "Grüße");
        // The cap cut the last character: still UTF-8, not the code page.
        let cut = &"Grüß".as_bytes()[..5];
        assert_eq!(output_text(cut, true, cp850), "Grü\u{FFFD}");
        // Neither reads it: replaced.
        assert_eq!(output_text(b"a\xFFb", false, |_| None), "a\u{FFFD}b");
    }

    /// The `exec.run` text names the shell and, for Windows PowerShell 5.1,
    /// how to chain commands there.
    #[test]
    fn the_run_action_names_its_shell() {
        assert_eq!(
            shell_summary(Some("powershell.exe")),
            "Runs a command in Windows PowerShell 5.1 (`powershell.exe -NoProfile -Command`): \
             PowerShell syntax, not cmd or sh. Chain commands with `;`; `&&` and `a & b` are \
             parser errors there."
        );
        assert_eq!(
            shell_summary(Some(r"C:\Program Files\PowerShell\7\pwsh.exe")),
            "Runs a command in PowerShell 7 (`C:\\Program Files\\PowerShell\\7\\pwsh.exe \
             -NoProfile -Command`): PowerShell syntax, not cmd or sh."
        );
        assert_eq!(
            shell_summary(Some("cmd.exe")),
            "Runs a command in cmd (`cmd.exe /C`): cmd syntax."
        );
        assert_eq!(
            shell_summary(Some("/bin/bash")),
            "Runs a command with `/bin/bash -c`."
        );
        let default = shell_summary(None);
        if cfg!(windows) {
            assert!(default.contains("Windows PowerShell 5.1"), "{default}");
        } else {
            assert_eq!(default, "Runs a command with `/bin/sh -c`.");
        }
    }
}

/// Windows only: the real shell, code pages and process table. The owner
/// runs these on a Windows machine.
#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    fn opts() -> RunOptions {
        RunOptions {
            shell: None,
            landlock: None,
            exe: PathBuf::from("nerve-node.exe"),
            output_cap: 64 * 1024,
            sudo: None,
            account: None,
            own: Vec::new(),
        }
    }

    fn call(cmd: &str, cwd: &Path, timeout: Duration) -> RunCall {
        RunCall {
            command: cmd.into(),
            cwd: cwd.to_path_buf(),
            timeout: Some(timeout),
        }
    }

    #[test]
    fn code_pages_decode() {
        assert_eq!(
            crate::win::code_page_text(850, b"Gr\x81\xE1e").as_deref(),
            Some("Grüße")
        );
        assert_eq!(
            crate::win::code_page_text(1252, b"Gr\xFC\xDFe").as_deref(),
            Some("Grüße")
        );
        assert_ne!(crate::win::console_code_page(), 0);
    }

    /// What Windows PowerShell 5.1 prints, on stdout and stderr, comes back
    /// with its umlauts whatever the console code page is.
    #[tokio::test]
    async fn powershell_output_keeps_its_umlauts() {
        let d = tempfile::tempdir().unwrap();
        let c = call(
            "Write-Output 'Grüße'; [Console]::Error.WriteLine('Größe')",
            d.path(),
            Duration::from_secs(60),
        );
        let r = run(&c, &opts(), |_| {}).await.unwrap();
        assert_eq!(r["stdout"].as_str().unwrap().trim_end(), "Grüße", "{r}");
        assert_eq!(r["stderr"].as_str().unwrap().trim_end(), "Größe", "{r}");
    }

    /// The pid a process wrote to `file`, once it is there.
    async fn pid_in(file: &Path) -> u32 {
        for _ in 0..600 {
            if let Ok(t) = std::fs::read_to_string(file)
                && let Ok(pid) = t.trim().parse()
            {
                return pid;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("no pid in {}", file.display())
    }

    async fn gone(pid: u32) -> bool {
        for _ in 0..100 {
            if !crate::win::running(pid) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }

    /// A timeout ends a child of the shell and a grandchild whose parent
    /// exited long before (the parent lives 1.5 s, so the poll sees it).
    #[tokio::test]
    async fn a_timeout_ends_a_grandchild_whose_parent_exited() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(
            d.path().join("inner.ps1"),
            "$p = Start-Process ping -ArgumentList '-n','120','127.0.0.1' -WindowStyle Hidden -PassThru\r\n\
             Set-Content -Path grandchild.pid -Value $p.Id\r\n\
             Start-Sleep -Milliseconds 1500\r\n",
        )
        .unwrap();
        let command = "$c = Start-Process ping -ArgumentList '-n','120','127.0.0.1' -WindowStyle Hidden -PassThru; \
             Set-Content -Path child.pid -Value $c.Id; \
             Start-Process powershell -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','inner.ps1' -WindowStyle Hidden; \
             Start-Sleep 120";
        let c = call(command, d.path(), Duration::from_secs(15));
        let task = tokio::spawn(async move { run(&c, &opts(), |_| {}).await });
        let child = pid_in(&d.path().join("child.pid")).await;
        let grandchild = pid_in(&d.path().join("grandchild.pid")).await;
        let e = task.await.unwrap().unwrap_err();
        assert_eq!(e.kind(), ErrorCode::Timeout);
        assert!(gone(child).await, "the shell's child outlived the timeout");
        assert!(
            gone(grandchild).await,
            "the orphaned grandchild outlived the timeout"
        );
    }

    /// Ends `pid` when a failed test left it running.
    fn sweep(pid: u32) {
        if let Some(start) = crate::win::start_of(pid) {
            crate::win::terminate(pid, start);
        }
    }

    /// Runs `command` in `dir` until `pid_file` names a process, then
    /// cancels the call the way the link does (the task is aborted, so the
    /// run future is dropped); whether that process is gone afterwards.
    async fn ended_by_cancel(command: &str, dir: &Path, pid_file: &str) -> bool {
        let c = call(command, dir, Duration::from_secs(120));
        let task = tokio::spawn(async move { run(&c, &opts(), |_| {}).await });
        let pid = pid_in(&dir.join(pid_file)).await;
        // Long enough for every parent in between to have exited.
        tokio::time::sleep(Duration::from_millis(1500)).await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        let ended = gone(pid).await;
        sweep(pid);
        ended
    }

    /// A cancel ends a grandchild whose parents exited at once: three cmd
    /// levels that each start the next and exit.
    #[tokio::test]
    async fn a_cancel_ends_a_grandchild_whose_parents_exited_at_once() {
        let d = tempfile::tempdir().unwrap();
        let w = |name: &str, text: &str| std::fs::write(d.path().join(name), text).unwrap();
        w("a.cmd", "@start \"\" /b cmd /c b.cmd\r\n");
        w("b.cmd", "@start \"\" /b cmd /c c.cmd\r\n");
        w(
            "c.cmd",
            "@start \"\" /b powershell -NoProfile -ExecutionPolicy Bypass -File gc.ps1\r\n",
        );
        w(
            "gc.ps1",
            "Set-Content -Path gc.pid -Value $PID\r\nStart-Sleep 120\r\n",
        );
        assert!(
            ended_by_cancel("cmd /c a.cmd; Start-Sleep 120", d.path(), "gc.pid").await,
            "the grandchild outlived the cancel"
        );
    }

    /// A process that keeps starting its successor and exiting, each one a
    /// grandchild whose parent is gone: a walk of the process table loses
    /// the chain when one hop lives shorter than a poll, the job holds every
    /// one. Each hop adds a line to `hops.txt`; after the cancel the file
    /// must stop growing.
    #[tokio::test]
    async fn a_cancel_ends_a_chain_of_processes_that_hand_over_and_exit() {
        let d = tempfile::tempdir().unwrap();
        // `stop` ends a chain a failed test left running.
        std::fs::write(
            d.path().join("hop.cmd"),
            "@if exist stop exit /b\r\n@echo x>>hops.txt\r\n@start \"\" /b cmd /c hop.cmd\r\n",
        )
        .unwrap();
        // Ten chains side by side, so the walk has a lot to keep up with.
        std::fs::write(
            d.path().join("go.cmd"),
            "@start \"\" /b cmd /c hop.cmd\r\n".repeat(10),
        )
        .unwrap();
        let c = call(
            "cmd /c go.cmd; Start-Sleep 120",
            d.path(),
            Duration::from_secs(120),
        );
        let task = tokio::spawn(async move { run(&c, &opts(), |_| {}).await });
        let hops = d.path().join("hops.txt");
        let count = || {
            std::fs::read_to_string(&hops)
                .map(|t| t.lines().count())
                .unwrap_or(0)
        };
        // Long enough for many hops.
        tokio::time::sleep(Duration::from_secs(4)).await;
        assert!(count() > 10, "the chain did not run: {} hops", count());
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        tokio::time::sleep(Duration::from_millis(500)).await;
        let after = count();
        tokio::time::sleep(Duration::from_secs(2)).await;
        let later = count();
        std::fs::write(d.path().join("stop"), "").unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(after, later, "the chain went on after the cancel");
    }

    /// A process the command starts through WMI. Its parent is the WMI
    /// provider host (WmiPrvSE.exe), and a new process is born into its
    /// parent's job, so it is in the provider host's job, not the
    /// command's: no job object holds it, and neither does the walk. Kept
    /// as the open gap it is (run it with `--ignored`); closing it takes
    /// keeping the command from WMI, which a job cannot.
    #[tokio::test]
    #[ignore = "open gap: WMI starts the process outside the command's job"]
    async fn a_cancel_ends_a_process_started_through_wmi() {
        let d = tempfile::tempdir().unwrap();
        let command = "$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create \
             -Arguments @{CommandLine = 'powershell -NoProfile -Command Start-Sleep 120'}; \
             Set-Content -Path wmi.pid -Value $r.ProcessId; \
             Start-Sleep 120";
        assert!(
            ended_by_cancel(command, d.path(), "wmi.pid").await,
            "the process started through WMI outlived the cancel"
        );
    }

    /// The shell runs in a job of its own, nested in the job the test runs
    /// in when there is one (a CI runner, an SSH session).
    #[tokio::test]
    async fn the_shell_runs_in_a_job_of_its_own() {
        let d = tempfile::tempdir().unwrap();
        let c = call("exit 0", d.path(), Duration::from_secs(60));
        let mut held = false;
        let r = run(&c, &opts(), |e| held = e.has_job()).await.unwrap();
        assert_eq!(r["exit_code"], 0, "{r}");
        assert!(held, "the shell ran without a job");
    }

    /// Command A's shell exits at once while a ping it started in the
    /// background keeps A's output open; then commands B run one after
    /// another until a B shell gets A's old shell pid. Neither may end the
    /// other's processes: A's ping runs on, and every B exits with its own
    /// code. Windows takes minutes to give a pid out again, so run it with
    /// `--ignored`.
    #[tokio::test]
    #[ignore = "slow: waits until Windows gives a shell's pid to another shell"]
    async fn a_shell_pid_given_to_another_command_reaches_no_other_job() {
        let d = tempfile::tempdir().unwrap();
        let mut o = opts();
        o.shell = Some("cmd.exe".into());
        let a = call(
            "start /b ping -n 900 127.0.0.1",
            d.path(),
            Duration::from_secs(1200),
        );
        let (tx, rx) = tokio::sync::oneshot::channel();
        let oa = o.clone();
        let task = tokio::spawn(async move {
            run(&a, &oa, |e| {
                let _ = tx.send(e.pid());
            })
            .await
        });
        let a_pid = rx.await.unwrap();
        assert!(gone(a_pid).await, "A's shell did not exit");
        let mut reused = false;
        for _ in 0..20_000 {
            let mut b_pid = 0;
            let b = call("exit 0", d.path(), Duration::from_secs(60));
            let r = run(&b, &o, |e| b_pid = e.pid()).await.unwrap();
            assert_eq!(r["exit_code"], 0, "A's end ended a B: {r}");
            if b_pid == a_pid {
                reused = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
        let a_runs = !task.is_finished();
        task.abort();
        assert!(reused, "no B shell got A's pid");
        assert!(a_runs, "A's command ended when a B shell got its pid");
    }

    /// Run by [`a_node_that_dies_leaves_no_command_running`] in a process
    /// of its own, which that test then kills: a command whose shell starts
    /// a ping and waits.
    #[tokio::test]
    #[ignore = "a helper of a_node_that_dies_leaves_no_command_running"]
    async fn helper_runs_a_command_until_killed() {
        let dir = PathBuf::from(std::env::var_os("NERVE_TEST_DIR").expect("set by the test"));
        let command = "Set-Content -Path shell.pid -Value $PID; \
             $p = Start-Process ping -ArgumentList '-n','120','127.0.0.1' -WindowStyle Hidden -PassThru; \
             Set-Content -Path ping.pid -Value $p.Id; \
             Start-Sleep 120";
        let _ = run(
            &call(command, &dir, Duration::from_secs(120)),
            &opts(),
            |_| {},
        )
        .await;
    }

    /// A node that dies without ending its commands (killed, crashed)
    /// leaves none running: its handle to the job closes with it, and the
    /// job's KILL_ON_JOB_CLOSE ends every process in it. The walk dies with
    /// the node and ends nothing.
    #[tokio::test]
    async fn a_node_that_dies_leaves_no_command_running() {
        let d = tempfile::tempdir().unwrap();
        let mut node = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "exec::windows_tests::helper_runs_a_command_until_killed",
            ])
            .env("NERVE_TEST_DIR", d.path())
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let shell = pid_in(&d.path().join("shell.pid")).await;
        let ping = pid_in(&d.path().join("ping.pid")).await;
        // TerminateProcess: no destructor of the node runs, as in a crash.
        node.kill().unwrap();
        node.wait().unwrap();
        let shell_gone = gone(shell).await;
        let ping_gone = gone(ping).await;
        sweep(shell);
        sweep(ping);
        assert!(shell_gone, "the shell outlived the node");
        assert!(ping_gone, "the shell's child outlived the node");
    }
}
