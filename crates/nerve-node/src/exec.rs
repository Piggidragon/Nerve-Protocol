//! The `exec` capability (spec §7.3): shell commands, each in its own
//! process group so the whole tree can be signalled and is killed when the
//! call ends or the link drops.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde::Deserialize;
use serde_json::{Map, Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

use nerve_policy::config::CenterPolicy;
use nerve_policy::paths::{to_wire, within};
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
    /// `cwd` defaults to the owner's home.
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
pub fn landlock_spec(policy: &CenterPolicy, home: &Path, own: &[PathBuf]) -> LandlockSpec {
    let folders = |f: &dyn Fn(&nerve_policy::config::Folder) -> bool| -> Vec<PathBuf> {
        policy
            .folders
            .iter()
            .filter(|x| f(x))
            .filter_map(|x| expand(home, &x.path))
            .collect()
    };
    LandlockSpec {
        read: leave_out(
            &[nerve_sandbox::system_dirs(), folders(&|x| x.access.read)].concat(),
            own,
        ),
        write: leave_out(
            &[
                nerve_sandbox::system_writable(),
                folders(&|x| x.access.write),
            ]
            .concat(),
            own,
        ),
        exec: leave_out(
            &[nerve_sandbox::system_dirs(), folders(&|x| x.access.execute)].concat(),
            own,
        ),
    }
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
    let real = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let own: Vec<PathBuf> = own.iter().map(|o| real(o)).collect();
    let mut out = Vec::new();
    for p in paths {
        let r = real(p);
        if own.iter().any(|o| within(&r, o)) {
            continue;
        }
        if own.iter().any(|o| within(o, &r)) {
            split(&r, &own, &mut out);
        } else {
            out.push(p.clone());
        }
    }
    out
}

/// Pushes the entries of `dir` (which holds an own folder) that hold none,
/// and goes down into the ones that do.
fn split(dir: &Path, own: &[PathBuf], out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let path = e.path();
        let link = e.file_type().is_ok_and(|t| t.is_symlink());
        let real = std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
        let inside = own.iter().any(|o| within(&real, o));
        let holds = own.iter().any(|o| within(o, &real));
        if inside || (holds && link) {
            continue;
        }
        if holds {
            split(&real, own, out);
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
pub fn sudo_line(sudo_path: &str, args: &str, prompt: &str) -> String {
    format!(
        "exec {} -S -k -p {} {args}",
        sh_quote(sudo_path),
        sh_quote(prompt)
    )
}

/// Checks `password` with `sudo -S -k -v`, which runs nothing and caches
/// nothing; its output is discarded.
pub async fn sudo_check(sudo_path: &str, password: &str) -> Result<(), String> {
    let mut child = Command::new(sudo_path)
        .args(["-S", "-k", "-v", "-p", ""])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("cannot run {sudo_path}: {e}"))?;
    let mut stdin = child.stdin.take().expect("piped");
    // sudo may exit before reading (no such user in sudoers); the exit
    // status says what matters.
    let _ = stdin.write_all(format!("{password}\n").as_bytes()).await;
    drop(stdin);
    match tokio::time::timeout(Duration::from_secs(30), child.wait()).await {
        Ok(Ok(s)) if s.success() => Ok(()),
        Ok(Ok(_)) => Err("the sudo password is wrong (sudo -v refused it)".into()),
        Ok(Err(e)) => Err(format!("waiting for sudo: {e}")),
        Err(_) => Err("sudo -v did not answer within 30 s".into()),
    }
}

/// Kills the command's whole process group when dropped: a cancelled call, a
/// dropped link and a finished command all leave nothing behind.
struct Group(Option<u32>);

impl Drop for Group {
    fn drop(&mut self) {
        if let Some(pid) = self.0 {
            kill_group(pid, Sig::Kill);
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

/// Signals the process group led by `pid`.
#[cfg(unix)]
pub fn kill_group(pid: u32, sig: Sig) {
    let s = match sig {
        Sig::Term => libc::SIGTERM,
        Sig::Kill => libc::SIGKILL,
        Sig::Int => libc::SIGINT,
    };
    // SAFETY: kill with a negative pid signals that process group only.
    unsafe {
        libc::kill(-(pid as libc::pid_t), s);
    }
}

#[cfg(not(unix))]
pub fn kill_group(pid: u32, _sig: Sig) {
    // Not done in 0.0.1: a Job Object would hold the whole tree; this ends
    // the shell and what taskkill finds below it.
    let _ = std::process::Command::new("taskkill")
        .args(["/T", "/F", "/PID", &pid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

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
    // The sudo switch is Linux only; elsewhere the wait or the end decides.
    false
}

/// Runs `call`. `started(pid)` hears the pid once the command runs (for
/// `exec.signal` and the control socket's ancestry check).
pub async fn run(
    call: &RunCall,
    opts: &RunOptions,
    started: impl FnOnce(u32),
) -> Result<Value, RpcError> {
    let (program, args) = shell_command(opts.shell.as_deref(), &call.command);
    let shim = opts.landlock.as_ref().map(|l| ShimSpec {
        program: program.clone().into(),
        args: args.clone(),
        parent: std::process::id(),
        landlock: Some(l.clone()),
    });
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
    #[cfg(target_os = "linux")]
    if opts.sudo.is_none() {
        // SAFETY: prctl is async-signal-safe and touches only this process.
        unsafe {
            cmd.pre_exec(|| {
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    cmd.current_dir(&call.cwd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    cmd.process_group(0);
    let mut child = cmd
        .spawn()
        .map_err(|e| RpcError::new(ErrorCode::Unavailable, format!("cannot start: {e}")))?;
    let group = Group(child.id());
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
    if let Some(pid) = pid {
        started(pid);
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
        "stdout": String::from_utf8_lossy(&out.0),
        "stderr": String::from_utf8_lossy(&err.0),
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

    /// A fake sudo at `dir/sudo`: with `asks` it prints its `-p` prompt to
    /// stderr and reads the password like `sudo -S`, else it asks for none
    /// (NOPASSWD, root). Either way it runs the command as its child.
    #[cfg(target_os = "linux")]
    fn fake_sudo(dir: &Path, asks: bool) -> String {
        use std::os::unix::fs::PermissionsExt;
        let ask = if asks {
            "printf %s \"$p\" >&2\nIFS= read -r pw\n[ \"$pw\" = right-pw ] || exit 1\n"
        } else {
            ""
        };
        let sudo = dir.join("sudo");
        std::fs::write(
            &sudo,
            format!(
                "#!/bin/sh\nwhile [ $# -gt 0 ]; do case \"$1\" in -S|-k) shift ;; \
                 -p) p=\"$2\"; shift 2 ;; *) break ;; esac; done\n{ask}\"$@\"\n"
            ),
        )
        .unwrap();
        std::fs::set_permissions(&sudo, std::fs::Permissions::from_mode(0o755)).unwrap();
        sudo.display().to_string()
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

    #[tokio::test]
    async fn timeout_kills_the_group() {
        let mut c = call("sleep 30 & sleep 30; wait");
        c.timeout = Some(Duration::from_millis(200));
        let mut pid = 0;
        let e = run(&c, &opts(1024), |p| pid = p).await.unwrap_err();
        assert_eq!(e.kind(), ErrorCode::Timeout);
        tokio::time::sleep(Duration::from_millis(100)).await;
        // SAFETY: signal 0 only checks whether the group exists.
        let alive = unsafe { libc::kill(-(pid as libc::pid_t), 0) } == 0;
        assert!(!alive, "the process group outlived the call");
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
        let spec = landlock_spec(&policy, &w, &own);
        for set in [&spec.read, &spec.write, &spec.exec] {
            assert!(set.contains(&w.join("a")), "{set:?}");
            assert!(!set.iter().any(|p| own[0].starts_with(p)), "{set:?}");
        }
    }

    /// Every combination of the three flags puts a folder in exactly the
    /// sets of its flags: `w` without `r` is in `write` only.
    #[test]
    fn each_folder_flag_puts_it_in_its_own_set() {
        let w = std::env::temp_dir();
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
            let spec = landlock_spec(&policy, &w, &[]);
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
