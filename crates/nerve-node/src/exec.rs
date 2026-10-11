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

use nerve_policy::config::{Access, CenterPolicy};
use nerve_policy::paths::to_wire;
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
    /// command rules and the execute folders.
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
/// the system and its folders, writes its read-write folders, runs programs
/// from the system and its execute folders.
pub fn landlock_spec(policy: &CenterPolicy, home: &Path) -> LandlockSpec {
    let folders = |f: &dyn Fn(&nerve_policy::config::Folder) -> bool| -> Vec<PathBuf> {
        policy
            .folders
            .iter()
            .filter(|x| f(x))
            .filter_map(|x| expand(home, &x.path))
            .collect()
    };
    LandlockSpec {
        read: [nerve_sandbox::system_dirs(), folders(&|_| true)].concat(),
        write: [
            nerve_sandbox::system_writable(),
            folders(&|x| x.access == Access::Rw),
        ]
        .concat(),
        exec: [nerve_sandbox::system_dirs(), folders(&|x| x.execute)].concat(),
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
            c.args(&args).stdin(Stdio::null());
            c
        }
    };
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
    if let Some(spec) = shim {
        let mut stdin = child.stdin.take().expect("piped");
        let json = serde_json::to_vec(&spec).map_err(|e| RpcError::internal(e.to_string()))?;
        stdin
            .write_all(&json)
            .await
            .map_err(|e| RpcError::internal(format!("cannot hand the shim its spec: {e}")))?;
        drop(stdin);
    }
    if let Some(pid) = child.id() {
        started(pid);
    }
    let stdout = child.stdout.take().expect("piped");
    let stderr = child.stderr.take().expect("piped");
    let cap = opts.output_cap.min(OUTPUT_HARD_CAP);
    let work = async {
        let (o, e, st) = tokio::join!(capped(stdout, cap), capped(stderr, cap), child.wait());
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

    fn opts(cap: usize) -> RunOptions {
        RunOptions {
            shell: None,
            landlock: None,
            exe: PathBuf::from("/nonexistent"),
            output_cap: cap,
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
