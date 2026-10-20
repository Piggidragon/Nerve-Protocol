//! Runs `nerve-node` for the app: this same program with arguments, which
//! behaves as `nerve-node` (src/main.rs), with `--json`, and reads its
//! answer (docs/user/commands.md). The app never parses text meant for
//! people, and has the CLI's checks because it runs the CLI. On a node
//! installed as a service the CLI of an owner has the running node run the
//! command (nerve_node::owner); a command that needs an administrator, or
//! any for a user who is no owner, goes through the elevated broker
//! (crate::broker) instead, which runs the same program the same way.
//!
//! On Linux the app reads the owner token for its runs ([`Tokens`]) and
//! hands it to each on a pipe, so that a session without the owners' group
//! yet switches to it once per token, not once per command.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::Value;

use crate::broker;

/// Starts the CLI: which program, the folders it is given, and whether it
/// goes through the broker.
#[derive(Clone)]
pub struct Runner {
    exe: PathBuf,
    dirs: Vec<String>,
    broker: Option<Arc<broker::Client>>,
    tokens: Arc<Tokens>,
}

/// What a run of the program gave back.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Output {
    pub ok: bool,
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// A command that keeps running and gives a line at a time (`audit
/// --follow`); it ends when this is dropped.
pub struct Follow {
    stop: Option<Box<dyn FnOnce() + Send>>,
}

impl Follow {
    pub fn new(stop: Box<dyn FnOnce() + Send>) -> Follow {
        Follow { stop: Some(stop) }
    }
}

impl Drop for Follow {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            stop();
        }
    }
}

impl Runner {
    /// This program. The node's folders come from `NERVE_CONFIG_DIR` and
    /// `NERVE_STATE_DIR` when they are set, which the CLI reads too, else
    /// they are the CLI's defaults.
    pub fn this_program() -> Result<Runner, String> {
        let exe = std::env::current_exe().map_err(|e| format!("this program: {e}"))?;
        Ok(Runner::new(exe, None, None))
    }

    /// `exe` as the CLI, with `--config-dir` and `--state-dir` when given.
    pub fn new(exe: PathBuf, config_dir: Option<PathBuf>, state_dir: Option<PathBuf>) -> Runner {
        let mut dirs = Vec::new();
        if let Some(c) = config_dir {
            dirs.push("--config-dir".into());
            dirs.push(c.display().to_string());
        }
        if let Some(s) = state_dir {
            dirs.push("--state-dir".into());
            dirs.push(s.display().to_string());
        }
        Runner {
            exe,
            dirs,
            broker: None,
            tokens: Tokens::installed(),
        }
    }

    /// The same runner, handing its runs the token `tokens` read.
    pub fn with_tokens(&self, tokens: Arc<Tokens>) -> Runner {
        Runner {
            tokens,
            ..self.clone()
        }
    }

    pub fn exe(&self) -> &PathBuf {
        &self.exe
    }

    /// The same runner, its commands going through `broker`.
    pub fn through(&self, broker: Arc<broker::Client>) -> Runner {
        Runner {
            broker: Some(broker),
            ..self.clone()
        }
    }

    /// The same runner, its commands run directly again.
    pub fn direct(&self) -> Runner {
        Runner {
            broker: None,
            ..self.clone()
        }
    }

    /// Whether the commands go through the broker.
    pub fn elevated(&self) -> bool {
        self.broker.is_some()
    }

    fn args(&self, args: &[&str]) -> Vec<String> {
        let mut all = self.dirs.clone();
        all.push("--json".into());
        all.extend(args.iter().map(|a| a.to_string()));
        all
    }

    /// Runs `nerve-node --json <args>` and returns its answer, or the error
    /// it gave.
    pub fn run(&self, args: &[&str]) -> Result<Value, String> {
        self.run_with(args, None)
    }

    /// [`Runner::run`] with `input` as the first line of stdin, for a
    /// password or a passphrase: never an argument, which every process of
    /// the user could read.
    pub fn run_with(&self, args: &[&str], input: Option<&str>) -> Result<Value, String> {
        let args = self.args(args);
        let out = match &self.broker {
            Some(b) => b.run(args, input)?,
            None => run_process(&self.exe, &args, &[], input, Some(&self.tokens))?,
        };
        answer(out.ok, out.code, &out.stdout, &out.stderr)
    }

    /// Runs `nerve-node --json <args>` that keeps answering (`--follow`):
    /// `each` gets every entry, or the error that ended it.
    pub fn follow(
        &self,
        args: &[&str],
        each: impl FnMut(Result<Value, String>) + Send + 'static,
    ) -> Result<Follow, String> {
        let args = self.args(args);
        let each = Arc::new(Mutex::new(each));
        let on_line = {
            let each = each.clone();
            move |line: String| {
                if let Some(v) = entry(&line) {
                    (each.lock().unwrap_or_else(|p| p.into_inner()))(v);
                }
            }
        };
        let on_end = move |out: Output| {
            if !out.ok
                && let Err(e) = answer(out.ok, out.code, b"", &out.stderr)
            {
                (each.lock().unwrap_or_else(|p| p.into_inner()))(Err(e));
            }
        };
        match &self.broker {
            Some(b) => b.follow(args, Box::new(on_line), Box::new(on_end)),
            None => follow_process(
                &self.exe,
                &args,
                &[],
                Some(&self.tokens),
                Box::new(on_line),
                Box::new(on_end),
            ),
        }
    }
}

/// One line of a command that keeps answering: an entry, or the error it
/// ended with. Anything else is no answer.
fn entry(line: &str) -> Option<Result<Value, String>> {
    let v: Value = serde_json::from_str(line.trim()).ok()?;
    match v["error"].as_str() {
        Some(e) if v.as_object().is_some_and(|o| o.len() == 1) => Some(Err(e.to_string())),
        _ => Some(Ok(v)),
    }
}

/// What the broker's commands get in their environment besides this
/// process's: the app's user on Windows (crate::broker).
pub type Env = [(String, String)];

/// Runs `exe` with `args` and `env`, `input` as the first line of stdin,
/// and the owner token of `tokens` handed, and waits.
pub fn run_process(
    exe: &PathBuf,
    args: &[String],
    env: &Env,
    input: Option<&str>,
    tokens: Option<&Tokens>,
) -> Result<Output, String> {
    let mut c = Command::new(exe);
    c.args(args)
        .envs(env.iter().map(|(k, v)| (k, v)))
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = spawn(c, exe, tokens)?;
    if let Some(text) = input {
        let mut stdin = child.stdin.take().expect("piped");
        // A command that ends before it reads leaves its own answer.
        let _ = stdin.write_all(format!("{text}\n").as_bytes());
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("nerve-node did not end: {e}"))?;
    Ok(Output {
        ok: out.status.success(),
        code: out.status.code(),
        stdout: out.stdout,
        stderr: out.stderr,
    })
}

/// Starts `exe` with `args` and `env`, and the owner token of `tokens`
/// handed, and gives each line it prints to `on_line`, then how it ended to
/// `on_end`, unless it was ended on purpose. The returned [`Follow`] ends
/// it.
pub fn follow_process(
    exe: &PathBuf,
    args: &[String],
    env: &Env,
    tokens: Option<&Tokens>,
    mut on_line: Box<dyn FnMut(String) + Send>,
    on_end: Box<dyn FnOnce(Output) + Send>,
) -> Result<Follow, String> {
    let mut c = Command::new(exe);
    c.args(args)
        .envs(env.iter().map(|(k, v)| (k, v)))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = spawn(c, exe, tokens)?;
    let stdout = child.stdout.take().expect("piped");
    let mut stderr = child.stderr.take().expect("piped");
    let child = Arc::new(Mutex::new(child));
    let stopped = Arc::new(AtomicBool::new(false));
    {
        let (child, stopped) = (child.clone(), stopped.clone());
        std::thread::spawn(move || {
            let err = std::thread::spawn(move || {
                let mut b = Vec::new();
                let _ = std::io::Read::read_to_end(&mut stderr, &mut b);
                b
            });
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if stopped.load(Ordering::SeqCst) {
                    break;
                }
                on_line(line);
            }
            let status = child.lock().unwrap_or_else(|p| p.into_inner()).wait();
            let stderr = err.join().unwrap_or_default();
            if !stopped.load(Ordering::SeqCst) {
                on_end(Output {
                    ok: status.as_ref().is_ok_and(|s| s.success()),
                    code: status.ok().and_then(|s| s.code()),
                    stdout: Vec::new(),
                    stderr,
                });
            }
        });
    }
    Ok(Follow::new(Box::new(move || {
        stopped.store(true, Ordering::SeqCst);
        let _ = child.lock().unwrap_or_else(|p| p.into_inner()).kill();
    })))
}

/// Starts `c`, the program `exe`, with the owner token of `tokens` handed
/// on a pipe (Linux) whose descriptor [`nerve_node::owner::HANDED_VAR`]
/// names: never in the environment or the arguments, which every process
/// of the user could read.
#[allow(unused_mut)]
fn spawn(
    mut c: Command,
    exe: &std::path::Path,
    tokens: Option<&Tokens>,
) -> Result<std::process::Child, String> {
    #[cfg(unix)]
    let _pipe = match tokens {
        Some(t) => Some(
            hand(&mut c, t.get()).map_err(|e| format!("cannot start {}: {e}", exe.display()))?,
        ),
        None => None,
    };
    #[cfg(not(unix))]
    let _ = tokens;
    // The pipe's end here closes once the child has its own.
    c.spawn()
        .map_err(|e| format!("cannot start {}: {e}", exe.display()))
}

/// Gives `c` a pipe that holds `token` (nothing for none), its descriptor
/// named by [`nerve_node::owner::HANDED_VAR`]; the read end, which the
/// caller keeps until `c` has started.
#[cfg(unix)]
fn hand(c: &mut Command, token: Option<String>) -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::process::CommandExt;
    let mut fds = [0; 2];
    // SAFETY: two new descriptors, closed on exec, so that no other child
    // this app starts meanwhile keeps either.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the new descriptors, each owned once.
    let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    // A token is far less than a pipe holds, so this does not wait, and
    // the child reads to the end once this end is closed.
    let mut write = std::fs::File::from(write);
    if let Some(t) = token {
        write.write_all(t.as_bytes())?;
    }
    drop(write);
    // Not one of 0 to 2, which the child's own input and output take.
    let read = if read.as_raw_fd() < 3 {
        // SAFETY: a copy of an open descriptor, at 3 or above.
        let fd = unsafe { libc::fcntl(read.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
        if fd == -1 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: the new copy, owned once.
        unsafe { OwnedFd::from_raw_fd(fd) }
    } else {
        read
    };
    let fd = read.as_raw_fd();
    c.env(nerve_node::owner::HANDED_VAR, fd.to_string());
    // SAFETY: one plain system call between fork and exec: the child keeps
    // the read end across its exec.
    unsafe {
        c.pre_exec(move || {
            if libc::fcntl(fd, libc::F_SETFD, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(read)
}

/// The owner token the app hands its runs of the CLI, read once for each
/// token the node writes. A session that began before `install` made its
/// user an owner reads it through `sg`, which logs each switch to the
/// group (on Debian and Ubuntu two lines in the auth log): once per start
/// of the node, not once for every command of the status poll. A file
/// that is not there (no node, or a stopped one) is not read.
pub struct Tokens {
    file: PathBuf,
    read: Box<dyn Fn() -> Option<String> + Send + Sync>,
    /// The file as it was when last read, and what was read from it then:
    /// a failed read is not tried again before the node writes a new one.
    last: Mutex<Option<(Stamp, Option<String>)>>,
}

/// Which file a token file is: a new token is a new file (`rename`).
type Stamp = (u64, u64, i64, i64, i64, i64);

impl Tokens {
    /// The installed node's, shared by all the runners of this app.
    pub fn installed() -> Arc<Tokens> {
        static ONE: std::sync::OnceLock<Arc<Tokens>> = std::sync::OnceLock::new();
        ONE.get_or_init(|| {
            #[cfg(unix)]
            {
                let at = nerve_node::owner::socket_here();
                let file = nerve_node::owner::token_file(&at);
                Arc::new(Tokens::new(file, move || {
                    nerve_node::owner::read_token(&at).ok()
                }))
            }
            #[cfg(not(unix))]
            {
                Arc::new(Tokens::new(PathBuf::new(), || None))
            }
        })
        .clone()
    }

    /// The token in `file`, as `read` reads it.
    pub fn new(file: PathBuf, read: impl Fn() -> Option<String> + Send + Sync + 'static) -> Tokens {
        Tokens {
            file,
            read: Box::new(read),
            last: Mutex::new(None),
        }
    }

    /// The token for a run now: the one read before while the file is the
    /// same, else read now.
    pub fn get(&self) -> Option<String> {
        let stamp = stamp(&self.file)?;
        // Held while reading, so that runs started together read once.
        let mut last = self.last.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((s, t)) = &*last
            && *s == stamp
        {
            return t.clone();
        }
        let token = (self.read)();
        *last = Some((stamp, token.clone()));
        token
    }
}

/// Which file is at `file` now; `None` when none is. Everyone may look
/// (the runtime folder is open), though only the owners may read it.
fn stamp(file: &std::path::Path) -> Option<Stamp> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::metadata(file).ok()?;
        Some((
            m.dev(),
            m.ino(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        ))
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        None
    }
}

/// What a run of the CLI answered: its JSON, or its error. A run that gave
/// no JSON says why with the last line of stderr, which also carries the
/// log's events before it.
pub fn answer(ok: bool, code: Option<i32>, stdout: &[u8], stderr: &[u8]) -> Result<Value, String> {
    let text = String::from_utf8_lossy(stdout);
    let last = text.lines().rev().find(|l| !l.trim().is_empty());
    let parsed = last.and_then(|l| serde_json::from_str::<Value>(l).ok());
    match parsed {
        Some(v) if ok => Ok(v),
        Some(v) if v["error"].is_string() => Err(v["error"].as_str().unwrap_or_default().into()),
        _ => {
            let err = String::from_utf8_lossy(stderr);
            let why = err
                .lines()
                .rev()
                .map(str::trim)
                .find(|l| !l.is_empty())
                .map(|l| l.strip_prefix("nerve-node: ").unwrap_or(l).to_string());
            Err(match (why, code) {
                (Some(why), _) => why,
                (None, Some(c)) => format!("nerve-node ended with exit code {c} and said nothing"),
                (None, None) => "nerve-node was stopped before it answered".into(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The program at `path`, a script of `text`, written by a child so
    /// that no thread of this test holds it open for writing when it runs
    /// (ETXTBSY).
    #[cfg(target_os = "linux")]
    fn script(path: &std::path::Path, text: &str) {
        let made = Command::new("sh")
            .arg("-c")
            .arg("cat > \"$1\" && chmod 755 \"$1\"")
            .arg("sh")
            .arg(path)
            .stdin(Stdio::piped())
            .spawn()
            .and_then(|mut c| {
                c.stdin.take().unwrap().write_all(text.as_bytes())?;
                c.wait()
            })
            .unwrap();
        assert!(made.success());
    }

    /// The app's runs of the CLI get the owner token on a pipe, not in
    /// their environment or arguments, and the app reads it once for each
    /// token the node writes: in a session without the owners' group each
    /// read is a switch to it, which `sg` logs, so the status poll every
    /// few seconds must not read it for every command.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_token_is_read_once_for_each_token_and_handed_on_a_pipe() {
        use std::sync::atomic::AtomicUsize;
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("owner.token");
        std::fs::write(&file, "tok-3f9a1\n").unwrap();
        // What the CLI got: the handed token, whether the environment
        // holds it, and the variable's descriptor.
        let cli = d.path().join("cli");
        script(
            &cli,
            "#!/bin/sh\n\
             t=$(cat \"/proc/self/fd/$NERVE_OWNER_TOKEN_FD\")\n\
             n=0; [ -n \"$t\" ] && n=$(env | grep -c -F -- \"$t\")\n\
             printf '{\"token\":\"%s\",\"env\":%s,\"fd\":%s,\"args\":\"%s\"}\\n' \"$t\" \"$n\" \"$NERVE_OWNER_TOKEN_FD\" \"$*\"\n",
        );
        let reads = Arc::new(AtomicUsize::new(0));
        let tokens = {
            let (file, reads) = (file.clone(), reads.clone());
            Arc::new(Tokens::new(file.clone(), move || {
                reads.fetch_add(1, Ordering::SeqCst);
                std::fs::read_to_string(&file)
                    .ok()
                    .map(|t| t.trim().to_string())
            }))
        };
        let runner = Runner::new(cli, None, None).with_tokens(tokens);
        let got = |r: &Runner| {
            let v = r.run(&["status"]).unwrap();
            assert_eq!(v["env"], 0, "{v}");
            assert!(v["fd"].as_i64().unwrap() > 2, "{v}");
            assert!(!v["args"].as_str().unwrap().contains("tok-"), "{v}");
            v["token"].as_str().unwrap().to_string()
        };
        // The status poll, a page's reads and a follow.
        for _ in 0..6 {
            assert_eq!(got(&runner), "tok-3f9a1");
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let follow = runner
            .follow(&["audit", "--follow"], move |v| {
                let _ = tx.send(v);
            })
            .unwrap();
        let v = rx
            .recv_timeout(std::time::Duration::from_secs(30))
            .unwrap()
            .unwrap();
        assert_eq!(v["token"], "tok-3f9a1");
        drop(follow);
        assert_eq!(reads.load(Ordering::SeqCst), 1);

        // The node started again: a new file with a new token, read once.
        let next = d.path().join(".owner.token.tmp");
        std::fs::write(&next, "tok-77c0e\n").unwrap();
        std::fs::rename(&next, &file).unwrap();
        for _ in 0..4 {
            assert_eq!(got(&runner), "tok-77c0e");
        }
        assert_eq!(reads.load(Ordering::SeqCst), 2);

        // The node stopped: no file, nothing read, an empty pipe handed.
        std::fs::remove_file(&file).unwrap();
        assert_eq!(got(&runner), "");
        assert_eq!(reads.load(Ordering::SeqCst), 2);

        // A read that fails is not tried again for the same file.
        std::fs::write(&file, "tok-1b2c3\n").unwrap();
        let failing = {
            let reads = reads.clone();
            Arc::new(Tokens::new(file.clone(), move || {
                reads.fetch_add(1, Ordering::SeqCst);
                None
            }))
        };
        let runner = runner.with_tokens(failing);
        for _ in 0..3 {
            assert_eq!(got(&runner), "");
        }
        assert_eq!(reads.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn the_answer_is_the_json_on_stdout() {
        let v = answer(true, Some(0), b"{\"daemon\":\"running\"}\n", b"").unwrap();
        assert_eq!(v["daemon"], "running");
        // The error on stdout, not the log's events on stderr.
        let e = answer(
            false,
            Some(1),
            b"{\"error\":\"no center named x\"}\n",
            b"2026-10-18 INFO something\nnerve-node: no center named x\n",
        )
        .unwrap_err();
        assert_eq!(e, "no center named x");
    }

    #[test]
    fn a_run_without_json_says_why_from_stderr() {
        let e = answer(false, Some(2), b"", b"error: unexpected argument '--x'\n\n").unwrap_err();
        assert_eq!(e, "error: unexpected argument '--x'");
        let e = answer(false, Some(1), b"", b"nerve-node: cannot read node.toml\n").unwrap_err();
        assert_eq!(e, "cannot read node.toml");
        let e = answer(false, None, b"", b"").unwrap_err();
        assert!(e.contains("stopped"), "{e}");
        // Success without JSON is no answer either.
        assert!(answer(true, Some(0), b"text\n", b"").is_err());
    }

    #[test]
    fn a_followed_line_is_an_entry_or_the_error() {
        assert_eq!(
            entry("{\"ts\":1,\"msg\":\"x\"}").unwrap().unwrap()["msg"],
            "x"
        );
        assert_eq!(entry("{\"error\":\"gone\"}").unwrap().unwrap_err(), "gone");
        // An entry may have a field named error.
        assert!(entry("{\"ts\":1,\"error\":\"e\"}").unwrap().is_ok());
        assert!(entry("not json").is_none());
    }
}
