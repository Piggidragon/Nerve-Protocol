//! Runs `nerve-node` for the app: this same program with arguments, which
//! behaves as `nerve-node` (src/main.rs), with `--json`, and reads its
//! answer (docs/user/commands.md). The app never parses text meant for
//! people, and has the CLI's checks because it runs the CLI.

use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use serde_json::Value;

/// Starts the CLI: which program, and the folders it is given.
#[derive(Debug, Clone)]
pub struct Runner {
    exe: PathBuf,
    dirs: Vec<OsString>,
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
            dirs.push(c.into());
        }
        if let Some(s) = state_dir {
            dirs.push("--state-dir".into());
            dirs.push(s.into());
        }
        Runner { exe, dirs }
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
        let mut cmd = Command::new(&self.exe);
        cmd.args(&self.dirs)
            .arg("--json")
            .args(args)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd
            .spawn()
            .map_err(|e| format!("cannot start {}: {e}", self.exe.display()))?;
        if let Some(text) = input {
            let mut stdin = child.stdin.take().expect("piped");
            // A command that ends before it reads leaves its own answer.
            let _ = stdin.write_all(format!("{text}\n").as_bytes());
        }
        let out = child
            .wait_with_output()
            .map_err(|e| format!("nerve-node did not end: {e}"))?;
        answer(
            out.status.success(),
            out.status.code(),
            &out.stdout,
            &out.stderr,
        )
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
}
