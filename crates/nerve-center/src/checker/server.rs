//! The local `llama-server` the center can run itself (docs/dev/action-checker.md).
//!
//! The center does not download llama.cpp; the owner points at a build (or
//! one on `PATH`). The server listens on `127.0.0.1` on a free port, CPU only
//! by default, and llama-server downloads the model (`-hf`) into a cache under
//! the center's state folder. The center checks `/v1/models` says `decisions`
//! and refuses a non-decision model. A server that dies is restarted with
//! backoff; it ends with the center, with no orphan.

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::task::JoinHandle;

use super::config::ModelConfig;
use super::model::{self, Endpoint};

/// How far along the local server is, for the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    Starting,
    Downloading,
    Ready,
    Failed,
}

/// The local server's live state, shown in the UI.
#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub phase: Phase,
    /// The loopback endpoint, once it is listening.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// A reason, when it failed.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub message: String,
    /// The last lines llama-server wrote, so a problem is visible.
    pub output: Vec<String>,
}

const OUTPUT_KEEP: usize = 20;

#[derive(Debug, Default)]
struct Inner {
    phase: Option<Phase>,
    url: Option<String>,
    message: String,
    output: std::collections::VecDeque<String>,
}

/// A running (or restarting) local llama-server. Dropping it ends the server.
pub struct LocalServer {
    inner: Arc<Mutex<Inner>>,
    port: u16,
    task: JoinHandle<()>,
}

impl Drop for LocalServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl LocalServer {
    /// Starts the supervisor for `cfg` in `state_dir`. The model cache goes
    /// under the state folder (`LLAMA_CACHE`). It returns at once; the status
    /// moves from starting to ready (or failed) as the server comes up.
    pub fn start(cfg: &ModelConfig, state_dir: &PathBuf) -> Result<LocalServer, String> {
        if cfg.hf_repo.is_empty() && cfg.model_file.is_empty() {
            return Err("set a model to download (-hf) or a local model file".into());
        }
        let port = free_port()?;
        let inner = Arc::new(Mutex::new(Inner::default()));
        let args = build_args(cfg, port);
        let program = if cfg.llama_server.is_empty() {
            "llama-server".to_string()
        } else {
            cfg.llama_server.clone()
        };
        let cache = state_dir.join("model-cache");
        let gpu = cfg.gpu_layers;
        let timeout = Duration::from_millis(cfg.timeout_ms.max(100));
        let task = tokio::spawn(supervise(
            program, args, cache, gpu, port, timeout, inner.clone(),
        ));
        Ok(LocalServer { inner, port, task })
    }

    /// The endpoint for the client, once the server is listening.
    pub fn endpoint(&self) -> Endpoint {
        Endpoint::parse(&format!("http://127.0.0.1:{}", self.port), None, None)
            .expect("a loopback URL parses")
    }

    pub fn ready(&self) -> bool {
        self.inner.lock().unwrap().phase == Some(Phase::Ready)
    }

    pub fn status(&self) -> Status {
        let i = self.inner.lock().unwrap();
        Status {
            phase: i.phase.unwrap_or(Phase::Starting),
            url: i.url.clone(),
            message: i.message.clone(),
            output: i.output.iter().cloned().collect(),
        }
    }
}

/// The llama-server command line (without the program itself), CPU only
/// unless the owner set GPU layers.
fn build_args(cfg: &ModelConfig, port: u16) -> Vec<String> {
    let mut args = vec![
        "--host".into(),
        "127.0.0.1".into(),
        "--port".into(),
        port.to_string(),
        "-ngl".into(),
        cfg.gpu_layers.to_string(),
    ];
    if cfg.threads > 0 {
        args.push("-t".into());
        args.push(cfg.threads.to_string());
    }
    if !cfg.hf_repo.is_empty() {
        args.push("-hf".into());
        args.push(cfg.hf_repo.clone());
    }
    if !cfg.model_file.is_empty() {
        args.push("-m".into());
        args.push(cfg.model_file.clone());
    }
    args
}

/// A free loopback port: bind to port 0, read the port, and drop the
/// listener. A short race until llama-server binds it; the center accepts it
/// (docs).
fn free_port() -> Result<u16, String> {
    let l = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    l.local_addr().map(|a| a.port()).map_err(|e| e.to_string())
}

/// Runs the server, restarting it with backoff until the task is aborted. A
/// non-decision model is a reason not to restart.
async fn supervise(
    program: String,
    args: Vec<String>,
    cache: PathBuf,
    _gpu: u32,
    port: u16,
    timeout: Duration,
    inner: Arc<Mutex<Inner>>,
) {
    let mut backoff = Duration::from_secs(1);
    loop {
        set(&inner, |i| {
            i.phase = Some(Phase::Starting);
            i.url = None;
        });
        match run_once(&program, &args, &cache, port, timeout, &inner).await {
            RunEnd::NotDecision => {
                // A clear, final failure: do not restart.
                return;
            }
            RunEnd::Exited => {}
            RunEnd::StartFailed(e) => {
                set(&inner, |i| {
                    i.phase = Some(Phase::Failed);
                    i.message = format!("cannot start {program}: {e}");
                });
            }
        }
        // Wait before the next try; a success resets the backoff.
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

enum RunEnd {
    /// The process could not be started.
    StartFailed(String),
    /// It ran and exited (crash or stop); restart after the backoff.
    Exited,
    /// It loaded a model that is not a decision model; do not restart.
    NotDecision,
}

async fn run_once(
    program: &str,
    args: &[String],
    cache: &PathBuf,
    port: u16,
    timeout: Duration,
    inner: &Arc<Mutex<Inner>>,
) -> RunEnd {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .env("LLAMA_CACHE", cache)
        // The owner's own model server is on the GPUs; the local checker
        // model never touches them.
        .env("CUDA_VISIBLE_DEVICES", "")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    cmd.process_group(0);
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return RunEnd::StartFailed(e.to_string()),
    };
    // Follow stderr into the ring buffer, flagging a download.
    if let Some(err) = child.stderr.take() {
        let inner = inner.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(err).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                set(&inner, |i| {
                    if i.phase != Some(Phase::Ready) && is_download(&line) {
                        i.phase = Some(Phase::Downloading);
                    }
                    push_line(&mut i.output, line);
                });
            }
        });
    }
    // Probe until it is ready, it exits, or we are aborted.
    let endpoint = Endpoint::parse(&format!("http://127.0.0.1:{port}"), None, None)
        .expect("a loopback URL parses");
    let url = format!("http://127.0.0.1:{port}");
    loop {
        tokio::select! {
            status = child.wait() => {
                let how = status.map(|s| s.to_string()).unwrap_or_else(|e| e.to_string());
                set(inner, |i| {
                    if i.phase != Some(Phase::Failed) {
                        i.phase = Some(Phase::Starting);
                    }
                    i.url = None;
                    push_line(&mut i.output, format!("llama-server ended ({how})"));
                });
                return RunEnd::Exited;
            }
            _ = tokio::time::sleep(Duration::from_millis(500)) => {
                match tokio::time::timeout(timeout, model::is_decision_model(&endpoint)).await {
                    Ok(Ok(true)) => {
                        set(inner, |i| {
                            i.phase = Some(Phase::Ready);
                            i.url = Some(url.clone());
                            i.message.clear();
                        });
                        // Stay here until the child exits; then restart.
                        let how = child.wait().await
                            .map(|s| s.to_string()).unwrap_or_else(|e| e.to_string());
                        set(inner, |i| {
                            i.phase = Some(Phase::Starting);
                            i.url = None;
                            push_line(&mut i.output, format!("llama-server ended ({how})"));
                        });
                        return RunEnd::Exited;
                    }
                    Ok(Ok(false)) => {
                        set(inner, |i| {
                            i.phase = Some(Phase::Failed);
                            i.message = "the loaded model is not a decision model: /v1/models has no \"decisions\". Use a System One model.".into();
                        });
                        let _ = child.start_kill();
                        let _ = child.wait().await;
                        return RunEnd::NotDecision;
                    }
                    // Not up yet, or a transient error: keep probing.
                    _ => {}
                }
            }
        }
    }
}

fn is_download(line: &str) -> bool {
    let l = line.to_ascii_lowercase();
    l.contains("download") || l.contains("fetching") || l.contains("%|")
}

fn push_line(buf: &mut std::collections::VecDeque<String>, line: String) {
    buf.push_back(line);
    while buf.len() > OUTPUT_KEEP {
        buf.pop_front();
    }
}

fn set(inner: &Arc<Mutex<Inner>>, f: impl FnOnce(&mut Inner)) {
    f(&mut inner.lock().unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_are_cpu_only_by_default() {
        let cfg = ModelConfig {
            hf_repo: "LiquidAI/d1-3B-GGUF:Q4_K_M".into(),
            ..Default::default()
        };
        let args = build_args(&cfg, 12345);
        assert!(args.windows(2).any(|w| w == ["-ngl", "0"]));
        assert!(args.windows(2).any(|w| w == ["--port", "12345"]));
        assert!(args.windows(2).any(|w| w == ["-hf", "LiquidAI/d1-3B-GGUF:Q4_K_M"]));
    }

    #[test]
    fn a_download_line_is_recognised() {
        assert!(is_download("downloading model.gguf"));
        assert!(is_download("  45%|████      | 200M/440M"));
        assert!(!is_download("llama_server: model loaded"));
    }
}
